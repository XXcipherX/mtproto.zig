//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const compat = @import("compat.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const proxy = @import("proxy/proxy.zig");
const web_capability = @import("web/capability.zig");
const web_relay = @import("web/relay.zig");

// Custom lock-free log function: formats into a stack buffer and writes
// to stderr in a single write() syscall. On Linux, write() is atomic for
// sizes <= PIPE_BUF (4096 bytes), so messages from different threads
// don't interleave. This avoids the global stderr_mutex that Zig's
// default logger uses, which causes catastrophic contention under
// hundreds of concurrent threads.
// Runtime log level, set from config.toml at startup.
// Checked by lockFreeLog to filter messages without recompilation.
pub var runtime_log_level: std.log.Level = .info;

pub const std_options = std.Options{
    // Set comptime level to .debug so all log calls are compiled in.
    // Runtime filtering is done in lockFreeLog via runtime_log_level.
    .log_level = .debug,
    .logFn = lockFreeLog,
};

// Left-align the standard Zig level name to the longest built-in label. This
// keeps the level, scope, and message columns aligned without padding after
// the scope.
const log_level_field_width: usize = "warning".len;

fn formatLogPrefix(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    out: []u8,
) []u8 {
    const level_txt = comptime message_level.asText();
    const suffix_txt = comptime if (scope == .default) ":" else " (" ++ @tagName(scope) ++ "):";
    const prefix_len = log_level_field_width + suffix_txt.len;

    std.debug.assert(out.len >= prefix_len + 1);
    @memcpy(out[0..level_txt.len], level_txt);
    @memset(out[level_txt.len..log_level_field_width], ' ');
    @memcpy(out[log_level_field_width..prefix_len], suffix_txt);
    out[prefix_len] = ' ';
    return out[0 .. prefix_len + 1];
}

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime filter: skip messages below configured level
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log_level)) return;

    var buf: [4096]u8 = undefined;
    const prefix = formatLogPrefix(message_level, scope, &buf);
    const body = std.fmt.bufPrint(buf[prefix.len..], format ++ "\n", args) catch return;
    compat.writeStderr(buf[0 .. prefix.len + body.len]);
}

const log = std.log.scoped(.mtproto);

// ============= Output Helpers (Zig 0.16 compatible) =============

threadlocal var stdout_accumulator: ?*std.Io.Writer = null;

fn writeStdoutBytes(bytes: []const u8) void {
    if (stdout_accumulator) |writer| {
        writer.writeAll(bytes) catch {};
        return;
    }
    compat.writeStdout(bytes);
}

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeStdoutBytes(slice);
}

/// Write a formatted string to stderr.
fn writeStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    compat.writeStderr(slice);
}

/// Write a hex byte to stdout.
fn writeHexByte(byte: u8) void {
    const hex = "0123456789abcdef";
    const out = [2]u8{ hex[byte >> 4], hex[byte & 0x0f] };
    writeStdoutBytes(&out);
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    writeStdoutBytes(s);
}

fn writeUsage() void {
    writeStderr(
        "\n  Usage: mtproto-proxy [config.toml] [--show-secrets | --print-links]\n" ++
            "         mtproto-proxy --check-config [config.toml]\n" ++
            "         mtproto-proxy web-relay [config.toml]\n\n",
        .{},
    );
}

fn ignoreSigpipe() void {
    if (builtin.os.tag != .linux) return;
    const action = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(.PIPE, &action, null);
}

const invalid_shutdown_event_fd: posix.fd_t = -1;
var shutdown_event_fd = std.atomic.Value(posix.fd_t).init(invalid_shutdown_event_fd);

fn shutdownSignalMask() posix.sigset_t {
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, .INT);
    posix.sigaddset(&mask, .TERM);
    return mask;
}

fn shutdownSignalHandler(_: posix.SIG) callconv(.c) void {
    const fd = shutdown_event_fd.load(.acquire);
    if (fd == invalid_shutdown_event_fd) return;

    const increment: u64 = 1;
    _ = linux.write(fd, @ptrCast(&increment), @sizeOf(u64));
}

const ShutdownSignalBridge = struct {
    fd: posix.fd_t,
    old_int_action: posix.Sigaction,
    old_term_action: posix.Sigaction,
    previous_mask: posix.sigset_t,

    fn init() !ShutdownSignalBridge {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

        const signal_mask = shutdownSignalMask();
        var previous_mask: posix.sigset_t = undefined;
        posix.sigprocmask(posix.SIG.BLOCK, &signal_mask, &previous_mask);
        errdefer posix.sigprocmask(posix.SIG.SETMASK, &previous_mask, null);

        const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        const fd: posix.fd_t = switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        };
        errdefer _ = linux.close(fd);

        shutdown_event_fd.store(fd, .release);
        errdefer shutdown_event_fd.store(invalid_shutdown_event_fd, .release);

        const action = posix.Sigaction{
            .handler = .{ .handler = shutdownSignalHandler },
            .mask = signal_mask,
            .flags = 0,
        };
        var old_int_action: posix.Sigaction = undefined;
        var old_term_action: posix.Sigaction = undefined;
        posix.sigaction(.INT, &action, &old_int_action);
        posix.sigaction(.TERM, &action, &old_term_action);

        posix.sigprocmask(posix.SIG.UNBLOCK, &signal_mask, null);
        return .{
            .fd = fd,
            .old_int_action = old_int_action,
            .old_term_action = old_term_action,
            .previous_mask = previous_mask,
        };
    }

    fn deinit(self: *ShutdownSignalBridge) void {
        const signal_mask = shutdownSignalMask();
        posix.sigprocmask(posix.SIG.BLOCK, &signal_mask, null);

        posix.sigaction(.INT, &self.old_int_action, null);
        posix.sigaction(.TERM, &self.old_term_action, null);
        shutdown_event_fd.store(invalid_shutdown_event_fd, .release);
        _ = linux.close(self.fd);

        posix.sigprocmask(posix.SIG.SETMASK, &self.previous_mask, null);
        self.fd = invalid_shutdown_event_fd;
    }
};

const CapacityEstimate = struct {
    effective_memory_bytes: u64,
    allocatable_bytes: u64,
    per_conn_bytes: u64,
    managed_initial_per_conn_bytes: u64,
    managed_burst_reserve_bytes: u64,
    safe_connections: u32,
};

fn detectTotalRamBytes(allocator: std.mem.Allocator) ?u64 {
    if (builtin.os.tag != .linux) return null;

    if (detectTotalRamBytesSysinfo()) |total| {
        return total;
    }

    const content = compat.readFileAbsoluteAlloc(allocator, "/proc/meminfo", 16 * 1024) catch return null;
    defer allocator.free(content);

    const key = "MemTotal:";
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;

        var i: usize = key.len;
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
        const start = i;
        while (i < line.len and line[i] >= '0' and line[i] <= '9') : (i += 1) {}
        if (i == start) return null;

        const total_kib = std.fmt.parseInt(u64, line[start..i], 10) catch return null;
        return total_kib * 1024;
    }

    return null;
}

fn detectTotalRamBytesSysinfo() ?u64 {
    if (builtin.os.tag != .linux) return null;

    var info: std.os.linux.Sysinfo = undefined;
    const rc = std.os.linux.sysinfo(&info);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;

    const mem_unit: u128 = if (info.mem_unit == 0) 1 else info.mem_unit;
    const total_bytes: u128 = @as(u128, info.totalram) * mem_unit;
    if (total_bytes == 0 or total_bytes > std.math.maxInt(u64)) return null;
    return @intCast(total_bytes);
}

const CgroupVersion = enum {
    v1,
    v2,
};

const CgroupMount = struct {
    version: CgroupVersion,
    root: []const u8,
    mount_point: []const u8,
};

fn parseCgroupMemoryLimit(version: CgroupVersion, content: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, content, &[_]u8{ ' ', '\t', '\n', '\r' });
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "max")) return null;
    const limit = std.fmt.parseInt(u64, trimmed, 10) catch return null;
    return switch (version) {
        // cgroup v1 represents an unlimited controller with zero or a huge
        // architecture-dependent sentinel.
        .v1 => if (limit == 0 or limit >= (@as(u64, 1) << 60)) null else limit,
        // In cgroup v2 only the literal "max" is unlimited. Numeric zero is a
        // real hard limit and must fail the startup capacity check.
        .v2 => limit,
    };
}

fn readCgroupMemoryLimitFile(
    allocator: std.mem.Allocator,
    version: CgroupVersion,
    path: []const u8,
) ?u64 {
    const content = compat.readFileAbsoluteAlloc(allocator, path, 256) catch return null;
    defer allocator.free(content);
    return parseCgroupMemoryLimit(version, content);
}

fn minMemoryLimit(current: ?u64, candidate: ?u64) ?u64 {
    const value = candidate orelse return current;
    return if (current) |existing| @min(existing, value) else value;
}

fn controllerListContains(controllers: []const u8, expected: []const u8) bool {
    var items = std.mem.splitScalar(u8, controllers, ',');
    while (items.next()) |controller| {
        if (std.mem.eql(u8, controller, expected)) return true;
    }
    return false;
}

fn parseCgroupMountLine(line: []const u8) ?CgroupMount {
    var fields = std.mem.tokenizeScalar(u8, line, ' ');
    _ = fields.next() orelse return null; // mount ID
    _ = fields.next() orelse return null; // parent ID
    _ = fields.next() orelse return null; // major:minor
    const root = fields.next() orelse return null;
    const mount_point = fields.next() orelse return null;
    _ = fields.next() orelse return null; // mount options

    while (fields.next()) |field| {
        if (!std.mem.eql(u8, field, "-")) continue;

        const fs_type = fields.next() orelse return null;
        _ = fields.next() orelse return null; // mount source
        const super_options = fields.next() orelse return null;
        if (std.mem.eql(u8, fs_type, "cgroup2")) {
            return .{ .version = .v2, .root = root, .mount_point = mount_point };
        }
        if (std.mem.eql(u8, fs_type, "cgroup") and
            controllerListContains(super_options, "memory"))
        {
            return .{ .version = .v1, .root = root, .mount_point = mount_point };
        }
        return null;
    }
    return null;
}

fn decodeMountInfoPath(encoded: []const u8, output: []u8) ?[]const u8 {
    var source_index: usize = 0;
    var output_index: usize = 0;
    while (source_index < encoded.len) {
        if (output_index == output.len) return null;
        if (encoded[source_index] != '\\') {
            output[output_index] = encoded[source_index];
            source_index += 1;
            output_index += 1;
            continue;
        }

        if (source_index + 3 >= encoded.len) return null;
        const digits = encoded[source_index + 1 .. source_index + 4];
        var value: u16 = 0;
        for (digits) |digit| {
            if (digit < '0' or digit > '7') return null;
            value = value * 8 + @as(u16, digit - '0');
        }
        if (value == 0 or value > std.math.maxInt(u8)) return null;
        output[output_index] = @intCast(value);
        source_index += 4;
        output_index += 1;
    }
    return output[0..output_index];
}

fn isSafeAbsoluteCgroupPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

fn pathIsWithin(child: []const u8, parent: []const u8) bool {
    if (std.mem.eql(u8, parent, "/")) return child.len > 0 and child[0] == '/';
    if (!std.mem.startsWith(u8, child, parent)) return false;
    return child.len == parent.len or child[parent.len] == '/';
}

fn parentCgroupPath(path: []const u8) ?[]const u8 {
    if (!isSafeAbsoluteCgroupPath(path) or std.mem.eql(u8, path, "/")) return null;
    const trimmed = std.mem.trimEnd(u8, path, "/");
    if (trimmed.len <= 1) return "/";
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return null;
    return if (slash == 0) "/" else trimmed[0..slash];
}

fn mountedCgroupLeafPath(
    output: []u8,
    mount_point: []const u8,
    mount_root: []const u8,
    membership: []const u8,
) ?[]const u8 {
    if (!isSafeAbsoluteCgroupPath(mount_point) or
        !isSafeAbsoluteCgroupPath(mount_root) or
        !isSafeAbsoluteCgroupPath(membership))
    {
        return null;
    }

    const normalized_mount = if (mount_point.len > 1)
        std.mem.trimEnd(u8, mount_point, "/")
    else
        mount_point;
    var relative = membership;
    if (std.mem.eql(u8, membership, "/")) {
        relative = "";
    } else if (!std.mem.eql(u8, mount_root, "/") and pathIsWithin(membership, mount_root)) {
        relative = membership[mount_root.len..];
    } else if (!std.mem.eql(u8, mount_root, "/")) {
        // A non-root mount can be a bind of an unrelated cgroup subtree.
        // Do not guess a namespace-relative mapping for a non-root membership:
        // a false match could invent a smaller limit and refuse startup.
        return null;
    }

    if (relative.len == 0) {
        return std.fmt.bufPrint(output, "{s}", .{normalized_mount}) catch null;
    }
    if (std.mem.eql(u8, normalized_mount, "/")) {
        return std.fmt.bufPrint(output, "{s}", .{relative}) catch null;
    }
    return std.fmt.bufPrint(output, "{s}{s}", .{ normalized_mount, relative }) catch null;
}

fn scanCgroupHierarchy(
    allocator: std.mem.Allocator,
    version: CgroupVersion,
    mount_point: []const u8,
    leaf: []const u8,
) ?u64 {
    if (!pathIsWithin(leaf, mount_point)) return null;

    const filename = switch (version) {
        .v1 => "memory.limit_in_bytes",
        .v2 => "memory.max",
    };
    var best: ?u64 = null;
    var current = leaf;
    while (true) {
        var limit_path_buf: [4096]u8 = undefined;
        const limit_path: ?[]const u8 = if (std.mem.eql(u8, current, "/"))
            std.fmt.bufPrint(&limit_path_buf, "/{s}", .{filename}) catch null
        else
            std.fmt.bufPrint(&limit_path_buf, "{s}/{s}", .{ current, filename }) catch null;
        if (limit_path) |path| {
            best = minMemoryLimit(
                best,
                readCgroupMemoryLimitFile(allocator, version, path),
            );
        }

        if (std.mem.eql(u8, current, mount_point)) break;
        const parent = parentCgroupPath(current) orelse break;
        if (!pathIsWithin(parent, mount_point)) break;
        current = parent;
    }
    return best;
}

fn scanMountedCgroup(
    allocator: std.mem.Allocator,
    mount: CgroupMount,
    membership: []const u8,
    mapped: *bool,
) ?u64 {
    mapped.* = false;
    var root_buf: [4096]u8 = undefined;
    const mount_root = decodeMountInfoPath(mount.root, &root_buf) orelse return null;
    var mount_point_buf: [4096]u8 = undefined;
    const mount_point = decodeMountInfoPath(mount.mount_point, &mount_point_buf) orelse return null;
    var leaf_buf: [4096]u8 = undefined;
    const leaf = mountedCgroupLeafPath(
        &leaf_buf,
        mount_point,
        mount_root,
        membership,
    ) orelse return null;
    mapped.* = true;
    return scanCgroupHierarchy(allocator, mount.version, mount_point, leaf);
}

fn scanConventionalCgroupMounts(
    allocator: std.mem.Allocator,
    v1_membership: ?[]const u8,
    v2_membership: ?[]const u8,
) ?u64 {
    var best: ?u64 = null;
    best = minMemoryLimit(
        best,
        readCgroupMemoryLimitFile(allocator, .v2, "/sys/fs/cgroup/memory.max"),
    );
    best = minMemoryLimit(
        best,
        readCgroupMemoryLimitFile(
            allocator,
            .v1,
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ),
    );
    var mapped = false;
    if (v2_membership) |cgroup_path| {
        best = minMemoryLimit(best, scanMountedCgroup(
            allocator,
            .{ .version = .v2, .root = "/", .mount_point = "/sys/fs/cgroup" },
            cgroup_path,
            &mapped,
        ));
    }
    if (v1_membership) |cgroup_path| {
        best = minMemoryLimit(best, scanMountedCgroup(
            allocator,
            .{ .version = .v1, .root = "/", .mount_point = "/sys/fs/cgroup/memory" },
            cgroup_path,
            &mapped,
        ));
    }
    return best;
}

fn detectCgroupMemoryLimitBytes(allocator: std.mem.Allocator) ?u64 {
    if (builtin.os.tag != .linux) return null;

    const membership = compat.readFileAbsoluteAlloc(
        allocator,
        "/proc/self/cgroup",
        64 * 1024,
    ) catch return scanConventionalCgroupMounts(allocator, null, null);
    defer allocator.free(membership);
    var v1_membership: ?[]const u8 = null;
    var v2_membership: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, membership, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first_colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const second_rel = std.mem.indexOfScalar(u8, line[first_colon + 1 ..], ':') orelse continue;
        const second_colon = first_colon + 1 + second_rel;
        const hierarchy = line[0..first_colon];
        const controllers = line[first_colon + 1 .. second_colon];
        const cgroup_path = line[second_colon + 1 ..];
        if (!isSafeAbsoluteCgroupPath(cgroup_path)) continue;

        if (std.mem.eql(u8, hierarchy, "0") and controllers.len == 0) {
            v2_membership = cgroup_path;
        } else if (controllerListContains(controllers, "memory")) {
            v1_membership = cgroup_path;
        }
    }

    const mountinfo = compat.readFileAbsoluteAlloc(
        allocator,
        "/proc/self/mountinfo",
        1024 * 1024,
    ) catch return scanConventionalCgroupMounts(
        allocator,
        v1_membership,
        v2_membership,
    );
    defer allocator.free(mountinfo);
    var best: ?u64 = null;
    var mapped_any = false;
    var mount_lines = std.mem.splitScalar(u8, mountinfo, '\n');
    while (mount_lines.next()) |line| {
        const mount = parseCgroupMountLine(line) orelse continue;
        const cgroup_path = switch (mount.version) {
            .v1 => v1_membership,
            .v2 => v2_membership,
        } orelse continue;
        var mapped = false;
        best = minMemoryLimit(
            best,
            scanMountedCgroup(allocator, mount, cgroup_path, &mapped),
        );
        mapped_any = mapped_any or mapped;
    }
    return if (mapped_any)
        best
    else
        scanConventionalCgroupMounts(allocator, v1_membership, v2_membership);
}

fn detectEffectiveMemoryBytes(allocator: std.mem.Allocator) ?u64 {
    const host = detectTotalRamBytes(allocator);
    const cgroup = detectCgroupMemoryLimitBytes(allocator);
    if (host) |host_bytes| {
        if (cgroup) |limit| return @min(host_bytes, limit);
        return host_bytes;
    }
    return cgroup;
}

fn percentOfMemory(value: u64, percent: u8) u64 {
    return @intCast((@as(u128, value) * @as(u128, percent)) / 100);
}

fn estimateCapacity(cfg: *const config.Config, total_ram_bytes: u64) CapacityEstimate {
    // Guaranteed per-connection baseline in the epoll model. Relay queue pages,
    // MiddleProxy growth, and shared scratch are charged to one runtime-enforced
    // managed budget instead of multiplying their rare maxima by every slot.
    const tls_working_bytes: u64 = @intCast(6 * 1024);
    const requires_middle_proxy_runtime = cfg.requiresMiddleProxyRuntime();
    const managed_initial_per_conn_bytes: u64 = if (requires_middle_proxy_runtime)
        @intCast(config.Config.middle_proxy_initial_stream_buffer_bytes * 2)
    else
        0;
    const overhead_bytes: u64 = 2 * 1024;
    const per_conn_bytes =
        tls_working_bytes +
        managed_initial_per_conn_bytes +
        overhead_bytes;

    // Keep safety headroom for kernel TCP memory, page cache, and baseline process state.
    const usable_bytes = percentOfMemory(total_ram_bytes, 70);
    const reserve_bytes = @max(
        @as(u64, 256 * 1024 * 1024),
        percentOfMemory(total_ram_bytes, 10),
    );
    const allocatable_bytes = if (usable_bytes > reserve_bytes) usable_bytes - reserve_bytes else 0;

    // Half of the post-reserve budget is a shared hard ceiling for queue pages,
    // MP stream-buffer capacity, and MP scratch. The other half guarantees the
    // fixed baseline for every admitted connection.
    const managed_burst_reserve_bytes = allocatable_bytes / 2;
    const connection_budget_bytes = allocatable_bytes - managed_burst_reserve_bytes;

    const raw_cap = if (per_conn_bytes > 0) connection_budget_bytes / per_conn_bytes else 0;
    const safe_connections_u64 = @min(raw_cap, @as(u64, std.math.maxInt(u32)));

    return .{
        .effective_memory_bytes = total_ram_bytes,
        .allocatable_bytes = allocatable_bytes,
        .per_conn_bytes = per_conn_bytes,
        .managed_initial_per_conn_bytes = managed_initial_per_conn_bytes,
        .managed_burst_reserve_bytes = managed_burst_reserve_bytes,
        .safe_connections = @intCast(safe_connections_u64),
    };
}

fn managedBufferLimitForConnections(
    capacity_estimate: ?CapacityEstimate,
    max_connections: u32,
) u64 {
    const est = capacity_estimate orelse return proxy.default_managed_buffer_limit_bytes;
    if (est.per_conn_bytes < est.managed_initial_per_conn_bytes) return 0;
    const unmanaged_per_conn_bytes =
        est.per_conn_bytes - est.managed_initial_per_conn_bytes;
    const unmanaged_total_wide =
        @as(u128, unmanaged_per_conn_bytes) * @as(u128, max_connections);
    if (unmanaged_total_wide >= @as(u128, est.allocatable_bytes)) return 0;

    const max_managed_bytes =
        est.allocatable_bytes - @as(u64, @intCast(unmanaged_total_wide));
    const managed_initial_wide =
        @as(u128, est.managed_initial_per_conn_bytes) * @as(u128, max_connections);
    const desired_wide =
        @as(u128, est.managed_burst_reserve_bytes) + managed_initial_wide;
    return @intCast(@min(
        desired_wide,
        @as(u128, max_managed_bytes),
    ));
}

fn enforceCapacitySafety(cfg: *config.Config, capacity_estimate: ?CapacityEstimate) !void {
    const est = capacity_estimate orelse {
        if (builtin.os.tag == .linux and !cfg.unsafe_override_limits) {
            const log_main = std.log.scoped(.config);
            log_main.warn(
                "could not detect total RAM; skipping max_connections RAM admission clamp. " ++
                    "set a conservative [server].max_connections to avoid OOM.",
                .{},
            );
        }
        return;
    };

    if (est.safe_connections < 32) {
        const log_main = std.log.scoped(.config);
        if (cfg.unsafe_override_limits) {
            log_main.warn(
                "baseline RAM ceiling is only {d} connections; " ++
                    "unsafe_override_limits=true, keeping configured limit {d}",
                .{ est.safe_connections, cfg.max_connections },
            );
            return;
        }
        log_main.warn(
            "baseline RAM ceiling is {d} connections, below the minimum supported capacity of 32",
            .{est.safe_connections},
        );
        return error.InsufficientMemoryBudget;
    }

    if (cfg.max_connections <= est.safe_connections) return;

    const log_main = std.log.scoped(.config);
    if (cfg.unsafe_override_limits) {
        log_main.warn(
            "max_connections={d} exceeds baseline RAM ceiling ({d}); " ++
                "unsafe_override_limits=true, keeping configured limit.",
            .{ cfg.max_connections, est.safe_connections },
        );
        return;
    }

    const configured_limit = cfg.max_connections;
    cfg.max_connections = est.safe_connections;

    log_main.warn(
        "auto-clamping max_connections from {d} to baseline RAM ceiling {d} " ++
            "(effective memory limit {d} MiB, ~{d} KiB baseline/connection). " ++
            "To disable this RAM admission clamp, set unsafe_override_limits = true in [server].",
        .{
            configured_limit,
            est.safe_connections,
            est.effective_memory_bytes / (1024 * 1024),
            est.per_conn_bytes / 1024,
        },
    );
}

// ============= Startup Banner =============

fn writeConnectionLinkEntries(cfg: config.Config) void {
    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const magenta = "\x1b[35m";
    const red = "\x1b[31m";

    // Public discovery used by MiddleProxy runs is intentionally not available
    // while rendering links, so they require an explicitly configured address.
    const has_ip = cfg.public_ip != null;
    const server_ip = cfg.public_ip orelse "<SERVER_IP>";
    const web_only = cfg.web.onlyActive();
    if (!has_ip and !web_only) {
        writeRaw("      " ++ red ++ "⚠  public_ip is not configured; replace <SERVER_IP> manually." ++ R ++ "\n");
    }

    var web_domain_buf: [web_capability.max_host_len]u8 = undefined;
    const web_domain: ?[]const u8 = blk: {
        if (!cfg.web.enabled) break :blk null;
        const raw = cfg.web.domain orelse break :blk null;
        break :blk web_capability.normalizeHost(raw, &web_domain_buf) catch null;
    };

    var users = cfg.users;
    var it = users.iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ B ++ magenta ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});

        if (!web_only) {
            writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "proxy?server={s}&port={d}&secret=", .{ server_ip, cfg.port });
            writeRaw(green ++ "ee");
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");

            writeStdout("      " ++ D ++ "t.me/proxy?server={s}&port={d}&secret=ee", .{ server_ip, cfg.port });
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");
        }

        if (web_domain) |domain| {
            writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "webproxy?server={s}&secret=" ++ green ++ "dd", .{domain});
            for (entry.value_ptr.*) |byte| writeHexByte(byte);
            writeRaw(R ++ "\n");

            writeStdout("      " ++ D ++ "t.me/webproxy?server={s}&secret=dd", .{domain});
            for (entry.value_ptr.*) |byte| writeHexByte(byte);
            writeRaw(R ++ "\n");
        }
    }
}

fn runWebRelay(allocator: std.mem.Allocator, cfg: *const config.Config) !void {
    var domain_buf: [web_capability.max_host_len]u8 = undefined;
    var opts = web_relay.Options.fromConfig(cfg, &domain_buf) catch |err| {
        const hint = switch (err) {
            error.WebProxyDisabled => "set [web].enabled = true",
            error.MissingDomain => "set [web].domain to the public WEB hostname",
            error.InvalidDomain => "[web].domain must be an ASCII DNS hostname, not an IP",
            error.InvalidBackend => "[web].backend must be host:port",
            error.NoUsersConfigured => "add at least one [access.users] entry",
        };
        writeStderr("web relay cannot start: {s} ({s})\n", .{ @errorName(err), hint });
        return err;
    };
    opts.backend = web_relay.resolveBackend(allocator, cfg) catch |err| {
        writeStderr("web relay cannot resolve [web].backend: {s}\n", .{@errorName(err)});
        return err;
    };

    var relay = try web_relay.Relay.init(allocator, opts, cfg);
    defer relay.deinit();
    try relay.run();
}

/// Print connection links and return without starting the proxy.
fn printConnectionLinks(cfg: config.Config) void {
    var output = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer output.deinit();
    stdout_accumulator = &output.writer;
    defer stdout_accumulator = null;

    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const yellow = "\x1b[33m";

    writeRaw("\n  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CONNECTION LINKS" ++ R ++ " " ++ D ++ "────────────────────────────" ++ R ++ "\n");
    writeConnectionLinkEntries(cfg);
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ yellow ++ "Links contain access secrets; keep this terminal private." ++ R ++ "\n\n");

    stdout_accumulator = null;
    compat.writeStdout(output.written());
}

/// Print a stylish startup banner with config summary.
fn printBanner(
    cfg: config.Config,
    capacity_estimate: ?CapacityEstimate,
    managed_buffer_limit_bytes: u64,
    show_secrets: bool,
) void {
    var output = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer output.deinit();
    stdout_accumulator = &output.writer;
    defer stdout_accumulator = null;

    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const white = "\x1b[97m";

    // Public discovery used by MiddleProxy runs after the listener is ready.
    // Connection links therefore use only an explicitly configured address.
    const has_ip = cfg.public_ip != null;
    const server_ip = cfg.public_ip orelse "<SERVER_IP>";

    // Logo
    writeRaw("\n" ++ B ++ cyan);
    writeRaw("       __  __ _____ ____            _\n");
    writeRaw("      |  \\/  |_   _|  _ \\ _ __ ___ | |_ ___\n");
    writeRaw("      | |\\/| | | | | |_) | '__/ _ \\| __/ _ \\\n");
    writeRaw("      | |  | | | | |  __/| | | (_) | || (_) |\n");
    writeRaw("      |_|  |_| |_| |_|   |_|  \\___/ \\__\\___/\n");
    writeRaw(R);
    writeStdout("      {s}{s}zig edition{s}\n\n", .{ D, white, R });

    // ─── SERVER ─────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SERVER" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    writeStdout("      Listen       " ++ B ++ green ++ "0.0.0.0:{d}" ++ R ++ "\n", .{cfg.port});
    writeStdout("      Public IP    " ++ B ++ "{s}{s}" ++ R ++ "\n", .{
        if (has_ip) green else yellow,
        server_ip,
    });
    writeStdout("      TLS Domain   " ++ B ++ yellow ++ "{s}" ++ R ++ "\n", .{cfg.tls_domain});
    writeRaw("      Masking      " ++ B);
    if (cfg.mask) {
        writeRaw(green ++ "enabled");
    } else {
        writeRaw(yellow ++ "disabled");
    }
    writeRaw(R ++ "\n");
    writeRaw("      WEB Proxy    " ++ B);
    if (cfg.web.enabled) {
        writeStdout(
            green ++ "{s}" ++ R ++ " ({s})",
            .{ if (cfg.web.onlyActive()) "WEB-only" else "enabled", cfg.web.domain orelse "domain missing" },
        );
    } else {
        writeRaw(D ++ "disabled" ++ R);
    }
    writeRaw("\n\n");

    if (capacity_estimate) |est| {
        const capacity_mode = if (cfg.use_middle_proxy)
            "middleproxy mode"
        else if (cfg.force_media_middle_proxy)
            "media middleproxy mode"
        else
            "direct DC1..5 + required DC203 middleproxy";
        writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CAPACITY" ++ R ++ " " ++ D ++ "────────────────────────────────────" ++ R ++ "\n");
        writeStdout("      Memory limit " ++ B ++ "{d} MiB" ++ R ++ "\n", .{est.effective_memory_bytes / (1024 * 1024)});
        writeStdout("      Baseline     ~{d} KiB/connection ({s})\n", .{
            est.per_conn_bytes / 1024,
            capacity_mode,
        });
        writeStdout("      Dynamic pool ~{d} MiB shared hard limit\n", .{
            managed_buffer_limit_bytes / (1024 * 1024),
        });
        writeStdout("      RAM ceiling  " ++ B ++ "~{d}" ++ R ++ " baseline connections\n", .{est.safe_connections});
        writeStdout("      Configured   " ++ B ++ "{d}" ++ R ++ " connections\n", .{cfg.max_connections});
        if (cfg.web.enabled) {
            const web_slots = @as(u64, cfg.web.max_sessions) * (@as(u64, cfg.web.max_streams) + 1);
            writeStdout("      WEB budget   up to {d} slots ({d} sessions × ({d} streams + carrier))\n", .{
                web_slots,
                cfg.web.max_sessions,
                cfg.web.max_streams,
            });
        }
        writeRaw("      Admission    pauses at 90%, resumes at 80%\n");
        if (cfg.max_connections > est.safe_connections) {
            writeStdout("      " ++ yellow ++ "configured limit exceeds baseline RAM ceiling" ++ R ++ "\n", .{});
        }
        writeRaw("\n");
    }

    // ─── USERS ──────────────────────────────────────
    writeStdout("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "USERS" ++ R ++ " ({d}) " ++ D ++ "────────────────────────────────────" ++ R ++ "\n", .{cfg.users.count()});
    var users = cfg.users;
    var it = users.iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ green ++ "●" ++ R ++ " " ++ B ++ "{s}" ++ R, .{entry.key_ptr.*});
        if (show_secrets) {
            writeRaw("  " ++ D);
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
        } else {
            writeRaw("  " ++ D ++ "secret redacted");
        }
        writeRaw(R ++ "\n");
    }
    writeRaw("\n");

    // ─── LINKS ──────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "LINKS" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    if (!show_secrets) {
        writeRaw("      Secrets and connection links are hidden by default.\n");
        writeRaw("      Use --print-links only in a private terminal.\n");
    } else {
        writeConnectionLinkEntries(cfg);
    }

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Waiting for connections..." ++ R ++ "\n\n");

    stdout_accumulator = null;
    compat.writeStdout(output.written());
}

pub fn main(init: std.process.Init) !void {
    // Use page_allocator instead of GeneralPurposeAllocator for production.
    // GPA has an internal mutex that causes deadlocks under heavy thread contention
    // (1000+ simultaneous connections all doing TLS validation allocations).
    const allocator = std.heap.page_allocator;
    ignoreSigpipe();

    // Parse config path and explicit secret-display modes.
    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    var config_path: []const u8 = "config.toml";
    var config_path_set = false;
    var show_secrets = false;
    var print_links = false;
    var check_config = false;
    var web_relay_mode = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "web-relay") and !config_path_set and !web_relay_mode) {
            web_relay_mode = true;
        } else if (std.mem.eql(u8, arg, "--show-secrets")) {
            show_secrets = true;
        } else if (std.mem.eql(u8, arg, "--print-links")) {
            print_links = true;
        } else if (std.mem.eql(u8, arg, "--check-config")) {
            check_config = true;
        } else if (!config_path_set) {
            config_path = arg;
            config_path_set = true;
        } else {
            writeUsage();
            return error.InvalidArguments;
        }
    }

    if ((show_secrets and print_links) or
        (check_config and (show_secrets or print_links or web_relay_mode)))
    {
        writeUsage();
        return error.InvalidArguments;
    }

    // Parse config
    var cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeUsage();
        return err;
    };
    defer cfg.deinit(allocator);

    // Apply runtime log level from config
    runtime_log_level = cfg.log_level;

    cfg.validate() catch |err| {
        writeStderr(
            "\x1b[1m\x1b[31m  ✗ Invalid config '{s}': {s} ({s})\x1b[0m\n",
            .{ config_path, config.Config.validationErrorMessage(err), @errorName(err) },
        );
        return err;
    };

    if (check_config) {
        writeStdout("Config '{s}' is valid\n", .{config_path});
        return;
    }

    if (web_relay_mode) {
        if (show_secrets or print_links) return error.InvalidArguments;
        cfg.emitWarnings();
        return runWebRelay(allocator, &cfg);
    }

    if (print_links) {
        printConnectionLinks(cfg);
        return;
    }

    var shutdown_signals = try ShutdownSignalBridge.init();
    defer shutdown_signals.deinit();

    if (!std.crypto.core.aes.has_hardware_support and (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)) {
        const log_main = std.log.scoped(.config);
        log_main.warn(
            "AES backend is software-only for this build/target. MiddleProxy video traffic will be CPU-heavy. " ++
                "Rebuild with CPU features enabled (example: -Dcpu=native or -Dcpu=x86_64_v3+aes).",
            .{},
        );
    }

    const capacity_estimate = if (detectEffectiveMemoryBytes(allocator)) |memory_limit|
        estimateCapacity(&cfg, memory_limit)
    else
        null;

    try enforceCapacitySafety(&cfg, capacity_estimate);
    const managed_buffer_limit_bytes =
        managedBufferLimitForConnections(capacity_estimate, cfg.max_connections);

    // Print the startup banner without blocking on external discovery.
    printBanner(
        cfg,
        capacity_estimate,
        managed_buffer_limit_bytes,
        show_secrets,
    );

    // Emit config warnings (e.g. buffer too small, memory concerns)
    cfg.emitWarnings();

    // Create shared state (DI — no globals)
    var state = try proxy.ProxyState.initWithManagedBufferLimit(
        allocator,
        cfg,
        managed_buffer_limit_bytes,
    );
    defer state.deinit();

    // Run the proxy
    try state.run(shutdown_signals.fd);
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
    _ = @import("proxy/web_support.zig");
    _ = @import("web/frame.zig");
    _ = @import("web/capability.zig");
    _ = @import("web/ws.zig");
    _ = @import("web/http.zig");
    _ = @import("web/page.zig");
    _ = web_relay;
}

test "shutdown signal mask covers SIGINT and SIGTERM" {
    const mask = shutdownSignalMask();
    try std.testing.expect(posix.sigismember(&mask, .INT));
    try std.testing.expect(posix.sigismember(&mask, .TERM));
}

test "capacity safety clamp enforces safe cap when override disabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 2 * 1024 * 1024 * 1024,
        .allocatable_bytes = 1200 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 256 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 585), cfg.max_connections);
}

test "capacity safety clamp keeps configured limit when override enabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = true,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 2 * 1024 * 1024 * 1024,
        .allocatable_bytes = 1200 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 256 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 4096), cfg.max_connections);
}

test "capacity estimate accounts for mandatory DC 203 MiddleProxy overhead" {
    var direct_cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
        .middleproxy_buffer_kb = 1024,
    };
    defer direct_cfg.deinit(std.testing.allocator);

    var media_cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = true,
        .middleproxy_buffer_kb = 1024,
    };
    defer media_cfg.deinit(std.testing.allocator);

    const total_ram_bytes: u64 = 2 * 1024 * 1024 * 1024;
    const direct_est = estimateCapacity(&direct_cfg, total_ram_bytes);
    const media_est = estimateCapacity(&media_cfg, total_ram_bytes);

    try std.testing.expectEqual(media_est.managed_initial_per_conn_bytes, direct_est.managed_initial_per_conn_bytes);
    try std.testing.expectEqual(media_est.per_conn_bytes, direct_est.per_conn_bytes);
    try std.testing.expectEqual(media_est.safe_connections, direct_est.safe_connections);
}

test "capacity estimate reserves one shared managed buffer pool" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const total_ram_bytes: u64 = 960 * 1024 * 1024;
    const est = estimateCapacity(&cfg, total_ram_bytes);

    try std.testing.expectEqual(@as(u64, 416 * 1024 * 1024), est.allocatable_bytes);
    try std.testing.expectEqual(@as(u64, 208 * 1024 * 1024), est.managed_burst_reserve_bytes);

    try std.testing.expectEqual(
        @as(u64, 2 * config.Config.middle_proxy_initial_stream_buffer_bytes),
        est.managed_initial_per_conn_bytes,
    );
    try std.testing.expectEqual(@as(u64, 40 * 1024), est.per_conn_bytes);
    try std.testing.expectEqual(@as(u32, 5_324), est.safe_connections);
    try std.testing.expectEqual(
        @as(u64, 216 * 1024 * 1024),
        managedBufferLimitForConnections(est, 256),
    );

    const unmanaged_per_conn =
        est.per_conn_bytes - est.managed_initial_per_conn_bytes;
    const safe_limit =
        managedBufferLimitForConnections(est, est.safe_connections);
    try std.testing.expect(
        safe_limit +
            @as(u64, est.safe_connections) * unmanaged_per_conn <=
            est.allocatable_bytes,
    );

    const overridden_connections = est.safe_connections + 1;
    try std.testing.expectEqual(
        est.allocatable_bytes -
            @as(u64, overridden_connections) * unmanaged_per_conn,
        managedBufferLimitForConnections(est, overridden_connections),
    );
    try std.testing.expectEqual(
        proxy.default_managed_buffer_limit_bytes,
        managedBufferLimitForConnections(null, 256),
    );
}

test "capacity estimate handles the largest finite cgroup v2 limit" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    const est = estimateCapacity(&cfg, std.math.maxInt(u64));
    try std.testing.expectEqual(std.math.maxInt(u64), est.effective_memory_bytes);
    try std.testing.expectEqual(std.math.maxInt(u32), est.safe_connections);
}

test "cgroup memory limit parser distinguishes v1 and v2 unlimited values" {
    try std.testing.expectEqual(
        @as(?u64, 536_870_912),
        parseCgroupMemoryLimit(.v1, "536870912\n"),
    );
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit(.v1, "0\n"));
    try std.testing.expectEqual(
        @as(?u64, null),
        parseCgroupMemoryLimit(.v1, "9223372036854771712\n"),
    );
    try std.testing.expectEqual(@as(?u64, 0), parseCgroupMemoryLimit(.v2, "0\n"));
    try std.testing.expectEqual(
        @as(?u64, @as(u64, 1) << 60),
        parseCgroupMemoryLimit(.v2, "1152921504606846976\n"),
    );
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit(.v2, "max\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit(.v2, "invalid\n"));
}

test "cgroup helpers preserve controller and ancestor boundaries" {
    try std.testing.expect(controllerListContains("cpu,memory,io", "memory"));
    try std.testing.expect(!controllerListContains("cpu,notmemory,io", "memory"));
    try std.testing.expectEqualStrings("/tenant/service", parentCgroupPath("/tenant/service/leaf").?);
    try std.testing.expectEqualStrings("/tenant", parentCgroupPath("/tenant/service").?);
    try std.testing.expectEqualStrings("/", parentCgroupPath("/tenant").?);
    try std.testing.expect(parentCgroupPath("/") == null);
    try std.testing.expectEqualStrings("/tenant", parentCgroupPath("/tenant/service///").?);
}

test "cgroup mountinfo parser maps namespaced and subtree paths" {
    const mount = parseCgroupMountLine(
        "36 25 0:32 /tenant /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw",
    ).?;
    try std.testing.expectEqual(CgroupVersion.v2, mount.version);

    var path_buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/sys/fs/cgroup/service",
        mountedCgroupLeafPath(&path_buf, mount.mount_point, mount.root, "/tenant/service").?,
    );
    try std.testing.expectEqualStrings(
        "/sys/fs/cgroup",
        mountedCgroupLeafPath(&path_buf, mount.mount_point, mount.root, "/").?,
    );
    try std.testing.expect(
        mountedCgroupLeafPath(&path_buf, mount.mount_point, "/other", "/tenant/service") == null,
    );

    const v1_mount = parseCgroupMountLine(
        "40 25 0:35 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory",
    ).?;
    try std.testing.expectEqual(CgroupVersion.v1, v1_mount.version);
    try std.testing.expect(
        parseCgroupMountLine("41 25 0:36 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu") == null,
    );
}

test "capacity safety refuses a budget below the supported minimum" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 32,
        .unsafe_override_limits = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 128 * 1024 * 1024,
        .allocatable_bytes = 0,
        .per_conn_bytes = 8 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 0,
        .safe_connections = 0,
    };
    try std.testing.expectError(error.InsufficientMemoryBudget, enforceCapacitySafety(&cfg, est));
}
