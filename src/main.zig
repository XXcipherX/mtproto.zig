//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const compat = @import("compat.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const proxy = @import("proxy/proxy.zig");

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

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime filter: skip messages below configured level
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log_level)) return;

    const level_txt = comptime message_level.asText();
    const prefix2 = comptime if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
    compat.writeStderr(msg);
}

const log = std.log.scoped(.mtproto);

// ============= Output Helpers (Zig 0.16 compatible) =============

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    compat.writeStdout(slice);
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
    compat.writeStdout(&out);
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    compat.writeStdout(s);
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

const CapacityEstimate = struct {
    effective_memory_bytes: u64,
    per_conn_bytes: u64,
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

fn parseCgroupMemoryLimit(content: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, content, &[_]u8{ ' ', '\t', '\n', '\r' });
    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "max")) return null;
    const limit = std.fmt.parseInt(u64, trimmed, 10) catch return null;
    // cgroup v1 represents an unlimited controller with a huge sentinel.
    if (limit == 0 or limit >= (@as(u64, 1) << 60)) return null;
    return limit;
}

fn readCgroupMemoryLimitFile(allocator: std.mem.Allocator, path: []const u8) ?u64 {
    const content = compat.readFileAbsoluteAlloc(allocator, path, 256) catch return null;
    defer allocator.free(content);
    return parseCgroupMemoryLimit(content);
}

fn minMemoryLimit(current: ?u64, candidate: ?u64) ?u64 {
    const value = candidate orelse return current;
    return if (current) |existing| @min(existing, value) else value;
}

fn detectCgroupMemoryLimitBytes(allocator: std.mem.Allocator) ?u64 {
    if (builtin.os.tag != .linux) return null;

    const paths = [_][]const u8{
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    };
    var best: ?u64 = null;
    for (paths) |path| {
        best = minMemoryLimit(best, readCgroupMemoryLimitFile(allocator, path));
    }

    const membership = compat.readFileAbsoluteAlloc(allocator, "/proc/self/cgroup", 64 * 1024) catch return best;
    defer allocator.free(membership);
    var lines = std.mem.splitScalar(u8, membership, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first_colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const second_rel = std.mem.indexOfScalar(u8, line[first_colon + 1 ..], ':') orelse continue;
        const second_colon = first_colon + 1 + second_rel;
        const hierarchy = line[0..first_colon];
        const controllers = line[first_colon + 1 .. second_colon];
        const cgroup_path = line[second_colon + 1 ..];
        if (cgroup_path.len == 0 or cgroup_path[0] != '/') continue;

        var limit_path_buf: [4096]u8 = undefined;
        const limit_path = if (std.mem.eql(u8, hierarchy, "0") and controllers.len == 0)
            std.fmt.bufPrint(&limit_path_buf, "/sys/fs/cgroup{s}/memory.max", .{cgroup_path}) catch continue
        else if (std.mem.indexOf(u8, controllers, "memory") != null)
            std.fmt.bufPrint(&limit_path_buf, "/sys/fs/cgroup/memory{s}/memory.limit_in_bytes", .{cgroup_path}) catch continue
        else
            continue;
        best = minMemoryLimit(best, readCgroupMemoryLimitFile(allocator, limit_path));
    }
    return best;
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

fn estimateCapacity(cfg: *const config.Config, total_ram_bytes: u64) CapacityEstimate {
    // Approximate per-connection user-space working set in the epoll model:
    // - preallocated slot state and small relay buffers
    // - optional middle-proxy stream buffers (budgeted as 2 per-connection caps)
    // - allocator/socket bookkeeping cushion
    const tls_working_bytes: u64 = @intCast(6 * 1024);
    const uses_middle_proxy = cfg.usesAnyMiddleProxy();
    const middleproxy_per_conn_bytes: u64 = if (uses_middle_proxy)
        @intCast(cfg.middleProxyBufferBytes() * 2)
    else
        0;
    // Event loop also keeps shared C2S/S2C scratch for middle-proxy paths.
    // Media-only middle-proxy mode still needs that shared budget.
    const middleproxy_shared_bytes: u64 = if (uses_middle_proxy)
        @intCast(cfg.middleProxySharedScratchBytes())
    else
        0;
    const overhead_bytes: u64 = 2 * 1024;
    const per_conn_bytes = tls_working_bytes + middleproxy_per_conn_bytes + overhead_bytes;

    // Keep safety headroom for kernel TCP memory, page cache, and baseline process state.
    const usable_bytes = (total_ram_bytes * 70) / 100;
    const reserve_bytes = @max(@as(u64, 256 * 1024 * 1024), (total_ram_bytes * 10) / 100);
    const fixed_overhead_bytes = reserve_bytes + middleproxy_shared_bytes;
    const budget_bytes = if (usable_bytes > fixed_overhead_bytes) usable_bytes - fixed_overhead_bytes else 0;

    const raw_cap = if (per_conn_bytes > 0) budget_bytes / per_conn_bytes else 0;
    const safe_connections_u64 = @min(raw_cap, @as(u64, std.math.maxInt(u32)));

    return .{
        .effective_memory_bytes = total_ram_bytes,
        .per_conn_bytes = per_conn_bytes,
        .safe_connections = @intCast(safe_connections_u64),
    };
}

fn enforceCapacitySafety(cfg: *config.Config, capacity_estimate: ?CapacityEstimate) !void {
    const est = capacity_estimate orelse {
        if (builtin.os.tag == .linux and !cfg.unsafe_override_limits) {
            const log_main = std.log.scoped(.config);
            log_main.warn(
                "could not detect total RAM; skipping max_connections safety clamp. " ++
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
                "effective memory budget supports only {d} connections; " ++
                    "unsafe_override_limits=true, keeping configured limit {d}",
                .{ est.safe_connections, cfg.max_connections },
            );
            return;
        }
        log_main.warn(
            "effective memory budget supports only {d} connections, below the minimum safe capacity of 32",
            .{est.safe_connections},
        );
        return error.InsufficientMemoryBudget;
    }

    if (cfg.max_connections <= est.safe_connections) return;

    const log_main = std.log.scoped(.config);
    if (cfg.unsafe_override_limits) {
        log_main.warn(
            "max_connections={d} is above RAM-safe estimate ({d}); " ++
                "unsafe_override_limits=true, keeping configured limit.",
            .{ cfg.max_connections, est.safe_connections },
        );
        return;
    }

    const configured_limit = cfg.max_connections;
    cfg.max_connections = est.safe_connections;

    log_main.warn(
        "auto-clamping max_connections from {d} to {d} " ++
            "(effective memory limit {d} MiB, ~{d} KiB/connection). " ++
            "To disable this safety clamp, set unsafe_override_limits = true in [server].",
        .{
            configured_limit,
            est.safe_connections,
            est.effective_memory_bytes / (1024 * 1024),
            est.per_conn_bytes / 1024,
        },
    );
}

// ============= Startup Banner =============

/// Print a stylish startup banner with config summary and connection links.
fn printBanner(cfg: config.Config, capacity_estimate: ?CapacityEstimate, show_secrets: bool) void {
    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const magenta = "\x1b[35m";
    const white = "\x1b[97m";
    const red = "\x1b[31m";

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
    writeRaw(R ++ "\n\n");

    if (capacity_estimate) |est| {
        const capacity_mode = if (cfg.use_middle_proxy)
            "middleproxy mode"
        else if (cfg.force_media_middle_proxy)
            "media middleproxy mode"
        else
            "direct mode";
        writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CAPACITY" ++ R ++ " " ++ D ++ "────────────────────────────────────" ++ R ++ "\n");
        writeStdout("      Memory limit " ++ B ++ "{d} MiB" ++ R ++ "\n", .{est.effective_memory_bytes / (1024 * 1024)});
        writeStdout("      Per conn     ~{d} KiB ({s})\n", .{
            est.per_conn_bytes / 1024,
            capacity_mode,
        });
        writeStdout("      Safe cap     " ++ B ++ "~{d}" ++ R ++ " connections\n", .{est.safe_connections});
        if (cfg.max_connections > est.safe_connections) {
            writeStdout("      " ++ yellow ++ "max_connections={d} is above safe estimate" ++ R ++ "\n", .{cfg.max_connections});
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
        writeRaw("      Use --show-secrets only in a private terminal.\n");
    } else if (!has_ip) {
        writeRaw("      " ++ red ++ "⚠  Could not detect IP. Replace <SERVER_IP> manually." ++ R ++ "\n");
    }

    if (show_secrets) {
        var users_for_links = cfg.users;
        var it2 = users_for_links.iterator();
        while (it2.next()) |entry| {
            writeStdout("      " ++ B ++ magenta ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});

            // tg:// deep link
            writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "proxy?server={s}&port={d}&secret=", .{ server_ip, cfg.port });
            writeRaw(green ++ "ee");
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");

            // t.me link
            writeStdout("      " ++ D ++ "t.me/proxy?server={s}&port={d}&secret=ee", .{ server_ip, cfg.port });
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");
        }
    }

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Waiting for connections..." ++ R ++ "\n\n");
}

pub fn main(init: std.process.Init) !void {
    // Use page_allocator instead of GeneralPurposeAllocator for production.
    // GPA has an internal mutex that causes deadlocks under heavy thread contention
    // (1000+ simultaneous connections all doing TLS validation allocations).
    const allocator = std.heap.page_allocator;
    ignoreSigpipe();

    // Parse config path and explicit secret-display opt-in.
    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    var config_path: []const u8 = "config.toml";
    var config_path_set = false;
    var show_secrets = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--show-secrets")) {
            show_secrets = true;
        } else if (!config_path_set) {
            config_path = arg;
            config_path_set = true;
        } else {
            writeStderr("\n  Usage: mtproto-proxy [config.toml] [--show-secrets]\n\n", .{});
            return error.InvalidArguments;
        }
    }

    // Parse config
    var cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeStderr("\n  Usage: mtproto-proxy [config.toml] [--show-secrets]\n\n", .{});
        return err;
    };
    defer cfg.deinit(allocator);

    // Apply runtime log level from config
    runtime_log_level = cfg.log_level;

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

    // Print the startup banner without blocking on external discovery.
    printBanner(cfg, capacity_estimate, show_secrets);

    // Emit config warnings (e.g. buffer too small, memory concerns)
    cfg.emitWarnings();

    // Create shared state (DI — no globals)
    var state = try proxy.ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Run the proxy
    try state.run();
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
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
        .per_conn_bytes = 2 * 1024 * 1024,
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
        .per_conn_bytes = 2 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 4096), cfg.max_connections);
}

test "capacity estimate accounts for media-only middle proxy overhead" {
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

    try std.testing.expect(media_est.per_conn_bytes > direct_est.per_conn_bytes);
    try std.testing.expect(media_est.safe_connections < direct_est.safe_connections);
}

test "cgroup memory limit parser handles finite and unlimited values" {
    try std.testing.expectEqual(@as(?u64, 536_870_912), parseCgroupMemoryLimit("536870912\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit("max\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit("9223372036854771712\n"));
    try std.testing.expectEqual(@as(?u64, null), parseCgroupMemoryLimit("invalid\n"));
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
        .per_conn_bytes = 8 * 1024,
        .safe_connections = 0,
    };
    try std.testing.expectError(error.InsufficientMemoryBudget, enforceCapacitySafety(&cfg, est));
}
