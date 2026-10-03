//! Detect effective host/cgroup memory without owning the caller's std.Io.
const std = @import("std");
const builtin = @import("builtin");
const linux_fs = @import("linux_fs.zig");

fn detectTotalRamBytes(allocator: std.mem.Allocator, io: std.Io) ?u64 {
    if (builtin.target.os.tag != .linux) return null;

    if (detectTotalRamBytesSysinfo()) |total| {
        return total;
    }

    const content = linux_fs.readPseudoFileAlloc(allocator, io, "/proc/meminfo", 16 * 1024) catch return null;
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
    if (builtin.target.os.tag != .linux) return null;

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
    io: std.Io,
    version: CgroupVersion,
    path: []const u8,
) ?u64 {
    const content = linux_fs.readPseudoFileAlloc(allocator, io, path, 256) catch return null;
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
    const slash = std.mem.findScalarLast(u8, trimmed, '/') orelse return null;
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
        return std.mem.print(output, "{s}", .{normalized_mount}) catch null;
    }
    if (std.mem.eql(u8, normalized_mount, "/")) {
        return std.mem.print(output, "{s}", .{relative}) catch null;
    }
    return std.mem.print(output, "{s}{s}", .{ normalized_mount, relative }) catch null;
}

fn scanCgroupHierarchy(
    allocator: std.mem.Allocator,
    io: std.Io,
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
            std.mem.print(&limit_path_buf, "/{s}", .{filename}) catch null
        else
            std.mem.print(&limit_path_buf, "{s}/{s}", .{ current, filename }) catch null;
        if (limit_path) |path| {
            best = minMemoryLimit(
                best,
                readCgroupMemoryLimitFile(allocator, io, version, path),
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
    io: std.Io,
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
    return scanCgroupHierarchy(allocator, io, mount.version, mount_point, leaf);
}

fn scanConventionalCgroupMounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    v1_membership: ?[]const u8,
    v2_membership: ?[]const u8,
) ?u64 {
    var best: ?u64 = null;
    best = minMemoryLimit(
        best,
        readCgroupMemoryLimitFile(allocator, io, .v2, "/sys/fs/cgroup/memory.max"),
    );
    best = minMemoryLimit(
        best,
        readCgroupMemoryLimitFile(
            allocator,
            io,
            .v1,
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ),
    );
    var mapped = false;
    if (v2_membership) |cgroup_path| {
        best = minMemoryLimit(best, scanMountedCgroup(
            allocator,
            io,
            .{ .version = .v2, .root = "/", .mount_point = "/sys/fs/cgroup" },
            cgroup_path,
            &mapped,
        ));
    }
    if (v1_membership) |cgroup_path| {
        best = minMemoryLimit(best, scanMountedCgroup(
            allocator,
            io,
            .{ .version = .v1, .root = "/", .mount_point = "/sys/fs/cgroup/memory" },
            cgroup_path,
            &mapped,
        ));
    }
    return best;
}

fn detectCgroupMemoryLimitBytes(allocator: std.mem.Allocator, io: std.Io) ?u64 {
    if (builtin.target.os.tag != .linux) return null;

    const membership = linux_fs.readPseudoFileAlloc(
        allocator,
        io,
        "/proc/self/cgroup",
        64 * 1024,
    ) catch return scanConventionalCgroupMounts(allocator, io, null, null);
    defer allocator.free(membership);
    var v1_membership: ?[]const u8 = null;
    var v2_membership: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, membership, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first_colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const second_rel = std.mem.findScalar(u8, line[first_colon + 1 ..], ':') orelse continue;
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

    const mountinfo = linux_fs.readPseudoFileAlloc(
        allocator,
        io,
        "/proc/self/mountinfo",
        1024 * 1024,
    ) catch return scanConventionalCgroupMounts(
        allocator,
        io,
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
            scanMountedCgroup(allocator, io, mount, cgroup_path, &mapped),
        );
        mapped_any = mapped_any or mapped;
    }
    return if (mapped_any)
        best
    else
        scanConventionalCgroupMounts(allocator, io, v1_membership, v2_membership);
}

pub fn detectEffectiveMemoryBytes(allocator: std.mem.Allocator, io: std.Io) ?u64 {
    const host = detectTotalRamBytes(allocator, io);
    const cgroup = detectCgroupMemoryLimitBytes(allocator, io);
    if (host) |host_bytes| {
        if (cgroup) |limit| return @min(host_bytes, limit);
        return host_bytes;
    }
    return cgroup;
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
