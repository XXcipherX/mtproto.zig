//! Compatibility shims for Zig 0.16 stdlib API moves.

const std = @import("std");

fn globalIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn io() std.Io {
    return globalIo();
}

pub fn sleep(ns: u64) void {
    std.Io.sleep(globalIo(), .{ .nanoseconds = @intCast(ns) }, .awake) catch {};
}

pub fn readFileAbsoluteAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    const local_io = globalIo();
    const file = try std.Io.Dir.openFileAbsolute(local_io, path, .{});
    defer file.close(local_io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(local_io, &read_buf);
    return reader.interface.allocRemaining(allocator, .limited(max_bytes));
}

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    const local_io = globalIo();
    const file = try std.Io.Dir.cwd().openFile(local_io, path, .{});
    defer file.close(local_io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(local_io, &read_buf);
    return reader.interface.allocRemaining(allocator, .limited(max_bytes));
}

pub fn nanoTimestamp() i128 {
    return @intCast(std.Io.Timestamp.now(globalIo(), .real).nanoseconds);
}

pub fn milliTimestamp() i64 {
    return std.Io.Timestamp.now(globalIo(), .real).toMilliseconds();
}

pub fn timestamp() i64 {
    return std.Io.Timestamp.now(globalIo(), .real).toSeconds();
}

pub fn randomBytes(buf: []u8) void {
    const local_io = globalIo();
    local_io.randomSecure(buf) catch local_io.random(buf);
}

pub fn randomInt(comptime T: type) T {
    var source = std.Random.IoSource{ .io = globalIo() };
    return source.interface().int(T);
}

pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;
    var source = std.Random.IoSource{ .io = globalIo() };
    return source.interface().intRangeLessThan(T, 0, max);
}

pub fn writeStdout(bytes: []const u8) void {
    std.Io.File.stdout().writeStreamingAll(globalIo(), bytes) catch {};
}

pub fn writeStderr(bytes: []const u8) void {
    std.Io.File.stderr().writeStreamingAll(globalIo(), bytes) catch {};
}

pub const Mutex = struct {
    inner: std.Io.Mutex = .init,

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(globalIo());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(globalIo());
    }
};
