//! Compatibility shims for Zig 0.16 stdlib API moves.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub fn initThreadedIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.heap.page_allocator, .{});
}

pub fn sleep(ns: u64) void {
    if (builtin.os.tag == .linux) {
        sleepLinux(ns);
        return;
    }

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    std.Io.sleep(threaded_io.io(), .{ .nanoseconds = @intCast(ns) }, .awake) catch {};
}

pub fn readFileAbsoluteAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    const local_io = threaded_io.io();
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
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    const local_io = threaded_io.io();
    const file = try std.Io.Dir.cwd().openFile(local_io, path, .{});
    defer file.close(local_io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(local_io, &read_buf);
    return reader.interface.allocRemaining(allocator, .limited(max_bytes));
}

pub fn nanoTimestamp() i128 {
    if (builtin.os.tag == .linux) return nanoTimestampLinux();

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    return @intCast(std.Io.Timestamp.now(threaded_io.io(), .real).nanoseconds);
}

pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_ms));
}

pub fn timestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_s));
}

pub fn randomBytes(buf: []u8) void {
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    const local_io = threaded_io.io();
    local_io.randomSecure(buf) catch local_io.random(buf);
}

pub fn randomInt(comptime T: type) T {
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    var source = std.Random.IoSource{ .io = threaded_io.io() };
    return source.interface().int(T);
}

pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    var source = std.Random.IoSource{ .io = threaded_io.io() };
    return source.interface().intRangeLessThan(T, 0, max);
}

pub fn writeStdout(bytes: []const u8) void {
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    std.Io.File.stdout().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

pub fn writeStderr(bytes: []const u8) void {
    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    std.Io.File.stderr().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

pub const Mutex = struct {
    locked: std.atomic.Value(bool) = .init(false),

    pub fn lock(self: *Mutex) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic)) |_| {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *Mutex) void {
        self.locked.store(false, .release);
    }
};

fn nanoTimestampLinux() i128 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    switch (posix.errno(linux.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec),
        else => return 0,
    }
}

fn sleepLinux(ns: u64) void {
    const linux = std.os.linux;
    var req = linux.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: linux.timespec = undefined;

    while (true) {
        switch (posix.errno(linux.nanosleep(&req, &rem))) {
            .SUCCESS => return,
            .INTR => req = rem,
            else => return,
        }
    }
}
