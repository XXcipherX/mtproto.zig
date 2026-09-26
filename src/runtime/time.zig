//! Synchronous daemon clocks and sleep. The Linux epoll data plane needs
//! cheap CLOCK_MONOTONIC samples without creating an Io context per event.

const std = @import("std");
const builtin = @import("builtin");

pub fn realtimeNano() i128 {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var ts: linux.timespec = undefined;
        return switch (linux.errno(linux.clock_gettime(.REALTIME, &ts))) {
            .SUCCESS => @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec),
            else => 0,
        };
    }

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    return @intCast(std.Io.Timestamp.now(threaded_io.io(), .real).nanoseconds);
}

pub fn realtimeSeconds() i64 {
    return @intCast(@divTrunc(realtimeNano(), std.time.ns_per_s));
}

pub fn monotonicNano() i128 {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var ts: linux.timespec = undefined;
        if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) {
            // Deadlines must never silently switch to wall-clock time.
            @panic("CLOCK_MONOTONIC unavailable");
        }
        return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    }

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    return @intCast(std.Io.Timestamp.now(threaded_io.io(), .awake).nanoseconds);
}

pub fn monotonicMilli() i64 {
    return @intCast(@divTrunc(monotonicNano(), std.time.ns_per_ms));
}

pub fn sleep(ns: u64) void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var req = linux.timespec{
            .sec = @intCast(ns / std.time.ns_per_s),
            .nsec = @intCast(ns % std.time.ns_per_s),
        };
        var rem: linux.timespec = undefined;
        while (true) {
            switch (linux.errno(linux.nanosleep(&req, &rem))) {
                .SUCCESS => return,
                .INTR => req = rem,
                else => return,
            }
        }
    }

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    std.Io.sleep(threaded_io.io(), .{ .nanoseconds = @intCast(ns) }, .awake) catch {};
}
