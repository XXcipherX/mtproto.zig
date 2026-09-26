//! Kernel-thread synchronization for shared proxy state.
//!
//! Zig 0.16 std.Io.Mutex requires an Io context for lock/unlock and permits
//! cancellation. Epoll workers, metadata refresh and DNS cache call these
//! locks synchronously from ordinary threads, including cleanup paths with
//! no owning Io context. Keep this uncancelable futex mutex instead of adding
//! an I/O runtime or spin-waiting across slow DNS/metadata critical sections.

const std = @import("std");
const builtin = @import("builtin");

pub const BlockingMutex = struct {
    state: std.atomic.Value(u32) = .init(unlocked),

    const unlocked: u32 = 0;
    const locked: u32 = 1;
    const contended: u32 = 2;

    pub fn lock(self: *BlockingMutex) void {
        if (self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
        while (self.state.swap(contended, .acquire) != unlocked) {
            futexWait(&self.state, contended);
        }
    }

    pub fn unlock(self: *BlockingMutex) void {
        if (self.state.swap(unlocked, .release) == contended) {
            futexWake(&self.state, 1);
        }
    }
};

fn futexWait(ptr: *const std.atomic.Value(u32), expect: u32) void {
    if (builtin.os.tag != .linux) {
        while (ptr.load(.monotonic) == expect) std.atomic.spinLoopHint();
        return;
    }
    const linux = std.os.linux;
    const rc = linux.futex_4arg(ptr, .{ .cmd = .WAIT, .private = true }, expect, null);
    switch (linux.errno(rc)) {
        .SUCCESS, .INTR, .AGAIN, .INVAL => {},
        .TIMEDOUT, .FAULT => unreachable,
        else => {},
    }
}

fn futexWake(ptr: *const std.atomic.Value(u32), max_waiters: u32) void {
    if (builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const rc = linux.futex_3arg(
        &ptr.raw,
        .{ .cmd = .WAKE, .private = true },
        @min(max_waiters, std.math.maxInt(i32)),
    );
    switch (linux.errno(rc)) {
        .SUCCESS, .INVAL, .FAULT => {},
        else => {},
    }
}
