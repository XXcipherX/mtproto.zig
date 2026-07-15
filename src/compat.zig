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

/// Monotonic process-local clock for elapsed-time measurements and deadlines.
/// Unlike `nanoTimestamp`, this clock is not affected by wall-clock updates.
pub fn monotonicNanoTimestamp() i128 {
    if (builtin.os.tag == .linux) return monotonicNanoTimestampLinux();

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    return @intCast(std.Io.Timestamp.now(threaded_io.io(), .awake).nanoseconds);
}

pub fn monotonicMilliTimestamp() i64 {
    return @intCast(@divTrunc(monotonicNanoTimestamp(), std.time.ns_per_ms));
}

pub fn timestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_s));
}

pub fn randomBytes(buf: []u8) void {
    randomBytesSecure(buf) catch @panic("secure random entropy unavailable");
}

const SecureDrbg = struct {
    const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
    const buffer_size = 1024;
    const reseed_interval = 1024 * 1024;

    key: [ChaCha20.key_length]u8 = [_]u8{0} ** ChaCha20.key_length,
    nonce: [ChaCha20.nonce_length]u8 = [_]u8{0} ** ChaCha20.nonce_length,
    buffer: [buffer_size]u8 = [_]u8{0} ** buffer_size,
    buffer_pos: usize = buffer_size,
    counter: u32 = 0,
    generated: usize = reseed_interval,
    initialized: bool = false,

    fn fill(self: *SecureDrbg, out: []u8) !void {
        var offset: usize = 0;
        while (offset < out.len) {
            if (!self.initialized or self.generated >= reseed_interval) try self.reseed();
            if (self.buffer_pos == self.buffer.len) self.refill();

            const until_reseed = reseed_interval - self.generated;
            const take = @min(out.len - offset, @min(self.buffer.len - self.buffer_pos, until_reseed));
            @memcpy(out[offset .. offset + take], self.buffer[self.buffer_pos .. self.buffer_pos + take]);
            self.buffer_pos += take;
            self.generated += take;
            offset += take;
        }
    }

    fn reseed(self: *SecureDrbg) !void {
        var seed: [ChaCha20.key_length + ChaCha20.nonce_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try randomBytesFromOs(&seed);

        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.nonce);
        std.crypto.secureZero(u8, &self.buffer);
        @memcpy(self.key[0..], seed[0..ChaCha20.key_length]);
        @memcpy(self.nonce[0..], seed[ChaCha20.key_length..]);
        self.buffer_pos = self.buffer.len;
        self.counter = 0;
        self.generated = 0;
        self.initialized = true;
    }

    fn refill(self: *SecureDrbg) void {
        ChaCha20.stream(&self.buffer, self.counter, self.key, self.nonce);
        self.counter +%= self.buffer.len / ChaCha20.block_length;
        self.buffer_pos = 0;
    }
};

threadlocal var secure_drbg: SecureDrbg = .{};

fn randomBytesSecure(buf: []u8) !void {
    try secure_drbg.fill(buf);
}

fn randomBytesFromOs(buf: []u8) !void {
    if (builtin.os.tag == .linux) {
        try randomBytesSecureLinux(buf);
        return;
    }

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    try threaded_io.io().randomSecure(buf);
}

pub fn randomInt(comptime T: type) T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    randomBytes(bytes[0..]);
    return std.mem.readInt(T, bytes[0..], .little);
}

pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;
    const upper_bound = std.math.maxInt(T) - (std.math.maxInt(T) % max);
    while (true) {
        const value = randomInt(T);
        if (value < upper_bound) return value % max;
    }
}

pub fn writeStdout(bytes: []const u8) void {
    if (builtin.os.tag == .linux) {
        writeLinuxFd(std.os.linux.STDOUT_FILENO, bytes);
        return;
    }

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    std.Io.File.stdout().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

pub fn writeStderr(bytes: []const u8) void {
    if (builtin.os.tag == .linux) {
        writeLinuxFd(std.os.linux.STDERR_FILENO, bytes);
        return;
    }

    var threaded_io = initThreadedIo();
    defer threaded_io.deinit();
    std.Io.File.stderr().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

fn writeLinuxFd(fd: i32, bytes: []const u8) void {
    const linux = std.os.linux;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return;
                offset += rc;
            },
            .INTR => continue,
            else => return,
        }
    }
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
        .TIMEDOUT => unreachable,
        .FAULT => unreachable,
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

fn nanoTimestampLinux() i128 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    switch (posix.errno(linux.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec),
        else => return 0,
    }
}

fn monotonicNanoTimestampLinux() i128 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    switch (posix.errno(linux.clock_gettime(.MONOTONIC, &ts))) {
        .SUCCESS => return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec),
        else => return nanoTimestampLinux(),
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

fn randomBytesSecureLinux(buf: []u8) !void {
    const linux = std.os.linux;
    var offset: usize = 0;
    while (offset < buf.len) {
        const rc = linux.getrandom(buf[offset..].ptr, buf.len - offset, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.EntropyUnavailable;
                offset += rc;
            },
            .INTR => continue,
            else => return error.EntropyUnavailable,
        }
    }
}
