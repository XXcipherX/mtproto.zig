//! Per-thread ChaCha20 CSPRNG for the proxy hot path.
//!
//! std.Random.IoSource uses Io.random, not Io.randomSecure, and a secure Io
//! request for every nonce would add a syscall on the relay path. Seed and
//! periodically reseed each thread from the OS CSPRNG instead.

const std = @import("std");
const builtin = @import("builtin");

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

pub fn bytes(buf: []u8) void {
    secure_drbg.fill(buf) catch @panic("secure random entropy unavailable");
}

pub fn int(comptime T: type) T {
    var result: [@sizeOf(T)]u8 = undefined;
    bytes(&result);
    return std.mem.readInt(T, &result, .little);
}

pub fn range(comptime T: type, max: T) T {
    if (max == 0) return 0;
    const upper_bound = std.math.maxInt(T) - (std.math.maxInt(T) % max);
    while (true) {
        const value = int(T);
        if (value < upper_bound) return value % max;
    }
}

fn randomBytesFromOs(buf: []u8) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var offset: usize = 0;
        while (offset < buf.len) {
            const rc = linux.getrandom(buf[offset..].ptr, buf.len - offset, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.EntropyUnavailable;
                    offset += rc;
                },
                .INTR => continue,
                else => return error.EntropyUnavailable,
            }
        }
        return;
    }

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    try threaded_io.io().randomSecure(buf);
}
