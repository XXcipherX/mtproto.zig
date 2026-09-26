const std = @import("std");
const net = @import("../net_helpers.zig");
const crypto = @import("../crypto/crypto.zig");
const constants = @import("../protocol/constants.zig");
const runtime_time = @import("../runtime/time.zig");
const runtime_sync = @import("../runtime/sync.zig");
const WedgeRecoveryGate = @import("wedge_recovery.zig").WedgeRecoveryGate;

/// Per-/24 (IPv4) or /48 (IPv6) subnet rate limiter.
/// Fixed-size open-addressed hash table — zero heap allocation.
/// Token bucket per subnet: each second refills up to max_per_sec tokens.
pub const SubnetRateLimit = struct {
    const BUCKETS = 65536;
    const MAX_PROBES = 8;
    const stale_after_s: i64 = 60;

    // Keep naturally aligned fields first: padding multiplied by BUCKETS
    // directly increases the process-wide security table allocation.
    pub const Entry = struct {
        subnet_key: u64 = 0,
        last_refill_s: i64 = 0,
        used: bool = false,
        tokens: u8 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() SubnetRateLimit {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    pub fn indexFor(self: *const SubnetRateLimit, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    pub fn findEntry(self: *SubnetRateLimit, key: u64) ?*Entry {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];
            if (!e.used) return null;
            if (e.subnet_key == key) return e;
        }
        return null;
    }

    /// Returns true if the connection is allowed, false if rate-limited.
    pub fn check(self: *SubnetRateLimit, addr: net.Address, max_per_sec: u8) bool {
        if (max_per_sec == 0) return true;
        const key = subnetKey(addr);
        const now_s = @divTrunc(runtime_time.monotonicMilli(), 1000);

        const start = self.indexFor(key);
        var first_stale_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];

            if (!e.used) {
                e.* = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
                return true;
            }

            if (e.subnet_key == key) {
                // Refill tokens based on elapsed seconds
                const elapsed = now_s - e.last_refill_s;
                if (elapsed > 0) {
                    const refill: u16 = @intCast(@min(elapsed, 255));
                    const topped = @as(u16, e.tokens) + refill * @as(u16, max_per_sec);
                    e.tokens = @intCast(@min(@as(u16, max_per_sec), topped));
                    e.last_refill_s = now_s;
                }

                if (e.tokens > 0) {
                    e.tokens -= 1;
                    return true;
                }
                return false;
            }

            if (now_s - e.last_refill_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
        }

        if (first_stale_idx) |victim_idx| {
            self.entries[victim_idx] = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
            return true;
        }

        // The probed window is occupied by live buckets; reject this connection
        // instead of evicting an active subnet and resetting its limiter state.
        return false;
    }

    pub fn subnetKey(addr: net.Address) u64 {
        const normalized = switch (addr) {
            .ip4 => addr,
            .ip6 => |v6| net.Address.fromIp6(v6),
        };
        return switch (normalized) {
            .ip4 => |v4| @as(u64, v4.bytes[0]) << 16 |
                @as(u64, v4.bytes[1]) << 8 |
                @as(u64, v4.bytes[2]),
            .ip6 => |v6| blk: {
                const ip6 = &v6.bytes;
                // Preserve all /48 bits, namespaced away from IPv4 keys.
                break :blk @as(u64, 1) << 63 |
                    @as(u64, ip6[0]) << 40 |
                    @as(u64, ip6[1]) << 32 |
                    @as(u64, ip6[2]) << 24 |
                    @as(u64, ip6[3]) << 16 |
                    @as(u64, ip6[4]) << 8 |
                    @as(u64, ip6[5]);
            },
        };
    }
};

pub const ReplayCache = struct {
    const BUCKETS = 8192;
    const MAX_PROBES = 8;
    // A validated FakeTLS timestamp can remain acceptable for at most the
    // distance between the lower and upper skew bounds. Retaining entries
    // longer only increases cache pressure after the handshake is already
    // guaranteed to fail timestamp validation.
    const stale_after_s: i64 = constants.time_skew_max - constants.time_skew_min;

    const Entry = struct {
        used: bool = false,
        key: u64 = 0,
        digest: [32]u8 = [_]u8{0} ** 32,
        last_seen_s: i64 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() ReplayCache {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    fn digestKey(digest: *const [32]u8) u64 {
        return std.mem.readInt(u64, digest[0..8], .little);
    }

    fn indexFor(self: *const ReplayCache, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    pub fn checkAndInsert(self: *ReplayCache, digest: *const [32]u8) bool {
        const key = digestKey(digest);
        const now_s = @divTrunc(runtime_time.monotonicMilli(), 1000);
        const start = self.indexFor(key);

        var first_stale_idx: ?usize = null;
        var oldest_idx: usize = start;
        var oldest_seen_s: i64 = std.math.maxInt(i64);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];

            if (!e.used) {
                e.* = .{ .used = true, .key = key, .digest = digest.*, .last_seen_s = now_s };
                return false;
            }

            if (e.key == key and std.crypto.timing_safe.eql([32]u8, e.digest, digest.*)) {
                e.last_seen_s = now_s;
                return true;
            }

            if (now_s - e.last_seen_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
            if (e.last_seen_s < oldest_seen_s) {
                oldest_seen_s = e.last_seen_s;
                oldest_idx = idx;
            }
        }

        // Cache pressure is not proof of replay. Reuse the oldest entry in the
        // bounded probe window rather than rejecting a fresh authenticated
        // handshake as a replay.
        const victim_idx = first_stale_idx orelse oldest_idx;
        self.entries[victim_idx] = .{ .used = true, .key = key, .digest = digest.*, .last_seen_s = now_s };
        return false;
    }
};

/// Bounds unauthenticated connections per IPv4 /24 or IPv6 /48. The charge is
/// taken after a pool slot is acquired and released only after authentication
/// succeeds (or the slot closes), so silent and one-byte clients share one
/// finite allowance without penalizing established relays behind large NATs.
pub const SubnetHandshakeLimit = struct {
    const BUCKETS = 16384;
    const MAX_PROBES = 8;

    // Field order is intentional for the same fixed-table layout reason above.
    const Entry = struct {
        subnet_key: u64 = 0,
        inflight: u16 = 0,
        used: bool = false,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() SubnetHandshakeLimit {
        return .{ .hash_seed = crypto.randomInt(u64) };
    }

    fn indexFor(self: *const SubnetHandshakeLimit, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    pub fn reserve(self: *SubnetHandshakeLimit, key: u64, limit: u16) bool {
        const start = self.indexFor(key);
        var free_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const entry = &self.entries[idx];
            if (entry.used and entry.subnet_key == key) {
                if (entry.inflight >= limit) return false;
                entry.inflight += 1;
                return true;
            }
            if ((!entry.used or entry.inflight == 0) and free_idx == null) free_idx = idx;
        }

        const idx = free_idx orelse return false;
        self.entries[idx] = .{ .used = true, .subnet_key = key, .inflight = 1 };
        return true;
    }

    pub fn release(self: *SubnetHandshakeLimit, key: u64) void {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const entry = &self.entries[(start + probe) & (BUCKETS - 1)];
            if (!entry.used or entry.subnet_key != key) continue;
            if (entry.inflight > 0) entry.inflight -= 1;
            if (entry.inflight == 0) entry.used = false;
            return;
        }
    }
};

pub fn subnetHandshakeLimit(max_connections: u32) u16 {
    return @intCast(@min(@as(u32, 128), @max(@as(u32, 16), max_connections / 8)));
}

/// These fixed tables are process-wide: reuseport must not multiply subnet,
/// replay, or wedge-recovery allowances by the number of workers. Admission
/// checks avoid the ordinary per-byte relay path; the optional iOS wedge gate
/// has its own lock when that recovery mode is enabled.
pub const SecurityState = struct {
    lock: runtime_sync.BlockingMutex,
    wedge_lock: runtime_sync.BlockingMutex,
    subnet_limiter: SubnetRateLimit,
    subnet_handshakes: SubnetHandshakeLimit,
    replay_cache: ReplayCache,
    wedge_recovery_gate: WedgeRecoveryGate,

    pub fn create(allocator: std.mem.Allocator) !*SecurityState {
        const security = try allocator.create(SecurityState);
        security.lock = .{};
        security.wedge_lock = .{};
        security.subnet_limiter.hash_seed = crypto.randomInt(u64);
        for (&security.subnet_limiter.entries) |*entry| entry.* = .{};
        security.subnet_handshakes.hash_seed = crypto.randomInt(u64);
        for (&security.subnet_handshakes.entries) |*entry| entry.* = .{};
        security.replay_cache.hash_seed = crypto.randomInt(u64);
        for (&security.replay_cache.entries) |*entry| entry.* = .{};
        security.wedge_recovery_gate.hash_seed = crypto.randomInt(u64);
        for (&security.wedge_recovery_gate.entries) |*entry| entry.* = .{};
        security.wedge_recovery_gate.untracked_suppression_reported = false;
        return security;
    }
};

/// Numeric limits do not publish connection memory to another worker: relaxed
/// ordering is sufficient; the CAS itself makes each reservation indivisible.
pub fn reserveGlobalCount(counter: *std.atomic.Value(u32), limit: u32) bool {
    var current = counter.load(.monotonic);
    while (current < limit) {
        if (counter.cmpxchgWeak(current, current + 1, .monotonic, .monotonic)) |observed| {
            current = observed;
        } else return true;
    }
    return false;
}

pub fn releaseGlobalCount(counter: *std.atomic.Value(u32)) void {
    const previous = counter.fetchSub(1, .monotonic);
    std.debug.assert(previous > 0);
}

pub fn countStat(counter: *std.atomic.Value(u64)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

test "subnet rate limit - subnet key groups /24 IPv4" {
    // 10.0.1.5 and 10.0.1.200 should have the same /24 key
    const addr1 = net.ip4(.{ 10, 0, 1, 5 }, 443);
    const addr2 = net.ip4(.{ 10, 0, 1, 200 }, 443);
    const addr3 = net.ip4(.{ 10, 0, 2, 5 }, 443);

    const key1 = SubnetRateLimit.subnetKey(addr1);
    const key2 = SubnetRateLimit.subnetKey(addr2);
    const key3 = SubnetRateLimit.subnetKey(addr3);

    try std.testing.expectEqual(key1, key2); // same /24
    try std.testing.expect(key1 != key3); // different /24
}

test "subnet rate limit - IPv4-mapped IPv6 keys match native IPv4 /24" {
    const native_v4 = net.ip4(.{ 203, 0, 113, 42 }, 443);

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 42 };
    const mapped = net.ip6(mapped_bytes, 443, 0, 0);

    const native_key = SubnetRateLimit.subnetKey(native_v4);
    const mapped_key = SubnetRateLimit.subnetKey(mapped);
    try std.testing.expectEqual(native_key, mapped_key);

    const mapped_other_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 198, 51, 100, 1 };
    const mapped_other = net.ip6(mapped_other_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(mapped_other) != mapped_key);

    const native6_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const native6 = net.ip6(native6_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(native6) != mapped_key);
}

test "subnet rate limit - preserves every IPv6 /48 prefix bit" {
    const prefix_a = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00 } ++ [_]u8{0} ** 10;
    const prefix_b = [_]u8{ 0x20, 0x01, 0x0d, 0xb9, 0x00, 0x01 } ++ [_]u8{0} ** 10;
    const addr_a = net.ip6(prefix_a, 443, 0, 0);
    const addr_b = net.ip6(prefix_b, 443, 0, 0);

    try std.testing.expect(SubnetRateLimit.subnetKey(addr_a) != SubnetRateLimit.subnetKey(addr_b));
}

test "subnet rate limit - allows up to max then blocks" {
    var limiter = SubnetRateLimit{};
    const addr = net.ip4(.{ 192, 168, 1, 100 }, 443);

    // max_per_sec = 3 → should allow 3 then block
    // First call resets entry with tokens = max-1 = 2, returns true
    try std.testing.expect(limiter.check(addr, 3));
    // Two more with existing tokens
    try std.testing.expect(limiter.check(addr, 3));
    try std.testing.expect(limiter.check(addr, 3));
    // Now should be blocked
    try std.testing.expect(!limiter.check(addr, 3));
    try std.testing.expect(!limiter.check(addr, 3));
}

test "subnet rate limit - disabled when max_per_sec is 0" {
    var limiter = SubnetRateLimit{};
    const addr = net.ip4(.{ 1, 2, 3, 4 }, 443);

    // With max_per_sec = 0, always allows
    for (0..100) |_| {
        try std.testing.expect(limiter.check(addr, 0));
    }
}

test "subnet rate limit - stale entry resets" {
    var limiter = SubnetRateLimit{};
    const addr = net.ip4(.{ 10, 20, 30, 40 }, 443);

    // Drain tokens
    _ = limiter.check(addr, 1);
    try std.testing.expect(!limiter.check(addr, 1));

    // Make entry stale (>60s old)
    const key = SubnetRateLimit.subnetKey(addr);
    const entry = limiter.findEntry(key) orelse return error.TestExpectedEqual;
    entry.last_refill_s -= SubnetRateLimit.stale_after_s + 1;

    // Should reset and allow again
    try std.testing.expect(limiter.check(addr, 1));
}

test "subnet rate limit - live probe window is not evicted" {
    var limiter = SubnetRateLimit{};
    const addr = net.ip4(.{ 203, 0, 113, 42 }, 443);
    const key = SubnetRateLimit.subnetKey(addr);
    const start = limiter.indexFor(key);
    const now_s = @divTrunc(runtime_time.monotonicMilli(), 1000);

    var probe: usize = 0;
    while (probe < SubnetRateLimit.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (SubnetRateLimit.BUCKETS - 1);
        limiter.entries[idx] = .{
            .used = true,
            .subnet_key = 0x80000000 + @as(u64, @intCast(probe)),
            .tokens = 1,
            .last_refill_s = now_s,
        };
    }

    try std.testing.expect(!limiter.check(addr, 1));

    probe = 0;
    while (probe < SubnetRateLimit.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (SubnetRateLimit.BUCKETS - 1);
        try std.testing.expectEqual(0x80000000 + @as(u64, @intCast(probe)), limiter.entries[idx].subnet_key);
    }
}

test "subnet rate limit - different subnets are independent" {
    var limiter = SubnetRateLimit{};
    const addr_a = net.ip4(.{ 10, 0, 1, 100 }, 443);
    const addr_b = net.ip4(.{ 10, 0, 2, 100 }, 443);

    // Drain subnet A
    _ = limiter.check(addr_a, 1);
    try std.testing.expect(!limiter.check(addr_a, 1));

    // Subnet B should still work
    try std.testing.expect(limiter.check(addr_b, 1));
}

test "replay cache detects duplicate digest" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0xAB} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest));
    try std.testing.expect(cache.checkAndInsert(&digest));
}

test "replay cache accepts distinct digests" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    const digest_b = [_]u8{0x22} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
}

test "replay cache compares full digest on key collision" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    var digest_b = digest_a;
    digest_b[31] ^= 0xff;

    try std.testing.expectEqual(ReplayCache.digestKey(&digest_a), ReplayCache.digestKey(&digest_b));
    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
    try std.testing.expect(cache.checkAndInsert(&digest_a));
    try std.testing.expect(cache.checkAndInsert(&digest_b));
}

test "replay cache replaces oldest live entry without reporting false replay" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0x5a} ** 32;
    const start = cache.indexFor(ReplayCache.digestKey(&digest));
    const now_s = @divTrunc(runtime_time.monotonicMilli(), 1000);

    var probe: usize = 0;
    while (probe < ReplayCache.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (ReplayCache.BUCKETS - 1);
        var occupied_digest = [_]u8{0} ** 32;
        @memset(&occupied_digest, @intCast(probe + 1));
        cache.entries[idx] = .{
            .used = true,
            .key = @as(u64, @intCast(probe + 1)),
            .digest = occupied_digest,
            .last_seen_s = now_s - @as(i64, @intCast(probe)),
        };
    }

    try std.testing.expect(!cache.checkAndInsert(&digest));
    probe = 0;
    while (probe + 1 < ReplayCache.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (ReplayCache.BUCKETS - 1);
        try std.testing.expectEqual(@as(u64, @intCast(probe + 1)), cache.entries[idx].key);
    }
    const replaced_idx = (start + ReplayCache.MAX_PROBES - 1) & (ReplayCache.BUCKETS - 1);
    try std.testing.expectEqual(ReplayCache.digestKey(&digest), cache.entries[replaced_idx].key);
    try std.testing.expect(cache.checkAndInsert(&digest));
}

test "subnet handshake limit bounds and releases unauthenticated slots" {
    var limiter = SubnetHandshakeLimit.init();
    limiter.hash_seed = 0;
    const key: u64 = 0x010203;

    try std.testing.expect(limiter.reserve(key, 2));
    try std.testing.expect(limiter.reserve(key, 2));
    try std.testing.expect(!limiter.reserve(key, 2));

    limiter.release(key);
    try std.testing.expect(limiter.reserve(key, 2));
    limiter.release(key);
    limiter.release(key);
}

test "subnet handshake limit scales within defensive bounds" {
    try std.testing.expectEqual(@as(u16, 16), subnetHandshakeLimit(32));
    try std.testing.expectEqual(@as(u16, 64), subnetHandshakeLimit(512));
    try std.testing.expectEqual(@as(u16, 128), subnetHandshakeLimit(100_000));
}
