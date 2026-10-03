//! Membership-only prefilter for 43-character WEB credentials. A prefix hit must
//! still be followed by the caller's full constant-time authentication scan.
const std = @import("std");

pub const encoded_len: usize = 43;
pub const prefix_bits: usize = 64;

/// Read the first eight decoded bytes without decoding or allocating the whole
/// credential. Eleven base64url characters contain 66 bits: the low two bits of
/// character 11 belong to byte nine, so they must not affect this prefix.
pub fn prefix(text: []const u8) ?u64 {
    if (text.len != encoded_len) return null;
    var value: u64 = 0;
    for (text[0..10]) |byte| value = (value << 6) | (base64Bits(byte) orelse return null);
    const last = base64Bits(text[10]) orelse return null;
    return (value << 4) | @as(u64, last >> 2);
}

fn base64Bits(byte: u8) ?u6 {
    return switch (byte) {
        'A'...'Z' => @intCast(byte - 'A'),
        'a'...'z' => @intCast(byte - 'a' + 26),
        '0'...'9' => @intCast(byte - '0' + 52),
        '-' => 62,
        '_' => 63,
        else => null,
    };
}

const Context = struct {
    key: [16]u8,

    pub fn hash(self: Context, value: u64) u64 {
        var digest: [8]u8 = undefined;
        std.crypto.auth.siphash.SipHash64(2, 4).create(&digest, std.mem.asBytes(&value), &self.key);
        return std.mem.readInt(u64, &digest, .little);
    }

    pub fn eql(_: Context, a: u64, b: u64) bool {
        return a == b;
    }
};

/// Reference counts let distinct credentials share a prefix. No positions or
/// borrowed credential slices are stored, so moving authoritative entries is safe.
/// Owned and mutated only by the WEB relay's event-loop thread.
pub const PrefixIndex = struct {
    const Map = std.HashMapUnmanaged(u64, usize, Context, 80);
    counts: Map = .empty,
    hash_key: [16]u8 = @splat(0),
    seeded: bool = false,
    removals_since_rehash: usize = 0,

    pub fn init(io: std.Io) !PrefixIndex {
        var result: PrefixIndex = .{};
        errdefer std.crypto.secureZero(u8, &result.hash_key);
        try std.Io.randomSecure(io, &result.hash_key);
        result.seeded = true;
        return result;
    }

    pub fn deinit(self: *PrefixIndex, allocator: std.mem.Allocator) void {
        self.counts.deinit(allocator);
        std.crypto.secureZero(u8, &self.hash_key);
        self.* = .{};
    }

    pub fn add(self: *PrefixIndex, allocator: std.mem.Allocator, text: []const u8) !void {
        std.debug.assert(self.seeded);
        const value = prefix(text) orelse return error.InvalidCredential;
        const entry = try self.counts.getOrPutContext(allocator, value, .{ .key = self.hash_key });
        if (entry.found_existing) entry.value_ptr.* += 1 else entry.value_ptr.* = 1;
    }

    pub fn contains(self: *const PrefixIndex, text: []const u8) bool {
        if (!self.seeded or self.counts.count() == 0) return false;
        const value = prefix(text) orelse return false;
        return self.counts.containsContext(value, .{ .key = self.hash_key });
    }

    /// Called exactly once for every removed authoritative credential.
    pub fn remove(self: *PrefixIndex, text: []const u8) void {
        const value = prefix(text).?;
        const count = self.counts.getPtrContext(value, .{ .key = self.hash_key }).?;
        std.debug.assert(count.* > 0);
        if (count.* > 1) {
            count.* -= 1;
        } else {
            const removed = self.counts.removeContext(value, .{ .key = self.hash_key });
            std.debug.assert(removed);
            self.removals_since_rehash += 1;
            // Zig's map retains tombstones after removal. Bound their accumulation
            // so repeated token churn cannot turn a miss into a whole-table probe.
            // Both maintenance operations are in-place and require no allocator.
            if (self.counts.count() == 0) {
                self.counts.clearRetainingCapacity();
                self.removals_since_rehash = 0;
            } else if (self.removals_since_rehash >= @max(@as(usize, 1), self.counts.capacity() / 16)) {
                self.counts.rehash(Context{ .key = self.hash_key });
                self.removals_since_rehash = 0;
            }
        }
    }
};

test "credential prefix retains 64 decoded bits across base64 boundaries" {
    var bytes: [32]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @intCast(i * 7);
    var text: [encoded_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&text, &bytes);
    const expected = std.mem.readInt(u64, bytes[0..8], .big);
    try std.testing.expectEqual(@as(?u64, expected), prefix(&text));
    const original = text;
    // Every possible low-two-bit value of symbol 11 has the same byte-8 prefix.
    for ([_]u8{ 0x00, 0x40, 0x80, 0xc0 }) |byte9| {
        bytes[8] = byte9;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&text, &bytes);
        try std.testing.expectEqual(@as(?u64, expected), prefix(&text));
    }
    try std.testing.expect(!std.mem.eql(u8, &original, &text));
    try std.testing.expect(prefix(text[0 .. text.len - 1]) == null);
    text[0] = '!';
    try std.testing.expect(prefix(&text) == null);
}

test "credential prefix index retains colliding members until the last removal" {
    const allocator = std.testing.allocator;
    var index = try PrefixIndex.init(std.testing.io);
    defer index.deinit(allocator);
    const a: [encoded_len]u8 = @splat('A');
    var b = a;
    b[20] = 'B';
    var missing = a;
    missing[0] = 'B';
    try index.add(allocator, &a);
    try index.add(allocator, &b);
    try std.testing.expectEqual(@as(usize, 1), index.counts.count());
    try std.testing.expect(index.contains(&a) and index.contains(&b));
    try std.testing.expect(!index.contains(&missing));
    index.remove(&a);
    try std.testing.expect(index.contains(&b));
    index.remove(&b);
    try std.testing.expect(!index.contains(&a));
    try std.testing.expectEqual(@as(usize, 0), index.counts.count());
}

fn testCredential(value: u64) [encoded_len]u8 {
    var bytes: [32]u8 = @splat(0);
    std.mem.writeInt(u64, bytes[0..8], value, .big);
    var text: [encoded_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&text, &bytes);
    return text;
}

test "credential prefix churn preserves members and collision references through rehash" {
    const allocator = std.testing.allocator;
    // A fixed hash key makes this synthetic workload deterministic.
    var index = PrefixIndex{ .seeded = true };
    defer index.deinit(allocator);
    const anchor = testCredential(std.math.maxInt(u64));
    var same_prefix = anchor;
    same_prefix[20] = 'B';
    try index.add(allocator, &anchor);
    try index.add(allocator, &same_prefix);
    var residents: [64][encoded_len]u8 = undefined;
    for (&residents, 0..) |*text, i| {
        text.* = testCredential(@intCast(i + 1));
        try index.add(allocator, text);
    }
    for (0..32) |round| {
        for (&residents, 0..) |*text, i| {
            index.remove(text);
            try std.testing.expect(!index.contains(text));
            text.* = testCredential(@intCast(1 + (round + 1) * residents.len + i));
            try index.add(allocator, text);
        }
        for (residents) |text| try std.testing.expect(index.contains(&text));
        try std.testing.expect(index.contains(&anchor) and index.contains(&same_prefix));
        try std.testing.expect(index.removals_since_rehash < @max(@as(usize, 1), index.counts.capacity() / 16));
    }
    index.remove(&anchor);
    try std.testing.expect(index.contains(&same_prefix));
    index.remove(&same_prefix);
    try std.testing.expect(!index.contains(&anchor));
    for (residents) |text| index.remove(&text);
    try std.testing.expectEqual(@as(usize, 0), index.counts.count());
    try std.testing.expectEqual(@as(usize, 0), index.removals_since_rehash);
    try index.add(allocator, &anchor);
    try std.testing.expect(index.contains(&anchor));
}
