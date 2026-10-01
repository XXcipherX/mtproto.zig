//! Bounded, short-lived carrier credentials; never derived from the user's secret.
const std = @import("std");
const credential_index = @import("credential_index.zig");

pub const Token = [43]u8;
pub const lifetime_ms: i64 = 120_000;

const Entry = struct {
    token: Token,
    user: []const u8,
    expires: i64,
    active: ?i32 = null,
};

pub const Store = struct {
    entries: std.ArrayList(Entry) = .empty,
    prefixes: credential_index.PrefixIndex = .{},

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.prefixes.deinit(allocator);
    }

    pub fn issue(self: *Store, allocator: std.mem.Allocator, io: std.Io, user: []const u8, now: i64, limit: usize) !Token {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].expires <= now) {
                self.removeEntry(i);
            } else {
                i += 1;
            }
        }
        if (self.entries.items.len >= limit) return error.Capacity;

        var entropy: [32]u8 = undefined;
        try std.Io.randomSecure(io, &entropy);
        var token: Token = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &entropy);
        if (!self.prefixes.seeded) self.prefixes = try credential_index.PrefixIndex.init(io);
        try self.appendEntry(allocator, .{
            .token = token,
            .user = user,
            .expires = now + lifetime_ms,
        });
        return token;
    }

    fn appendEntry(self: *Store, allocator: std.mem.Allocator, entry: Entry) !void {
        // Reserve authoritative storage first. After prefix insertion succeeds,
        // append cannot fail, so no allocation failure leaves a phantom prefix.
        try self.entries.ensureUnusedCapacity(allocator, 1);
        try self.prefixes.add(allocator, &entry.token);
        self.entries.appendAssumeCapacity(entry);
    }

    fn removeEntry(self: *Store, i: usize) void {
        const removed = self.entries.swapRemove(i);
        self.prefixes.remove(&removed.token);
    }

    /// Match without revealing which byte differed. A token may have one in-flight
    /// carrier and is removed permanently once that carrier reaches WELCOME.
    pub fn acquire(self: *Store, text: []const u8, fd: i32, now: i64) ?[]const u8 {
        return self.acquireCounted(text, fd, now, null);
    }

    fn acquireCounted(self: *Store, text: []const u8, fd: i32, now: i64, comparisons: ?*usize) ?[]const u8 {
        if (text.len != 43) return null;
        if (!self.prefixes.contains(text)) return null;
        var matched: ?usize = null;
        for (self.entries.items, 0..) |entry, i| {
            if (comparisons) |count| count.* += 1;
            if (std.crypto.timing_safe.eql(Token, text[0..43].*, entry.token)) matched = i;
        }
        const entry = &self.entries.items[matched orelse return null];
        if (now >= entry.expires or entry.active != null) return null;
        entry.active = fd;
        return entry.user;
    }

    pub fn release(self: *Store, text: []const u8, fd: i32, consumed: bool) void {
        for (self.entries.items, 0..) |*entry, i| {
            if (entry.active == fd and std.mem.eql(u8, text, &entry.token)) {
                if (consumed) {
                    self.removeEntry(i);
                } else {
                    entry.active = null;
                }
                return;
            }
        }
    }
};

test "carrier credentials expire and cannot attach twice or resume an adopted session" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    const token = try store.issue(allocator, std.testing.io, "alice", 1000, 4);
    try std.testing.expectEqual(@as(usize, 43), token.len);
    for (token) |c| try std.testing.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    try std.testing.expectEqualStrings("alice", store.acquire(&token, 8, 1001).?);
    try std.testing.expect(store.acquire(&token, 9, 1002) == null);
    store.release(&token, 8, false);
    try std.testing.expectEqualStrings("alice", store.acquire(&token, 9, 1003).?);
    store.release(&token, 9, true);
    try std.testing.expect(store.acquire(&token, 10, 1004) == null);

    const fresh = try store.issue(allocator, std.testing.io, "bob", 2000, 4);
    try std.testing.expect(store.acquire(&fresh, 11, 2000 + lifetime_ms) == null);
}

test "expired entries release issuance capacity and failed acquisition does not consume" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    const first = try store.issue(allocator, std.testing.io, "alice", 0, 1);
    try std.testing.expectError(error.Capacity, store.issue(allocator, std.testing.io, "bob", 1, 1));
    try std.testing.expect(store.acquire("bad", 1, 2) == null);
    const next = try store.issue(allocator, std.testing.io, "bob", lifetime_ms, 1);
    try std.testing.expect(!std.mem.eql(u8, &first, &next));
    try std.testing.expectEqualStrings("bob", store.acquire(&next, 1, lifetime_ms + 1).?);
}

fn testToken(first_eight_bytes: u64, remainder: u8) Token {
    var bytes: [32]u8 = undefined;
    @memset(&bytes, remainder);
    std.mem.writeInt(u64, bytes[0..8], first_eight_bytes, .big);
    var token: Token = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &bytes);
    return token;
}

fn expectIndexConsistent(store: *const Store) !void {
    var references: usize = 0;
    var counts = store.prefixes.counts.valueIterator();
    while (counts.next()) |count| references += count.*;
    try std.testing.expectEqual(store.entries.items.len, references);
    for (store.entries.items) |entry| try std.testing.expect(store.prefixes.contains(&entry.token));
}

test "token prefix collisions survive active, retry, consumption, expiry and swap removal" {
    const allocator = std.testing.allocator;
    var store = Store{ .prefixes = try credential_index.PrefixIndex.init(std.testing.io) };
    defer store.deinit(allocator);
    const first = testToken(7, 0);
    const second = testToken(7, 0xff);
    const wrong_remainder = testToken(7, 0x71);
    const other = testToken(8, 0);
    try store.appendEntry(allocator, .{ .token = first, .user = "alice", .expires = 100 });
    try store.appendEntry(allocator, .{ .token = second, .user = "bob", .expires = 200 });
    try store.appendEntry(allocator, .{ .token = other, .user = "carol", .expires = 300 });
    try expectIndexConsistent(&store);
    var comparisons: usize = 0;
    try std.testing.expect(store.acquireCounted(&wrong_remainder, 1, 1, &comparisons) == null);
    try std.testing.expectEqual(@as(usize, 3), comparisons);
    try std.testing.expectEqualStrings("alice", store.acquire(&first, 1, 1).?);
    try std.testing.expect(store.acquire(&first, 2, 2) == null);
    store.release(&first, 2, true); // A wrong owner cannot remove its prefix.
    try expectIndexConsistent(&store);
    store.release(&first, 1, false);
    try std.testing.expectEqualStrings("alice", store.acquire(&first, 2, 3).?);
    store.release(&first, 2, true); // Moves the unrelated final entry.
    try std.testing.expect(store.acquire(&first, 3, 4) == null);
    try std.testing.expectEqualStrings("bob", store.acquire(&second, 3, 4).?);
    store.release(&second, 3, false);
    try std.testing.expectEqualStrings("carol", store.acquire(&other, 4, 4).?);
    store.release(&other, 4, false);
    try expectIndexConsistent(&store);

    try std.testing.expect(store.acquire(&second, 5, 200) == null);
    _ = try store.issue(allocator, std.testing.io, "fresh", 200, 3);
    try std.testing.expect(!store.prefixes.contains(&second));
    try std.testing.expect(store.prefixes.contains(&other));
    try expectIndexConsistent(&store);
    _ = try store.issue(allocator, std.testing.io, "replacement", 200 + lifetime_ms, 1);
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
    try std.testing.expect(!store.prefixes.contains(&other));
    try expectIndexConsistent(&store);
}

test "negative token lookup performs zero full comparisons for bounded large stores" {
    const allocator = std.testing.allocator;
    const missing = testToken(std.math.maxInt(u64), 0);
    for ([_]usize{ 1, 64, 4096 }) |size| {
        var store = Store{ .prefixes = try credential_index.PrefixIndex.init(std.testing.io) };
        defer store.deinit(allocator);
        for (0..size) |i| try store.appendEntry(allocator, .{
            .token = testToken(@intCast(i), 0x71),
            .user = "user",
            .expires = lifetime_ms,
        });
        var comparisons: usize = 0;
        try std.testing.expect(store.acquireCounted(&missing, 1, 1, &comparisons) == null);
        try std.testing.expectEqual(@as(usize, 0), comparisons);
        const hit = store.entries.items[size - 1].token;
        try std.testing.expectEqualStrings("user", store.acquireCounted(&hit, 1, 1, &comparisons).?);
        try std.testing.expectEqual(size, comparisons);
        store.release(&hit, 1, true);
        try std.testing.expect(!store.prefixes.contains(&hit));
        try expectIndexConsistent(&store);
    }
}

fn tokenIndexAllocationTest(allocator: std.mem.Allocator) !void {
    var store = Store{};
    defer store.deinit(allocator);
    for (0..96) |_| {
        _ = store.issue(allocator, std.testing.io, "user", 0, 96) catch |err| {
            try expectIndexConsistent(&store);
            return err;
        };
        try expectIndexConsistent(&store);
    }
}

test "token entry and prefix growth stay consistent on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, tokenIndexAllocationTest, .{});
}
