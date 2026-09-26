const std = @import("std");
const ConnectionSlot = @import("connection.zig").ConnectionSlot;

pub const epoll_listener_token: u64 = 0;
pub const epoll_timer_token: u64 = 1;
pub const epoll_shutdown_token: u64 = 2;
const max_slot_generation: u32 = 0x7fff_ffff;

pub const SlotFdRole = enum(u1) {
    client = 0,
    upstream = 1,
};

pub const SlotEventToken = struct {
    index: u32,
    generation: u32,
    role: SlotFdRole,
};

pub fn nextSlotGeneration(current: u32) u32 {
    const next = (current +% 1) & max_slot_generation;
    return if (next == 0) 1 else next;
}

pub fn encodeSlotEventToken(slot: *const ConnectionSlot, role: SlotFdRole) u64 {
    const generation = switch (role) {
        .client => slot.client_event_generation,
        .upstream => slot.upstream_event_generation,
    };
    return @as(u64, slot.index) |
        (@as(u64, generation) << 32) |
        (@as(u64, @intFromEnum(role)) << 63);
}

pub fn decodeSlotEventToken(token: u64) ?SlotEventToken {
    const generation: u32 = @intCast((token >> 32) & @as(u64, max_slot_generation));
    if (generation == 0) return null;
    return .{
        .index = @truncate(token),
        .generation = generation,
        .role = @enumFromInt(@as(u1, @truncate(token >> 63))),
    };
}

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    slots: []?*ConnectionSlot,
    free_stack: []u32,
    free_count: u32,

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !ConnectionPool {
        const slots = try allocator.alloc(?*ConnectionSlot, capacity);
        errdefer allocator.free(slots);

        const free_stack = try allocator.alloc(u32, capacity);
        errdefer allocator.free(free_stack);

        for (slots) |*slot| {
            slot.* = null;
        }

        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            free_stack[i] = @intCast(capacity - 1 - i);
        }

        return ConnectionPool{
            .allocator = allocator,
            .slots = slots,
            .free_stack = free_stack,
            .free_count = capacity,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.slots) |slot_opt| {
            if (slot_opt) |slot_ptr| {
                slot_ptr.resetOwnedBuffers(self.allocator);
                self.allocator.destroy(slot_ptr);
            }
        }
        self.allocator.free(self.free_stack);
        self.allocator.free(self.slots);
    }

    pub fn acquire(self: *ConnectionPool) ?*ConnectionSlot {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const idx = self.free_stack[self.free_count];
        if (self.slots[idx] == null) {
            const fresh = self.allocator.create(ConnectionSlot) catch {
                self.free_stack[self.free_count] = idx;
                self.free_count += 1;
                return null;
            };
            fresh.* = .{};
            self.slots[idx] = fresh;
        }

        const slot = self.slots[idx].?;
        const event_generation = slot.event_generation;
        slot.* = .{};
        slot.index = idx;
        slot.event_generation = event_generation;
        slot.client_queue.allocator = self.allocator;
        slot.upstream_queue.allocator = self.allocator;
        return slot;
    }

    pub fn release(self: *ConnectionPool, slot: *ConnectionSlot) void {
        self.free_stack[self.free_count] = slot.index;
        self.free_count += 1;
        slot.phase = .idle;
    }

    pub fn getByToken(self: *ConnectionPool, token: SlotEventToken) ?*ConnectionSlot {
        if (@as(usize, token.index) >= self.slots.len) return null;
        const slot = self.slots[token.index] orelse return null;
        if (slot.phase == .idle) return null;
        const current_generation = switch (token.role) {
            .client => slot.client_event_generation,
            .upstream => slot.upstream_event_generation,
        };
        if (current_generation != token.generation) return null;
        return slot;
    }
};

test "epoll slot tokens preserve registration generation and fd role" {
    var slot = ConnectionSlot{
        .index = 123,
        .client_event_generation = 77,
        .upstream_event_generation = 91,
    };

    const client = decodeSlotEventToken(encodeSlotEventToken(&slot, .client)).?;
    try std.testing.expectEqual(@as(u32, 123), client.index);
    try std.testing.expectEqual(@as(u32, 77), client.generation);
    try std.testing.expectEqual(SlotFdRole.client, client.role);

    const upstream = decodeSlotEventToken(encodeSlotEventToken(&slot, .upstream)).?;
    try std.testing.expectEqual(@as(u32, 91), upstream.generation);
    try std.testing.expectEqual(SlotFdRole.upstream, upstream.role);
    try std.testing.expectEqual(@as(u32, 1), nextSlotGeneration(max_slot_generation));
    try std.testing.expect(decodeSlotEventToken(epoll_listener_token) == null);
    try std.testing.expect(decodeSlotEventToken(epoll_timer_token) == null);
    try std.testing.expect(decodeSlotEventToken(epoll_shutdown_token) == null);
}

test "stale epoll token is rejected after pool slot reuse" {
    var conn_pool = try ConnectionPool.init(std.testing.allocator, 1);
    defer conn_pool.deinit();

    const first = conn_pool.acquire() orelse return error.TestExpectedEqual;
    first.phase = .relaying;
    first.event_generation = nextSlotGeneration(first.event_generation);
    first.client_event_generation = first.event_generation;
    const stale = decodeSlotEventToken(encodeSlotEventToken(first, .client)).?;
    try std.testing.expect(conn_pool.getByToken(stale) == first);
    conn_pool.release(first);

    const reused = conn_pool.acquire() orelse return error.TestExpectedEqual;
    defer conn_pool.release(reused);
    reused.phase = .relaying;
    reused.event_generation = nextSlotGeneration(reused.event_generation);
    reused.client_event_generation = reused.event_generation;
    try std.testing.expect(conn_pool.getByToken(stale) == null);
    const current = decodeSlotEventToken(encodeSlotEventToken(reused, .client)).?;
    try std.testing.expect(conn_pool.getByToken(current) == reused);
}
