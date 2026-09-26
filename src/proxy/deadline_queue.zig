const std = @import("std");
const connection = @import("connection.zig");
const ConnectionSlot = connection.ConnectionSlot;

pub const DeadlineEntry = struct {
    deadline_ns: i128,
    slot_index: u32,
};

comptime {
    // One entry per active slot; avoid multiplying an accidental layout growth
    // by the configured connection cap.
    if (@sizeOf(DeadlineEntry) > 48) @compileError("DeadlineEntry exceeded its per-slot size budget");
}

/// The EventLoop owns the backing storage. Slot pointers are borrowed only for
/// an operation so the queue cannot retain a pointer into a moved EventLoop.
pub const DeadlineQueue = struct {
    pub const empty: DeadlineQueue = .{};

    entries: std.ArrayList(DeadlineEntry) = .empty,

    pub fn ensureTotalCapacity(self: *DeadlineQueue, allocator: std.mem.Allocator, capacity: usize) !void {
        try self.entries.ensureTotalCapacity(allocator, capacity);
    }

    pub fn deinit(self: *DeadlineQueue, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }

    pub fn peek(self: *const DeadlineQueue) ?DeadlineEntry {
        return if (self.entries.items.len == 0) null else self.entries.items[0];
    }

    fn less(self: *const DeadlineQueue, lhs: usize, rhs: usize) bool {
        return self.entries.items[lhs].deadline_ns < self.entries.items[rhs].deadline_ns;
    }

    fn swap(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, lhs: usize, rhs: usize) void {
        if (lhs == rhs) return;
        std.mem.swap(DeadlineEntry, &self.entries.items[lhs], &self.entries.items[rhs]);
        slots[@as(usize, self.entries.items[lhs].slot_index)].?.timer_heap_index = @intCast(lhs);
        slots[@as(usize, self.entries.items[rhs].slot_index)].?.timer_heap_index = @intCast(rhs);
    }

    fn siftUp(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, start: usize) void {
        var index = start;
        while (index > 0) {
            const parent = (index - 1) / 2;
            if (!self.less(index, parent)) break;
            self.swap(slots, index, parent);
            index = parent;
        }
    }

    fn siftDown(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, start: usize) void {
        var index = start;
        while (true) {
            const left = index * 2 + 1;
            if (left >= self.entries.items.len) break;
            const right = left + 1;
            const child = if (right < self.entries.items.len and self.less(right, left)) right else left;
            if (!self.less(child, index)) break;
            self.swap(slots, index, child);
            index = child;
        }
    }

    fn removeAt(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, index: usize) void {
        const removed = self.entries.items[index];
        slots[@as(usize, removed.slot_index)].?.timer_heap_index = connection.no_timer_heap_index;
        const last = self.entries.pop().?;
        if (index == self.entries.items.len) return;

        self.entries.items[index] = last;
        slots[@as(usize, last.slot_index)].?.timer_heap_index = @intCast(index);
        if (index > 0 and self.less(index, (index - 1) / 2)) {
            self.siftUp(slots, index);
        } else {
            self.siftDown(slots, index);
        }
    }

    pub fn remove(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, slot: *ConnectionSlot) void {
        if (slot.timer_heap_index == connection.no_timer_heap_index) return;
        self.removeAt(slots, @as(usize, slot.timer_heap_index));
    }

    pub fn update(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, slot: *ConnectionSlot, next: i128) void {
        if (slot.timer_heap_index == connection.no_timer_heap_index) {
            std.debug.assert(self.entries.items.len < self.entries.capacity);
            slot.timer_heap_index = @intCast(self.entries.items.len);
            self.entries.appendAssumeCapacity(.{ .deadline_ns = next, .slot_index = slot.index });
            self.siftUp(slots, @as(usize, slot.timer_heap_index));
        } else {
            const index = @as(usize, slot.timer_heap_index);
            const previous = self.entries.items[index].deadline_ns;
            self.entries.items[index].deadline_ns = next;
            if (next < previous) self.siftUp(slots, index) else self.siftDown(slots, index);
        }
    }

    pub fn popExpired(self: *DeadlineQueue, slots: []const ?*ConnectionSlot, now_ns: i128) ?u32 {
        const first = self.peek() orelse return null;
        if (first.deadline_ns > now_ns) return null;
        self.removeAt(slots, 0);
        return first.slot_index;
    }
};

test "deadline queue updates earlier/later and removes root, middle and last" {
    var slots_storage = [_]ConnectionSlot{
        .{ .index = 0 }, .{ .index = 1 }, .{ .index = 2 }, .{ .index = 3 },
    };
    const slots = [_]?*ConnectionSlot{ &slots_storage[0], &slots_storage[1], &slots_storage[2], &slots_storage[3] };
    var queue: DeadlineQueue = .empty;
    try queue.ensureTotalCapacity(std.testing.allocator, slots.len);
    defer queue.deinit(std.testing.allocator);

    queue.update(&slots, &slots_storage[0], 40);
    queue.update(&slots, &slots_storage[1], 10);
    queue.update(&slots, &slots_storage[2], 30);
    queue.update(&slots, &slots_storage[3], 20);
    try std.testing.expectEqual(@as(i128, 10), queue.peek().?.deadline_ns);

    queue.update(&slots, &slots_storage[1], 50);
    try std.testing.expectEqual(@as(i128, 20), queue.peek().?.deadline_ns);
    queue.update(&slots, &slots_storage[0], 5);
    try std.testing.expectEqual(@as(u32, 0), queue.peek().?.slot_index);

    queue.remove(&slots, &slots_storage[0]);
    try std.testing.expectEqual(connection.no_timer_heap_index, slots_storage[0].timer_heap_index);
    try std.testing.expectEqual(@as(u32, 3), queue.peek().?.slot_index);
    queue.remove(&slots, &slots_storage[2]);
    queue.remove(&slots, &slots_storage[1]);
    try std.testing.expectEqual(@as(?u32, null), queue.popExpired(&slots, 19));
    try std.testing.expectEqual(@as(?u32, 3), queue.popExpired(&slots, 20));
    try std.testing.expect(queue.peek() == null);
}

test "deadline queue clears slot index before reuse" {
    var slot = ConnectionSlot{ .index = 0 };
    const slots = [_]?*ConnectionSlot{&slot};
    var queue: DeadlineQueue = .empty;
    try queue.ensureTotalCapacity(std.testing.allocator, 1);
    defer queue.deinit(std.testing.allocator);

    queue.update(&slots, &slot, 7);
    try std.testing.expectEqual(@as(?u32, 0), queue.popExpired(&slots, 7));
    try std.testing.expectEqual(connection.no_timer_heap_index, slot.timer_heap_index);
    slot = .{ .index = 0 };
    queue.update(&slots, &slot, 9);
    try std.testing.expectEqual(@as(?u32, 0), queue.popExpired(&slots, 9));
    try std.testing.expect(queue.peek() == null);
}

test "deadline queue matches a reference over deterministic updates and removals" {
    var storage: [8]ConnectionSlot = undefined;
    var slots: [8]?*ConnectionSlot = undefined;
    for (&storage, 0..) |*slot, index| {
        slot.* = .{ .index = @intCast(index) };
        slots[index] = slot;
    }
    var expected = [_]?i128{null} ** storage.len;
    var queue: DeadlineQueue = .empty;
    try queue.ensureTotalCapacity(std.testing.allocator, storage.len);
    defer queue.deinit(std.testing.allocator);

    var seed: u64 = 0x4e6f_6465_7175_6575;
    for (0..500) |_| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        const index: usize = @intCast(seed % storage.len);
        if (seed % 3 == 0) {
            queue.remove(&slots, &storage[index]);
            expected[index] = null;
        } else {
            const deadline: i128 = @intCast((seed >> 16) % 1000);
            queue.update(&slots, &storage[index], deadline);
            expected[index] = deadline;
        }

        var minimum: ?i128 = null;
        for (expected, 0..) |deadline, idx| {
            if (deadline) |value| {
                minimum = if (minimum) |current| @min(current, value) else value;
                const heap_index = storage[idx].timer_heap_index;
                try std.testing.expect(heap_index != connection.no_timer_heap_index);
                try std.testing.expectEqual(@as(u32, @intCast(idx)), queue.entries.items[heap_index].slot_index);
                try std.testing.expectEqual(value, queue.entries.items[heap_index].deadline_ns);
            } else {
                try std.testing.expectEqual(connection.no_timer_heap_index, storage[idx].timer_heap_index);
            }
        }
        if (minimum) |value| {
            try std.testing.expectEqual(value, queue.peek().?.deadline_ns);
        } else {
            try std.testing.expect(queue.peek() == null);
        }
    }

    while (queue.popExpired(&slots, 1000)) |index| {
        try std.testing.expect(expected[index] != null);
        expected[index] = null;
    }
    try std.testing.expect(queue.peek() == null);
    for (expected) |deadline| try std.testing.expect(deadline == null);
}
