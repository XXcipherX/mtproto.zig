//! Intrusive page-block relay queues and retained worker-local free list.
//! The owning EventLoop supplies one managed allocator and deinitializes its pool
//! after every slot has released its queue blocks.
const std = @import("std");
const posix = std.posix;
const Config = @import("../config.zig").Config;
const ManagedBufferAllocator = @import("managed_buffer_allocator.zig").ManagedBufferAllocator;

const msg_block_header_size: usize = @sizeOf(?*anyopaque) + @sizeOf(usize);
const msg_block_payload_size: usize = std.heap.page_size_min - msg_block_header_size;

const MsgBlock = struct {
    next: ?*@This() = null,
    len: usize = 0,
    data: [msg_block_payload_size]u8 = undefined,
};

comptime {
    if (@sizeOf(MsgBlock) != std.heap.page_size_min) {
        @compileError("MsgBlock must occupy exactly one minimum target page");
    }
}

fn blockStorage(blk: *MsgBlock) []u8 {
    return blk.data[0..];
}

fn blockStorageConst(blk: *const MsgBlock) []const u8 {
    return blk.data[0..];
}

fn allocateMsgBlock(allocator: std.mem.Allocator) !*MsgBlock {
    const blk = try allocator.create(MsgBlock);
    blk.* = .{};
    return blk;
}

fn wipeMsgBlock(blk: *MsgBlock) void {
    std.crypto.secureZero(u8, blockStorage(blk));
    blk.len = 0;
}

fn destroyMsgBlock(allocator: std.mem.Allocator, blk: *MsgBlock) void {
    wipeMsgBlock(blk);
    blk.next = null;
    allocator.destroy(blk);
}

pub const MessageBlockPool = struct {
    const max_free_blocks: usize = 1024;

    allocator: std.mem.Allocator,
    free_head: ?*MsgBlock = null,
    free_count: usize = 0,

    pub fn deinit(self: *MessageBlockPool) void {
        var current = self.free_head;
        while (current) |blk| {
            const next = blk.next;
            destroyMsgBlock(self.allocator, blk);
            current = next;
        }
        self.free_head = null;
        self.free_count = 0;
    }

    fn acquire(self: *MessageBlockPool) !*MsgBlock {
        const blk = self.free_head orelse return allocateMsgBlock(self.allocator);
        self.free_head = blk.next;
        self.free_count -= 1;
        blk.next = null;
        blk.len = 0;
        return blk;
    }

    fn recycle(self: *MessageBlockPool, blk: *MsgBlock) void {
        if (self.free_count >= max_free_blocks) {
            destroyMsgBlock(self.allocator, blk);
            return;
        }
        wipeMsgBlock(blk);
        blk.next = self.free_head;
        self.free_head = blk;
        self.free_count += 1;
    }
};

pub const MessageQueue = struct {
    const max_pending_bytes: usize = Config.relay_queue_max_pending_bytes;

    allocator: std.mem.Allocator,
    pool: ?*MessageBlockPool = null,
    head: ?*MsgBlock = null,
    tail: ?*MsgBlock = null,
    offset: usize = 0,
    total_len: usize = 0,

    pub fn deinit(self: *MessageQueue) void {
        self.clear();
    }

    pub fn clear(self: *MessageQueue) void {
        var current = self.head;
        while (current) |blk| {
            const next = blk.next;
            self.recycleBlock(blk);
            current = next;
        }
        self.head = null;
        self.tail = null;
        self.offset = 0;
        self.total_len = 0;
    }

    pub fn isEmpty(self: *const MessageQueue) bool {
        return self.total_len == 0;
    }

    pub fn appendCopy(self: *MessageQueue, data: []const u8) !void {
        if (data.len == 0) return;
        try self.ensureCanAppend(data.len);

        var off: usize = 0;
        if (self.tail) |tail| {
            const available = blockStorage(tail).len - tail.len;
            const take = @min(data.len, available);
            if (take > 0) {
                @memcpy(
                    blockStorage(tail)[tail.len .. tail.len + take],
                    data[0..take],
                );
                tail.len += take;
                self.total_len += take;
                off = take;
            }
        }

        while (off < data.len) {
            const take = @min(data.len - off, msg_block_payload_size);
            const blk = try self.acquireBlock();
            blk.len = take;
            blk.next = null;
            @memcpy(blockStorage(blk)[0..take], data[off .. off + take]);

            if (self.tail) |tail| {
                tail.next = blk;
            } else {
                self.head = blk;
            }
            self.tail = blk;
            self.total_len += take;
            off += take;
        }
    }

    pub fn ensureCanAppend(self: *const MessageQueue, additional_len: usize) !void {
        if (additional_len > max_pending_bytes or self.total_len > max_pending_bytes - additional_len) {
            return error.PendingQueueOverflow;
        }
    }

    pub fn prepareIovecs(self: *const MessageQueue, out: []posix.iovec_const, max_bytes: usize) usize {
        if (self.head == null or max_bytes == 0) return 0;

        var count: usize = 0;
        var prepared: usize = 0;
        var local_off = self.offset;
        var current = self.head;
        while (current) |blk| {
            if (count >= out.len or prepared >= max_bytes) break;

            if (local_off >= blk.len) {
                local_off -= blk.len;
                current = blk.next;
                continue;
            }

            const storage = blockStorageConst(blk);
            const take = @min(blk.len - local_off, max_bytes - prepared);
            out[count] = .{ .base = storage[local_off..blk.len].ptr, .len = take };
            count += 1;
            prepared += take;
            local_off = 0;
            current = blk.next;
        }
        return count;
    }

    pub fn consume(self: *MessageQueue, bytes: usize) !void {
        if (bytes == 0 or self.total_len == 0) return;

        var remaining = @min(bytes, self.total_len);
        self.total_len -= remaining;

        while (remaining > 0) {
            const blk = self.head orelse unreachable;
            const blk_left = blk.len - self.offset;

            if (remaining < blk_left) {
                self.offset += remaining;
                remaining = 0;
                break;
            }

            remaining -= blk_left;
            self.offset = 0;
            self.head = blk.next;
            if (self.head == null) self.tail = null;
            self.recycleBlock(blk);
        }

        if (self.total_len == 0) {
            self.head = null;
            self.tail = null;
            self.offset = 0;
        }
    }

    fn acquireBlock(self: *MessageQueue) !*MsgBlock {
        if (self.pool) |pool| return pool.acquire();
        return allocateMsgBlock(self.allocator);
    }

    fn recycleBlock(self: *MessageQueue, blk: *MsgBlock) void {
        if (self.pool) |pool| {
            pool.recycle(blk);
        } else {
            destroyMsgBlock(self.allocator, blk);
        }
    }
};

pub const QueueMemoryBudget = struct {
    per_connection_bytes: u64,
    shared_pool_bytes: u64,
};

/// Conservative physical-memory budget for page-allocator-backed relay queues.
///
/// Each connection owns two queues. The extra active block per queue covers a
/// consumed prefix retained in the head block while unread bytes refill the
/// queue to its byte cap. The event-loop pool is shared across all connections.
pub fn queueMemoryBudget(runtime_page_size: usize) QueueMemoryBudget {
    std.debug.assert(std.math.isPowerOfTwo(runtime_page_size));
    std.debug.assert(runtime_page_size >= std.heap.page_size_min);

    const full_queue_blocks =
        (MessageQueue.max_pending_bytes + msg_block_payload_size - 1) /
        msg_block_payload_size;
    const active_blocks_per_queue = full_queue_blocks + 1;
    const per_connection_wide =
        @as(u128, active_blocks_per_queue) * 2 * @as(u128, runtime_page_size);
    const shared_pool_wide =
        @as(u128, MessageBlockPool.max_free_blocks) * @as(u128, runtime_page_size);
    std.debug.assert(per_connection_wide <= std.math.maxInt(u64));
    std.debug.assert(shared_pool_wide <= std.math.maxInt(u64));

    return .{
        .per_connection_bytes = @intCast(per_connection_wide),
        .shared_pool_bytes = @intCast(shared_pool_wide),
    };
}

comptime {
    // Two queue headers live inline in each ConnectionSlot; page data remains
    // out of line and is already guarded by MsgBlock's exact page invariant.
    if (@sizeOf(MessageQueue) > 96) @compileError("MessageQueue exceeded its per-connection size budget");
    if (@sizeOf(MessageBlockPool) > 64) @compileError("MessageBlockPool exceeded its per-worker size budget");
}

test "message queue consume is stable" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    try q.appendCopy("defg");
    try std.testing.expectEqual(@as(usize, 7), q.total_len);

    try q.consume(2);
    try std.testing.expectEqual(@as(usize, 5), q.total_len);

    var iov: [8]posix.iovec_const = undefined;
    const n = q.prepareIovecs(iov[0..], std.math.maxInt(usize));
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 'c'), iov[0].base[0]);

    try q.consume(5);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.offset);
    try std.testing.expect(q.head == null);
    try std.testing.expect(q.tail == null);
}

test "message queue uses page-sized blocks and fills the tail first" {
    try std.testing.expectEqual(std.heap.page_size_min, @sizeOf(MsgBlock));
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    const first = q.head.?;
    try q.appendCopy("defg");
    try std.testing.expect(q.head.? == first);
    try std.testing.expect(q.tail.? == first);
    try std.testing.expect(first.next == null);
    try std.testing.expectEqual(@as(usize, 7), first.len);
    try std.testing.expectEqualStrings("abcdefg", blockStorageConst(first)[0..first.len]);

    q.clear();

    var payload: [msg_block_payload_size + 1]u8 = [_]u8{0xA5} ** (msg_block_payload_size + 1);
    try q.appendCopy(&payload);
    const page_first = q.head.?;
    const page_second = page_first.next.?;
    try std.testing.expectEqual(msg_block_payload_size, page_first.len);
    try std.testing.expectEqual(@as(usize, 1), page_second.len);
    try std.testing.expect(q.tail.? == page_second);
    try std.testing.expect(page_second.next == null);
}

test "message queue consumed prefix permits one conservative extra block" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    var payload: [msg_block_payload_size]u8 = [_]u8{0x5A} ** msg_block_payload_size;
    try q.appendCopy(&payload);
    const first = q.head.?;
    try q.consume(1);
    try q.appendCopy(&[_]u8{0xA5});

    try std.testing.expectEqual(msg_block_payload_size, q.total_len);
    try std.testing.expect(q.head.? == first);
    try std.testing.expect(first.next != null);
    try std.testing.expect(q.tail.? == first.next.?);
}

test "message queue rejects pending byte overflow" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    q.total_len = MessageQueue.max_pending_bytes;
    try std.testing.expectError(error.PendingQueueOverflow, q.ensureCanAppend(1));
    q.total_len = 0;
}

test "shared message block pool trims and wipes recycled page blocks" {
    var pool = MessageBlockPool{ .allocator = std.testing.allocator };
    defer pool.deinit();

    var blocks: [MessageBlockPool.max_free_blocks + 8]*MsgBlock = undefined;
    for (&blocks) |*entry| {
        entry.* = try pool.acquire();
        @memset(blockStorage(entry.*), 0xA5);
        entry.*.len = msg_block_payload_size;
    }
    for (blocks) |blk| pool.recycle(blk);

    try std.testing.expectEqual(MessageBlockPool.max_free_blocks, pool.free_count);
    const recycled = pool.free_head.?;
    try std.testing.expectEqual(@as(usize, 0), recycled.len);
    for (blockStorageConst(recycled)) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "managed buffer budget includes retained message pages" {
    const page_bytes = @sizeOf(MsgBlock);
    var budget = ManagedBufferAllocator.init(std.testing.allocator, page_bytes);
    var pool = MessageBlockPool{ .allocator = budget.allocator() };

    const first = try pool.acquire();
    try std.testing.expectEqual(page_bytes, budget.used_bytes);
    try std.testing.expectError(error.OutOfMemory, pool.acquire());

    pool.recycle(first);
    try std.testing.expectEqual(page_bytes, budget.used_bytes);
    const reused = try pool.acquire();
    try std.testing.expect(reused == first);
    pool.recycle(reused);

    pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), budget.used_bytes);
}

test "queue memory budget covers two queues and the shared pool" {
    const runtime_page_size = std.heap.page_size_min;
    const full_queue_blocks =
        (MessageQueue.max_pending_bytes + msg_block_payload_size - 1) /
        msg_block_payload_size;
    const active_blocks_per_queue = full_queue_blocks + 1;
    const budget = queueMemoryBudget(runtime_page_size);

    try std.testing.expectEqual(
        @as(u64, @intCast(active_blocks_per_queue * 2 * runtime_page_size)),
        budget.per_connection_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(MessageBlockPool.max_free_blocks * runtime_page_size)),
        budget.shared_pool_bytes,
    );
}
