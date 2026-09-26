//! Worker-local managed allocation accounting. No remap: growth charges its transient peak.
const std = @import("std");

/// Exact worker-local partition of the process budget for dynamic relay and
/// MiddleProxy storage.
///
/// The epoll loop is single-threaded, so the accounting deliberately avoids
/// atomics. `remap` is refused: `Allocator.realloc` then allocates the new
/// region before releasing the old one, which makes transient growth count
/// against the limit instead of hiding a temporary RSS spike.
pub const ManagedBufferAllocator = struct {
    child: std.mem.Allocator,
    limit_bytes: usize,
    used_bytes: usize = 0,
    peak_bytes: usize = 0,
    denied_allocations: u64 = 0,

    pub fn init(child: std.mem.Allocator, limit_bytes: usize) ManagedBufferAllocator {
        return .{
            .child = child,
            .limit_bytes = limit_bytes,
        };
    }

    pub fn allocator(self: *ManagedBufferAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn reserve(self: *ManagedBufferAllocator, len: usize) bool {
        const next = std.math.add(usize, self.used_bytes, len) catch {
            self.denied_allocations +|= 1;
            return false;
        };
        if (next > self.limit_bytes) {
            self.denied_allocations +|= 1;
            return false;
        }
        self.used_bytes = next;
        self.peak_bytes = @max(self.peak_bytes, next);
        return true;
    }

    fn release(self: *ManagedBufferAllocator, len: usize) void {
        std.debug.assert(self.used_bytes >= len);
        self.used_bytes -= len;
    }

    fn fromContext(ctx: *anyopaque) *ManagedBufferAllocator {
        return @ptrCast(@alignCast(ctx));
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self = fromContext(ctx);
        if (!self.reserve(len)) return null;
        return self.child.rawAlloc(len, alignment, ret_addr) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self = fromContext(ctx);
        if (new_len == memory.len) return true;

        if (new_len > memory.len) {
            const extra = new_len - memory.len;
            if (!self.reserve(extra)) return false;
            if (self.child.rawResize(memory, alignment, new_len, ret_addr)) return true;
            self.release(extra);
            return false;
        }

        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.release(memory.len - new_len);
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self = fromContext(ctx);
        self.child.rawFree(memory, alignment, ret_addr);
        self.release(memory.len);
    }
};

test "managed buffer allocator enforces limit and accounts transient growth" {
    var budget = ManagedBufferAllocator.init(std.testing.allocator, 128);
    const allocator = budget.allocator();

    const first = try allocator.alloc(u8, 64);
    try std.testing.expectEqual(@as(usize, 64), budget.used_bytes);
    try std.testing.expectEqual(@as(usize, 64), budget.peak_bytes);

    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 65));
    try std.testing.expectEqual(@as(u64, 1), budget.denied_allocations);

    // The wrapper refuses remap, so realloc must reserve the replacement while
    // the old allocation is still resident. A failed growth leaves accounting
    // and ownership of the original allocation unchanged.
    try std.testing.expectError(error.OutOfMemory, allocator.realloc(first, 96));
    try std.testing.expectEqual(@as(usize, 64), budget.used_bytes);
    try std.testing.expectEqual(@as(u64, 2), budget.denied_allocations);

    allocator.free(first);
    try std.testing.expectEqual(@as(usize, 0), budget.used_bytes);
}
