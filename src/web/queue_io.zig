const std = @import("std");
const posix = std.posix;

const MessageQueue = @import("message_queue.zig").MessageQueue;

const max_scatter_parts: usize = 64;

pub const dispatch_byte_budget: usize = 256 * 1024;
pub const dispatch_operation_budget: usize = 64;

/// Shared across all sockets touched by one WEB dispatch, including EINTR retries.
pub const IoBudget = struct {
    bytes_remaining: usize = dispatch_byte_budget,
    operations_remaining: usize = dispatch_operation_budget,

    fn allowed(self: *const IoBudget, requested: usize) usize {
        if (self.operations_remaining == 0) return 0;
        return @min(requested, self.bytes_remaining);
    }

    fn begin(self: *IoBudget) bool {
        if (self.allowed(1) == 0) return false;
        self.operations_remaining -= 1;
        return true;
    }
};

pub fn readFd(fd: posix.fd_t, buffer: []u8, budget: ?*IoBudget) !usize {
    const limit = if (budget) |b| b.allowed(buffer.len) else buffer.len;
    if (limit == 0) return error.WouldBlock;
    while (true) {
        if (budget) |b| if (!b.begin()) return error.WouldBlock;
        const rc = posix.system.read(fd, buffer.ptr, limit);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (budget) |b| b.bytes_remaining -= n;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionReset,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn writeFd(fd: posix.fd_t, data: []const u8) !usize {
    while (true) {
        const rc = posix.system.write(fd, data.ptr, data.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE => return error.ConnectionReset,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn writevFd(fd: posix.fd_t, iovecs: []const posix.iovec_const, budget: ?*IoBudget) !usize {
    while (true) {
        if (budget) |b| if (!b.begin()) return error.WouldBlock;
        const rc = posix.system.writev(fd, iovecs.ptr, @intCast(iovecs.len));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (budget) |b| b.bytes_remaining -= n;
                return n;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE => return error.ConnectionReset,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn noteTraffic(counter: *std.atomic.Value(u64), bytes: usize) void {
    if (bytes == 0) return;
    _ = counter.fetchAdd(@intCast(bytes), .monotonic);
}

fn noteTrafficOptional(counter: ?*std.atomic.Value(u64), bytes: usize) void {
    if (counter) |ptr| noteTraffic(ptr, bytes);
}

pub fn queueOrWriteMsg(
    fd: posix.fd_t,
    queue: *MessageQueue,
    data: []const u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = writeFd(fd, data) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(data);
                return false;
            }
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        if (n == data.len) return true;
        try queue.appendCopy(data[n..]);
        return false;
    }

    try queue.appendCopy(data);
    return false;
}

/// A zero result means WouldBlock (or empty input); the caller owns the suffix.
pub fn writeMsgPair(
    fd: posix.fd_t,
    first: []const u8,
    second: []const u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
    budget: ?*IoBudget,
) !usize {
    var iovecs: [2]posix.iovec_const = undefined;
    var n_iov: usize = 0;
    const available = if (budget) |b| b.allowed(first.len + second.len) else first.len + second.len;
    const first_len = @min(first.len, available);
    const second_len = @min(second.len, available - first_len);
    if (first_len > 0) {
        iovecs[n_iov] = .{ .base = first.ptr, .len = first_len };
        n_iov += 1;
    }
    if (second_len > 0) {
        iovecs[n_iov] = .{ .base = second.ptr, .len = second_len };
        n_iov += 1;
    }
    if (n_iov == 0) return 0;
    const n = writevFd(fd, iovecs[0..n_iov], budget) catch |err| {
        if (err == error.WouldBlock) return 0;
        return err;
    };
    if (n == 0) return error.ConnectionReset;
    noteTraffic(counter, n);
    noteTrafficOptional(user_counter, n);
    return n;
}

pub fn queueOrWriteMsgPair(
    fd: posix.fd_t,
    queue: *MessageQueue,
    first: []const u8,
    second: []const u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (first.len == 0 and second.len == 0) return true;

    if (queue.isEmpty()) {
        const total_len = first.len + second.len;
        const n = try writeMsgPair(fd, first, second, counter, user_counter, null);
        if (n == total_len) return true;

        if (n < first.len) {
            try queue.appendCopy(first[n..]);
            try queue.appendCopy(second);
            return false;
        }

        const consumed_second = n - first.len;
        if (consumed_second < second.len) {
            try queue.appendCopy(second[consumed_second..]);
        }
        return false;
    }

    try queue.appendCopy(first);
    try queue.appendCopy(second);
    return false;
}

pub fn queueOrWriteOwnedMsg(
    fd: posix.fd_t,
    queue: *MessageQueue,
    owned: []u8,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
) !bool {
    if (owned.len == 0) {
        queue.allocator.free(owned);
        return true;
    }

    if (queue.isEmpty()) {
        const n = writeFd(fd, owned) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendOwned(owned);
                return false;
            }
            queue.allocator.free(owned);
            return err;
        };

        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        if (n == owned.len) {
            queue.allocator.free(owned);
            return true;
        }

        const remaining = owned[n..];
        // Free `owned` on the appendCopy error path too — `try` here would leak it (every
        // other exit frees it). Matches the OOM-safety of the sibling write helpers.
        queue.appendCopy(remaining) catch |err| {
            queue.allocator.free(owned);
            return err;
        };
        queue.allocator.free(owned);
        return false;
    }

    try queue.appendOwned(owned);
    return false;
}

pub fn flushQueue(
    fd: posix.fd_t,
    queue: *MessageQueue,
    counter: *std.atomic.Value(u64),
    user_counter: ?*std.atomic.Value(u64),
    budget: ?*IoBudget,
) !bool {
    if (queue.isEmpty()) return true;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;

    while (!queue.isEmpty()) {
        var n_iov = queue.prepareIovecs(iovecs[0..]);
        if (n_iov == 0) return true;

        if (budget) |b| {
            var left = b.allowed(std.math.maxInt(usize));
            if (left == 0) return false;
            var count: usize = 0;
            for (iovecs[0..n_iov]) |*iov| {
                if (left == 0) break;
                iov.len = @min(iov.len, left);
                left -= iov.len;
                count += 1;
            }
            n_iov = count;
        }

        var total_req: usize = 0;
        for (iovecs[0..n_iov]) |iov| total_req += iov.len;

        const n = writevFd(fd, iovecs[0..n_iov], budget) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        noteTraffic(counter, n);
        noteTrafficOptional(user_counter, n);
        try queue.consume(n);

        if (n < total_req) return false;
    }

    return true;
}
