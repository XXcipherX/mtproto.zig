const std = @import("std");
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const connection = @import("connection.zig");
const ConnectionSlot = connection.ConnectionSlot;
const MessageQueue = @import("message_queue.zig").MessageQueue;
const socket_ops = @import("socket_ops.zig");
const writeFd = socket_ops.writeFd;
const writevFd = socket_ops.writevFd;
const max_scatter_parts: usize = 64;
const queue_flush_operation_budget: usize = 8;
const event_io_byte_budget = connection.event_io_byte_budget;
const tls_header_len = connection.tls_header_len;

pub fn clientRelayAtFrameBoundary(slot: *const ConnectionSlot) bool {
    if (slot.phase == .mask_relaying) return true;
    if (slot.phase != .relaying) return false;
    if (slot.client_transport == .direct_obfuscated) {
        if (slot.middle_ctx) |*mp| return mp.c2sAtFrameBoundary();
        return true;
    }
    if (slot.relay_tls_hdr_pos != 0 or
        slot.relay_tls_body_len != 0 or
        slot.relay_tls_body_pos != 0)
    {
        return false;
    }
    if (slot.middle_ctx) |*mp| return mp.c2sAtFrameBoundary();
    return true;
}

pub fn upstreamRelayAtFrameBoundary(slot: *const ConnectionSlot) bool {
    if (slot.phase == .mask_relaying) return true;
    if (slot.phase != .relaying) return false;
    if (slot.middle_ctx) |*mp| return mp.s2cAtFrameBoundary();
    return true;
}

pub fn relayHalfCloseComplete(slot: *const ConnectionSlot) bool {
    return slot.client_read_closed and
        slot.upstream_read_closed and
        slot.client_write_shutdown and
        slot.upstream_write_shutdown and
        !slot.hasClientPending() and
        !slot.hasUpstreamPending();
}

pub fn shutdownWriteFd(fd: posix.fd_t) !void {
    while (true) {
        const rc = posix.system.shutdown(fd, posix.SHUT.WR);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .NOTCONN => return error.SocketUnconnected,
            .BADF, .INVAL, .NOTSOCK => unreachable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn readSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, buffer: []u8) !usize {
    const limited = if (slot.event_io_budget) |budget|
        buffer[0..budget.allowedBytes(buffer.len)]
    else
        buffer;
    if (limited.len == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try posix.read(fd, limited);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

fn writeSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, data: []const u8) !usize {
    const limited = if (slot.event_io_budget) |budget|
        data[0..budget.allowedBytes(data.len)]
    else
        data;
    if (limited.len == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try writeFd(fd, limited);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

fn writevSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    var limited_iovecs: [max_scatter_parts]posix.iovec_const = undefined;
    var limited_count: usize = 0;
    var remaining = if (slot.event_io_budget) |budget| budget.allowedBytes(std.math.maxInt(usize)) else std.math.maxInt(usize);
    if (remaining == 0) return error.WouldBlock;

    for (iovecs) |iov| {
        if (remaining == 0 or limited_count == limited_iovecs.len) break;
        const take = @min(iov.len, remaining);
        if (take == 0) continue;
        limited_iovecs[limited_count] = .{ .base = iov.base, .len = take };
        limited_count += 1;
        remaining -= take;
    }
    if (limited_count == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try writevFd(fd, limited_iovecs[0..limited_count]);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

pub fn queueTlsAppRecords(slot: *ConnectionSlot, payload: []u8) !void {
    var off: usize = 0;
    var header: [tls_header_len]u8 = undefined;

    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, slot.drs.nextRecordSize());

        header[0] = constants.tls_record_application;
        header[1] = constants.tls_version[0];
        header[2] = constants.tls_version[1];
        std.mem.writeInt(u16, header[3..5], @intCast(chunk_len), .big);

        _ = try queueClientPair(slot, header[0..], payload[off .. off + chunk_len]);
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
    }
}

fn queueOrWriteMsg(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue, data: []const u8) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = writeSlotFd(slot, fd, data) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(data);
                return false;
            }
            return err;
        };

        if (n == data.len) return true;
        try queue.appendCopy(data[n..]);
        return false;
    }

    try queue.appendCopy(data);
    return false;
}

fn queueOrWriteMsgPair(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue, first: []const u8, second: []const u8) !bool {
    if (first.len == 0 and second.len == 0) return true;

    if (queue.isEmpty()) {
        var iovecs: [2]posix.iovec_const = undefined;
        var n_iov: usize = 0;
        if (first.len > 0) {
            iovecs[n_iov] = .{ .base = first.ptr, .len = first.len };
            n_iov += 1;
        }
        if (second.len > 0) {
            iovecs[n_iov] = .{ .base = second.ptr, .len = second.len };
            n_iov += 1;
        }

        const total_len = first.len + second.len;
        const n = writevSlotFd(slot, fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) {
                try queue.ensureCanAppend(total_len);
                try queue.appendCopy(first);
                try queue.appendCopy(second);
                return false;
            }
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        if (n == total_len) return true;

        if (n < first.len) {
            try queue.ensureCanAppend(first.len - n + second.len);
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

    try queue.ensureCanAppend(first.len + second.len);
    try queue.appendCopy(first);
    try queue.appendCopy(second);
    return false;
}

fn flushQueue(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue) !usize {
    if (queue.isEmpty()) return 0;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;
    var total_written: usize = 0;
    var operations: usize = 0;

    while (!queue.isEmpty() and operations < queue_flush_operation_budget and total_written < event_io_byte_budget) {
        const local_remaining = event_io_byte_budget - total_written;
        const max_bytes = if (slot.event_io_budget) |budget| budget.allowedBytes(local_remaining) else local_remaining;
        const n_iov = queue.prepareIovecs(iovecs[0..], max_bytes);
        if (n_iov == 0) return total_written;

        const n = writevSlotFd(slot, fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) return total_written;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        try queue.consume(n);
        total_written += n;
        operations += 1;

        if (n < iovecs[0].len) return total_written;
    }

    return total_written;
}

pub fn queueClient(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot, slot.client_fd, &slot.client_queue, data);
}

pub fn queueClientPair(slot: *ConnectionSlot, first: []const u8, second: []const u8) !bool {
    return queueOrWriteMsgPair(slot, slot.client_fd, &slot.client_queue, first, second);
}

pub fn queueUpstream(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot, slot.upstream_fd, &slot.upstream_queue, data);
}

pub fn flushClientPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot, slot.client_fd, &slot.client_queue);
}

pub fn flushUpstreamPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot, slot.upstream_fd, &slot.upstream_queue);
}

test "relay EOF requires complete transport frames" {
    var slot = ConnectionSlot{};
    slot.phase = .relaying;
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
    try std.testing.expect(upstreamRelayAtFrameBoundary(&slot));

    slot.relay_tls_hdr_pos = 1;
    try std.testing.expect(!clientRelayAtFrameBoundary(&slot));
    slot.relay_tls_hdr_pos = 0;
    slot.relay_tls_body_len = 16;
    slot.relay_tls_body_pos = 8;
    try std.testing.expect(!clientRelayAtFrameBoundary(&slot));

    slot.phase = .mask_relaying;
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
    try std.testing.expect(upstreamRelayAtFrameBoundary(&slot));
}

test "relay half-close completes only after both FIN paths drain" {
    var slot = ConnectionSlot{};
    slot.phase = .relaying;
    slot.client_read_closed = true;
    slot.upstream_read_closed = true;
    slot.client_write_shutdown = true;
    try std.testing.expect(!relayHalfCloseComplete(&slot));

    slot.upstream_write_shutdown = true;
    try std.testing.expect(relayHalfCloseComplete(&slot));

    slot.client_queue.total_len = 1;
    try std.testing.expect(!relayHalfCloseComplete(&slot));
    slot.client_queue.total_len = 0;
    slot.upstream_queue.total_len = 1;
    try std.testing.expect(!relayHalfCloseComplete(&slot));
}
