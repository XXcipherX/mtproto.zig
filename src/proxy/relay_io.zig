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
// Outbound FakeTLS sizing heuristic: reserve the TLS 1.3 content-type/tag
// margin (1 + 16 bytes) to avoid repeated bulk 0x4000 records. This is not a
// TLS legality limit, and FakeTLS does not actually add TLS AEAD overhead.
const max_faketls_app_payload_size: usize = constants.max_tls_plaintext_size - 17;
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

/// Yield application bytes from one TCP read. Only incomplete framing positions
/// survive the call; the caller must consume each borrowed payload before reusing
/// the worker's read scratch. CCS bodies do not enter the MTProto cipher stream.
pub fn nextClientTlsPayload(slot: *ConnectionSlot, remaining: *[]u8) !?[]u8 {
    while (remaining.len > 0) {
        if (slot.relay_tls_hdr_pos < tls_header_len) {
            const take = @min(tls_header_len - @as(usize, slot.relay_tls_hdr_pos), remaining.len);
            @memcpy(slot.relay_tls_hdr[slot.relay_tls_hdr_pos..][0..take], remaining.*[0..take]);
            slot.relay_tls_hdr_pos += @intCast(take);
            remaining.* = remaining.*[take..];
            if (slot.relay_tls_hdr_pos < tls_header_len) return null;

            slot.relay_record_type = slot.relay_tls_hdr[0];
            slot.relay_tls_body_len = std.mem.readInt(u16, slot.relay_tls_hdr[3..5], .big);
            slot.relay_tls_body_pos = 0;
            if (slot.relay_record_type != constants.tls_record_change_cipher and
                slot.relay_record_type != constants.tls_record_application)
            {
                return error.ConnectionReset;
            }
            if (slot.relay_tls_body_len == 0 or slot.relay_tls_body_len > constants.max_tls_ciphertext_size) {
                return error.ConnectionReset;
            }
        }

        const take = @min(@as(usize, slot.relay_tls_body_len - slot.relay_tls_body_pos), remaining.len);
        const payload = remaining.*[0..take];
        remaining.* = remaining.*[take..];
        slot.relay_tls_body_pos += @intCast(take);
        const application = slot.relay_record_type == constants.tls_record_application;
        if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
        }
        if (application and take > 0) return payload;
    }
    return null;
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
    var headers: [max_scatter_parts / 2][tls_header_len]u8 = undefined;
    var parts: [max_scatter_parts][]const u8 = undefined;
    var count: usize = 0;

    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, slot.drs.nextRecordSize(), max_faketls_app_payload_size);

        const header = &headers[count / 2];
        header[0] = constants.tls_record_application;
        header[1] = constants.tls_version[0];
        header[2] = constants.tls_version[1];
        std.mem.writeInt(u16, header[3..5], @intCast(chunk_len), .big);

        parts[count] = header[0..];
        parts[count + 1] = payload[off .. off + chunk_len];
        count += 2;
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
        if (count == parts.len) {
            _ = try queueOrWriteParts(slot, slot.client_fd, &slot.client_queue, &parts);
            count = 0;
        }
    }
    if (count > 0) _ = try queueOrWriteParts(slot, slot.client_fd, &slot.client_queue, parts[0..count]);
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
    return queueOrWriteParts(slot, fd, queue, &.{ first, second });
}

fn queueOrWriteParts(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue, parts: []const []const u8) !bool {
    if (parts.len > max_scatter_parts) return error.TooManyParts;
    var total: usize = 0;
    for (parts) |part| total = std.math.add(usize, total, part.len) catch return error.PendingQueueOverflow;
    if (total == 0) return true;
    try queue.ensureCanAppend(total);

    var written: usize = 0;
    if (queue.isEmpty()) {
        var iovecs: [max_scatter_parts]posix.iovec_const = undefined;
        var n_iov: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            iovecs[n_iov] = .{ .base = part.ptr, .len = part.len };
            n_iov += 1;
        }

        written = writevSlotFd(slot, fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendParts(parts);
                return false;
            }
            return err;
        };
        if (written == 0) return error.ConnectionReset;
        if (written == total) return true;
    }

    var suffix: [max_scatter_parts][]const u8 = undefined;
    var suffix_count: usize = 0;
    for (parts) |part| {
        const skip = @min(written, part.len);
        written -= skip;
        if (skip == part.len) continue;
        suffix[suffix_count] = part[skip..];
        suffix_count += 1;
    }
    try queue.appendParts(suffix[0..suffix_count]);
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

test "client TLS framing preserves cipher continuity at every pair of TCP splits" {
    const crypto = @import("../crypto/crypto.zig");
    const key = [_]u8{0x37} ** 32;
    const upstream_key = [_]u8{0x91} ** 32;
    const plaintext = "abcdefghijklmnopq";
    var ciphertext: [plaintext.len]u8 = undefined;
    @memcpy(&ciphertext, plaintext);
    var client_cipher = crypto.AesCtr.init(&key, 7);
    client_cipher.apply(&ciphertext);
    var expected: [plaintext.len]u8 = undefined;
    @memcpy(&expected, plaintext);
    var upstream_cipher = crypto.AesCtr.init(&upstream_key, 19);
    upstream_cipher.apply(&expected);

    // Three application records and an intervening CCS; split both headers and
    // bodies, including empty chunks and a partial final header/body.
    var wire: [plaintext.len + 4 * tls_header_len + 1]u8 = undefined;
    @memcpy(wire[0..5], &[_]u8{ 0x17, 3, 3, 0, 7 });
    @memcpy(wire[5..12], ciphertext[0..7]);
    @memcpy(wire[12..18], &[_]u8{ 0x14, 3, 3, 0, 1, 1 });
    @memcpy(wire[18..23], &[_]u8{ 0x17, 3, 3, 0, 3 });
    @memcpy(wire[23..26], ciphertext[7..10]);
    @memcpy(wire[26..31], &[_]u8{ 0x17, 3, 3, 0, 7 });
    @memcpy(wire[31..], ciphertext[10..]);

    for (0..wire.len + 1) |first| {
        for (first..wire.len + 1) |second| {
            var input = wire;
            var slot = ConnectionSlot{
                .phase = .relaying,
                .client_decryptor = crypto.AesCtr.init(&key, 7),
                .tg_encryptor = crypto.AesCtr.init(&upstream_key, 19),
            };
            var output: [plaintext.len]u8 = undefined;
            var written: usize = 0;
            for ([_][]u8{ input[0..first], input[first..second], input[second..] }) |chunk| {
                var remaining = chunk;
                while (try nextClientTlsPayload(&slot, &remaining)) |payload| {
                    slot.client_decryptor.?.apply(payload);
                    slot.tg_encryptor.?.apply(payload);
                    @memcpy(output[written..][0..payload.len], payload);
                    written += payload.len;
                }
                try std.testing.expectEqual(@as(usize, 0), remaining.len);
            }
            try std.testing.expectEqual(plaintext.len, written);
            try std.testing.expectEqualSlices(u8, &expected, &output);
            try std.testing.expect(clientRelayAtFrameBoundary(&slot));
        }
    }
}

test "client TLS framing rejects invalid records and retains truncated EOF state" {
    const complete = [_]u8{ 0x17, 3, 3, 0, 3, 'a', 'b', 'c' };
    for (1..complete.len) |prefix_len| {
        var input = complete;
        var slot = ConnectionSlot{ .phase = .relaying };
        var remaining = input[0..prefix_len];
        while (try nextClientTlsPayload(&slot, &remaining)) |_| {}
        try std.testing.expect(!clientRelayAtFrameBoundary(&slot));
    }
    for ([_][5]u8{
        .{ 0x15, 3, 3, 0, 1 }, // Alert keeps the existing ConnectionReset class.
        .{ 0x16, 3, 3, 0, 1 },
        .{ 0x17, 3, 3, 0, 0 },
        .{ 0x17, 3, 3, 0xff, 0xff },
    }) |header| {
        var input = header;
        var slot = ConnectionSlot{};
        var remaining: []u8 = &input;
        try std.testing.expectError(error.ConnectionReset, nextClientTlsPayload(&slot, &remaining));
    }
    var input = complete;
    var slot = ConnectionSlot{ .phase = .relaying };
    for (0..input.len) |pos| {
        var remaining = input[pos .. pos + 1];
        while (try nextClientTlsPayload(&slot, &remaining)) |_| {}
    }
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
}

fn relayTestSocketPair() ![2]posix.fd_t {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var fds: [2]posix.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return posix.unexpectedErrno(linux.errno(rc));
    return fds;
}

fn copyTestQueue(queue: *MessageQueue, destination: []u8) !void {
    try std.testing.expectEqual(destination.len, queue.total_len);
    var off: usize = 0;
    while (!queue.isEmpty()) {
        var iovecs: [max_scatter_parts]posix.iovec_const = undefined;
        const count = queue.prepareIovecs(&iovecs, destination.len - off);
        var copied: usize = 0;
        for (iovecs[0..count]) |iov| {
            @memcpy(destination[off + copied ..][0..iov.len], iov.base[0..iov.len]);
            copied += iov.len;
        }
        try std.testing.expect(copied > 0);
        try queue.consume(copied);
        off += copied;
    }
}

test "TLS records use one budgeted scatter write with exact wire output" {
    const fds = try relayTestSocketPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);
    var budget = connection.EventIoBudget{ .operations_remaining = 1 };
    var slot = ConnectionSlot{ .client_fd = fds[0], .event_io_budget = &budget };
    slot.drs.current_size = 7;
    var payload = "abcdefghijklmnopqrst".*;
    try queueTlsAppRecords(&slot, &payload);
    const expected = "\x17\x03\x03\x00\x07abcdefg" ++ "\x17\x03\x03\x00\x07hijklmn" ++ "\x17\x03\x03\x00\x06opqrst";
    var actual: [expected.len]u8 = undefined;
    try std.testing.expectEqual(actual.len, try posix.read(fds[1], &actual));
    try std.testing.expectEqualSlices(u8, expected, &actual);
    try std.testing.expect(slot.client_queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), budget.operations_remaining);
    try std.testing.expectEqual(event_io_byte_budget - expected.len, budget.bytes_remaining);
}

test "scatter partial writes preserve the suffix at every iovec boundary" {
    const parts = [_][]const u8{ "ab", "", "cde", "f", "ghij" };
    const expected = "abcdefghij";
    for (1..expected.len) |prefix| {
        const fds = try relayTestSocketPair();
        defer _ = std.os.linux.close(fds[0]);
        defer _ = std.os.linux.close(fds[1]);
        var budget = connection.EventIoBudget{ .bytes_remaining = prefix, .operations_remaining = 1 };
        var slot = ConnectionSlot{ .client_fd = fds[0], .event_io_budget = &budget };
        slot.client_queue.allocator = std.testing.allocator;
        defer slot.client_queue.deinit();
        try std.testing.expect(!try queueOrWriteParts(&slot, fds[0], &slot.client_queue, &parts));
        try std.testing.expect(budget.exhausted());
        var actual: [expected.len]u8 = undefined;
        try std.testing.expectEqual(prefix, try posix.read(fds[1], actual[0..prefix]));
        try copyTestQueue(&slot.client_queue, actual[prefix..]);
        try std.testing.expectEqualSlices(u8, expected, &actual);
    }
}

test "scatter fallback preserves ordering and copies reused TLS headers" {
    var budget = connection.EventIoBudget{ .operations_remaining = 0 };
    var slot = ConnectionSlot{ .event_io_budget = &budget };
    slot.client_queue.allocator = std.testing.allocator;
    defer slot.client_queue.deinit();
    try std.testing.expect(!try queueOrWriteParts(&slot, slot.client_fd, &slot.client_queue, &.{ "pre", "fix" }));
    slot.drs.current_size = 1; // Force more than one 64-part batch without large fixtures.
    var payload: [73]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @intCast(i);
    try queueTlsAppRecords(&slot, &payload);
    var actual: [6 + payload.len * 6]u8 = undefined;
    try copyTestQueue(&slot.client_queue, &actual);
    try std.testing.expectEqualStrings("prefix", actual[0..6]);
    for (payload, 0..) |byte, i| {
        const offset = 6 + i * 6;
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 3, 3, 0, 1 }, actual[offset..][0..5]);
        try std.testing.expectEqual(byte, actual[offset + 5]);
    }
    const too_many = [_][]const u8{""} ** (max_scatter_parts + 1);
    try std.testing.expectError(error.TooManyParts, queueOrWriteParts(&slot, slot.client_fd, &slot.client_queue, &too_many));
}

test "scatter EAGAIN queues all parts without charging unsent bytes" {
    const fds = try relayTestSocketPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);
    const fill = [_]u8{0} ** 4096;
    var blocked = false;
    for (0..1024) |_| {
        _ = writeFd(fds[0], &fill) catch |err| {
            if (err != error.WouldBlock) return err;
            blocked = true;
            break;
        };
    }
    try std.testing.expect(blocked);
    var budget = connection.EventIoBudget{};
    var slot = ConnectionSlot{ .client_fd = fds[0], .event_io_budget = &budget };
    slot.client_queue.allocator = std.testing.allocator;
    defer slot.client_queue.deinit();
    try std.testing.expect(!try queueOrWriteParts(&slot, fds[0], &slot.client_queue, &.{ "ab", "cd" }));
    var actual: [4]u8 = undefined;
    try copyTestQueue(&slot.client_queue, &actual);
    try std.testing.expectEqualStrings("abcd", &actual);
    try std.testing.expectEqual(connection.event_io_operation_budget - 1, budget.operations_remaining);
    try std.testing.expectEqual(event_io_byte_budget, budget.bytes_remaining);
}

test "bulk FakeTLS records avoid 0x4000 and roundtrip with either DRS policy" {
    const payload = try std.testing.allocator.alloc(u8, 40 * 16_384 + 137);
    defer std.testing.allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i * 131 + 17);

    for ([_]bool{ false, true }) |enabled| {
        var budget = connection.EventIoBudget{ .operations_remaining = 0 };
        var slot = ConnectionSlot{
            .phase = .relaying,
            .event_io_budget = &budget,
            .drs = connection.DynamicRecordSizer.init(enabled),
        };
        slot.client_queue.allocator = std.testing.allocator;
        defer slot.client_queue.deinit();
        try queueTlsAppRecords(&slot, payload);
        const wire = try std.testing.allocator.alloc(u8, slot.client_queue.total_len);
        defer std.testing.allocator.free(wire);
        try copyTestQueue(&slot.client_queue, wire);

        var wire_pos: usize = 0;
        var payload_pos: usize = 0;
        var records: usize = 0;
        while (wire_pos < wire.len) {
            try std.testing.expect(wire.len - wire_pos >= tls_header_len);
            const header = wire[wire_pos..][0..tls_header_len];
            try std.testing.expectEqualSlices(u8, &.{ 0x17, 3, 3 }, header[0..3]);
            const body_len: usize = std.mem.readInt(u16, header[3..5], .big);
            try std.testing.expect(body_len > 0 and body_len < 0x4000);
            // DRS still warms up for eight records; only the encoded bulk cap changes.
            const expected_limit: usize = if (enabled and records < 8) 1369 else 16_367;
            try std.testing.expectEqual(@min(expected_limit, payload.len - payload_pos), body_len);
            wire_pos += tls_header_len;
            try std.testing.expect(wire.len - wire_pos >= body_len);
            try std.testing.expectEqualSlices(u8, payload[payload_pos..][0..body_len], wire[wire_pos..][0..body_len]);
            wire_pos += body_len;
            payload_pos += body_len;
            records += 1;
        }
        try std.testing.expect(records > max_scatter_parts / 2);
        try std.testing.expectEqual(payload.len, payload_pos);
        try std.testing.expectEqual(connection.DynamicRecordSizer.full_size, slot.drs.nextRecordSize());

        // Reassemble through the receiving parser as well as checking the wire above.
        var receiver = ConnectionSlot{ .phase = .relaying };
        var remaining = wire;
        payload_pos = 0;
        while (try nextClientTlsPayload(&receiver, &remaining)) |part| {
            try std.testing.expectEqualSlices(u8, payload[payload_pos..][0..part.len], part);
            payload_pos += part.len;
        }
        try std.testing.expectEqual(payload.len, payload_pos);
        try std.testing.expect(clientRelayAtFrameBoundary(&receiver));
    }
}
