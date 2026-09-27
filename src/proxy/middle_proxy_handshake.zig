//! Pure MiddleProxy handshake preparation. The worker owns fds, secrets and CBC state.

const std = @import("std");
const net = @import("../net_helpers.zig");
const crypto = @import("../crypto/crypto.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const middle_proxy_nat = @import("middle_proxy_nat.zig");

pub const frame_buf_size: usize = 2048;
pub const KeyIv = struct { [32]u8, [16]u8 };

/// Derive both direction keys from the already authenticated nonce response.
/// The caller holds the versioned-secret read lock and wipes both outputs.
pub fn deriveKeys(
    server_nonce: *const [16]u8,
    client_nonce: *const [16]u8,
    timestamp: u32,
    peer_addr: net.Address,
    local_addr: net.Address,
    nat_ip4: ?[4]u8,
    secret: []const u8,
    enc_keys: *KeyIv,
    dec_keys: *KeyIv,
) !net.Address {
    var ts_arr: [4]u8 = undefined;
    std.mem.writeInt(u32, &ts_arr, timestamp, .little);

    var middle_local_addr = local_addr;
    var tg_port: [2]u8 = undefined;
    var my_port: [2]u8 = undefined;
    var tg_ip_v4_opt: ?[4]u8 = null;
    var my_ip_v4_opt: ?[4]u8 = null;
    var tg_ip_v6_opt: ?[16]u8 = null;
    var my_ip_v6_opt: ?[16]u8 = null;

    if (peer_addr == .ip4 and local_addr == .ip4) {
        tg_ip_v4_opt = middle_proxy_nat.ipv4AddressBytesForMiddleProxyKdf(peer_addr);
        var my_ip_v4 = middle_proxy_nat.ipv4AddressBytesForMiddleProxyKdf(local_addr);

        if (nat_ip4) |nat_ip| {
            my_ip_v4 = middle_proxy_nat.ipv4BytesForMiddleProxyKdf(nat_ip);
            middle_local_addr = net.ip4(nat_ip, local_addr.ip4.port);
        }

        my_ip_v4_opt = my_ip_v4;
        std.mem.writeInt(u16, &tg_port, peer_addr.ip4.port, .little);
        std.mem.writeInt(u16, &my_port, local_addr.ip4.port, .little);
    } else if (peer_addr == .ip6 and local_addr == .ip6) {
        tg_ip_v6_opt = peer_addr.ip6.bytes;
        my_ip_v6_opt = local_addr.ip6.bytes;
        std.mem.writeInt(u16, &tg_port, peer_addr.ip6.port, .little);
        std.mem.writeInt(u16, &my_port, local_addr.ip6.port, .little);
    } else {
        return error.UnsupportedAddressFamily;
    }

    const tg_ip_v4_ptr: ?*const [4]u8 = if (tg_ip_v4_opt) |*ip| ip else null;
    const my_ip_v4_ptr: ?*const [4]u8 = if (my_ip_v4_opt) |*ip| ip else null;
    const my_ip_v6_ptr: ?*const [16]u8 = if (my_ip_v6_opt) |*ip| ip else null;
    const tg_ip_v6_ptr: ?*const [16]u8 = if (tg_ip_v6_opt) |*ip| ip else null;

    var client_keys = try middleproxy.getAesKeyAndIv(
        server_nonce,
        client_nonce,
        &ts_arr,
        tg_ip_v4_ptr,
        &my_port,
        "CLIENT",
        my_ip_v4_ptr,
        &tg_port,
        secret,
        my_ip_v6_ptr,
        tg_ip_v6_ptr,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&client_keys));
    var server_keys = try middleproxy.getAesKeyAndIv(
        server_nonce,
        client_nonce,
        &ts_arr,
        tg_ip_v4_ptr,
        &my_port,
        "SERVER",
        my_ip_v4_ptr,
        &tg_port,
        secret,
        my_ip_v6_ptr,
        tg_ip_v6_ptr,
    );
    defer std.crypto.secureZero(u8, std.mem.asBytes(&server_keys));
    enc_keys.* = .{ client_keys[0], client_keys[1] };
    dec_keys.* = .{ server_keys[0], server_keys[1] };
    return middle_local_addr;
}

/// Encode a single outgoing handshake frame into caller-owned scratch.
/// Cipher state and sequence number remain owned by the connection slot.
pub fn encodeFrame(
    buffer: []u8,
    seq_no: *i32,
    payload: []const u8,
    encryptor: ?*crypto.AesCbcEncryptor,
) ![]const u8 {
    const total_len: usize = payload.len + 12;
    if (total_len > buffer.len) return error.BadMiddleProxyFrameSize;

    std.mem.writeInt(u32, buffer[0..4], @intCast(total_len), .little);
    std.mem.writeInt(i32, buffer[4..8], seq_no.*, .little);
    seq_no.* = seq_no.* +% 1;

    @memcpy(buffer[8 .. 8 + payload.len], payload);
    const checksum = middleproxy.crc32(buffer[0 .. 8 + payload.len]);
    std.mem.writeInt(u32, buffer[8 + payload.len ..][0..4], checksum, .little);

    var frame_len = total_len;
    if (encryptor) |cipher| {
        const pad = (16 - (frame_len % 16)) % 16;
        if (frame_len + pad > buffer.len or pad % 4 != 0) return error.BadMiddleProxyFrameSize;
        var i: usize = 0;
        while (i < pad) : (i += 4) {
            std.mem.writeInt(u32, buffer[frame_len + i ..][0..4], 4, .little);
        }
        frame_len += pad;
        try cipher.encryptInPlace(buffer[0..frame_len]);
    }
    return buffer[0..frame_len];
}

test "encrypted MiddleProxy handshake frame keeps four-byte padding and checksum" {
    var frame: [64]u8 = undefined;
    var seq_no: i32 = -2;
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;
    var encryptor = crypto.AesCbcEncryptor.init(&key, &iv);
    defer encryptor.wipe();
    var decryptor = crypto.AesCbcDecryptor.init(&key, &iv);
    defer decryptor.wipe();
    const payload = [_]u8{7} ** 32;

    const encoded = try encodeFrame(&frame, &seq_no, &payload, &encryptor);
    try std.testing.expectEqual(@as(usize, 48), encoded.len);
    try decryptor.decryptInPlace(frame[0..encoded.len]);
    try std.testing.expectEqual(@as(u32, 44), std.mem.readInt(u32, frame[0..4], .little));
    try std.testing.expectEqual(@as(i32, -2), std.mem.readInt(i32, frame[4..8], .little));
    try std.testing.expectEqualSlices(u8, &payload, frame[8..40]);
    try std.testing.expectEqual(middleproxy.crc32(frame[0..40]), std.mem.readInt(u32, frame[40..44], .little));
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, frame[44..48], .little));
    try std.testing.expectEqual(@as(i32, -1), seq_no);
}

test "plain MiddleProxy handshake frame keeps wire length, sequence and checksum" {
    var frame: [64]u8 = undefined;
    var seq_no: i32 = -2;
    const encoded = try encodeFrame(&frame, &seq_no, "nonce", null);
    try std.testing.expectEqual(@as(usize, 17), encoded.len);
    try std.testing.expectEqual(@as(u32, 17), std.mem.readInt(u32, encoded[0..4], .little));
    try std.testing.expectEqual(@as(i32, -2), std.mem.readInt(i32, encoded[4..8], .little));
    try std.testing.expectEqual(@as(i32, -1), seq_no);
    try std.testing.expectEqualSlices(u8, "nonce", encoded[8..13]);
    try std.testing.expectEqual(middleproxy.crc32(encoded[0..13]), std.mem.readInt(u32, encoded[13..17], .little));

    try std.testing.expectError(error.BadMiddleProxyFrameSize, encodeFrame(frame[0..8], &seq_no, "nonce", null));
    try std.testing.expectEqual(@as(i32, -1), seq_no);
}

test "MiddleProxy IPv4 NAT override changes KDF and effective local address" {
    const peer = net.ip4(.{ 149, 154, 167, 40 }, 443);
    const local = net.ip4(.{ 10, 0, 0, 2 }, 34567);
    const server_nonce = [_]u8{1} ** 16;
    const client_nonce = [_]u8{2} ** 16;
    var enc_direct: KeyIv = undefined;
    var dec_direct: KeyIv = undefined;
    var enc_nat: KeyIv = undefined;
    var dec_nat: KeyIv = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&enc_direct));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&dec_direct));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&enc_nat));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&dec_nat));

    const direct_addr = try deriveKeys(&server_nonce, &client_nonce, 123, peer, local, null, &middleproxy.proxy_secret, &enc_direct, &dec_direct);
    const nat_addr = try deriveKeys(&server_nonce, &client_nonce, 123, peer, local, .{ 203, 0, 113, 7 }, &middleproxy.proxy_secret, &enc_nat, &dec_nat);
    try std.testing.expect(net.exactAddressEql(local, direct_addr));
    try std.testing.expect(net.exactAddressEql(net.ip4(.{ 203, 0, 113, 7 }, 34567), nat_addr));
    try std.testing.expect(!std.mem.eql(u8, &enc_direct[0], &enc_nat[0]));
    try std.testing.expect(!std.mem.eql(u8, &dec_direct[0], &dec_nat[0]));
}
