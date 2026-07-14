const std = @import("std");
const net = @import("../net_compat.zig");
const posix = std.posix;
const config = @import("../config.zig");
const crypto = @import("../crypto/crypto.zig");
const constants = @import("constants.zig");

fn secureFree(allocator: std.mem.Allocator, buf: []u8) void {
    std.crypto.secureZero(u8, buf);
    allocator.free(buf);
}

pub const proxy_secret = [128]u8{
    0xc4, 0xf9, 0xfa, 0xca, 0x96, 0x78, 0xe6, 0xbb, 0x48, 0xad, 0x6c, 0x7e, 0x2c, 0xe5, 0xc0, 0xd2,
    0x44, 0x30, 0x64, 0x5d, 0x55, 0x4a, 0xdd, 0xeb, 0x55, 0x41, 0x9e, 0x03, 0x4d, 0xa6, 0x27, 0x21,
    0xd0, 0x46, 0xea, 0xab, 0x6e, 0x52, 0xab, 0x14, 0xa9, 0x5a, 0x44, 0x3e, 0xcf, 0xb3, 0x46, 0x3e,
    0x79, 0xa0, 0x5a, 0x66, 0x61, 0x2a, 0xdf, 0x9c, 0xae, 0xda, 0x8b, 0xe9, 0xa8, 0x0d, 0xa6, 0x98,
    0x6f, 0xb0, 0xa6, 0xff, 0x38, 0x7a, 0xf8, 0x4d, 0x88, 0xef, 0x3a, 0x64, 0x13, 0x71, 0x3e, 0x5c,
    0x33, 0x77, 0xf6, 0xe1, 0xa3, 0xd4, 0x7d, 0x99, 0xf5, 0xe0, 0xc5, 0x6e, 0xec, 0xe8, 0xf0, 0x5c,
    0x54, 0xc4, 0x90, 0xb0, 0x79, 0xe3, 0x1b, 0xef, 0x82, 0xff, 0x0e, 0xe8, 0xf2, 0xb0, 0xa3, 0x27,
    0x56, 0xd2, 0x49, 0xc5, 0xf2, 0x12, 0x69, 0x81, 0x6c, 0xb7, 0x06, 0x1b, 0x26, 0x5d, 0xb2, 0x12,
};

pub const rpc_proxy_req = [_]u8{ 0xee, 0xf1, 0xce, 0x36 };
pub const rpc_proxy_ans = [_]u8{ 0x0d, 0xda, 0x03, 0x44 };
pub const rpc_simple_ack = [_]u8{ 0x9b, 0x40, 0xac, 0x3b };
pub const rpc_close_ext = [_]u8{ 0xa2, 0x34, 0xb6, 0x5e };

pub const rpc_handshake = [_]u8{ 0xf5, 0xee, 0x82, 0x76 };
pub const rpc_nonce_req = [_]u8{ 0xaa, 0x87, 0xcb, 0x7a };
pub const rpc_crypto_aes = [_]u8{ 0x01, 0x00, 0x00, 0x00 };

pub const Flag = struct {
    pub const not_encrypted: u32 = 0x2;
    pub const has_ad_tag: u32 = 0x8;
    pub const magic: u32 = 0x1000;
    pub const extmode2: u32 = 0x20000;
    pub const pad: u32 = 0x8000000;
    pub const dropped: u32 = 0x10000000;
    pub const intermediate: u32 = 0x20000000;
    pub const abridged: u32 = 0x40000000;
    pub const quickack: u32 = 0x80000000;
};

pub fn getAesKeyAndIv(
    nonce_srv: *const [16]u8,
    nonce_clt: *const [16]u8,
    clt_ts: *const [4]u8,
    srv_ip: ?*const [4]u8,
    clt_port: *const [2]u8,
    purpose: []const u8,
    clt_ip: ?*const [4]u8,
    srv_port: *const [2]u8,
    secret: []const u8,
    clt_ipv6: ?*const [16]u8,
    srv_ipv6: ?*const [16]u8,
) !struct { [32]u8, [16]u8 } {
    var s_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &s_buf);
    var s_len: usize = 0;

    if ((clt_ipv6 == null) != (srv_ipv6 == null)) return error.IncompleteIpv6Pair;
    const ipv6_len: usize = if (clt_ipv6 != null) 32 else 0;
    const fixed_len: usize = 16 + 16 + 4 + 4 + 2 + 4 + 2 + 16 + ipv6_len + 16;
    if (purpose.len > s_buf.len - fixed_len or secret.len > s_buf.len - fixed_len - purpose.len) {
        return error.KdfInputTooLong;
    }

    const empty_ip4 = [_]u8{0} ** 4;
    const srv_ip_bytes = if (srv_ip) |ip| ip else &empty_ip4;
    const clt_ip_bytes = if (clt_ip) |ip| ip else &empty_ip4;

    // nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose + clt_ip + srv_port
    @memcpy(s_buf[s_len .. s_len + 16], nonce_srv);
    s_len += 16;
    @memcpy(s_buf[s_len .. s_len + 16], nonce_clt);
    s_len += 16;
    @memcpy(s_buf[s_len .. s_len + 4], clt_ts);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 4], srv_ip_bytes);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 2], clt_port);
    s_len += 2;
    @memcpy(s_buf[s_len .. s_len + purpose.len], purpose);
    s_len += purpose.len;
    @memcpy(s_buf[s_len .. s_len + 4], clt_ip_bytes);
    s_len += 4;
    @memcpy(s_buf[s_len .. s_len + 2], srv_port);
    s_len += 2;

    @memcpy(s_buf[s_len .. s_len + secret.len], secret);
    s_len += secret.len;
    @memcpy(s_buf[s_len .. s_len + 16], nonce_srv);
    s_len += 16;

    if (clt_ipv6 != null and srv_ipv6 != null) {
        @memcpy(s_buf[s_len .. s_len + 16], clt_ipv6.?);
        s_len += 16;
        @memcpy(s_buf[s_len .. s_len + 16], srv_ipv6.?);
        s_len += 16;
    }

    @memcpy(s_buf[s_len .. s_len + 16], nonce_clt);
    s_len += 16;

    const s = s_buf[0..s_len];

    var md5_all = crypto.md5(s[1..]);
    defer std.crypto.secureZero(u8, &md5_all);
    var sha1_all = crypto.sha1(s);
    defer std.crypto.secureZero(u8, &sha1_all);

    var key: [32]u8 = undefined;
    @memcpy(key[0..12], md5_all[0..12]);
    @memcpy(key[12..32], sha1_all[0..20]);

    const iv = crypto.md5(s[2..]);

    return .{ key, iv };
}

pub const MiddleProxyContext = struct {
    allocator: std.mem.Allocator,
    encryptor: crypto.AesCbc,
    decryptor: crypto.AesCbc,
    seq_no: i32 = -2,
    read_seq_no: i32 = 0,
    conn_id: [8]u8,
    remote_ip_port: [20]u8,
    our_ip_port: [20]u8,
    proto_tag: constants.ProtoTag,
    ad_tag: ?[16]u8 = null,

    // For S2C chunk parser
    s2c_buf: []u8,
    s2c_len: usize = 0,
    s2c_decrypted_len: usize = 0,

    // For C2S fragment parsing
    c2s_buf: []u8,
    c2s_len: usize = 0,

    buffer_limit: usize,

    pub const default_stream_buffer_size: usize = 128 * 1024;
    pub const initial_stream_buffer_size: usize = 16 * 1024;
    pub const shrink_stream_buffer_threshold: usize = initial_stream_buffer_size * 4;
    pub const max_stream_buffer_size: usize = config.Config.middle_proxy_stream_buffer_cap_bytes;
    pub const min_client_payload_size: usize = 20;
    const C2sPayloadInfo = struct {
        actual_len: usize,
        is_plain: bool,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        encryptor: crypto.AesCbc,
        decryptor: crypto.AesCbc,
        conn_id: [8]u8,
        initial_seq_no: i32,
        remote_addr: net.Address,
        our_addr: net.Address,
        proto_tag: constants.ProtoTag,
        ad_tag: ?[16]u8,
    ) !MiddleProxyContext {
        return initWithBuffer(
            allocator,
            encryptor,
            decryptor,
            conn_id,
            initial_seq_no,
            remote_addr,
            our_addr,
            proto_tag,
            ad_tag,
            default_stream_buffer_size,
        );
    }

    pub fn initWithBuffer(
        allocator: std.mem.Allocator,
        encryptor: crypto.AesCbc,
        decryptor: crypto.AesCbc,
        conn_id: [8]u8,
        initial_seq_no: i32,
        remote_addr: net.Address,
        our_addr: net.Address,
        proto_tag: constants.ProtoTag,
        ad_tag: ?[16]u8,
        buffer_size: usize,
    ) !MiddleProxyContext {
        const buffer_limit = @min(@max(buffer_size, initial_stream_buffer_size), max_stream_buffer_size);
        const initial_buffer_size = @min(buffer_limit, initial_stream_buffer_size);

        var rip: [20]u8 = undefined;
        var rport: u16 = 0;
        if (remote_addr.any.family == posix.AF.INET) {
            const ipv4_mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            @memcpy(rip[0..12], &ipv4_mapped);
            @memcpy(rip[12..16], std.mem.asBytes(&remote_addr.in.sa.addr));
            rport = remote_addr.in.sa.port;
        } else if (remote_addr.any.family == posix.AF.INET6) {
            @memcpy(rip[0..16], &remote_addr.in6.sa.addr);
            rport = remote_addr.in6.sa.port;
        } else return error.UnsupportedAddressType;
        std.mem.writeInt(u32, rip[16..20], std.mem.bigToNative(u16, rport), .little);

        var oip: [20]u8 = undefined;
        var oport: u16 = 0;
        if (our_addr.any.family == posix.AF.INET) {
            const ipv4_mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
            @memcpy(oip[0..12], &ipv4_mapped);
            @memcpy(oip[12..16], std.mem.asBytes(&our_addr.in.sa.addr));
            oport = our_addr.in.sa.port;
        } else if (our_addr.any.family == posix.AF.INET6) {
            @memcpy(oip[0..16], &our_addr.in6.sa.addr);
            oport = our_addr.in6.sa.port;
        } else return error.UnsupportedAddressType;
        std.mem.writeInt(u32, oip[16..20], std.mem.bigToNative(u16, oport), .little);

        const s2c_buf = try allocator.alloc(u8, initial_buffer_size);
        errdefer allocator.free(s2c_buf);

        const c2s_buf = try allocator.alloc(u8, initial_buffer_size);
        errdefer allocator.free(c2s_buf);

        return .{
            .allocator = allocator,
            .encryptor = encryptor,
            .decryptor = decryptor,
            .seq_no = initial_seq_no,
            .read_seq_no = 0,
            .conn_id = conn_id,
            .remote_ip_port = rip,
            .our_ip_port = oip,
            .proto_tag = proto_tag,
            .ad_tag = ad_tag,
            .s2c_buf = s2c_buf,
            .c2s_buf = c2s_buf,
            .buffer_limit = buffer_limit,
        };
    }

    pub fn deinit(self: *MiddleProxyContext) void {
        self.encryptor.wipe();
        self.decryptor.wipe();
        secureFree(self.allocator, self.s2c_buf);
        secureFree(self.allocator, self.c2s_buf);
        std.crypto.secureZero(u8, &self.conn_id);
        std.crypto.secureZero(u8, &self.remote_ip_port);
        std.crypto.secureZero(u8, &self.our_ip_port);
        if (self.ad_tag) |*tag| std.crypto.secureZero(u8, tag);
        self.s2c_len = 0;
        self.s2c_decrypted_len = 0;
        self.c2s_len = 0;
    }

    fn requiredBufferedCapacity(self: *const MiddleProxyContext, current_len: usize, extra_len: usize) !usize {
        const needed = try std.math.add(usize, current_len, extra_len);
        if (needed > self.buffer_limit) return error.MiddleProxyBufferOverflow;
        return needed;
    }

    fn nextBufferCapacity(current_capacity: usize, min_capacity: usize, limit: usize) usize {
        var next = current_capacity;
        while (next < min_capacity) {
            if (next >= limit / 2) return limit;
            next *= 2;
        }
        return next;
    }

    fn ensureC2sCapacity(self: *MiddleProxyContext, min_capacity: usize) !void {
        if (self.c2s_buf.len >= min_capacity) return;
        const next_capacity = nextBufferCapacity(self.c2s_buf.len, min_capacity, self.buffer_limit);
        const next = try self.allocator.alloc(u8, next_capacity);
        @memcpy(next[0..self.c2s_len], self.c2s_buf[0..self.c2s_len]);
        secureFree(self.allocator, self.c2s_buf);
        self.c2s_buf = next;
    }

    fn ensureS2cCapacity(self: *MiddleProxyContext, min_capacity: usize) !void {
        if (self.s2c_buf.len >= min_capacity) return;
        const next_capacity = nextBufferCapacity(self.s2c_buf.len, min_capacity, self.buffer_limit);
        const next = try self.allocator.alloc(u8, next_capacity);
        @memcpy(next[0..self.s2c_len], self.s2c_buf[0..self.s2c_len]);
        secureFree(self.allocator, self.s2c_buf);
        self.s2c_buf = next;
    }

    fn shrinkC2sIfIdle(self: *MiddleProxyContext) void {
        if (self.c2s_len != 0) return;
        if (self.c2s_buf.len <= shrink_stream_buffer_threshold) return;
        const next = self.allocator.alloc(u8, initial_stream_buffer_size) catch return;
        secureFree(self.allocator, self.c2s_buf);
        self.c2s_buf = next;
    }

    fn shrinkS2cIfIdle(self: *MiddleProxyContext) void {
        if (self.s2c_len != 0) return;
        if (self.s2c_buf.len <= shrink_stream_buffer_threshold) return;
        const next = self.allocator.alloc(u8, initial_stream_buffer_size) catch return;
        secureFree(self.allocator, self.s2c_buf);
        self.s2c_buf = next;
    }

    fn peekBufferedC2sByte(self: *const MiddleProxyContext, client_data: []const u8, idx: usize) u8 {
        if (idx < self.c2s_len) return self.c2s_buf[idx];
        return client_data[idx - self.c2s_len];
    }

    fn c2sFrameEncryptedLen(self: *const MiddleProxyContext, client_payload_len: usize) usize {
        const extra_len: usize = if (self.ad_tag != null) 28 else 0;
        const frame_total_len = 68 + extra_len + client_payload_len;
        const padding_needed = (16 - (frame_total_len % 16)) % 16;
        return frame_total_len + padding_needed;
    }

    fn firstEightAllZero(payload: []const u8) bool {
        std.debug.assert(payload.len >= 8);
        for (payload[0..8]) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    fn bufferedFirstEightAllZero(self: *const MiddleProxyContext, client_data: []const u8, start: usize) bool {
        for (0..8) |i| {
            if (self.peekBufferedC2sByte(client_data, start + i) != 0) return false;
        }
        return true;
    }

    fn readBufferedU32(self: *const MiddleProxyContext, client_data: []const u8, start: usize) u32 {
        var buf: [4]u8 = undefined;
        for (0..buf.len) |i| {
            buf[i] = self.peekBufferedC2sByte(client_data, start + i);
        }
        return std.mem.readInt(u32, buf[0..4], .little);
    }

    fn plainMtprotoActualPayloadLen(frame_payload_len: usize, message_data_len: u32) !usize {
        const actual_len = std.math.add(usize, 20, @as(usize, message_data_len)) catch {
            return error.InvalidPayloadLength;
        };
        if (actual_len > frame_payload_len) return error.InvalidPayloadLength;
        if (frame_payload_len - actual_len > 15) return error.InvalidPayloadLength;
        return actual_len;
    }

    fn encryptedMtprotoActualPayloadLen(frame_payload_len: usize) !usize {
        if (frame_payload_len < 24) return error.InvalidPayloadLength;

        const padding_len = (frame_payload_len - 24) & 15;
        const actual_len = frame_payload_len - padding_len;
        if ((actual_len & 3) != 0) return error.InvalidPayloadLength;
        return actual_len;
    }

    fn securePayloadInfo(payload: []const u8) !C2sPayloadInfo {
        if (payload.len >= 20 and firstEightAllZero(payload)) {
            const message_data_len = std.mem.readInt(u32, payload[16..20], .little);
            if (plainMtprotoActualPayloadLen(payload.len, message_data_len)) |actual_len| {
                return .{ .actual_len = actual_len, .is_plain = true };
            } else |_| {}
        }
        return .{ .actual_len = try encryptedMtprotoActualPayloadLen(payload.len), .is_plain = false };
    }

    fn validateC2sPayloadLength(self: *const MiddleProxyContext, header_len: usize, payload_len: usize) !void {
        if (payload_len < min_client_payload_size or
            (self.proto_tag != .secure and (payload_len & 3) != 0))
        {
            return error.InvalidPayloadLength;
        }
        if (header_len > self.buffer_limit or payload_len > self.buffer_limit - header_len) {
            return error.MiddleProxyBufferOverflow;
        }
    }

    fn securePayloadInfoBuffered(
        self: *const MiddleProxyContext,
        client_data: []const u8,
        payload_start: usize,
        payload_len: usize,
    ) !C2sPayloadInfo {
        if (payload_len >= 20 and self.bufferedFirstEightAllZero(client_data, payload_start)) {
            const message_data_len = self.readBufferedU32(client_data, payload_start + 16);
            if (plainMtprotoActualPayloadLen(payload_len, message_data_len)) |actual_len| {
                return .{ .actual_len = actual_len, .is_plain = true };
            } else |_| {}
        }
        return .{ .actual_len = try encryptedMtprotoActualPayloadLen(payload_len), .is_plain = false };
    }

    pub fn requiredC2sScratchCapacity(self: *const MiddleProxyContext, client_data: []const u8) !usize {
        const total_input_len = try self.requiredBufferedCapacity(self.c2s_len, client_data.len);
        var pos: usize = 0;
        var total_written: usize = 0;

        while (pos < total_input_len) {
            var payload_len: usize = 0;
            var header_len: usize = 0;

            switch (self.proto_tag) {
                .abridged => {
                    if (total_input_len - pos < 1) break;
                    const first = self.peekBufferedC2sByte(client_data, pos);
                    const len_val = first & 0x7F;
                    if (len_val < 127) {
                        header_len = 1;
                        payload_len = @as(usize, len_val) * 4;
                    } else {
                        if (total_input_len - pos < 4) break;

                        var header_buf: [4]u8 = undefined;
                        for (0..header_buf.len) |i| {
                            header_buf[i] = self.peekBufferedC2sByte(client_data, pos + i);
                        }

                        header_len = 4;
                        payload_len = std.mem.readInt(u32, header_buf[0..4], .little) >> 8;
                        payload_len *= 4;
                    }
                },
                .intermediate, .secure => {
                    if (total_input_len - pos < 4) break;

                    var header_buf: [4]u8 = undefined;
                    for (0..header_buf.len) |i| {
                        header_buf[i] = self.peekBufferedC2sByte(client_data, pos + i);
                    }

                    header_len = 4;
                    var len_u32 = std.mem.readInt(u32, header_buf[0..4], .little);
                    len_u32 &= 0x7FFFFFFF;
                    payload_len = len_u32;
                },
            }

            try self.validateC2sPayloadLength(header_len, payload_len);

            if (total_input_len - pos < header_len + payload_len) break;

            var actual_payload_len = payload_len;
            if (self.proto_tag == .secure) {
                actual_payload_len = (try self.securePayloadInfoBuffered(client_data, pos + header_len, payload_len)).actual_len;
            }

            total_written += self.c2sFrameEncryptedLen(actual_payload_len);
            pos += header_len + payload_len;
        }

        return total_written;
    }

    /// Takes arbitrary bytes from the client stream, wraps them in RPC_PROXY_REQ,
    /// frames them into MTProtoFrame(s), encrypts with AES-CBC, and stores them in `out_buf`.
    /// Returns the number of bytes written to `out_buf` (which must be sent to the DC).
    pub fn encapsulateC2S(self: *MiddleProxyContext, client_data: []const u8, out_buf: []u8) ![]const u8 {
        const total_input_len = try self.requiredBufferedCapacity(self.c2s_len, client_data.len);
        try self.ensureC2sCapacity(total_input_len);
        @memcpy(self.c2s_buf[self.c2s_len .. self.c2s_len + client_data.len], client_data);
        self.c2s_len += client_data.len;

        var pos: usize = 0;
        var total_written: usize = 0;

        while (pos < self.c2s_len) {
            var payload_len: usize = 0;
            var header_len: usize = 0;
            var is_quickack: bool = false; // 1. Track QuickAck per-packet

            switch (self.proto_tag) {
                .abridged => {
                    if (self.c2s_len - pos < 1) break;
                    const first: u8 = self.c2s_buf[pos];
                    is_quickack = (first & 0x80) != 0; // Extract QuickAck

                    const len_val = first & 0x7F;
                    if (len_val < 127) {
                        header_len = 1;
                        payload_len = @as(usize, len_val) * 4;
                    } else {
                        if (self.c2s_len - pos < 4) break;
                        header_len = 4;
                        payload_len = std.mem.readInt(u32, self.c2s_buf[pos..][0..4], .little) >> 8;
                        payload_len *= 4;
                    }
                },
                .intermediate, .secure => {
                    if (self.c2s_len - pos < 4) break;
                    header_len = 4;
                    var len_u32 = std.mem.readInt(u32, self.c2s_buf[pos..][0..4], .little);
                    is_quickack = (len_u32 & 0x80000000) != 0; // Extract QuickAck
                    len_u32 &= 0x7FFFFFFF;
                    payload_len = len_u32;
                },
            }

            try self.validateC2sPayloadLength(header_len, payload_len);

            if (self.c2s_len - pos < header_len + payload_len) {
                break; // Need more data
            }

            var actual_payload_len = payload_len;
            var is_plain = false;
            if (self.proto_tag == .secure) {
                const info = try securePayloadInfo(
                    self.c2s_buf[pos + header_len .. pos + header_len + payload_len],
                );
                actual_payload_len = info.actual_len;
                is_plain = info.is_plain;
            }

            const payload = self.c2s_buf[pos + header_len .. pos + header_len + actual_payload_len];

            // 3. Pass is_quickack to the encapsulator
            const written = try self.encapsulateSingleMessageC2SWithPlainFlag(payload, is_quickack, is_plain or self.proto_tag != .secure, out_buf[total_written..]);
            total_written += written;

            // Note: Advance `pos` by the FULL payload_len so we safely consume/discard the padding bytes
            pos += header_len + payload_len;
        }

        if (pos > 0) {
            const remaining = self.c2s_len - pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.c2s_buf[0..remaining], self.c2s_buf[pos..self.c2s_len]);
            }
            self.c2s_len = remaining;
            self.shrinkC2sIfIdle();
        }

        return out_buf[0..total_written];
    }

    pub fn requiredS2cScratchCapacity(self: *const MiddleProxyContext, dc_chunk: []const u8) !usize {
        return self.requiredBufferedCapacity(self.s2c_len, dc_chunk.len);
    }

    pub fn encapsulateSingleMessageC2S(self: *MiddleProxyContext, client_data: []const u8, is_quickack: bool, out_buf: []u8) !usize {
        return self.encapsulateSingleMessageC2SWithPlainFlag(client_data, is_quickack, true, out_buf);
    }

    fn encapsulateSingleMessageC2SWithPlainFlag(self: *MiddleProxyContext, client_data: []const u8, is_quickack: bool, allow_plain_detection: bool, out_buf: []u8) !usize {
        // MiddleProxy CBC padding is encoded as complete 4-byte NOOP markers.
        // An unaligned inner payload cannot be padded to a 16-byte AES block
        // without writing a partial marker outside the advertised frame.
        if ((client_data.len & 3) != 0) return error.InvalidPayloadLength;

        var flags = Flag.magic | Flag.extmode2;
        if (self.ad_tag != null) {
            flags |= Flag.has_ad_tag;
        }
        switch (self.proto_tag) {
            .abridged => flags |= Flag.abridged,
            .intermediate => flags |= Flag.intermediate,
            .secure => flags |= Flag.intermediate | Flag.pad,
        }

        if (is_quickack) flags |= 0x80000000; // Flag.quickack

        // Check if plain (no obfuscation)
        var all_zeros = true;
        const check_len = @min(8, client_data.len);
        for (client_data[0..check_len]) |b| {
            if (b != 0) all_zeros = false;
        }
        if (allow_plain_detection and all_zeros and client_data.len >= 8) flags |= Flag.not_encrypted;

        // Write directly into out_buf to avoid fixed-size stack buffer overflow
        // on large client packets.
        const extra_len: usize = if (self.ad_tag != null) 28 else 0;
        const rpc_len = 56 + extra_len + client_data.len;
        const frame_total_len = rpc_len + 12;
        const padding_needed = (16 - (frame_total_len % 16)) % 16;
        const encrypted_len = frame_total_len + padding_needed;
        if (out_buf.len < encrypted_len) return error.OutBufOverflow;

        var out_len: usize = 0;
        std.mem.writeInt(u32, out_buf[out_len..][0..4], @intCast(frame_total_len), .little);
        out_len += 4;
        std.mem.writeInt(i32, out_buf[out_len..][0..4], self.seq_no, .little);
        out_len += 4;
        self.seq_no = self.seq_no +% 1;

        @memcpy(out_buf[out_len .. out_len + 4], &rpc_proxy_req);
        out_len += 4;
        std.mem.writeInt(u32, out_buf[out_len..][0..4], flags, .little);
        out_len += 4;
        @memcpy(out_buf[out_len .. out_len + 8], &self.conn_id);
        out_len += 8;
        @memcpy(out_buf[out_len .. out_len + 20], &self.remote_ip_port);
        out_len += 20;
        @memcpy(out_buf[out_len .. out_len + 20], &self.our_ip_port);
        out_len += 20;

        if (self.ad_tag) |ad_tag| {
            const extra_size: u32 = 24;
            std.mem.writeInt(u32, out_buf[out_len..][0..4], extra_size, .little);
            out_len += 4;

            const proxy_tag = [_]u8{ 0xae, 0x26, 0x1e, 0xdb };
            @memcpy(out_buf[out_len .. out_len + 4], &proxy_tag);
            out_len += 4;

            out_buf[out_len] = 16;
            out_len += 1;

            @memcpy(out_buf[out_len .. out_len + 16], &ad_tag);
            out_len += 16;

            const aligner = [_]u8{ 0x00, 0x00, 0x00 };
            @memcpy(out_buf[out_len .. out_len + 3], &aligner);
            out_len += 3;
        }

        @memcpy(out_buf[out_len .. out_len + client_data.len], client_data);
        out_len += client_data.len;

        // CRC32 of length + seq + payload (which starts at out_buf[0])
        const checksum = crc32(out_buf[0..out_len]);
        std.mem.writeInt(u32, out_buf[out_len..][0..4], checksum, .little);
        out_len += 4;

        // AES CBC Padding requires NO-OP length markers (0x04000000)
        var i: usize = 0;
        while (i < padding_needed) : (i += 4) {
            std.mem.writeInt(u32, out_buf[out_len + i ..][0..4], 4, .little);
        }
        out_len += padding_needed;

        std.debug.assert(out_len == encrypted_len);

        try self.encryptor.encryptInPlace(out_buf[0..out_len]);
        return out_len;
    }

    /// Takes raw AES-CBC bytes from DC, decrypts them block by block, parses MTProtoFrames,
    /// strips RPC_PROXY_ANS, and writes the inner payload into `out_buf`.
    pub fn decapsulateS2C(self: *MiddleProxyContext, dc_chunk: []const u8, out_buf: []u8) ![]u8 {
        const total_input_len = try self.requiredBufferedCapacity(self.s2c_len, dc_chunk.len);
        try self.ensureS2cCapacity(total_input_len);
        @memcpy(self.s2c_buf[self.s2c_len .. self.s2c_len + dc_chunk.len], dc_chunk);
        self.s2c_len += dc_chunk.len;

        // Decrypt any newly arrived full 16-byte blocks in one batch.
        const undec_len = self.s2c_len - self.s2c_decrypted_len;
        const decrypt_len = undec_len - (undec_len % 16);
        if (decrypt_len > 0) {
            const start = self.s2c_decrypted_len;
            const end = start + decrypt_len;
            try self.decryptor.decryptInPlace(self.s2c_buf[start..end]);
            self.s2c_decrypted_len = end;
        }

        var out_pos: usize = 0;
        var parse_pos: usize = 0;

        // Parse fully decrypted MTProto frames.
        // Mirrors telemt behavior: parse by frame_len, treat 0x04 words as NO-OP,
        // keep decrypt stream running continuously across arbitrary read boundaries.
        while (self.s2c_decrypted_len - parse_pos >= 4) {
            const frame_len = std.mem.readInt(u32, self.s2c_buf[parse_pos..][0..4], .little);

            // MTProto CBC stream may contain standalone NO-OP padding words
            // (0x04 00 00 00). Python reference reader skips them.
            if (frame_len == 4) {
                parse_pos += 4;
                continue;
            }

            if (frame_len < 12 or frame_len > (1 << 24)) {
                // AES-CBC decryption is stateful across records, so dropping the current
                // window without rewinding the chaining IV cannot produce a safe resync.
                // Fail closed instead of continuing with corrupted stream state.
                return error.BadMiddleProxyFrameLen;
            }

            if (self.s2c_decrypted_len - parse_pos < frame_len) {
                break; // Not enough decrypted data yet
            }

            const frame_end = parse_pos + frame_len;
            const expected_checksum = std.mem.readInt(u32, self.s2c_buf[frame_end - 4 ..][0..4], .little);
            const computed_checksum = crc32(self.s2c_buf[parse_pos .. frame_end - 4]);
            if (expected_checksum != computed_checksum) return error.BadMiddleProxyChecksum;

            const frame_seq_no = std.mem.readInt(i32, self.s2c_buf[parse_pos + 4 ..][0..4], .little);
            if (frame_seq_no != self.read_seq_no) return error.BadMiddleProxySeqNo;
            self.read_seq_no = self.read_seq_no +% 1;

            // Payload is after Length (4) and SeqNo (4), and before CRC32 (4)
            const payload = self.s2c_buf[parse_pos + 8 .. frame_end - 4];

            if (payload.len >= 4 and std.mem.eql(u8, payload[0..4], &rpc_simple_ack)) {
                // RPC_SIMPLE_ACK format: type(4) + conn_id(8) + confirm(4)
                if (payload.len != 16) return error.BadMiddleProxyPayload;
                if (!std.mem.eql(u8, payload[4..12], &self.conn_id)) return error.BadMiddleProxyConnId;
                const confirm = payload[12..16];
                if (out_pos + confirm.len > out_buf.len) return error.OutBufOverflow;
                const confirm_value = std.mem.readInt(u32, confirm, .little);
                std.mem.writeInt(
                    u32,
                    out_buf[out_pos..][0..4],
                    confirm_value,
                    if (self.proto_tag == .abridged) .big else .little,
                );
                out_pos += confirm.len;
            } else if (payload.len >= 4 and std.mem.eql(u8, payload[0..4], &rpc_close_ext)) {
                if (payload.len != 12) return error.BadMiddleProxyPayload;
                if (!std.mem.eql(u8, payload[4..12], &self.conn_id)) return error.BadMiddleProxyConnId;
                return error.ConnectionReset;
            } else if (payload.len >= 4 and std.mem.eql(u8, payload[0..4], &rpc_proxy_ans)) {
                // RPC_PROXY_ANS format: type(4) + flags(4) + conn_id(8) + conn_data
                if (payload.len < 16) return error.BadMiddleProxyPayload;
                const flags = std.mem.readInt(u32, payload[4..8], .little);
                try self.validateProxyAnsFlags(flags);
                if (!std.mem.eql(u8, payload[8..16], &self.conn_id)) return error.BadMiddleProxyConnId;
                const conn_data = payload[16..];

                var pad_len: usize = 0;
                var pad_buf: [15]u8 = undefined;
                if (self.proto_tag == .secure) {
                    pad_len = crypto.randomRange(usize, 16);
                    if (pad_len > 0) {
                        crypto.randomBytes(pad_buf[0..pad_len]);
                    }
                }

                var header_len: usize = 0;
                var header_buf: [4]u8 = undefined;

                switch (self.proto_tag) {
                    .abridged => {
                        const len_div_4: usize = (conn_data.len + pad_len) / 4;
                        if (len_div_4 < 127) {
                            header_buf[0] = @intCast(len_div_4);
                            header_len = 1;
                        } else {
                            header_buf[0] = 127;
                            header_buf[1] = @truncate(len_div_4);
                            header_buf[2] = @truncate(len_div_4 >> 8);
                            header_buf[3] = @truncate(len_div_4 >> 16);
                            header_len = 4;
                        }
                    },
                    .intermediate, .secure => {
                        std.mem.writeInt(u32, header_buf[0..4], @intCast(conn_data.len + pad_len), .little);
                        header_len = 4;
                    },
                }

                if (out_pos + header_len + conn_data.len + pad_len > out_buf.len) return error.OutBufOverflow;

                @memcpy(out_buf[out_pos .. out_pos + header_len], header_buf[0..header_len]);
                out_pos += header_len;

                @memcpy(out_buf[out_pos .. out_pos + conn_data.len], conn_data);
                out_pos += conn_data.len;

                if (pad_len > 0) {
                    @memcpy(out_buf[out_pos .. out_pos + pad_len], pad_buf[0..pad_len]);
                    out_pos += pad_len;
                }
            }
            // Ignore other RPC types (e.g. RPC_SIMPLE_ACK, RPC_CLOSE_EXT)

            parse_pos = frame_end;
        }

        if (parse_pos > 0 and parse_pos <= self.s2c_len) {
            const remaining = self.s2c_len - parse_pos;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.s2c_buf[0..remaining], self.s2c_buf[parse_pos..self.s2c_len]);
            }
            self.s2c_len = remaining;
            self.s2c_decrypted_len -= parse_pos;
            self.shrinkS2cIfIdle();
        }

        return out_buf[0..out_pos];
    }

    fn validateProxyAnsFlags(self: *const MiddleProxyContext, flags: u32) !void {
        const known_flags = Flag.not_encrypted | Flag.has_ad_tag | Flag.magic | Flag.extmode2 |
            Flag.pad | Flag.dropped | Flag.intermediate | Flag.abridged | Flag.quickack;
        if ((flags & ~known_flags) != 0) return error.BadMiddleProxyFlags;
        if ((flags & Flag.dropped) != 0) return error.MiddleProxyDroppedResponse;
        const mode_header = flags & (Flag.magic | Flag.extmode2);
        if (mode_header != 0 and mode_header != (Flag.magic | Flag.extmode2)) {
            return error.BadMiddleProxyFlags;
        }
        if ((flags & Flag.has_ad_tag) != 0 and self.ad_tag == null) {
            return error.BadMiddleProxyFlags;
        }

        switch (self.proto_tag) {
            .abridged => {
                if ((flags & (Flag.intermediate | Flag.pad)) != 0) return error.BadMiddleProxyFlags;
            },
            .intermediate => {
                if ((flags & (Flag.abridged | Flag.pad)) != 0) return error.BadMiddleProxyFlags;
            },
            .secure => {
                if ((flags & Flag.abridged) != 0) return error.BadMiddleProxyFlags;
                if ((flags & Flag.pad) != 0 and (flags & Flag.intermediate) == 0) return error.BadMiddleProxyFlags;
            },
        }
    }
};

pub fn crc32(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}

test "encapsulated c2s keeps rpc_proxy_req header" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    try std.testing.expect(total_len >= 12 + 4);

    const payload = encrypted_out[8 .. total_len - 4];
    try std.testing.expect(payload.len >= 4);
    try std.testing.expectEqualSlices(u8, &rpc_proxy_req, payload[0..4]);
}

test "encapsulated c2s omits ad_tag block when absent" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const payload = encrypted_out[8 .. total_len - 4];

    const flags = std.mem.readInt(u32, payload[4..8], .little);
    try std.testing.expect((flags & Flag.has_ad_tag) == 0);
    try std.testing.expectEqual(@as(usize, 56 + client_data.len), payload.len);
}

test "encapsulate c2s rejects unaligned non-secure payload length" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    const client_data = [_]u8{ 0xde, 0xad, 0xbe };
    var encrypted_out: [128]u8 = undefined;

    try std.testing.expectError(
        error.InvalidPayloadLength,
        ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]),
    );
}

test "encapsulated c2s includes ad_tag block when present" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;
    const ad_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        ad_tag,
    );
    defer ctx.deinit();

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expect(written >= 16);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const payload = encrypted_out[8 .. total_len - 4];

    const flags = std.mem.readInt(u32, payload[4..8], .little);
    try std.testing.expect((flags & Flag.has_ad_tag) != 0);

    const extra_size = std.mem.readInt(u32, payload[56..60], .little);
    try std.testing.expectEqual(@as(u32, 24), extra_size);
    const proxy_tag = [_]u8{ 0xae, 0x26, 0x1e, 0xdb };
    try std.testing.expectEqualSlices(u8, &proxy_tag, payload[60..64]);
    try std.testing.expectEqual(@as(u8, 16), payload[64]);
    try std.testing.expectEqualSlices(u8, &ad_tag, payload[65..81]);
}

test "required c2s scratch capacity accounts for buffered partial frame" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    ctx.c2s_buf[0] = @intCast(MiddleProxyContext.min_client_payload_size);
    ctx.c2s_buf[1] = 0;
    ctx.c2s_len = 2;

    var tail = [_]u8{0} ** (2 + MiddleProxyContext.min_client_payload_size);
    @memset(tail[2..], 0xef);
    const required = try ctx.requiredC2sScratchCapacity(tail[0..]);

    try std.testing.expectEqual(ctx.c2sFrameEncryptedLen(MiddleProxyContext.min_client_payload_size), required);
}

test "secure c2s strips encrypted padded-intermediate padding" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .secure,
        null,
    );
    defer ctx.deinit();

    var mtproto_payload: [40]u8 = undefined;
    @memcpy(mtproto_payload[0..8], &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    @memset(mtproto_payload[8..24], 0xaa);
    @memset(mtproto_payload[24..], 0xbb);

    var packet: [4 + mtproto_payload.len + 12]u8 = undefined;
    std.mem.writeInt(u32, packet[0..4], @intCast(packet.len - 4), .little);
    @memcpy(packet[4 .. 4 + mtproto_payload.len], &mtproto_payload);
    @memset(packet[4 + mtproto_payload.len ..], 0x7b);

    const required = try ctx.requiredC2sScratchCapacity(packet[0..]);
    try std.testing.expectEqual(ctx.c2sFrameEncryptedLen(mtproto_payload.len), required);

    var encrypted_out: [512]u8 = undefined;
    const out = try ctx.encapsulateC2S(packet[0..], encrypted_out[0..]);
    try std.testing.expectEqual(@as(usize, 0), ctx.c2s_len);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..out.len]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const rpc_payload = encrypted_out[8 .. total_len - 4];
    const flags = std.mem.readInt(u32, rpc_payload[4..8], .little);
    try std.testing.expect((flags & Flag.pad) != 0);
    try std.testing.expectEqual(@as(usize, 56 + mtproto_payload.len), rpc_payload.len);
    try std.testing.expectEqualSlices(u8, &mtproto_payload, rpc_payload[56..]);
}

test "secure c2s strips plain padded-intermediate padding" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .secure,
        null,
    );
    defer ctx.deinit();

    var mtproto_payload: [32]u8 = undefined;
    @memset(mtproto_payload[0..8], 0);
    @memset(mtproto_payload[8..16], 0x11);
    std.mem.writeInt(u32, mtproto_payload[16..20], 12, .little);
    @memset(mtproto_payload[20..], 0xcc);

    var packet: [4 + mtproto_payload.len + 7]u8 = undefined;
    std.mem.writeInt(u32, packet[0..4], @intCast(packet.len - 4), .little);
    @memcpy(packet[4 .. 4 + mtproto_payload.len], &mtproto_payload);
    @memset(packet[4 + mtproto_payload.len ..], 0x5d);

    const required = try ctx.requiredC2sScratchCapacity(packet[0..]);
    try std.testing.expectEqual(ctx.c2sFrameEncryptedLen(mtproto_payload.len), required);

    var encrypted_out: [512]u8 = undefined;
    const out = try ctx.encapsulateC2S(packet[0..], encrypted_out[0..]);
    try std.testing.expectEqual(@as(usize, 0), ctx.c2s_len);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..out.len]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const rpc_payload = encrypted_out[8 .. total_len - 4];
    const flags = std.mem.readInt(u32, rpc_payload[4..8], .little);
    try std.testing.expect((flags & Flag.pad) != 0);
    try std.testing.expect((flags & Flag.not_encrypted) != 0);
    try std.testing.expectEqual(@as(usize, 56 + mtproto_payload.len), rpc_payload.len);
    try std.testing.expectEqualSlices(u8, &mtproto_payload, rpc_payload[56..]);
}

test "secure c2s rejects unaligned plain mtproto payload data" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .secure,
        null,
    );
    defer ctx.deinit();

    var mtproto_payload: [33]u8 = undefined;
    @memset(mtproto_payload[0..8], 0);
    @memset(mtproto_payload[8..16], 0x22);
    std.mem.writeInt(u32, mtproto_payload[16..20], 13, .little);
    @memset(mtproto_payload[20..], 0xdd);

    var packet: [4 + mtproto_payload.len + 5]u8 = undefined;
    std.mem.writeInt(u32, packet[0..4], @intCast(packet.len - 4), .little);
    @memcpy(packet[4 .. 4 + mtproto_payload.len], &mtproto_payload);
    @memset(packet[4 + mtproto_payload.len ..], 0xa7);

    const required = try ctx.requiredC2sScratchCapacity(packet[0..]);
    try std.testing.expectEqual(ctx.c2sFrameEncryptedLen(mtproto_payload.len), required);

    var encrypted_out: [512]u8 = undefined;
    try std.testing.expectError(error.InvalidPayloadLength, ctx.encapsulateC2S(packet[0..], encrypted_out[0..]));
}

test "secure c2s treats invalid plain-looking payload as encrypted" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .secure,
        null,
    );
    defer ctx.deinit();

    var encrypted_payload: [116]u8 = undefined;
    @memset(encrypted_payload[0..8], 0);
    @memset(encrypted_payload[8..], 0x34);
    std.mem.writeInt(u32, encrypted_payload[16..20], 0x7fff_ffff, .little);

    var packet: [4 + encrypted_payload.len]u8 = undefined;
    std.mem.writeInt(u32, packet[0..4], encrypted_payload.len, .little);
    @memcpy(packet[4..], &encrypted_payload);

    const actual_payload_len: usize = 104;
    const required = try ctx.requiredC2sScratchCapacity(packet[0..]);
    try std.testing.expectEqual(ctx.c2sFrameEncryptedLen(actual_payload_len), required);

    var encrypted_out: [512]u8 = undefined;
    const out = try ctx.encapsulateC2S(packet[0..], encrypted_out[0..]);
    try std.testing.expectEqual(@as(usize, 0), ctx.c2s_len);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..out.len]);

    const total_len = std.mem.readInt(u32, encrypted_out[0..4], .little);
    const rpc_payload = encrypted_out[8 .. total_len - 4];
    const flags = std.mem.readInt(u32, rpc_payload[4..8], .little);
    try std.testing.expect((flags & Flag.pad) != 0);
    try std.testing.expect((flags & Flag.not_encrypted) == 0);
    try std.testing.expectEqual(@as(usize, 56 + actual_payload_len), rpc_payload.len);
    try std.testing.expectEqualSlices(u8, encrypted_payload[0..actual_payload_len], rpc_payload[56..]);
}

test "decapsulate s2c skips noop padding words" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    // Build plaintext stream:
    // - one full 16-byte NO-OP block (4x uint32(4))
    // - one RPC_SIMPLE_ACK frame (len=28, padded to 32)
    var plain: [48]u8 = undefined;
    var off: usize = 0;

    // 16-byte NO-OP block
    var i: usize = 0;
    while (i < 16) : (i += 4) {
        std.mem.writeInt(u32, plain[off + i ..][0..4], 4, .little);
    }
    off += 16;

    // RPC_SIMPLE_ACK frame: total_len=28, payload=16
    const total_len: u32 = 28;
    std.mem.writeInt(u32, plain[off..][0..4], total_len, .little);
    std.mem.writeInt(i32, plain[off + 4 ..][0..4], 0, .little);

    // payload: type(4) + conn_id(8) + confirm(4)
    @memcpy(plain[off + 8 .. off + 12], &rpc_simple_ack);
    @memcpy(plain[off + 12 .. off + 20], &ctx.conn_id);
    const confirm = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    @memcpy(plain[off + 20 .. off + 24], &confirm);

    const checksum = crc32(plain[off .. off + 24]);
    std.mem.writeInt(u32, plain[off + 24 ..][0..4], checksum, .little);

    // Padded tail for len=28 -> 32
    std.mem.writeInt(u32, plain[off + 28 ..][0..4], 4, .little);

    // Encrypt the full stream as one CBC chain
    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    var out_buf: [128]u8 = undefined;
    const out = try ctx.decapsulateS2C(wire[0..], out_buf[0..]);
    try std.testing.expectEqual(@as(usize, 4), out.len);
    try std.testing.expectEqualSlices(u8, &confirm, out);
}

test "decapsulate s2c validates seq" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    // Build one plaintext RPC_PROXY_ANS frame with seq=0 and 4-byte body.
    var plain: [32]u8 = undefined;
    const total_len: u32 = 32;
    std.mem.writeInt(u32, plain[0..4], total_len, .little);
    std.mem.writeInt(i32, plain[4..8], 0, .little);
    @memcpy(plain[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain[12..16], 0, .little); // flags
    @memcpy(plain[16..24], &ctx.conn_id);
    std.mem.writeInt(u32, plain[24..28], 0x12345678, .little); // data
    const checksum = crc32(plain[0..28]);
    std.mem.writeInt(u32, plain[28..32], checksum, .little);

    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    var out_buf: [128]u8 = undefined;
    const out = try ctx.decapsulateS2C(wire[0..], out_buf[0..]);
    try std.testing.expectEqual(@as(usize, 8), out.len); // len(4) + data(4)

    // Send a second valid frame with wrong seq (5 instead of expected 1)
    var plain2: [32]u8 = undefined;
    std.mem.writeInt(u32, plain2[0..4], total_len, .little);
    std.mem.writeInt(i32, plain2[4..8], 5, .little);
    @memcpy(plain2[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain2[12..16], 0, .little);
    @memcpy(plain2[16..24], &ctx.conn_id);
    std.mem.writeInt(u32, plain2[24..28], 0x01020304, .little);
    const checksum2 = crc32(plain2[0..28]);
    std.mem.writeInt(u32, plain2[28..32], checksum2, .little);

    var wire2 = plain2;
    try enc.encryptInPlace(wire2[0..]);

    try std.testing.expectError(error.BadMiddleProxySeqNo, ctx.decapsulateS2C(wire2[0..], out_buf[0..]));
}

test "decapsulate s2c rejects checksum mismatch without resyncing" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    var plain: [32]u8 = undefined;
    const total_len: u32 = 32;
    std.mem.writeInt(u32, plain[0..4], total_len, .little);
    std.mem.writeInt(i32, plain[4..8], 0, .little);
    @memcpy(plain[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain[12..16], 0, .little);
    @memcpy(plain[16..24], &ctx.conn_id);
    std.mem.writeInt(u32, plain[24..28], 0x12345678, .little);
    const checksum = crc32(plain[0..28]);
    std.mem.writeInt(u32, plain[28..32], checksum ^ 0x1, .little);

    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    var out_buf: [128]u8 = undefined;
    try std.testing.expectError(error.BadMiddleProxyChecksum, ctx.decapsulateS2C(wire[0..], out_buf[0..]));
}

test "middle proxy sequence counters wrap without panicking" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        std.math.maxInt(i32),
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    const client_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var encrypted_out: [512]u8 = undefined;

    const written = try ctx.encapsulateSingleMessageC2S(client_data[0..], false, encrypted_out[0..]);
    try std.testing.expectEqual(std.math.minInt(i32), ctx.seq_no);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(encrypted_out[0..written]);
    try std.testing.expectEqual(std.math.maxInt(i32), std.mem.readInt(i32, encrypted_out[4..8], .little));

    ctx.read_seq_no = std.math.maxInt(i32);

    var plain: [32]u8 = undefined;
    const total_len: u32 = 32;
    std.mem.writeInt(u32, plain[0..4], total_len, .little);
    std.mem.writeInt(i32, plain[4..8], std.math.maxInt(i32), .little);
    @memcpy(plain[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain[12..16], 0, .little);
    @memcpy(plain[16..24], &ctx.conn_id);
    std.mem.writeInt(u32, plain[24..28], 0x12345678, .little);
    const checksum = crc32(plain[0..28]);
    std.mem.writeInt(u32, plain[28..32], checksum, .little);

    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    var out_buf: [128]u8 = undefined;
    _ = try ctx.decapsulateS2C(wire[0..], out_buf[0..]);
    try std.testing.expectEqual(std.math.minInt(i32), ctx.read_seq_no);
}

test "decapsulate s2c rejects invalid frame length instead of resyncing" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    var plain: [16]u8 = undefined;
    std.mem.writeInt(u32, plain[0..4], 8, .little);
    @memset(plain[4..], 0);

    var enc = crypto.AesCbc.init(&key, &iv);
    var wire = plain;
    try enc.encryptInPlace(wire[0..]);

    var out_buf: [64]u8 = undefined;
    try std.testing.expectError(error.BadMiddleProxyFrameLen, ctx.decapsulateS2C(wire[0..], out_buf[0..]));
}

test "encapsulate c2s supports payloads larger than 64KiB" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.init(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
    );
    defer ctx.deinit();

    const payload_len = 96 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 0x42);

    const out_buf = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(out_buf);

    const written = try ctx.encapsulateSingleMessageC2S(payload, false, out_buf);
    try std.testing.expect(written > payload_len);

    var decryptor = crypto.AesCbc.init(&key, &iv);
    try decryptor.decryptInPlace(out_buf[0..written]);

    const total_len = std.mem.readInt(u32, out_buf[0..4], .little);
    try std.testing.expectEqual(@as(usize, total_len), 56 + payload_len + 12);

    const rpc_payload = out_buf[8 .. total_len - 4];
    try std.testing.expectEqualSlices(u8, &rpc_proxy_req, rpc_payload[0..4]);
}

test "middle proxy context grows c2s buffer on demand within configured cap" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.initWithBuffer(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
        128 * 1024,
    );
    defer ctx.deinit();

    try std.testing.expectEqual(MiddleProxyContext.initial_stream_buffer_size, ctx.c2s_buf.len);

    const payload_len = 96 * 1024;
    const packet = try allocator.alloc(u8, 4 + payload_len);
    defer allocator.free(packet);
    std.mem.writeInt(u32, packet[0..4], payload_len, .little);
    @memset(packet[4..], 0x42);

    const required = try ctx.requiredC2sScratchCapacity(packet);
    const out_buf = try allocator.alloc(u8, required);
    defer allocator.free(out_buf);

    const out = try ctx.encapsulateC2S(packet, out_buf);
    try std.testing.expect(out.len > payload_len);
    try std.testing.expectEqual(@as(usize, 0), ctx.c2s_len);
    try std.testing.expectEqual(MiddleProxyContext.initial_stream_buffer_size, ctx.c2s_buf.len);
}

test "middle proxy context still enforces configured c2s cap" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.initWithBuffer(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
        64 * 1024,
    );
    defer ctx.deinit();

    const payload_len = 96 * 1024;
    const packet = try allocator.alloc(u8, 4 + payload_len);
    defer allocator.free(packet);
    std.mem.writeInt(u32, packet[0..4], payload_len, .little);
    @memset(packet[4..], 0x42);

    try std.testing.expectError(error.MiddleProxyBufferOverflow, ctx.requiredC2sScratchCapacity(packet));
}

test "middle proxy context grows s2c buffer on demand within configured cap" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;

    var ctx = try MiddleProxyContext.initWithBuffer(
        allocator,
        crypto.AesCbc.init(&key, &iv),
        crypto.AesCbc.init(&key, &iv),
        [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 },
        -2,
        net.Address.initIp4(.{ 10, 20, 30, 40 }, 12345),
        net.Address.initIp4(.{ 91, 105, 192, 110 }, 443),
        .intermediate,
        null,
        128 * 1024,
    );
    defer ctx.deinit();

    try std.testing.expectEqual(MiddleProxyContext.initial_stream_buffer_size, ctx.s2c_buf.len);

    const conn_data_len = 96 * 1024;
    const total_len: usize = 28 + conn_data_len;
    const padded_len = (total_len + 15) & ~@as(usize, 15);
    const plain = try allocator.alloc(u8, padded_len);
    defer allocator.free(plain);
    @memset(plain, 0);

    std.mem.writeInt(u32, plain[0..4], @intCast(total_len), .little);
    std.mem.writeInt(i32, plain[4..8], 0, .little);
    @memcpy(plain[8..12], &rpc_proxy_ans);
    std.mem.writeInt(u32, plain[12..16], 0, .little);
    @memcpy(plain[16..24], &ctx.conn_id);
    @memset(plain[24 .. 24 + conn_data_len], 0x5a);
    const checksum = crc32(plain[0 .. total_len - 4]);
    std.mem.writeInt(u32, plain[total_len - 4 .. total_len], checksum, .little);
    var pad_off = total_len;
    while (pad_off < padded_len) : (pad_off += 4) {
        std.mem.writeInt(u32, plain[pad_off..][0..4], 4, .little);
    }

    var enc = crypto.AesCbc.init(&key, &iv);
    try enc.encryptInPlace(plain);

    const required = try ctx.requiredS2cScratchCapacity(plain);
    const out_buf = try allocator.alloc(u8, required);
    defer allocator.free(out_buf);

    const out = try ctx.decapsulateS2C(plain, out_buf);
    try std.testing.expectEqual(@as(usize, 4 + conn_data_len), out.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.s2c_len);
    try std.testing.expectEqual(@as(usize, 0), ctx.s2c_decrypted_len);
    try std.testing.expectEqual(MiddleProxyContext.initial_stream_buffer_size, ctx.s2c_buf.len);
}

test "middle proxy KDF rejects inputs beyond its fixed buffer" {
    const nonce = [_]u8{0} ** 16;
    const timestamp = [_]u8{0} ** 4;
    const port = [_]u8{0} ** 2;
    const oversized_secret = [_]u8{0} ** 512;

    try std.testing.expectError(error.KdfInputTooLong, getAesKeyAndIv(
        &nonce,
        &nonce,
        &timestamp,
        null,
        &port,
        "CLIENT",
        null,
        &port,
        &oversized_secret,
        null,
        null,
    ));
}
