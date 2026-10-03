//! Client-independent MiddleProxy RPC authentication state.
//!
//! The owner supplies the fd, nonblocking read operation, versioned secret and
//! deadlines. A cold ConnectionSlot and a worker-local warm entry can therefore
//! use the same framing, CBC and sequence-number state machine.
const std = @import("std");
const net = @import("../net_helpers.zig");
const crypto = @import("../crypto/crypto.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const handshake = @import("middle_proxy_handshake.zig");

pub const Step = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,

    pub fn awaitingMiddleProxy(self: Step) bool {
        return switch (self) {
            .sending_rpc_nonce,
            .waiting_rpc_nonce_response,
            .sending_rpc_handshake,
            .waiting_rpc_handshake_response,
            => true,
            .none, .done => false,
        };
    }
};

/// Only the caller that successfully takes this value owns its CBC state.
pub const AuthenticatedState = struct {
    encryptor: crypto.AesCbcEncryptor,
    decryptor: crypto.AesCbcDecryptor,
    write_seq_no: i32,
    read_seq_no: i32,
    peer_addr: net.Address,
    effective_local_addr: net.Address,

    pub fn wipe(self: *AuthenticatedState) void {
        self.encryptor.wipe();
        self.decryptor.wipe();
        self.write_seq_no = 0;
        self.read_seq_no = 0;
    }
};

pub const MiddleProxyTransport = struct {
    step: Step = .none,
    write_seq_no: i32 = -2,
    read_seq_no: i32 = -2,
    nonce: [16]u8 = @splat(0),
    timestamp: u32 = 0,
    server_nonce: [16]u8 = @splat(0),
    enc: ?crypto.AesCbcEncryptor = null,
    dec: ?crypto.AesCbcDecryptor = null,
    peer_addr: ?net.Address = null,
    effective_local_addr: ?net.Address = null,
    frame_buf: ?[]u8 = null,
    frame_have: usize = 0,
    frame_need: usize = 0,
    frame_total_len: usize = 0,
    frame_padded_len: usize = 0,
    frame_first_decrypted: bool = false,

    pub fn begin(
        self: *MiddleProxyTransport,
        output: []u8,
        key_selector: *const [4]u8,
        nonce: *const [16]u8,
        timestamp: u32,
    ) ![]const u8 {
        std.debug.assert(self.step == .none);
        self.nonce = nonce.*;
        self.timestamp = timestamp;
        self.write_seq_no = -2;
        self.read_seq_no = -2;
        self.frame_have = 0;
        self.frame_need = 0;

        var msg: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &msg);
        @memcpy(msg[0..4], &middleproxy.rpc_nonce_req);
        @memcpy(msg[4..8], key_selector);
        @memcpy(msg[8..12], &middleproxy.rpc_crypto_aes);
        std.mem.writeInt(u32, msg[12..16], timestamp, .little);
        @memcpy(msg[16..32], nonce);
        const frame = try handshake.encodeFrame(output, &self.write_seq_no, &msg, null);
        self.step = .sending_rpc_nonce;
        return frame;
    }

    pub fn writeDrained(self: *MiddleProxyTransport) void {
        switch (self.step) {
            .sending_rpc_nonce => {
                self.step = .waiting_rpc_nonce_response;
                self.resetFrame(false);
            },
            .sending_rpc_handshake => {
                self.step = .waiting_rpc_handshake_response;
                self.resetFrame(true);
            },
            else => {},
        }
    }

    pub fn acceptNonceResponse(
        self: *MiddleProxyTransport,
        output: []u8,
        payload: []const u8,
        peer_addr: net.Address,
        local_addr: net.Address,
        nat_ip4: ?[4]u8,
        secret: []const u8,
    ) ![]const u8 {
        try self.validateNonceResponse(payload, secret);

        self.server_nonce = payload[16..32][0..16].*;
        var enc_keys: handshake.KeyIv = undefined;
        var dec_keys: handshake.KeyIv = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&enc_keys));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&dec_keys));
        const effective_local = try handshake.deriveKeys(
            &self.server_nonce,
            &self.nonce,
            self.timestamp,
            peer_addr,
            local_addr,
            nat_ip4,
            secret,
            &enc_keys,
            &dec_keys,
        );
        self.enc = crypto.AesCbcEncryptor.init(&enc_keys[0], &enc_keys[1]);
        self.dec = crypto.AesCbcDecryptor.init(&dec_keys[0], &dec_keys[1]);
        self.peer_addr = peer_addr;
        self.effective_local_addr = effective_local;

        var msg: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &msg);
        @memcpy(msg[0..4], &middleproxy.rpc_handshake);
        @memset(msg[4..8], 0);
        @memcpy(msg[8..20], "IPIPPRPDTIME");
        @memcpy(msg[20..32], "IPIPPRPDTIME");
        const frame = try handshake.encodeFrame(output, &self.write_seq_no, &msg, &self.enc.?);
        self.step = .sending_rpc_handshake;
        return frame;
    }

    /// Validate before querying socket addresses, preserving the cold path's
    /// endpoint-versus-local failure classification when both could fail.
    pub fn validateNonceResponse(self: *const MiddleProxyTransport, payload: []const u8, secret: []const u8) !void {
        if (self.step != .waiting_rpc_nonce_response or payload.len != 32 or secret.len < 4 or
            !std.mem.eql(u8, payload[0..4], &middleproxy.rpc_nonce_req) or
            !std.mem.eql(u8, payload[4..8], secret[0..4]) or
            !std.mem.eql(u8, payload[8..12], &middleproxy.rpc_crypto_aes))
        {
            return error.BadMiddleProxyNonceResponse;
        }
    }

    pub fn acceptHandshakeResponse(self: *MiddleProxyTransport, payload: []const u8) !void {
        if (self.step != .waiting_rpc_handshake_response or payload.len != 32 or
            !std.mem.eql(u8, payload[0..4], &middleproxy.rpc_handshake) or
            !std.mem.eql(u8, payload[20..32], "IPIPPRPDTIME"))
        {
            return error.BadMiddleProxyHandshakeResponse;
        }
        self.step = .done;
    }

    /// Move the post-auth CBC chaining and RPC sequence state exactly once.
    pub fn takeAuthenticatedState(self: *MiddleProxyTransport) !AuthenticatedState {
        if (self.step != .done or self.enc == null or self.dec == null or
            self.peer_addr == null or self.effective_local_addr == null)
        {
            return error.MiddleProxyNotAuthenticated;
        }
        const result = AuthenticatedState{
            .encryptor = self.enc.?,
            .decryptor = self.dec.?,
            .write_seq_no = self.write_seq_no,
            .read_seq_no = self.read_seq_no,
            .peer_addr = self.peer_addr.?,
            .effective_local_addr = self.effective_local_addr.?,
        };
        if (self.enc) |*enc| enc.wipe();
        if (self.dec) |*dec| dec.wipe();
        self.enc = null;
        self.dec = null;
        return result;
    }

    pub fn tryReadFrame(
        self: *MiddleProxyTransport,
        allocator: std.mem.Allocator,
        reader: anytype,
        comptime readFn: anytype,
        encrypted: bool,
    ) !?[]const u8 {
        const frame_buf = try self.ensureFrameBuf(allocator);
        while (true) {
            if (self.frame_need == 0) self.resetFrame(encrypted);
            if (self.frame_have < self.frame_need) {
                const n = readFn(reader, frame_buf[self.frame_have..self.frame_need]) catch |err| {
                    if (err == error.WouldBlock) return null;
                    return err;
                };
                if (n == 0) return error.EndOfStream;
                self.frame_have += n;
                if (self.frame_have < self.frame_need) return null;
            }

            if (!encrypted) {
                if (self.frame_total_len == 0) {
                    self.frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (self.frame_total_len < 12 or self.frame_total_len > frame_buf.len)
                        return error.BadMiddleProxyFrameSize;
                    self.frame_need = self.frame_total_len;
                    continue;
                }
            } else {
                if (!self.frame_first_decrypted) {
                    try self.dec.?.decryptInPlace(frame_buf[0..16]);
                    self.frame_first_decrypted = true;
                    self.frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (self.frame_total_len < 12 or self.frame_total_len > (1 << 24))
                        return error.BadMiddleProxyFrameSize;
                    self.frame_padded_len = std.mem.alignForward(usize, self.frame_total_len, 16);
                    if (self.frame_padded_len > frame_buf.len) return error.BadMiddleProxyFrameSize;
                    self.frame_need = self.frame_padded_len;
                    if (self.frame_have < self.frame_need) return null;
                }
                if (self.frame_padded_len > 16)
                    try self.dec.?.decryptInPlace(frame_buf[16..self.frame_padded_len]);
            }

            const frame = frame_buf[0..self.frame_total_len];
            const seq_no = std.mem.readInt(i32, frame[4..8], .little);
            if (seq_no != self.read_seq_no) return error.BadMiddleProxySeqNo;
            self.read_seq_no +%= 1;
            const checksum = std.mem.readInt(u32, frame[frame.len - 4 ..][0..4], .little);
            if (checksum != middleproxy.crc32(frame[0 .. frame.len - 4]))
                return error.BadMiddleProxyChecksum;

            const payload_len = frame.len - 12;
            @memmove(frame_buf[0..payload_len], frame[8 .. frame.len - 4]);
            self.resetFrame(encrypted);
            return frame_buf[0..payload_len];
        }
    }

    fn ensureFrameBuf(self: *MiddleProxyTransport, allocator: std.mem.Allocator) ![]u8 {
        if (self.frame_buf) |buf| return buf;
        const buf = try allocator.alloc(u8, handshake.frame_buf_size);
        self.frame_buf = buf;
        return buf;
    }

    pub fn resetFrame(self: *MiddleProxyTransport, encrypted: bool) void {
        self.frame_have = 0;
        self.frame_total_len = 0;
        self.frame_padded_len = 0;
        self.frame_first_decrypted = false;
        self.frame_need = if (encrypted) 16 else 4;
    }

    pub fn deinit(self: *MiddleProxyTransport, allocator: std.mem.Allocator) void {
        if (self.frame_buf) |buf| {
            std.crypto.secureZero(u8, buf);
            allocator.free(buf);
        }
        if (self.enc) |*enc| enc.wipe();
        if (self.dec) |*dec| dec.wipe();
        std.crypto.secureZero(u8, &self.nonce);
        std.crypto.secureZero(u8, &self.server_nonce);
        self.* = .{};
    }
};

test "cold transport keeps nonce and authenticated CBC sequence parity" {
    const Reader = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn read(self: *@This(), dest: []u8) !usize {
            if (self.offset == self.bytes.len) return error.WouldBlock;
            const n = @min(dest.len, self.bytes.len - self.offset);
            @memcpy(dest[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }
    };
    const allocator = std.testing.allocator;
    const peer = net.ip4(.{ 149, 154, 167, 40 }, 443);
    const local = net.ip4(.{ 10, 0, 0, 2 }, 34567);
    const nat_ip4: [4]u8 = .{ 203, 0, 113, 7 };
    const nonce: [16]u8 = @splat(0x35);
    const server_nonce: [16]u8 = @splat(0x79);
    const timestamp: u32 = 1_700_000_000;
    var selector: [4]u8 = undefined;
    @memcpy(&selector, middleproxy.proxy_secret[0..4]);

    var transport: MiddleProxyTransport = .{};
    defer transport.deinit(allocator);

    var nonce_wire: [handshake.frame_buf_size]u8 = undefined;
    const nonce_frame = try transport.begin(&nonce_wire, &selector, &nonce, timestamp);
    var nonce_payload: [32]u8 = @splat(0);
    @memcpy(nonce_payload[0..4], &middleproxy.rpc_nonce_req);
    @memcpy(nonce_payload[4..8], &selector);
    @memcpy(nonce_payload[8..12], &middleproxy.rpc_crypto_aes);
    std.mem.writeInt(u32, nonce_payload[12..16], timestamp, .little);
    @memcpy(nonce_payload[16..32], &nonce);
    var expected_nonce_wire: [handshake.frame_buf_size]u8 = undefined;
    var expected_write_seq: i32 = -2;
    const expected_nonce_frame = try handshake.encodeFrame(&expected_nonce_wire, &expected_write_seq, &nonce_payload, null);
    try std.testing.expectEqualSlices(u8, expected_nonce_frame, nonce_frame);
    try std.testing.expectEqual(@as(i32, -1), transport.write_seq_no);

    transport.writeDrained();
    var nonce_answer = nonce_payload;
    @memcpy(nonce_answer[16..32], &server_nonce);
    try transport.validateNonceResponse(&nonce_answer, &middleproxy.proxy_secret);
    nonce_answer[4] ^= 1;
    try std.testing.expectError(error.BadMiddleProxyNonceResponse, transport.validateNonceResponse(&nonce_answer, &middleproxy.proxy_secret));
    nonce_answer[4] ^= 1;
    var nonce_answer_wire: [handshake.frame_buf_size]u8 = undefined;
    var server_seq: i32 = -2;
    const nonce_answer_frame = try handshake.encodeFrame(&nonce_answer_wire, &server_seq, &nonce_answer, null);
    var nonce_reader = Reader{ .bytes = nonce_answer_frame };
    const parsed_nonce = (try transport.tryReadFrame(allocator, &nonce_reader, Reader.read, false)).?;
    try std.testing.expectEqualSlices(u8, &nonce_answer, parsed_nonce);
    try std.testing.expectEqual(@as(i32, -1), transport.read_seq_no);

    var enc_keys: handshake.KeyIv = undefined;
    var dec_keys: handshake.KeyIv = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&enc_keys));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&dec_keys));
    const expected_local = try handshake.deriveKeys(
        &server_nonce,
        &nonce,
        timestamp,
        peer,
        local,
        nat_ip4,
        &middleproxy.proxy_secret,
        &enc_keys,
        &dec_keys,
    );
    var expected_encryptor = crypto.AesCbcEncryptor.init(&enc_keys[0], &enc_keys[1]);
    defer expected_encryptor.wipe();
    var server_encryptor = crypto.AesCbcEncryptor.init(&dec_keys[0], &dec_keys[1]);
    defer server_encryptor.wipe();

    var auth_wire: [handshake.frame_buf_size]u8 = undefined;
    const auth_frame = try transport.acceptNonceResponse(
        &auth_wire,
        parsed_nonce,
        peer,
        local,
        nat_ip4,
        &middleproxy.proxy_secret,
    );
    var auth_payload: [32]u8 = @splat(0);
    @memcpy(auth_payload[0..4], &middleproxy.rpc_handshake);
    @memcpy(auth_payload[8..20], "IPIPPRPDTIME");
    @memcpy(auth_payload[20..32], "IPIPPRPDTIME");
    var expected_auth_wire: [handshake.frame_buf_size]u8 = undefined;
    const expected_auth_frame = try handshake.encodeFrame(&expected_auth_wire, &expected_write_seq, &auth_payload, &expected_encryptor);
    try std.testing.expectEqualSlices(u8, expected_auth_frame, auth_frame);
    try std.testing.expectEqual(@as(i32, 0), transport.write_seq_no);

    transport.writeDrained();
    var auth_answer = auth_payload;
    @memset(auth_answer[8..20], 0x44);
    var answer_wire: [handshake.frame_buf_size]u8 = undefined;
    const answer_frame = try handshake.encodeFrame(&answer_wire, &server_seq, &auth_answer, &server_encryptor);
    var reader = Reader{ .bytes = answer_frame };
    var parsed_opt: ?[]const u8 = null;
    while (parsed_opt == null and reader.offset < reader.bytes.len) {
        parsed_opt = try transport.tryReadFrame(allocator, &reader, Reader.read, true);
    }
    const parsed = parsed_opt orelse return error.IncompleteMiddleProxyTestFrame;
    try std.testing.expectEqualSlices(u8, &auth_answer, parsed);
    try transport.acceptHandshakeResponse(parsed);
    var authenticated = try transport.takeAuthenticatedState();
    defer authenticated.wipe();
    try std.testing.expectError(error.MiddleProxyNotAuthenticated, transport.takeAuthenticatedState());
    try std.testing.expectEqual(@as(i32, 0), authenticated.write_seq_no);
    try std.testing.expectEqual(@as(i32, 0), authenticated.read_seq_no);
    try std.testing.expect(net.exactAddressEql(expected_local, authenticated.effective_local_addr));

    var next_wire: [handshake.frame_buf_size]u8 = undefined;
    var expected_next_wire: [handshake.frame_buf_size]u8 = undefined;
    const actual_next = try handshake.encodeFrame(&next_wire, &authenticated.write_seq_no, "client request!!", &authenticated.encryptor);
    const expected_next = try handshake.encodeFrame(&expected_next_wire, &expected_write_seq, "client request!!", &expected_encryptor);
    try std.testing.expectEqualSlices(u8, expected_next, actual_next);

    var second_answer_wire: [handshake.frame_buf_size]u8 = undefined;
    const second_answer = try handshake.encodeFrame(&second_answer_wire, &server_seq, "server response!", &server_encryptor);
    try authenticated.decryptor.decryptInPlace(second_answer_wire[0..second_answer.len]);
    try std.testing.expectEqual(@as(i32, 0), std.mem.readInt(i32, second_answer_wire[4..8], .little));
    try std.testing.expectEqualSlices(u8, "server response!", second_answer_wire[8..24]);
}
