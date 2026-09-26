const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_helpers.zig");
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const MessageQueue = @import("message_queue.zig").MessageQueue;
const WedgeTracker = @import("wedge_recovery.zig").WedgeTracker;

pub const tls_header_len = 5;
pub const event_io_byte_budget: usize = 256 * 1024;
pub const event_io_operation_budget: usize = 64;
const client_hello_inline_size: usize = 512;
const upstream_candidates_inline_cap: usize = 4;
pub const no_timer_heap_index = std.math.maxInt(u32);
pub const invalid_fd: posix.fd_t = switch (builtin.os.tag) {
    .windows => std.os.windows.INVALID_HANDLE_VALUE,
    else => -1,
};

pub const UpstreamKind = enum {
    none,
    dc,
    mask,
};

pub const ClientTransport = enum {
    fake_tls,
    direct_obfuscated,
};

pub const MaskCause = enum {
    none,
    non_tls,
    invalid_tls_length,
    missing_sni,
    malformed_client_hello,
    sni_mismatch,
    web_carrier,
    web_only,
    invalid_session_id,
    secret_mismatch,
    timestamp_skew,
    replay,
    validation_error,
};

pub const ConnectionPhase = enum {
    idle,
    reading_web_prefix,
    reading_tls_header,
    reading_direct_obfuscated_handshake,
    reading_client_hello_body,
    writing_server_hello_first,
    desync_wait,
    writing_server_hello_rest,
    reading_mtproto_tls_header,
    reading_mtproto_tls_body,
    connecting_upstream,
    writing_dc_nonce,
    middle_proxy_handshake,
    relaying,
    mask_relaying,
    closing,
};

pub const MiddleProxyHandshakeStep = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,

    pub fn awaitingMiddleProxy(self: MiddleProxyHandshakeStep) bool {
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

pub const DynamicRecordSizer = struct {
    current_size: usize,
    records_sent: u32,
    bytes_sent: u64,
    enabled: bool,

    const initial_size: usize = 1369;
    pub const full_size: usize = constants.max_tls_plaintext_size;
    const ramp_record_threshold: u32 = 8;
    const ramp_byte_threshold: u64 = 128 * 1024;

    pub fn init(enabled: bool) DynamicRecordSizer {
        return .{
            .current_size = if (enabled) initial_size else full_size,
            .records_sent = 0,
            .bytes_sent = 0,
            .enabled = enabled,
        };
    }

    pub fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    pub fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        if (!self.enabled or self.current_size == full_size) return;
        self.records_sent +|= 1;
        self.bytes_sent +|= @as(u64, @intCast(payload_len));
        if (self.current_size == initial_size and
            (self.records_sent >= ramp_record_threshold or self.bytes_sent >= ramp_byte_threshold))
        {
            self.current_size = full_size;
        }
    }
};

pub const EventIoBudget = struct {
    bytes_remaining: usize = event_io_byte_budget,
    operations_remaining: usize = event_io_operation_budget,

    pub fn exhausted(self: *const EventIoBudget) bool {
        return self.bytes_remaining == 0 or self.operations_remaining == 0;
    }

    pub fn allowedBytes(self: *const EventIoBudget, requested: usize) usize {
        if (self.operations_remaining == 0) return 0;
        return @min(requested, self.bytes_remaining);
    }

    pub fn beginOperation(self: *EventIoBudget) bool {
        if (self.exhausted()) return false;
        self.operations_remaining -= 1;
        return true;
    }

    pub fn recordBytes(self: *EventIoBudget, count: usize) void {
        self.bytes_remaining -= @min(count, self.bytes_remaining);
    }
};

pub const ConnectionSlot = struct {
    index: u32 = 0,
    event_generation: u32 = 0,
    client_event_generation: u32 = 0,
    upstream_event_generation: u32 = 0,
    timer_heap_index: u32 = no_timer_heap_index,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = invalid_fd,
    upstream_fd: posix.fd_t = invalid_fd,
    upstream_kind: UpstreamKind = .none,
    peer_addr: net.Address = undefined,
    /// Fixed from the kernel-reported address at accept time. A PROXY header may
    /// replace `peer_addr`, but can never grant relay trust.
    trusted_peer: bool = false,
    client_transport: ClientTransport = .fake_tls,

    phase: ConnectionPhase = .idle,
    active_reserved: bool = false,
    /// Set after the first client byte reserves a handshake-budget slot.
    /// Silent pre-warmed TCP sessions deliberately do not consume this budget.
    hs_counted: bool = false,
    subnet_key: u64 = 0,
    subnet_hs_counted: bool = false,

    created_at_ms: i64 = 0,
    /// Set when the upstream handshake completes and bidirectional relay starts.
    relay_started_at_ms: i64 = 0,
    first_byte_at_ms: i64 = 0,
    /// Timestamp for the current upstream connect attempt. Reset per candidate.
    upstream_connect_started_ms: i64 = 0,
    /// Fixed deadline for the current upstream connect attempt.
    upstream_connect_deadline_ms: i64 = 0,
    last_activity_ms: i64 = 0,
    idle_timeout_ms: i64 = 0,
    /// Non-secret hash of full real client IP plus access user. Source ports
    /// are deliberately excluded so reconnects share one recovery budget.
    wedge_client_key: u64 = 0,
    /// Advances only when client payload actually produces upstream bytes;
    /// MiddleProxy input fragments that remain buffered do not start a timer.
    wedge_forwarded_c2s_seq: u64 = 0,
    wedge: WedgeTracker = .{},
    desync_deadline_ns: i128 = 0,

    // Initial TLS handshake reassembly
    tls_hdr_buf: [tls_header_len]u8 = undefined,
    tls_hdr_pos: u8 = 0,
    tls_body_len: u16 = 0,
    tls_body_pos: u16 = 0,
    tls_record_type: u8 = 0,

    // Optional binary PROXY-v2 prefix from the trusted WEB relay.
    web_prefix_buf: [256]u8 = undefined,
    web_prefix_pos: u16 = 0,

    client_hello_inline: [client_hello_inline_size]u8 = undefined,
    client_hello_heap: ?[]u8 = null,
    client_hello_len: usize = 0,

    validation_secret: [16]u8 = [_]u8{0} ** 16,
    validation_digest: [32]u8 = [_]u8{0} ** 32,
    validation_session_id: [32]u8 = [_]u8{0} ** 32,
    validation_session_id_len: u8 = 0,
    validation_user: [32]u8 = [_]u8{0} ** 32,
    validation_user_len: u8 = 0,
    validation_force_direct: bool = false,

    server_hello: ?[]u8 = null,
    server_hello_off: usize = 0,

    // 64-byte MTProto handshake assembly from TLS appdata records
    handshake_buf: [constants.handshake_len]u8 = undefined,
    handshake_pos: u8 = 0,
    pipelined_data: ?[]u8 = null,
    pipelined_len: usize = 0,

    // Obfuscation / relay crypto state
    obf_params: ?obfuscation.ObfuscationParams = null,
    client_encryptor: ?crypto.AesCtr = null,
    client_decryptor: ?crypto.AesCtr = null,
    tg_encryptor: ?crypto.AesCtr = null,
    tg_decryptor: ?crypto.AesCtr = null,
    middle_ctx: ?middleproxy.MiddleProxyContext = null,

    dc_idx: i16 = 0,
    dc_abs: u16 = 0,
    proto_tag: constants.ProtoTag = .intermediate,
    use_fast_mode: bool = false,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,

    upstream_candidates_inline: [upstream_candidates_inline_cap]net.Address = undefined,
    upstream_candidates_heap: ?[]net.Address = null,
    upstream_candidate_count: usize = 0,
    upstream_candidate_next: u8 = 0,
    direct_fallback_addr: ?net.Address = null,
    direct_fallback_used: bool = false,
    current_upstream_addr: ?net.Address = null,

    // Pending initial bytes for direct DC path (promotion tag)
    dc_initial_tail: ?[]u8 = null,

    // Relay parsing state (C2S TLS records)
    relay_tls_hdr: [tls_header_len]u8 = undefined,
    relay_tls_hdr_pos: u8 = 0,
    relay_tls_body_len: u16 = 0,
    relay_tls_body_pos: u16 = 0,
    relay_record_type: u8 = 0,

    drs: DynamicRecordSizer = DynamicRecordSizer{
        .current_size = DynamicRecordSizer.full_size,
        .records_sent = 0,
        .bytes_sent = 0,
        .enabled = false,
    },
    c2s_bytes: u64 = 0,
    s2c_bytes: u64 = 0,

    // Non-blocking write queues (intrusive page-backed chains)
    client_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },
    upstream_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },

    // Masking: bytes already read from client before deciding to mask
    mask_prebuffer: ?[]u8 = null,
    mask_c2s_bytes: u64 = 0,
    mask_s2c_bytes: u64 = 0,
    mask_cause: MaskCause = .none,
    /// Server time minus authenticated client time for timestamp-skew masking.
    mask_timestamp_skew_s: ?i64 = null,
    mask_send_proxy_header: bool = false,
    /// Long-lived HTTPS/WebSocket carrier for the configured WEB domain. Unlike
    /// probe-cover relays it must not be cut off by mask_relay_max_secs.
    web_carrier: bool = false,

    // Non-blocking MiddleProxy handshake state
    mp_step: MiddleProxyHandshakeStep = .none,
    mp_write_seq_no: i32 = -2,
    mp_read_seq_no: i32 = -2,
    mp_nonce: [16]u8 = [_]u8{0} ** 16,
    mp_timestamp: u32 = 0,
    mp_rpc_nonce_ans: [16]u8 = [_]u8{0} ** 16,
    mp_enc: ?crypto.AesCbcEncryptor = null,
    mp_dec: ?crypto.AesCbcDecryptor = null,
    mp_frame_buf: ?[]u8 = null,
    mp_frame_have: usize = 0,
    mp_frame_need: usize = 0,
    mp_frame_total_len: usize = 0,
    mp_frame_padded_len: usize = 0,
    mp_frame_encrypted: bool = false,
    mp_frame_first_decrypted: bool = false,
    mp_step_deadline_ms: i64 = 0,
    mp_secret_version: u64 = 0,
    mp_nat_ip4: ?[4]u8 = null,

    // Current epoll interests
    client_interest_in: bool = false,
    client_interest_out: bool = false,
    client_interest_rdhup: bool = false,
    upstream_interest_in: bool = false,
    upstream_interest_out: bool = false,
    upstream_interest_rdhup: bool = false,
    client_registered: bool = false,
    upstream_registered: bool = false,
    event_io_budget: ?*EventIoBudget = null,
    client_read_closed: bool = false,
    upstream_read_closed: bool = false,
    client_write_shutdown: bool = false,
    upstream_write_shutdown: bool = false,

    pub fn hasClientPending(self: *const ConnectionSlot) bool {
        return !self.client_queue.isEmpty();
    }

    pub fn hasUpstreamPending(self: *const ConnectionSlot) bool {
        return !self.upstream_queue.isEmpty();
    }

    pub fn handshakeInProgress(self: *const ConnectionSlot) bool {
        return switch (self.phase) {
            .reading_web_prefix,
            .reading_tls_header,
            .reading_direct_obfuscated_handshake,
            .reading_client_hello_body,
            .writing_server_hello_first,
            .desync_wait,
            .writing_server_hello_rest,
            .reading_mtproto_tls_header,
            .reading_mtproto_tls_body,
            .connecting_upstream,
            .writing_dc_nonce,
            .middle_proxy_handshake,
            => true,
            else => false,
        };
    }

    pub fn resetOwnedBuffers(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        const client_block_pool = self.client_queue.pool;
        const upstream_block_pool = self.upstream_queue.pool;
        self.client_queue.deinit();
        self.upstream_queue.deinit();
        self.client_queue = .{ .allocator = allocator, .pool = client_block_pool };
        self.upstream_queue = .{ .allocator = allocator, .pool = upstream_block_pool };

        self.releaseClientHello(allocator);

        if (self.server_hello) |buf| secureFree(allocator, buf);
        self.server_hello = null;

        if (self.pipelined_data) |buf| secureFree(allocator, buf);
        self.pipelined_data = null;
        self.pipelined_len = 0;

        if (self.mask_prebuffer) |buf| secureFree(allocator, buf);
        self.mask_prebuffer = null;

        if (self.dc_initial_tail) |buf| secureFree(allocator, buf);
        self.dc_initial_tail = null;

        if (self.middle_ctx) |*mp| mp.deinit();
        self.middle_ctx = null;

        self.clearUpstreamCandidates(allocator);
        self.direct_fallback_addr = null;
        self.direct_fallback_used = false;
        self.current_upstream_addr = null;
        self.upstream_connect_started_ms = 0;
        self.upstream_connect_deadline_ms = 0;
        self.dc_abs = 0;
        self.is_media_path = false;

        if (self.mp_frame_buf) |buf| secureFree(allocator, buf);
        self.mp_frame_buf = null;

        if (self.obf_params) |*params| params.wipe();
        self.obf_params = null;

        if (self.client_encryptor) |*c| c.wipe();
        if (self.client_decryptor) |*c| c.wipe();
        if (self.tg_encryptor) |*c| c.wipe();
        if (self.tg_decryptor) |*c| c.wipe();
        if (self.mp_enc) |*c| c.wipe();
        if (self.mp_dec) |*c| c.wipe();

        self.client_encryptor = null;
        self.client_decryptor = null;
        self.tg_encryptor = null;
        self.tg_decryptor = null;
        self.mp_enc = null;
        self.mp_dec = null;
        std.crypto.secureZero(u8, &self.validation_secret);
        std.crypto.secureZero(u8, &self.validation_digest);
        std.crypto.secureZero(u8, &self.validation_session_id);
        std.crypto.secureZero(u8, &self.validation_user);
        std.crypto.secureZero(u8, &self.handshake_buf);
        std.crypto.secureZero(u8, &self.mp_nonce);
        std.crypto.secureZero(u8, &self.mp_rpc_nonce_ans);
        self.validation_session_id_len = 0;
        self.validation_user_len = 0;
        self.validation_force_direct = false;
        self.handshake_pos = 0;
        self.mp_timestamp = 0;
        self.mp_secret_version = 0;
        self.mp_nat_ip4 = null;
    }

    pub fn releaseClientHello(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        if (self.client_hello_heap) |buf| {
            secureFree(allocator, buf);
            self.client_hello_heap = null;
        } else if (self.client_hello_len > 0) {
            std.crypto.secureZero(u8, self.client_hello_inline[0..self.client_hello_len]);
        }
        self.client_hello_len = 0;
    }

    pub fn clientHelloBuf(self: *ConnectionSlot) []u8 {
        if (self.client_hello_heap) |buf| return buf;
        return self.client_hello_inline[0..self.client_hello_len];
    }

    pub fn releaseHandshakeOnly(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        self.releaseClientHello(allocator);
        if (self.server_hello) |buf| secureFree(allocator, buf);
        self.server_hello = null;

        self.clearUpstreamCandidates(allocator);

        if (self.mp_frame_buf) |buf| secureFree(allocator, buf);
        self.mp_frame_buf = null;
        self.mp_frame_have = 0;
        self.mp_frame_need = 0;
        self.mp_frame_total_len = 0;
        self.mp_frame_padded_len = 0;

        if (self.obf_params) |*params| params.wipe();
        self.obf_params = null;
        if (self.mp_enc) |*enc| enc.wipe();
        if (self.mp_dec) |*dec| dec.wipe();
        self.mp_enc = null;
        self.mp_dec = null;

        std.crypto.secureZero(u8, &self.validation_secret);
        std.crypto.secureZero(u8, &self.validation_digest);
        std.crypto.secureZero(u8, &self.validation_session_id);
        std.crypto.secureZero(u8, &self.validation_user);
        std.crypto.secureZero(u8, &self.handshake_buf);
        std.crypto.secureZero(u8, &self.mp_nonce);
        std.crypto.secureZero(u8, &self.mp_rpc_nonce_ans);
        self.validation_session_id_len = 0;
        self.validation_user_len = 0;
        self.validation_force_direct = false;
        self.handshake_pos = 0;
        self.mp_secret_version = 0;
        self.mp_nat_ip4 = null;
    }

    pub fn upstreamCandidates(self: *const ConnectionSlot) []const net.Address {
        if (self.upstream_candidate_count == 0) return &.{};
        if (self.upstream_candidates_heap) |candidates| {
            std.debug.assert(candidates.len == self.upstream_candidate_count);
            return candidates;
        }
        std.debug.assert(self.upstream_candidate_count <= self.upstream_candidates_inline.len);
        return self.upstream_candidates_inline[0..self.upstream_candidate_count];
    }

    pub fn clearUpstreamCandidates(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        if (self.upstream_candidates_heap) |candidates| allocator.free(candidates);
        self.upstream_candidates_heap = null;
        self.upstream_candidate_count = 0;
        self.upstream_candidate_next = 0;
    }

    pub fn setUpstreamCandidates(
        self: *ConnectionSlot,
        allocator: std.mem.Allocator,
        candidates: []const net.Address,
    ) !void {
        if (candidates.len <= self.upstream_candidates_inline.len) {
            var inline_copy: [upstream_candidates_inline_cap]net.Address = undefined;
            @memcpy(inline_copy[0..candidates.len], candidates);

            if (self.upstream_candidates_heap) |old| allocator.free(old);
            self.upstream_candidates_heap = null;
            @memcpy(self.upstream_candidates_inline[0..candidates.len], inline_copy[0..candidates.len]);
            self.upstream_candidate_count = candidates.len;
            self.upstream_candidate_next = 0;
            return;
        }

        const owned = try allocator.dupe(net.Address, candidates);
        if (self.upstream_candidates_heap) |old| allocator.free(old);
        self.upstream_candidates_heap = owned;
        self.upstream_candidate_count = owned.len;
        self.upstream_candidate_next = 0;
    }
};

/// Minimal production-path adapter used by the standalone handshake benchmark.
/// Keeping candidate staging here makes the benchmark exercise the same
/// inline/heap transition as a real connection without exposing ConnectionSlot.
pub const BenchCandidatePath = struct {
    slot: ConnectionSlot = .{},

    pub fn deinit(self: *BenchCandidatePath, allocator: std.mem.Allocator) void {
        self.slot.clearUpstreamCandidates(allocator);
    }

    pub fn apply(
        self: *BenchCandidatePath,
        allocator: std.mem.Allocator,
        candidates: []const net.Address,
    ) !usize {
        if (candidates.len == 0) return error.BenchEmptyCandidates;

        try self.slot.setUpstreamCandidates(allocator, candidates);
        const prepared = self.slot.upstreamCandidates();
        self.slot.upstream_candidate_next = 1;
        self.slot.current_upstream_addr = prepared[0];
        return prepared.len;
    }
};

pub fn secureFree(allocator: std.mem.Allocator, buf: []u8) void {
    std.crypto.secureZero(u8, buf);
    allocator.free(buf);
}

comptime {
    // Every worker can retain one slot per accepted connection. Leave ABI
    // headroom, but reject a large accidental inline-buffer expansion.
    if (@sizeOf(ConnectionSlot) > 6144) @compileError("ConnectionSlot exceeded its per-connection size budget");
}

test "MiddleProxyHandshakeStep.awaitingMiddleProxy gates reactive refresh" {
    try std.testing.expect(!MiddleProxyHandshakeStep.none.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_nonce.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_nonce_response.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_handshake.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_handshake_response.awaitingMiddleProxy());
    try std.testing.expect(!MiddleProxyHandshakeStep.done.awaitingMiddleProxy());
}

test "connection slot stores common candidate sets inline" {
    var slot = ConnectionSlot{};
    defer slot.clearUpstreamCandidates(std.testing.allocator);

    var candidates: [5]net.Address = undefined;
    for (&candidates, 0..) |*candidate, index| {
        candidate.* = net.ip4(.{ 192, 0, 2, @intCast(index + 1) }, @intCast(443 + index));
    }

    try slot.setUpstreamCandidates(std.testing.allocator, candidates[0..1]);
    try std.testing.expect(slot.upstream_candidates_heap == null);
    try std.testing.expectEqual(@as(usize, 1), slot.upstreamCandidates().len);
    try std.testing.expect(net.exactAddressEql(slot.upstreamCandidates()[0], candidates[0]));

    try slot.setUpstreamCandidates(std.testing.allocator, candidates[0..4]);
    try std.testing.expect(slot.upstream_candidates_heap == null);
    try std.testing.expectEqual(@as(usize, 4), slot.upstreamCandidates().len);
    for (slot.upstreamCandidates(), candidates[0..4]) |actual, expected| {
        try std.testing.expect(net.exactAddressEql(actual, expected));
    }

    try slot.setUpstreamCandidates(std.testing.allocator, &candidates);
    try std.testing.expect(slot.upstream_candidates_heap != null);
    try std.testing.expectEqual(@as(usize, 5), slot.upstreamCandidates().len);
    for (slot.upstreamCandidates(), candidates) |actual, expected| {
        try std.testing.expect(net.exactAddressEql(actual, expected));
    }

    try slot.setUpstreamCandidates(std.testing.allocator, candidates[0..1]);
    try std.testing.expect(slot.upstream_candidates_heap == null);
    try std.testing.expectEqual(@as(usize, 1), slot.upstreamCandidates().len);

    try slot.setUpstreamCandidates(std.testing.allocator, &.{});
    try std.testing.expectEqual(@as(usize, 0), slot.upstreamCandidates().len);
}

test "DRS disabled skips ramp and uses full TLS record size" {
    var drs = DynamicRecordSizer.init(false);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
    for (0..32) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "DRS enabled ramps" {
    var drs = DynamicRecordSizer.init(true);
    for (0..8) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
    const records_at_ramp = drs.records_sent;
    const bytes_at_ramp = drs.bytes_sent;
    drs.recordSent(std.math.maxInt(usize));
    try std.testing.expectEqual(records_at_ramp, drs.records_sent);
    try std.testing.expectEqual(bytes_at_ramp, drs.bytes_sent);
}

test "handshakeInProgress - phases" {
    var slot: ConnectionSlot = undefined;

    const hs_phases = [_]ConnectionPhase{
        .reading_web_prefix,
        .reading_tls_header,
        .reading_direct_obfuscated_handshake,
        .reading_client_hello_body,
        .writing_server_hello_first,
        .desync_wait,
        .writing_server_hello_rest,
        .reading_mtproto_tls_header,
        .reading_mtproto_tls_body,
        .connecting_upstream,
        .writing_dc_nonce,
        .middle_proxy_handshake,
    };
    for (hs_phases) |phase| {
        slot.phase = phase;
        try std.testing.expect(slot.handshakeInProgress());
    }

    // Non-handshake phases
    slot.phase = .idle;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .mask_relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .closing;
    try std.testing.expect(!slot.handshakeInProgress());
}
