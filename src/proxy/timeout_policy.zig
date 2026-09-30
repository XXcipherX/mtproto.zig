const std = @import("std");
const ConnectionSlot = @import("connection.zig").ConnectionSlot;
const MiddleProxyHandshakeStep = @import("connection.zig").MiddleProxyHandshakeStep;

pub fn secondsToMs(sec: u32) i64 {
    return @as(i64, @intCast(sec)) * std.time.ms_per_s;
}

pub fn budgetedConnectTimeoutMs(
    configured_timeout_ms: i64,
    first_byte_at_ms: i64,
    handshake_timeout_ms: i64,
    started_at_ms: i64,
    candidate_count: usize,
) i64 {
    if (first_byte_at_ms <= 0) return configured_timeout_ms;

    const handshake_deadline_ms = first_byte_at_ms + handshake_timeout_ms;
    const remaining_handshake_ms = @max(@as(i64, 1), handshake_deadline_ms - started_at_ms);
    const attempts = @max(@as(usize, 1), candidate_count);
    const fair_share_ms = @max(
        @as(i64, 1),
        @divTrunc(remaining_handshake_ms, @as(i64, @intCast(attempts))),
    );
    if (configured_timeout_ms <= 0) return fair_share_ms;
    return @min(configured_timeout_ms, fair_share_ms);
}

pub fn budgetedMiddleProxyStageTimeoutMs(
    configured_stage_timeout_ms: i64,
    first_byte_at_ms: i64,
    handshake_timeout_ms: i64,
    started_at_ms: i64,
    reserve_direct_fallback: bool,
) i64 {
    if (!reserve_direct_fallback or first_byte_at_ms <= 0) return configured_stage_timeout_ms;

    const handshake_deadline_ms = first_byte_at_ms + handshake_timeout_ms;
    const remaining_handshake_ms = @max(@as(i64, 1), handshake_deadline_ms - started_at_ms);
    const stage_share_ms = @max(@as(i64, 1), @divTrunc(remaining_handshake_ms, 2));
    return @min(configured_stage_timeout_ms, stage_share_ms);
}

pub fn upstreamConnectDeadlineMs(
    slot: *const ConnectionSlot,
    configured_timeout_ms: i64,
    handshake_timeout_ms: i64,
    started_at_ms: i64,
) i64 {
    const candidates = slot.upstreamCandidates();
    var candidate_count = if (candidates.len > 0) blk: {
        const next_index = @min(@as(usize, @intCast(slot.upstream_candidate_next)), candidates.len);
        break :blk candidates.len - next_index + 1;
    } else 1;
    if (slot.use_middle_proxy and !slot.direct_fallback_used and slot.direct_fallback_addr != null) {
        candidate_count += 1;
    }
    const attempt_timeout_ms = budgetedConnectTimeoutMs(
        configured_timeout_ms,
        slot.first_byte_at_ms,
        handshake_timeout_ms,
        started_at_ms,
        candidate_count,
    );
    if (attempt_timeout_ms <= 0) return 0;
    return started_at_ms + attempt_timeout_ms;
}

pub fn middleProxyStepDeadlineMs(
    slot: *const ConnectionSlot,
    step: MiddleProxyHandshakeStep,
    handshake_timeout_ms: i64,
    stage_timeout_ms: i64,
    now_ms: i64,
) i64 {
    if (step == .none or step == .done) return 0;
    const configured_stage_ms = @min(handshake_timeout_ms, stage_timeout_ms);
    const reserve_direct_fallback = slot.use_middle_proxy and
        !slot.direct_fallback_used and
        slot.direct_fallback_addr != null;
    const budget_ms = budgetedMiddleProxyStageTimeoutMs(
        configured_stage_ms,
        slot.first_byte_at_ms,
        handshake_timeout_ms,
        now_ms,
        reserve_direct_fallback,
    );
    return now_ms + budget_ms;
}

pub const SlotDeadlineInputs = struct {
    handshake_timeout_sec: u32,
    mask_relay_max_secs: u32,
    pre_first_byte_timeout_ms: i64,
    wedge_eligible: bool,
};

pub fn earlierDeadline(current: ?i128, candidate: i128) i128 {
    return if (current) |deadline| @min(deadline, candidate) else candidate;
}

fn deadlineMsToNs(deadline_ms: i64) i128 {
    return @as(i128, deadline_ms) * std.time.ns_per_ms;
}

pub const SlotDeadline = struct {
    deadline_ns: i128,
    kind: enum { absolute, relay_idle },
};

/// Classify the selected minimum, not merely the connection phase. Absolute
/// deadlines win ties so idle extension cannot defer a mandatory stage/wedge.
pub fn nextSlotDeadline(slot: *const ConnectionSlot, inputs: SlotDeadlineInputs) ?SlotDeadline {
    if (slot.phase == .idle) return null;
    if (slot.phase == .closing) return .{ .deadline_ns = 1, .kind = .absolute };

    var deadline: ?i128 = null;
    if (slot.phase == .desync_wait) {
        deadline = earlierDeadline(deadline, slot.desync_deadline_ns);
    }
    if (slot.phase == .connecting_upstream and slot.upstream_connect_deadline_ms > 0) {
        deadline = earlierDeadline(deadline, deadlineMsToNs(slot.upstream_connect_deadline_ms));
    }
    if (slot.phase == .middle_proxy_handshake and slot.mp_step_deadline_ms > 0) {
        deadline = earlierDeadline(deadline, deadlineMsToNs(slot.mp_step_deadline_ms));
    }

    if (slot.handshakeInProgress()) {
        const handshake_deadline_ms = if (slot.first_byte_at_ms == 0)
            slot.created_at_ms + @min(slot.idle_timeout_ms, inputs.pre_first_byte_timeout_ms)
        else
            slot.first_byte_at_ms + secondsToMs(inputs.handshake_timeout_sec);
        deadline = earlierDeadline(deadline, deadlineMsToNs(handshake_deadline_ms));
    } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
        if (slot.phase == .mask_relaying and !slot.web_carrier and inputs.mask_relay_max_secs > 0) {
            deadline = earlierDeadline(
                deadline,
                deadlineMsToNs(slot.created_at_ms + secondsToMs(inputs.mask_relay_max_secs)),
            );
        }
        if (inputs.wedge_eligible and !slot.hasClientPending()) {
            if (slot.wedge.nextDeadlineMs()) |wedge_deadline_ms| {
                deadline = earlierDeadline(deadline, deadlineMsToNs(wedge_deadline_ms));
            }
        }
        const idle_deadline = deadlineMsToNs(slot.last_activity_ms + slot.idle_timeout_ms);
        if (deadline == null or idle_deadline < deadline.?) {
            return .{ .deadline_ns = idle_deadline, .kind = .relay_idle };
        }
    }
    return if (deadline) |value| .{ .deadline_ns = value, .kind = .absolute } else null;
}

pub fn nextSlotDeadlineNs(slot: *const ConnectionSlot, inputs: SlotDeadlineInputs) ?i128 {
    return if (nextSlotDeadline(slot, inputs)) |deadline| deadline.deadline_ns else null;
}

pub fn idleTimeoutSeed(slot: *const ConnectionSlot) u64 {
    const created: u64 = if (slot.created_at_ms > 0) @intCast(slot.created_at_ms) else 0;
    var x = slot.conn_id ^ (created *% 0x9E37_79B9_7F4A_7C15);
    x +%= 0x9E37_79B9_7F4A_7C15;
    var z = x;
    z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
    z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
    return z ^ (z >> 31);
}

pub fn jitteredIdleTimeoutMs(base_sec: u32, jitter_pct: u8, seed: u64) i64 {
    const base_ms = secondsToMs(base_sec);
    if (jitter_pct == 0) return base_ms;

    const pct: i64 = @intCast(@min(@as(u8, 100), jitter_pct));
    const range = @divTrunc(base_ms * pct, 100);
    if (range <= 0) return base_ms;

    const span: u64 = @intCast(2 * range + 1);
    const offset = @as(i64, @intCast(seed % span)) - range;
    const floor_ms = @max(secondsToMs(5), @divTrunc(base_ms, 2));
    return @max(floor_ms, base_ms + offset);
}

test "jittered idle timeout keeps zero jitter exact" {
    try std.testing.expectEqual(secondsToMs(120), jitteredIdleTimeoutMs(120, 0, 12345));
}

test "connect timeout shares handshake budget across candidates" {
    try std.testing.expectEqual(
        @as(i64, 7000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 2_000, 2),
    );
    try std.testing.expectEqual(
        @as(i64, 10_000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 2_000, 1),
    );
    try std.testing.expectEqual(
        @as(i64, 7000),
        budgetedConnectTimeoutMs(0, 1_000, 15_000, 2_000, 2),
    );
    try std.testing.expectEqual(
        @as(i64, 5000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 11_000, 1),
    );
}

test "middle proxy stage reserves remaining handshake budget for direct fallback" {
    try std.testing.expectEqual(
        @as(i64, 1000),
        budgetedMiddleProxyStageTimeoutMs(5_000, 1_000, 5_000, 4_000, true),
    );
    try std.testing.expectEqual(
        @as(i64, 5_000),
        budgetedMiddleProxyStageTimeoutMs(5_000, 1_000, 5_000, 4_000, false),
    );
}

test "slot deadline policy preserves pre-first-byte, handshake and WEB carrier exemptions" {
    var slot: ConnectionSlot = .{};
    const inputs: SlotDeadlineInputs = .{
        .handshake_timeout_sec = 15,
        .mask_relay_max_secs = 60,
        .pre_first_byte_timeout_ms = 10_000,
        .wedge_eligible = false,
    };

    try std.testing.expectEqual(@as(?i128, null), nextSlotDeadlineNs(&slot, inputs));
    slot.phase = .reading_tls_header;
    slot.created_at_ms = 1000;
    slot.idle_timeout_ms = 120_000;
    try std.testing.expectEqual(@as(?i128, 11_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));

    slot.first_byte_at_ms = 2000;
    try std.testing.expectEqual(@as(?i128, 17_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));

    slot.phase = .mask_relaying;
    slot.last_activity_ms = 5000;
    try std.testing.expectEqual(@as(?i128, 61_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));
    slot.web_carrier = true;
    try std.testing.expectEqual(@as(?i128, 125_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));
}

test "connect and MiddleProxy step deadline keep candidate and fallback shares" {
    var slot: ConnectionSlot = .{};
    slot.first_byte_at_ms = 1000;
    slot.use_middle_proxy = true;
    slot.direct_fallback_addr = @import("../net_helpers.zig").ip4(.{ 149, 154, 167, 40 }, 443);
    try std.testing.expectEqual(@as(i64, 9000), upstreamConnectDeadlineMs(&slot, 10_000, 15_000, 2000));
    try std.testing.expectEqual(@as(i64, 15_000), middleProxyStepDeadlineMs(&slot, .sending_rpc_nonce, 15_000, 5000, 14_000));
    try std.testing.expectEqual(@as(i64, 0), middleProxyStepDeadlineMs(&slot, .done, 15_000, 5000, 6000));
}

test "only a selected sliding relay idle deadline permits lazy extension" {
    var slot = ConnectionSlot{
        .created_at_ms = 1000,
        .first_byte_at_ms = 2000,
        .last_activity_ms = 3000,
        .idle_timeout_ms = 10_000,
        .desync_deadline_ns = 5000 * std.time.ns_per_ms,
        .upstream_connect_deadline_ms = 6000,
        .mp_step_deadline_ms = 7000,
        .client_queue = .{ .allocator = std.testing.allocator },
    };
    defer slot.client_queue.deinit();
    var inputs: SlotDeadlineInputs = .{
        .handshake_timeout_sec = 15,
        .mask_relay_max_secs = 60,
        .pre_first_byte_timeout_ms = 10_000,
        .wedge_eligible = false,
    };
    for ([_]@import("connection.zig").ConnectionPhase{
        .reading_web_prefix,        .reading_tls_header,         .reading_direct_obfuscated_handshake,
        .reading_client_hello_body, .writing_server_hello_first, .desync_wait,
        .writing_server_hello_rest, .reading_mtproto_tls_header, .reading_mtproto_tls_body,
        .connecting_upstream,       .writing_dc_nonce,           .middle_proxy_handshake,
    }) |phase| {
        slot.phase = phase;
        const expected_ms: i64 = switch (phase) {
            .desync_wait => 5000,
            .connecting_upstream => 6000,
            .middle_proxy_handshake => 7000,
            else => 17_000,
        };
        const selected = nextSlotDeadline(&slot, inputs).?;
        try std.testing.expect(selected.kind == .absolute);
        try std.testing.expectEqual(@as(i128, expected_ms) * std.time.ns_per_ms, selected.deadline_ns);
    }
    slot.phase = .reading_tls_header;
    slot.first_byte_at_ms = 0;
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .absolute);
    try std.testing.expectEqual(@as(?i128, 11_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));

    slot.phase = .relaying;
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .relay_idle);
    try std.testing.expectEqual(@as(?i128, 13_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));
    inputs.wedge_eligible = true;
    slot.wedge.phase = .waiting_for_client;
    for ([_]i64{ 12_000, 13_000, 14_000 }) |wedge_ms| {
        slot.wedge.deadline_ms = wedge_ms;
        const selected = nextSlotDeadline(&slot, inputs).?;
        try std.testing.expectEqual(@as(i128, @min(wedge_ms, 13_000)) * std.time.ns_per_ms, selected.deadline_ns);
        try std.testing.expectEqual(wedge_ms > 13_000, selected.kind == .relay_idle);
    }
    slot.last_activity_ms = 5000; // Idle extension crosses the absolute wedge.
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .absolute);
    try std.testing.expectEqual(@as(?i128, 14_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));
    try slot.client_queue.appendCopy("pending reply");
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .relay_idle);
    slot.client_queue.clear();

    inputs.wedge_eligible = false;
    slot.phase = .mask_relaying;
    inputs.mask_relay_max_secs = 14; // Equal to the 15-second idle deadline.
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .absolute);
    slot.last_activity_ms = 6000;
    try std.testing.expectEqual(@as(?i128, 15_000 * std.time.ns_per_ms), nextSlotDeadlineNs(&slot, inputs));
    slot.web_carrier = true;
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .relay_idle);
    slot.web_carrier = false;
    inputs.mask_relay_max_secs = 0;
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .relay_idle);
    slot.phase = .closing;
    try std.testing.expect(nextSlotDeadline(&slot, inputs).?.kind == .absolute);
    try std.testing.expectEqual(@as(?i128, 1), nextSlotDeadlineNs(&slot, inputs));
    slot.phase = .idle;
    try std.testing.expect(nextSlotDeadline(&slot, inputs) == null);
}

test "jittered idle timeout stays bounded" {
    const base_ms = secondsToMs(120);
    const range_ms = @divTrunc(base_ms * 15, 100);

    var seed: u64 = 0;
    while (seed < 128) : (seed += 1) {
        const value = jitteredIdleTimeoutMs(120, 15, seed *% 0x9E37_79B9_7F4A_7C15);
        try std.testing.expect(value >= base_ms - range_ms);
        try std.testing.expect(value <= base_ms + range_ms);
    }

    try std.testing.expectEqual(secondsToMs(5), jitteredIdleTimeoutMs(5, 100, 0));
}
