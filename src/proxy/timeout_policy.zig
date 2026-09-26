const std = @import("std");
const ConnectionSlot = @import("connection.zig").ConnectionSlot;

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
