//! Admission thresholds, relay-queue and MiddleProxy framing budgets shared
//! by config, startup diagnostics and the worker-local runtime.
const std = @import("std");

pub const relay_queue_max_pending_bytes: usize = 4 * 1024 * 1024;
/// Leave room for MiddleProxy wrapping, TLS headers, and secure padding before
/// a complete stream payload reaches the relay queue.
pub const middle_proxy_relay_queue_headroom_bytes: usize = 256 * 1024;
pub const middle_proxy_c2s_scratch_headroom: usize = middle_proxy_relay_queue_headroom_bytes;
pub const middle_proxy_initial_stream_buffer_bytes: usize = 16 * 1024;
pub const middle_proxy_stream_buffer_cap_bytes: usize =
    relay_queue_max_pending_bytes - middle_proxy_relay_queue_headroom_bytes;

pub fn admissionPauseThreshold(max_connections: u32) u32 {
    return @intCast(@as(u64, max_connections) * 9 / 10);
}

pub fn admissionResumeThreshold(max_connections: u32) u32 {
    return @intCast(@as(u64, max_connections) * 8 / 10);
}

comptime {
    if (middle_proxy_stream_buffer_cap_bytes + middle_proxy_relay_queue_headroom_bytes != relay_queue_max_pending_bytes) {
        @compileError("MiddleProxy stream cap and framing headroom must equal the relay queue cap");
    }
}

test "MiddleProxy stream buffer and framing headroom fit the relay queue" {
    try std.testing.expectEqual(@as(usize, 3840 * 1024), middle_proxy_stream_buffer_cap_bytes);
    try std.testing.expectEqual(relay_queue_max_pending_bytes, middle_proxy_stream_buffer_cap_bytes + middle_proxy_relay_queue_headroom_bytes);
}

test "admission thresholds preserve rounding and accept the largest connection cap" {
    try std.testing.expectEqual(@as(u32, 460), admissionPauseThreshold(512));
    try std.testing.expectEqual(@as(u32, 409), admissionResumeThreshold(512));
    try std.testing.expectEqual(@as(u32, 3865470565), admissionPauseThreshold(std.math.maxInt(u32)));
    try std.testing.expectEqual(@as(u32, 3435973836), admissionResumeThreshold(std.math.maxInt(u32)));
}
