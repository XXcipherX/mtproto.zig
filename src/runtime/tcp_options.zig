const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

/// Preserve the existing syscall/error behavior as well as the option values.
/// Proxy ignores raw setsockopt errors and keeps tuning; WEB uses std.posix
/// mapping and stops the keepalive sequence at its first error.
pub const TuningPolicy = enum { proxy_raw, web_posix };

const relay_keepalive_min_idle_sec: u32 = 30;
const relay_keepalive_max_idle_sec: u32 = 60;
const relay_keepalive_interval_sec: u32 = 10;
const relay_keepalive_probe_count: u32 = 3;
// Linux evaluates TCP_USER_TIMEOUT against total idle time after a probe is
// outstanding. Give even the latest first probe its full three-probe window.
const relay_user_timeout_ms: u32 =
    (relay_keepalive_max_idle_sec + relay_keepalive_interval_sec * relay_keepalive_probe_count) * std.time.ms_per_s;

fn keepaliveIdleForFd(fd_number: u64) u32 {
    // A burst of relay admissions otherwise creates a matching burst of
    // kernel probes 60 seconds later. Spread them without making any socket
    // wait longer than the previous 60-second NAT/peer-liveness policy.
    const mixed = fd_number *% 0x9e3779b97f4a7c15;
    const span: u64 = relay_keepalive_max_idle_sec - relay_keepalive_min_idle_sec + 1;
    return relay_keepalive_min_idle_sec + @as(u32, @intCast((mixed >> 32) % span));
}

fn setOption(fd: posix.fd_t, level: i32, option: u32, bytes: []const u8, policy: TuningPolicy) bool {
    if (builtin.os.tag != .linux) return false;
    return switch (policy) {
        .proxy_raw => linux.errno(linux.setsockopt(fd, level, option, bytes.ptr, @intCast(bytes.len))) == .SUCCESS,
        .web_posix => blk: {
            posix.setsockopt(fd, level, option, bytes) catch break :blk false;
            break :blk true;
        },
    };
}

fn setIntOption(fd: posix.fd_t, level: i32, option: u32, value: c_int, policy: TuningPolicy) bool {
    return setOption(fd, level, option, std.mem.asBytes(&value), policy);
}

pub fn setTcpNoDelay(fd: posix.fd_t, policy: TuningPolicy) void {
    _ = setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1, policy);
}

pub fn setTcpKeepalive(fd: posix.fd_t, policy: TuningPolicy) void {
    if (!setIntOption(fd, linux.SOL.SOCKET, linux.SO.KEEPALIVE, 1, policy) and policy == .web_posix) return;
    const idle_sec = if (builtin.os.tag == .linux) keepaliveIdleForFd(@intCast(fd)) else relay_keepalive_max_idle_sec;
    if (!setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPIDLE, @intCast(idle_sec), policy) and policy == .web_posix) return;
    if (!setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPINTVL, @intCast(relay_keepalive_interval_sec), policy) and policy == .web_posix) return;
    _ = setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPCNT, @intCast(relay_keepalive_probe_count), policy);
}

/// TCP_USER_TIMEOUT applies to non-blocking sockets, unlike SO_SNDTIMEO.
pub fn setTcpUserTimeout(fd: posix.fd_t, timeout_ms: u32, policy: TuningPolicy) void {
    if (builtin.os.tag != .linux) return;
    if (policy == .proxy_raw) {
        const value: c_int = @intCast(timeout_ms);
        _ = setOption(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, std.mem.asBytes(&value), policy);
    } else {
        const value: c_uint = timeout_ms;
        _ = setOption(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, std.mem.asBytes(&value), policy);
    }
}

pub fn configureRelaySocket(fd: posix.fd_t, policy: TuningPolicy) void {
    setTcpNoDelay(fd, policy);
    setTcpKeepalive(fd, policy);
    setTcpUserTimeout(fd, relay_user_timeout_ms, policy);
}

test "relay user timeout does not preempt keepalive probe budget" {
    try std.testing.expectEqual(@as(u32, 90_000), relay_user_timeout_ms);
    const idle_span: usize = relay_keepalive_max_idle_sec - relay_keepalive_min_idle_sec + 1;
    var seen = [_]bool{false} ** idle_span;
    for (0..128) |fd| {
        const idle_sec = keepaliveIdleForFd(@intCast(fd));
        try std.testing.expect(idle_sec >= relay_keepalive_min_idle_sec);
        try std.testing.expect(idle_sec <= relay_keepalive_max_idle_sec);
        seen[@intCast(idle_sec - relay_keepalive_min_idle_sec)] = true;
    }
    var sampled_count: usize = 0;
    for (seen) |sampled| {
        if (sampled) sampled_count += 1;
    }
    try std.testing.expect(sampled_count >= 20);
}
