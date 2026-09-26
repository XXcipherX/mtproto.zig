const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

/// Preserve the existing syscall/error behavior as well as the option values.
/// Proxy ignores raw setsockopt errors and keeps tuning; WEB uses std.posix
/// mapping and stops the keepalive sequence at its first error.
pub const TuningPolicy = enum { proxy_raw, web_posix };

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
    if (!setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPIDLE, 60, policy) and policy == .web_posix) return;
    if (!setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPINTVL, 10, policy) and policy == .web_posix) return;
    _ = setIntOption(fd, linux.IPPROTO.TCP, linux.TCP.KEEPCNT, 3, policy);
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
    setTcpUserTimeout(fd, 30 * std.time.ms_per_s, policy);
}
