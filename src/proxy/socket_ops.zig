const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_helpers.zig");
const tcp_options = @import("../runtime/tcp_options.zig");
const posix = std.posix;
const linux = std.os.linux;

pub fn getsockoptErrorFd(fd: posix.fd_t) !void {
    if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;

    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
    if (err_code == 0) return;

    const err: @TypeOf(linux.errno(rc)) = @fromBackingInt(@intCast(err_code));
    switch (err) {
        .CONNREFUSED => return error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => return posix.unexpectedErrno(err),
    }
}

pub fn writeFd(fd: posix.fd_t, data: []const u8) !usize {
    if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;
    if (data.len == 0) return 0;

    while (true) {
        const rc = linux.write(fd, data.ptr, data.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .PIPE => return error.BrokenPipe,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn writevFd(fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;
    if (iovecs.len == 0) return 0;

    while (true) {
        const rc = linux.writev(fd, iovecs.ptr, iovecs.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .PIPE => return error.BrokenPipe,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn seekFdToStart(fd: posix.fd_t) !void {
    if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.lseek(fd, 0, linux.SEEK.SET);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .SPIPE => return error.Unseekable,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn setTcpUserTimeout(fd: posix.fd_t, timeout_ms: u32) void {
    tcp_options.setTcpUserTimeout(fd, timeout_ms, .proxy_raw);
}

pub fn setTcpKeepalive(fd: posix.fd_t) void {
    tcp_options.setTcpKeepalive(fd, .proxy_raw);
}

pub fn setTcpNoDelay(fd: posix.fd_t) void {
    tcp_options.setTcpNoDelay(fd, .proxy_raw);
}

pub fn configureRelaySocket(fd: posix.fd_t) void {
    tcp_options.configureRelaySocket(fd, .proxy_raw);
}

pub fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    return switch (normalized) {
        .ip4 => std.mem.print(buf, "[ipv4]:{d}", .{addr.getPort()}) catch "?",
        .ip6 => std.mem.print(buf, "[ipv6]:{d}", .{addr.getPort()}) catch "?",
    };
}

/// Format an authenticated client's real IP without its ephemeral source port.
/// Unlike `formatAddress`, this deliberately exposes the address: callers must
/// keep it out of production-level logs.
pub fn formatClientIp(addr: net.Address, buf: *[64]u8) []const u8 {
    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    switch (normalized) {
        .ip4 => |v4| {
            return std.mem.print(buf, "{d}.{d}.{d}.{d}", .{
                v4.bytes[0], v4.bytes[1], v4.bytes[2], v4.bytes[3],
            }) catch "?";
        },
        .ip6 => {
            var writer: std.Io.Writer = .fixed(buf);
            normalized.format(&writer) catch return "?";
            const endpoint = writer.buffered();
            if (endpoint.len < 2 or endpoint[0] != '[') return "?";
            const closing = std.mem.findScalar(u8, endpoint, ']') orelse return "?";
            return endpoint[1..closing];
        },
    }
}

pub fn socketConnectSucceeded(fd: linux.fd_t) bool {
    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const opt_rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    return linux.errno(opt_rc) == .SUCCESS and err_code == 0;
}

test "client IP formatting omits port and normalizes mapped IPv4" {
    var buf: [64]u8 = undefined;
    const native = net.ip4(.{ 203, 0, 113, 7 }, 54321);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(native, &buf));

    const mapped_bytes = @as([10]u8, @splat(0)) ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.ip6(mapped_bytes, 54321, 0, 0);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(mapped, &buf));
}
