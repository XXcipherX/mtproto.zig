const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_helpers.zig");
const posix = std.posix;
const linux = std.os.linux;

pub fn getsockoptErrorFd(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    if (err_code == 0) return;

    const err: @TypeOf(linux.errno(rc)) = @enumFromInt(err_code);
    switch (err) {
        .CONNREFUSED => return error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => return error.Unexpected,
    }
}

pub fn writeFd(fd: posix.fd_t, data: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
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
            else => return error.Unexpected,
        }
    }
}

pub fn writevFd(fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
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
            else => return error.Unexpected,
        }
    }
}

fn setSockOptBytes(fd: posix.fd_t, level: i32, optname: u32, bytes: []const u8) void {
    if (builtin.os.tag != .linux) return;

    const rc = linux.setsockopt(fd, level, optname, bytes.ptr, @intCast(bytes.len));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return,
    }
}

pub fn seekFdToStart(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.lseek(fd, 0, linux.SEEK.SET);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .SPIPE => return error.Unseekable,
        else => return error.Unexpected,
    }
}

pub fn setTcpUserTimeout(fd: posix.fd_t, timeout_ms: u32) void {
    const value: c_int = @intCast(timeout_ms);
    setSockOptBytes(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, std.mem.asBytes(&value));
}

pub fn setTcpKeepalive(fd: posix.fd_t) void {
    const sol_tcp: i32 = 6;

    const enable: c_int = 1;
    setSockOptBytes(fd, linux.SOL.SOCKET, linux.SO.KEEPALIVE, std.mem.asBytes(&enable));

    const idle: c_int = 60;
    setSockOptBytes(fd, sol_tcp, 4, std.mem.asBytes(&idle));

    const interval: c_int = 10;
    setSockOptBytes(fd, sol_tcp, 5, std.mem.asBytes(&interval));

    const count: c_int = 3;
    setSockOptBytes(fd, sol_tcp, 6, std.mem.asBytes(&count));
}

pub fn setTcpNoDelay(fd: posix.fd_t) void {
    const enable: c_int = 1;
    setSockOptBytes(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&enable));
}

pub fn configureRelaySocket(fd: posix.fd_t) void {
    setTcpNoDelay(fd);
    setTcpKeepalive(fd);
    setTcpUserTimeout(fd, 30 * std.time.ms_per_s);
}

pub fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    return switch (normalized) {
        .ip4 => std.fmt.bufPrint(buf, "[ipv4]:{d}", .{addr.getPort()}) catch "?",
        .ip6 => std.fmt.bufPrint(buf, "[ipv6]:{d}", .{addr.getPort()}) catch "?",
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
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                v4.bytes[0], v4.bytes[1], v4.bytes[2], v4.bytes[3],
            }) catch "?";
        },
        .ip6 => {
            var writer: std.Io.Writer = .fixed(buf);
            normalized.format(&writer) catch return "?";
            const endpoint = writer.buffered();
            if (endpoint.len < 2 or endpoint[0] != '[') return "?";
            const closing = std.mem.indexOfScalar(u8, endpoint, ']') orelse return "?";
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

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.ip6(mapped_bytes, 54321, 0, 0);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(mapped, &buf));
}
