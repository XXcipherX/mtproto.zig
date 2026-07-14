//! Small Zig 0.15-style networking facade for Zig 0.16.
//!
//! The proxy's hot path intentionally works with OS sockaddr layout. Zig 0.16
//! moved high-level networking to std.Io.net, so this file preserves the old
//! Address shape used by the codebase while delegating parsing and lookup to
//! the current stdlib where possible.

const builtin = @import("builtin");
const std = @import("std");
const compat = @import("compat.zig");
const posix = std.posix;

pub const Address = extern union {
    any: posix.sockaddr,
    in: Ip4Address,
    in6: Ip6Address,

    pub const Ip4Address = extern struct {
        sa: posix.sockaddr.in,
    };

    pub const Ip6Address = extern struct {
        sa: posix.sockaddr.in6,
    };

    pub const ListenOptions = struct {
        reuse_address: bool = false,
        reuse_port: bool = false,
        kernel_backlog: u31 = std.Io.net.default_kernel_backlog,
    };

    pub fn initIp4(ip: [4]u8, port: u16) Address {
        return .{ .in = .{ .sa = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.readInt(u32, &ip, .little),
        } } };
    }

    pub fn initIp6(ip: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Address {
        return .{ .in6 = .{ .sa = .{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = flowinfo,
            .addr = ip,
            .scope_id = scope_id,
        } } };
    }

    pub fn parseIp6(text: []const u8, port: u16) !Address {
        const parsed = try std.Io.net.IpAddress.parseIp6(text, port);
        return fromIoAddress(parsed);
    }

    pub fn parseIpAndPort(text: []const u8) !Address {
        const parsed = try std.Io.net.IpAddress.parseLiteral(text);
        return fromIoAddress(parsed);
    }

    pub fn eql(a: Address, b: Address) bool {
        if (a.any.family != b.any.family) return false;
        if (a.any.family == posix.AF.INET) {
            return a.in.sa.port == b.in.sa.port and a.in.sa.addr == b.in.sa.addr;
        }
        if (a.any.family == posix.AF.INET6) {
            return a.in6.sa.port == b.in6.sa.port and
                a.in6.sa.flowinfo == b.in6.sa.flowinfo and
                a.in6.sa.scope_id == b.in6.sa.scope_id and
                std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr);
        }
        return false;
    }

    pub fn getOsSockLen(a: Address) posix.socklen_t {
        return if (a.any.family == posix.AF.INET6)
            @intCast(@sizeOf(posix.sockaddr.in6))
        else
            @intCast(@sizeOf(posix.sockaddr.in));
    }

    pub fn listen(a: Address, options: ListenOptions) ListenError!Server {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        return linuxListen(a, options);
    }

    pub fn format(a: Address, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (a.any.family == posix.AF.INET) {
            const bytes = std.mem.asBytes(&a.in.sa.addr);
            try w.print("{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                std.mem.bigToNative(u16, a.in.sa.port),
            });
            return;
        }

        if (a.any.family == posix.AF.INET6) {
            const ip: std.Io.net.IpAddress = .{ .ip6 = .{
                .port = std.mem.bigToNative(u16, a.in6.sa.port),
                .bytes = a.in6.sa.addr,
                .flow = a.in6.sa.flowinfo,
                .interface = .{ .index = a.in6.sa.scope_id },
            } };
            try ip.format(w);
            return;
        }

        try w.print("(unsupported address family {d})", .{a.any.family});
    }
};

pub const AddressList = struct {
    allocator: std.mem.Allocator,
    addrs: []Address,

    pub fn deinit(self: AddressList) void {
        self.allocator.free(self.addrs);
    }
};

pub fn getAddressList(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    if (std.Io.net.IpAddress.parse(host, port)) |parsed| {
        const addrs = try allocator.alloc(Address, 1);
        errdefer allocator.free(addrs);
        addrs[0] = fromIoAddress(parsed);
        return .{ .allocator = allocator, .addrs = addrs };
    } else |_| {}

    try std.Io.net.HostName.validate(host);

    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();
    const io = threaded_io.io();
    const host_name: std.Io.net.HostName = .{ .bytes = host };
    var lookup_storage: [32]std.Io.net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_storage);

    try std.Io.net.HostName.lookup(host_name, io, &lookup_queue, .{ .port = port });

    var list: std.ArrayList(Address) = .empty;
    defer list.deinit(allocator);

    while (lookup_queue.getOneUncancelable(io)) |result| {
        switch (result) {
            .address => |addr| try list.append(allocator, fromIoAddress(addr)),
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Closed => {},
    }

    if (list.items.len == 0) return error.UnknownHostName;
    return .{ .allocator = allocator, .addrs = try list.toOwnedSlice(allocator) };
}

fn fromIoAddress(addr: std.Io.net.IpAddress) Address {
    return switch (addr) {
        .ip4 => |ip4| Address.initIp4(ip4.bytes, ip4.port),
        .ip6 => |ip6| Address.initIp6(ip6.bytes, ip6.port, ip6.flow, ip6.interface.index),
    };
}

pub const Stream = struct {
    handle: posix.fd_t,
};

pub const Server = struct {
    stream: Stream,

    pub fn deinit(self: *Server) void {
        if (builtin.os.tag == .linux) {
            _ = std.os.linux.close(self.stream.handle);
        }
        self.* = undefined;
    }
};

pub const ListenError = error{
    AddressFamilyNotSupported,
    AddressInUse,
    AddressNotAvailable,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    UnsupportedOperatingSystem,
    Unexpected,
};

fn linuxListen(a: Address, options: Address.ListenOptions) ListenError!Server {
    const linux = std.os.linux;
    const socket_rc = linux.socket(
        @intCast(a.any.family),
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    const fd: posix.fd_t = switch (posix.errno(socket_rc)) {
        .SUCCESS => @intCast(socket_rc),
        .ACCES, .PERM => return error.PermissionDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };
    errdefer _ = linux.close(fd);

    if (options.reuse_address) try linuxSetSockOptInt(fd, linux.SO.REUSEADDR, 1);
    if (options.reuse_port) try linuxSetSockOptInt(fd, linux.SO.REUSEPORT, 1);
    if (a.any.family == posix.AF.INET6) {
        try linuxSetSockOptIntAtLevel(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, 0);
    }

    const bind_rc = linux.bind(fd, &a.any, a.getOsSockLen());
    switch (posix.errno(bind_rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }

    const listen_rc = linux.listen(fd, options.kernel_backlog);
    switch (posix.errno(listen_rc)) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }

    return .{ .stream = .{ .handle = fd } };
}

fn linuxSetSockOptInt(fd: posix.fd_t, optname: u32, value: i32) ListenError!void {
    return linuxSetSockOptIntAtLevel(fd, std.os.linux.SOL.SOCKET, optname, value);
}

fn linuxSetSockOptIntAtLevel(fd: posix.fd_t, level: i32, optname: u32, value: i32) ListenError!void {
    const linux = std.os.linux;
    const bytes = std.mem.asBytes(&value);
    const rc = linux.setsockopt(
        fd,
        level,
        optname,
        bytes.ptr,
        @intCast(bytes.len),
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
}
