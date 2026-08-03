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
        return .{
            .in = .{
                .sa = .{
                    .port = std.mem.nativeToBig(u16, port),
                    // sockaddr stores the address in network byte order in memory.
                    // Interpret the byte array as a native integer so its memory bytes
                    // remain identical on both little- and big-endian targets.
                    .addr = std.mem.bytesToValue(u32, &ip),
                },
            },
        };
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

const resolver_config_max_bytes = 64 * 1024;
const resolver_line_max_bytes = 512;
const resolver_stop_poll_ns = 100 * std.time.ns_per_ms;

const AddressLookupEvent = union(enum) {
    lookup: anyerror!AddressList,
    stop: anyerror!void,
};

pub fn getAddressList(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    if (try addressListForLiteral(allocator, host, port)) |list| return list;

    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();
    const io = threaded_io.io();
    return getAddressListWithIo(allocator, host, port, io);
}

/// Resolve a host while cooperatively observing an updater stop flag. The
/// futures and their borrowed stack state are owned and canceled by this
/// calling thread. Zig 0.16 marks Future/Group cancellation as non-thread-safe;
/// Select cancellation itself is thread-safe, but still must not outlive the
/// buffers and arguments owned by this scope.
pub fn getAddressListCancelable(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    stop: *const std.atomic.Value(bool),
) !AddressList {
    if (stop.load(.acquire)) return error.UpdateCancelled;

    if (try addressListForLiteral(allocator, host, port)) |list| {
        if (stop.load(.acquire)) {
            list.deinit();
            return error.UpdateCancelled;
        }
        return list;
    }

    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();
    const io = threaded_io.io();

    var event_storage: [2]AddressLookupEvent = undefined;
    var select = std.Io.Select(AddressLookupEvent).init(io, &event_storage);
    try select.concurrent(.lookup, getAddressListWithIo, .{
        std.heap.page_allocator,
        host,
        port,
        io,
    });
    select.concurrent(.stop, waitForResolverStop, .{ io, stop }) catch |err| {
        drainAddressLookupSelect(&select);
        return err;
    };

    const selected = select.await() catch |err| {
        drainAddressLookupSelect(&select);
        return err;
    };
    defer drainAddressLookupSelect(&select);

    switch (selected) {
        .lookup => |result| {
            const worker_list = try result;
            defer worker_list.deinit();
            if (stop.load(.acquire)) return error.UpdateCancelled;

            return .{
                .allocator = allocator,
                .addrs = try allocator.dupe(Address, worker_list.addrs),
            };
        },
        .stop => |result| {
            try result;
            return error.UpdateCancelled;
        },
    }
}

fn getAddressListWithIo(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    io: std.Io,
) !AddressList {
    if (try addressListForLiteral(allocator, host, port)) |list| return list;

    try std.Io.net.HostName.validate(host);
    try validateSystemResolverForHost(allocator, io, host);

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

fn addressListForLiteral(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
) !?AddressList {
    const parsed = std.Io.net.IpAddress.parse(host, port) catch return null;
    const addrs = try allocator.alloc(Address, 1);
    errdefer allocator.free(addrs);
    addrs[0] = fromIoAddress(parsed);
    return .{ .allocator = allocator, .addrs = addrs };
}

fn waitForResolverStop(io: std.Io, stop: *const std.atomic.Value(bool)) !void {
    while (!stop.load(.acquire)) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = resolver_stop_poll_ns },
            .awake,
        );
    }
}

fn drainAddressLookupSelect(select: *std.Io.Select(AddressLookupEvent)) void {
    while (select.cancel()) |event| switch (event) {
        .lookup => |result| discardAddressListResult(result),
        .stop => |result| result catch {},
    };
}

fn discardAddressListResult(result: anyerror!AddressList) void {
    if (result) |list| {
        list.deinit();
    } else |_| {}
}

/// Preflight Zig 0.16's resolver parser before it sees a system configuration
/// that can otherwise reach an unchecked copy, division by zero, or DNS-name
/// assertion. The stdlib reopens resolv.conf for the actual lookup, so a
/// privileged concurrent replacement remains an unavoidable TOCTOU until the
/// stdlib accepts a caller-supplied parsed configuration.
pub fn validateSystemResolverForHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
) !void {
    if (builtin.os.tag != .linux) return;
    if (std.Io.net.IpAddress.parse(host, 0)) |_| return else |_| {}

    try std.Io.net.HostName.validate(host);

    const file = std.Io.Dir.openFileAbsolute(io, "/etc/resolv.conf", .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied => return,
        else => |e| return e,
    };
    defer file.close(io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    const content = reader.interface.allocRemaining(
        allocator,
        .limited(resolver_config_max_bytes),
    ) catch |err| switch (err) {
        error.StreamTooLong => return error.UnsafeResolverConfiguration,
        // Io.Reader erases the concrete file error; propagate cancellation so
        // the owning Select observes that its cancel request was acknowledged.
        error.ReadFailed => return reader.err orelse error.Unexpected,
        else => |e| return e,
    };
    defer allocator.free(content);

    try validateResolverConfigurationForHost(content, host);
}

fn validateResolverConfigurationForHost(content: []const u8, host: []const u8) !void {
    std.Io.net.HostName.validate(host) catch return error.UnsafeResolverConfiguration;

    const canonical_host = if (std.mem.endsWith(u8, host, "."))
        host[0 .. host.len - 1]
    else
        host;
    if (canonical_host.len > 253) return error.UnsafeResolverConfiguration;

    var attempts: u32 = 2;
    var ndots: u32 = 1;
    var search: []const u8 = "";
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        if (raw_line.len > resolver_line_max_bytes) {
            return error.UnsafeResolverConfiguration;
        }

        // Match Zig's parser exactly: '\r' is not a delimiter and therefore
        // remains part of the final token. Hiding it here would let preflight
        // accept a suffix that Zig later interprets as an overlong/invalid label.
        var comment_split = std.mem.splitScalar(u8, raw_line, '#');
        const line = comment_split.first();
        var line_it = std.mem.tokenizeAny(u8, line, " \t");
        const directive = line_it.next() orelse continue;

        if (std.mem.eql(u8, directive, "options")) {
            while (line_it.next()) |sub_token| {
                var option_it = std.mem.splitScalar(u8, sub_token, ':');
                const name = option_it.first();
                const value_text = option_it.next() orelse continue;
                const value = std.fmt.parseInt(u8, value_text, 10) catch |err| switch (err) {
                    error.Overflow => @as(u8, 255),
                    error.InvalidCharacter => continue,
                };

                if (std.mem.eql(u8, name, "attempts")) {
                    attempts = @min(value, 10);
                } else if (std.mem.eql(u8, name, "ndots")) {
                    ndots = @min(value, 15);
                }
            }
        } else if (std.mem.eql(u8, directive, "domain") or
            std.mem.eql(u8, directive, "search"))
        {
            const rest = line_it.rest();
            if (rest.len > std.Io.net.HostName.max_len) {
                return error.UnsafeResolverConfiguration;
            }
            search = rest;
        }
    }

    if (attempts == 0) return error.UnsafeResolverConfiguration;

    var search_it = std.mem.tokenizeAny(u8, search, " \t");
    while (search_it.next()) |suffix| {
        std.Io.net.HostName.validate(suffix) catch
            return error.UnsafeResolverConfiguration;

        const search_applies =
            !std.mem.endsWith(u8, host, ".") and
            std.mem.countScalar(u8, host, '.') < ndots;
        if (search_applies and canonical_host.len + 1 + suffix.len > 253) {
            return error.UnsafeResolverConfiguration;
        }
    }
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

test "initIp4 preserves network-order address bytes" {
    const ip = [4]u8{ 203, 0, 113, 42 };
    const addr = Address.initIp4(ip, 443);
    try std.testing.expectEqualSlices(u8, &ip, std.mem.asBytes(&addr.in.sa.addr));
}

test "resolver guard rejects zero attempts after last override" {
    try std.testing.expectError(
        error.UnsafeResolverConfiguration,
        validateResolverConfigurationForHost(
            "options attempts:2\noptions attempts:0\n",
            "gateway",
        ),
    );
    try validateResolverConfigurationForHost(
        "options attempts:0\noptions attempts:2\n",
        "gateway",
    );
}

test "resolver guard rejects oversized search and lines" {
    const oversized_search = "search " ++ ([_]u8{'a'} ** 256) ++ "\n";
    try std.testing.expectError(
        error.UnsafeResolverConfiguration,
        validateResolverConfigurationForHost(oversized_search, "gateway"),
    );

    const oversized_line = [_]u8{'#'} ** (resolver_line_max_bytes + 1);
    try std.testing.expectError(
        error.UnsafeResolverConfiguration,
        validateResolverConfigurationForHost(&oversized_line, "gateway"),
    );
}

test "resolver guard does not hide CR from Zig search tokens" {
    const label = [_]u8{'a'} ** 63;
    const content = "search " ++ label ++ "\r\n";
    try std.testing.expectError(
        error.UnsafeResolverConfiguration,
        validateResolverConfigurationForHost(content, "gateway"),
    );
}

test "resolver guard rejects host names beyond DNS wire limit" {
    var host = [_]u8{'a'} ** 254;
    host[63] = '.';
    host[127] = '.';
    host[191] = '.';
    try std.testing.expectError(
        error.UnsafeResolverConfiguration,
        validateResolverConfigurationForHost("", &host),
    );
}

test "cancelable address lookup honors a pre-set stop flag" {
    var stop = std.atomic.Value(bool).init(true);
    try std.testing.expectError(
        error.UpdateCancelled,
        getAddressListCancelable(std.testing.allocator, "127.0.0.1", 443, &stop),
    );
}
