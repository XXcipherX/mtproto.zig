//! Canonical Zig 0.16 IP addresses, hostname resolution, and Linux socket boundary.

const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;

pub const Address = std.Io.net.IpAddress;

pub fn ip4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn ip6(bytes: [16]u8, port: u16, flow: u32, scope_id: u32) Address {
    return .{ .ip6 = .{
        .bytes = bytes,
        .port = port,
        .flow = flow,
        .interface = .{ .index = scope_id },
    } };
}

fn family(addr: Address) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

/// Resolver snapshot comparison also includes IPv6 routing metadata. Zig's
/// IpAddress.eql intentionally compares only port and IP bytes.
pub fn exactAddressEql(a: Address, b: Address) bool {
    return switch (a) {
        .ip4 => |v4| switch (b) {
            .ip4 => |other| v4.eql(other),
            .ip6 => false,
        },
        .ip6 => |v6| switch (b) {
            .ip4 => false,
            .ip6 => |other| v6.eql(other) and v6.flow == other.flow and
                v6.interface.index == other.interface.index,
        },
    };
}

/// The only persistent address value is IpAddress. This temporary storage is
/// constructed at the Linux syscall boundary, with no allocation or parsing.
const Sockaddr = union(enum) {
    ip4: posix.sockaddr.in,
    ip6: posix.sockaddr.in6,

    fn init(addr: Address) Sockaddr {
        return switch (addr) {
            .ip4 => |value| .{ .ip4 = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, value.port),
                .addr = @bitCast(value.bytes),
                .zero = [_]u8{0} ** 8,
            } },
            .ip6 => |value| .{ .ip6 = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, value.port),
                .flowinfo = value.flow,
                .addr = value.bytes,
                .scope_id = value.interface.index,
            } },
        };
    }

    fn ptr(self: *const Sockaddr) *const posix.sockaddr {
        return switch (self.*) {
            .ip4 => @ptrCast(&self.ip4),
            .ip6 => @ptrCast(&self.ip6),
        };
    }

    fn len(self: *const Sockaddr) posix.socklen_t {
        return switch (self.*) {
            .ip4 => @sizeOf(posix.sockaddr.in),
            .ip6 => @sizeOf(posix.sockaddr.in6),
        };
    }
};

pub fn addressFromSockaddr(storage: *const posix.sockaddr.storage, len: posix.socklen_t) ?Address {
    return switch (storage.family) {
        posix.AF.INET => blk: {
            if (len < @sizeOf(posix.sockaddr.in)) break :blk null;
            const sa: *const posix.sockaddr.in = @ptrCast(storage);
            break :blk ip4(@bitCast(sa.addr), std.mem.bigToNative(u16, sa.port));
        },
        posix.AF.INET6 => blk: {
            if (len < @sizeOf(posix.sockaddr.in6)) break :blk null;
            const sa: *const posix.sockaddr.in6 = @ptrCast(storage);
            break :blk ip6(sa.addr, std.mem.bigToNative(u16, sa.port), sa.flowinfo, sa.scope_id);
        },
        else => null,
    };
}

pub const ListenOptions = struct {
    reuse_address: bool = false,
    reuse_port: bool = false,
    kernel_backlog: u31 = std.Io.net.default_kernel_backlog,
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

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
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

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
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
            .address => |addr| try list.append(allocator, addr),
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
    addrs[0] = parsed;
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

/// Worker-owned, nonblocking SO_REUSEPORT listener. The std.Io.net.Server
/// lifecycle requires an Io context, while this epoll data plane owns raw fds.
pub const Listener = struct {
    handle: posix.fd_t,

    pub fn deinit(self: *Listener) void {
        if (builtin.os.tag == .linux) _ = std.os.linux.close(self.handle);
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

pub fn listen(a: Address, options: ListenOptions) ListenError!Listener {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const linux = std.os.linux;
    const socket_rc = linux.socket(
        family(a),
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    const fd: posix.fd_t = switch (linux.errno(socket_rc)) {
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
    if (a == .ip6) {
        try linuxSetSockOptIntAtLevel(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, 0);
    }

    const sa = Sockaddr.init(a);
    const bind_rc = linux.bind(fd, sa.ptr(), sa.len());
    switch (linux.errno(bind_rc)) {
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
    switch (linux.errno(listen_rc)) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }

    return .{ .handle = fd };
}

pub const Accepted = struct {
    fd: posix.fd_t,
    peer: Address,
};

pub fn acceptFd(fd: posix.fd_t) !Accepted {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const linux = std.os.linux;
    var storage: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const rc = linux.accept4(fd, @ptrCast(&storage), &len, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
    const accepted_fd: posix.fd_t = switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .CONNABORTED => return error.ConnectionAborted,
        .CONNRESET => return error.ConnectionResetByPeer,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };
    const peer = addressFromSockaddr(&storage, len) orelse {
        _ = linux.close(accepted_fd);
        return error.UnsupportedAddressFamily;
    };
    return .{ .fd = accepted_fd, .peer = peer };
}

pub fn socketTcpNonblocking(addr: Address) !posix.fd_t {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const linux = std.os.linux;
    const rc = linux.socket(
        family(addr),
        linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        linux.IPPROTO.TCP,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.PermissionDenied,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

pub fn connectFd(fd: posix.fd_t, addr: Address) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const linux = std.os.linux;
    const sa = Sockaddr.init(addr);
    const rc = linux.connect(fd, sa.ptr(), sa.len());
    switch (linux.errno(rc)) {
        .SUCCESS, .ISCONN => {},
        .AGAIN => return error.WouldBlock,
        .INPROGRESS, .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => return error.Unexpected,
    }
}

fn namedAddress(fd: posix.fd_t, comptime peer: bool) !Address {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const linux = std.os.linux;
    var storage: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    const rc = if (peer)
        linux.getpeername(fd, @ptrCast(&storage), &len)
    else
        linux.getsockname(fd, @ptrCast(&storage), &len);
    if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
    return addressFromSockaddr(&storage, len) orelse error.UnsupportedAddressFamily;
}

pub fn peerAddress(fd: posix.fd_t) !Address {
    return namedAddress(fd, true);
}

pub fn localAddress(fd: posix.fd_t) !Address {
    return namedAddress(fd, false);
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
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
}

test "IpAddress IPv4 sockaddr conversion preserves bytes and port endian" {
    const ip = [4]u8{ 203, 0, 113, 42 };
    const addr = ip4(ip, 443);
    const sa = Sockaddr.init(addr);
    try std.testing.expectEqualSlices(u8, &ip, std.mem.asBytes(&sa.ip4.addr));
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 443), sa.ip4.port);

    var storage: posix.sockaddr.storage = undefined;
    @memcpy(std.mem.asBytes(&storage)[0..sa.len()], std.mem.asBytes(&sa.ip4));
    const decoded = addressFromSockaddr(&storage, sa.len()) orelse return error.TestExpectedEqual;
    try std.testing.expect(exactAddressEql(addr, decoded));
}

test "IpAddress IPv6 sockaddr conversion preserves bytes flow scope and port" {
    const bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 };
    const addr = ip6(bytes, 54321, 0x1234, 3);
    const sa = Sockaddr.init(addr);
    try std.testing.expectEqualSlices(u8, &bytes, &sa.ip6.addr);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 54321), sa.ip6.port);
    try std.testing.expectEqual(@as(u32, 0x1234), sa.ip6.flowinfo);
    try std.testing.expectEqual(@as(u32, 3), sa.ip6.scope_id);

    var storage: posix.sockaddr.storage = undefined;
    @memcpy(std.mem.asBytes(&storage)[0..sa.len()], std.mem.asBytes(&sa.ip6));
    const decoded = addressFromSockaddr(&storage, sa.len()) orelse return error.TestExpectedEqual;
    try std.testing.expect(exactAddressEql(addr, decoded));
    try std.testing.expect(!exactAddressEql(addr, ip6(bytes, 54321, 0x1234, 4)));
    try std.testing.expect(!exactAddressEql(addr, ip6(bytes, 54321, 0x1235, 3)));
}

test "sockaddr conversion rejects truncated addresses and retains mapped IPv6" {
    const mapped = ip6(
        [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 192, 0, 2, 9 },
        1234,
        0,
        0,
    );
    const sa = Sockaddr.init(mapped);
    var storage: posix.sockaddr.storage = undefined;
    @memcpy(std.mem.asBytes(&storage)[0..sa.len()], std.mem.asBytes(&sa.ip6));
    try std.testing.expect(addressFromSockaddr(&storage, sa.len() - 1) == null);
    const decoded = addressFromSockaddr(&storage, sa.len()) orelse return error.TestExpectedEqual;
    try std.testing.expect(decoded == .ip6);
    try std.testing.expect(exactAddressEql(mapped, decoded));
    const normalized = Address.fromIp6(decoded.ip6);
    try std.testing.expect(exactAddressEql(normalized, ip4(.{ 192, 0, 2, 9 }, 1234)));
}

test "Linux socket boundary preserves accept peer and local and remote names" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;

    var listener = try listen(ip4(.{ 127, 0, 0, 1 }, 0), .{});
    defer listener.deinit();
    const bound = try localAddress(listener.handle);

    const client_rc = linux.socket(family(bound), linux.SOCK.STREAM | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(client_rc));
    const client_fd: posix.fd_t = @intCast(client_rc);
    defer _ = linux.close(client_fd);

    try connectFd(client_fd, bound);
    const accepted = try acceptFd(listener.handle);
    defer _ = linux.close(accepted.fd);

    const client_local = try localAddress(client_fd);
    try std.testing.expect(exactAddressEql(accepted.peer, client_local));
    try std.testing.expect(exactAddressEql(try peerAddress(accepted.fd), client_local));
    try std.testing.expect(exactAddressEql(try peerAddress(client_fd), bound));
    try std.testing.expect(exactAddressEql(try localAddress(accepted.fd), bound));
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
