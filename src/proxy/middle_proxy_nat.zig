const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_helpers.zig");
const http_fetch = @import("../http_fetch.zig");

pub fn parseIpv4Literal(text: []const u8) ?[4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var ip: [4]u8 = undefined;
    var idx: usize = 0;

    while (parts.next()) |part| {
        if (idx >= ip.len or part.len == 0 or part.len > 3) return null;
        const octet = std.fmt.parseInt(u16, part, 10) catch return null;
        if (octet > 255) return null;
        ip[idx] = @intCast(octet);
        idx += 1;
    }

    if (idx != ip.len) return null;
    return ip;
}

pub fn isRunningInNonInitNetns() bool {
    if (builtin.os.tag != .linux) return false;

    var self_buf: [std.fs.max_path_bytes]u8 = undefined;
    var init_buf: [std.fs.max_path_bytes]u8 = undefined;

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const local_io = threaded_io.io();
    const self_len = std.Io.Dir.readLinkAbsolute(local_io, "/proc/self/ns/net", &self_buf) catch return false;
    const init_len = std.Io.Dir.readLinkAbsolute(local_io, "/proc/1/ns/net", &init_buf) catch return false;
    const self_ns = self_buf[0..self_len];
    const init_ns = init_buf[0..init_len];

    return !std.mem.eql(u8, self_ns, init_ns);
}

fn parseEndpointHost(endpoint: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, endpoint, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, trimmed, ']') orelse return null;
        const host = trimmed[1..close_idx];
        if (host.len == 0) return null;
        return host;
    }

    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |sep| {
        if (sep == 0) return null;
        return std.mem.trim(u8, trimmed[0..sep], &[_]u8{ ' ', '\t', '\r', '\n' });
    }

    return trimmed;
}

fn resolveHostnameIpv4(
    allocator: std.mem.Allocator,
    host: []const u8,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    if (stop) |stop_flag| {
        if (stop_flag.load(.acquire)) return error.UpdateCancelled;
    }

    var list = if (stop) |stop_flag|
        net.getAddressListCancelable(allocator, host, 443, stop_flag) catch |err| {
            if (err == error.UpdateCancelled) return err;
            return null;
        }
    else
        net.getAddressList(allocator, host, 443) catch return null;
    defer list.deinit();

    for (list.addrs) |addr| {
        if (addr == .ip4) return addr.ip4.bytes;
    }

    return null;
}

fn parseAwgEndpointIpv4FromConfig(
    allocator: std.mem.Allocator,
    content: []const u8,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    var in_peer = false;
    var lines = std.mem.splitScalar(u8, content, '\n');

    while (lines.next()) |raw_line| {
        if (stop) |stop_flag| {
            if (stop_flag.load(.acquire)) return error.UpdateCancelled;
        }

        const line_no_cr = std.mem.trimEnd(u8, raw_line, "\r");
        const line = std.mem.trim(u8, line_no_cr, &[_]u8{ ' ', '\t' });
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        if (line[0] == '[' and line[line.len - 1] == ']') {
            in_peer = std.ascii.eqlIgnoreCase(line, "[Peer]");
            continue;
        }
        if (!in_peer) continue;

        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
        if (!std.ascii.eqlIgnoreCase(key, "Endpoint")) continue;

        var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
        if (std.mem.indexOfScalar(u8, value, '#')) |idx| value = value[0..idx];
        if (std.mem.indexOfScalar(u8, value, ';')) |idx| value = value[0..idx];
        value = std.mem.trim(u8, value, &[_]u8{ ' ', '\t' });
        const host = parseEndpointHost(value) orelse continue;

        if (parseIpv4Literal(host)) |ip| return ip;
        if (try resolveHostnameIpv4(allocator, host, stop)) |resolved_ip| return resolved_ip;
    }

    return null;
}

pub fn detectAwgEndpointIpv4(
    allocator: std.mem.Allocator,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    if (builtin.os.tag != .linux) return null;

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const paths = [_][]const u8{
        "/etc/amnezia/amneziawg/awg0.conf",
        "/etc/amnezia/amneziawg/wg0.conf",
        "/etc/wireguard/wg0.conf",
    };

    for (paths) |path| {
        if (stop) |stop_flag| {
            if (stop_flag.load(.acquire)) return error.UpdateCancelled;
        }

        const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024 + 1)) catch continue;
        defer allocator.free(content);
        if (content.len > 64 * 1024) continue;

        if (try parseAwgEndpointIpv4FromConfig(allocator, content, stop)) |ip| return ip;
    }

    return null;
}

pub fn selectDetectedMiddleProxyNatIpv4(
    tunnel_active: bool,
    awg_ip: ?[4]u8,
    public_ip: ?[4]u8,
) ?[4]u8 {
    if (tunnel_active) {
        if (awg_ip) |ip| return ip;
    }
    return public_ip;
}

pub fn detectPublicIpv4(
    allocator: std.mem.Allocator,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    const services = [_][]const u8{
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://ipv4.icanhazip.com",
    };

    for (services) |url| {
        const stdout = http_fetch.fetchUrlBytes(
            allocator,
            url,
            .{
                .max_response_bytes = 64 * 1024,
                .stop = stop,
            },
        ) catch |err| {
            if (err == error.UpdateCancelled) return err;
            continue;
        };
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        const parsed = parseIpv4Literal(trimmed);
        allocator.free(stdout);
        if (parsed) |ip| return ip;
    }

    return null;
}

test "middle-proxy NAT selection ignores a stale AWG endpoint in direct mode" {
    const awg_ip = [4]u8{ 203, 0, 113, 9 };
    const public_ip = [4]u8{ 198, 51, 100, 20 };

    try std.testing.expectEqual(
        @as(?[4]u8, public_ip),
        selectDetectedMiddleProxyNatIpv4(false, awg_ip, public_ip),
    );
}

test "middle-proxy NAT selection uses AWG endpoint only in tunnel mode" {
    const awg_ip = [4]u8{ 203, 0, 113, 9 };
    const public_ip = [4]u8{ 198, 51, 100, 20 };

    try std.testing.expectEqual(
        @as(?[4]u8, awg_ip),
        selectDetectedMiddleProxyNatIpv4(true, awg_ip, public_ip),
    );
    try std.testing.expectEqual(
        @as(?[4]u8, public_ip),
        selectDetectedMiddleProxyNatIpv4(true, null, public_ip),
    );
}

pub fn formatIpv4Bytes(ip: [4]u8, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?.?.?.?";
}

pub fn ipv4BytesForMiddleProxyKdf(network_order_ip: [4]u8) [4]u8 {
    const value = std.mem.readInt(u32, &network_order_ip, .big);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, value, .little);
    return out;
}

pub fn ipv4AddressBytesForMiddleProxyKdf(addr: net.Address) [4]u8 {
    return ipv4BytesForMiddleProxyKdf(addr.ip4.bytes);
}

test "parse ipv4 literal" {
    const parsed = parseIpv4Literal("179.43.141.146") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
    try std.testing.expect(parseIpv4Literal("179.43.141") == null);
    try std.testing.expect(parseIpv4Literal("179.43.141.999") == null);
}

test "middle proxy ipv4 kdf bytes are endian explicit" {
    try std.testing.expectEqual([4]u8{ 146, 141, 43, 179 }, ipv4BytesForMiddleProxyKdf(.{ 179, 43, 141, 146 }));
}

test "parse endpoint host" {
    try std.testing.expectEqualStrings("179.43.141.146", parseEndpointHost("179.43.141.146:41182").?);
    try std.testing.expectEqualStrings("vpn.example.com", parseEndpointHost("vpn.example.com:51820").?);
    try std.testing.expectEqualStrings("2001:db8::1", parseEndpointHost("[2001:db8::1]:41182").?);
}

test "parse awg endpoint ipv4 from config" {
    const content =
        \\[Interface]
        \\Address = 100.83.12.60/32
        \\
        \\[Peer]
        \\PublicKey = x
        \\Endpoint = 179.43.141.146:41182
    ;

    const parsed = (try parseAwgEndpointIpv4FromConfig(
        std.testing.allocator,
        content,
        null,
    )) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
}
