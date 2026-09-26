//! WEB-proxy trust and PROXY protocol helpers for the monolithic data plane.
//! Trust is always decided from the kernel-reported peer before a PROXY header
//! can replace the diagnostic/client address.

const std = @import("std");
const net = @import("../net_helpers.zig");
pub const DnsCache = @import("../web/dns_cache.zig").Cache;

/// WEB terminator addresses refresh independently; failed lookups keep the last snapshot.
pub fn createMaskDns(allocator: std.mem.Allocator, spec: []const u8) !*DnsCache {
    const helpers = @import("../web/net_helpers.zig");
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.InvalidWebMaskBackend;
    const host = std.mem.trim(u8, spec[0..colon], "[] ");
    const port = try std.fmt.parseInt(u16, spec[colon + 1 ..], 10);
    if (host.len == 0 or port == 0) return error.InvalidWebMaskBackend;
    const cache = try DnsCache.create(allocator);
    errdefer cache.destroy();
    const list = helpers.getAddressList(allocator, host, port) catch null;
    defer if (list) |addresses| addresses.deinit();
    _ = try cache.add(host, port, if (list) |addresses| helpers.AddressCandidates.init(addresses.addrs) else .{});
    return cache;
}

pub const TrustedPeers = struct {
    enabled: bool = false,
    extra: []const net.Address = &.{},

    pub fn contains(self: *const TrustedPeers, addr: net.Address) bool {
        if (!self.enabled) return false;
        if (isLoopback(addr)) return true;
        for (self.extra) |candidate| {
            if (sameHost(candidate, addr)) return true;
        }
        return false;
    }
};

pub fn parseSources(allocator: std.mem.Allocator, sources: []const []const u8) ![]net.Address {
    if (sources.len == 0) return &.{};
    var out: std.ArrayList(net.Address) = .empty;
    errdefer out.deinit(allocator);
    for (sources) |source| {
        const text = std.mem.trim(u8, source, " \t");
        const parsed = std.Io.net.IpAddress.parse(text, 0) catch continue;
        try out.append(allocator, parsed);
    }
    if (out.items.len == 0) {
        out.deinit(allocator);
        return &.{};
    }
    return try out.toOwnedSlice(allocator);
}

fn normalized(addr: net.Address) net.Address {
    return switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
}

pub fn isLoopback(raw: net.Address) bool {
    const addr = normalized(raw);
    return switch (addr) {
        .ip4 => |v4| v4.bytes[0] == 127,
        .ip6 => |v6| std.mem.allEqual(u8, v6.bytes[0..15], 0) and v6.bytes[15] == 1,
    };
}

pub fn sameHost(a_raw: net.Address, b_raw: net.Address) bool {
    const a = normalized(a_raw);
    const b = normalized(b_raw);
    return switch (a) {
        .ip4 => |v4| switch (b) {
            .ip4 => |other| std.mem.eql(u8, &v4.bytes, &other.bytes),
            .ip6 => false,
        },
        .ip6 => |v6| switch (b) {
            .ip4 => false,
            .ip6 => |other| std.mem.eql(u8, &v6.bytes, &other.bytes) and
                v6.interface.index == other.interface.index,
        },
    };
}

pub const ParseResult = union(enum) {
    incomplete,
    invalid,
    ok: struct { consumed: usize, src: ?net.Address },
};

const v2_sig = [_]u8{ 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };

/// Parse the binary PROXY v2 form emitted by the WEB relay and terminator path.
pub fn parseProxyV2(buf: []const u8) ParseResult {
    if (buf.len == 0) return .incomplete;
    if (buf[0] != v2_sig[0]) return .invalid;
    if (buf.len < v2_sig.len) return if (std.mem.startsWith(u8, &v2_sig, buf)) .incomplete else .invalid;
    if (!std.mem.eql(u8, buf[0..v2_sig.len], &v2_sig)) return .invalid;
    if (buf.len < 16) return .incomplete;
    if (buf[12] >> 4 != 2) return .invalid;
    const payload_len = std.mem.readInt(u16, buf[14..16], .big);
    const total = 16 + @as(usize, payload_len);
    if (total > 256) return .invalid;
    if (buf.len < total) return .incomplete;
    if ((buf[12] & 0x0f) == 0) return .{ .ok = .{ .consumed = total, .src = null } };
    if ((buf[12] & 0x0f) != 1 or (buf[13] & 0x0f) != 1) return .invalid;
    return switch (buf[13] >> 4) {
        1 => if (payload_len < 12) .invalid else .{ .ok = .{
            .consumed = total,
            .src = net.ip4(buf[16..20].*, std.mem.readInt(u16, buf[24..26], .big)),
        } },
        2 => if (payload_len < 36) .invalid else .{ .ok = .{
            .consumed = total,
            .src = net.ip6(buf[16..32].*, std.mem.readInt(u16, buf[48..50], .big), 0, 0),
        } },
        else => .invalid,
    };
}

pub fn buildProxyV2(buf: *[64]u8, src_raw: ?net.Address, dst_raw: net.Address) []const u8 {
    @memcpy(buf[0..12], &v2_sig);
    const src = if (src_raw) |value| normalized(value) else null;
    const dst = normalized(dst_raw);
    if (src) |source| {
        if (source == .ip4) {
            const dst_bytes: [4]u8 = switch (dst) {
                .ip4 => |v4| v4.bytes,
                .ip6 => .{ 127, 0, 0, 1 },
            };
            buf[12] = 0x21;
            buf[13] = 0x11;
            std.mem.writeInt(u16, buf[14..16], 12, .big);
            @memcpy(buf[16..20], &source.ip4.bytes);
            @memcpy(buf[20..24], &dst_bytes);
            std.mem.writeInt(u16, buf[24..26], source.ip4.port, .big);
            std.mem.writeInt(u16, buf[26..28], dst.getPort(), .big);
            return buf[0..28];
        }
        if (source == .ip6) {
            const dst_bytes: [16]u8 = std.Io.net.Ip6Address.fromAny(dst).bytes;
            buf[12] = 0x21;
            buf[13] = 0x21;
            std.mem.writeInt(u16, buf[14..16], 36, .big);
            @memcpy(buf[16..32], &source.ip6.bytes);
            @memcpy(buf[32..48], &dst_bytes);
            std.mem.writeInt(u16, buf[48..50], source.ip6.port, .big);
            std.mem.writeInt(u16, buf[50..52], dst.getPort(), .big);
            return buf[0..52];
        }
    }
    buf[12] = 0x20;
    buf[13] = 0;
    std.mem.writeInt(u16, buf[14..16], 0, .big);
    return buf[0..16];
}

test "trusted WEB peers match loopback and configured addresses without ports" {
    const sources = [_][]const u8{ "10.200.200.1", "not-an-ip" };
    const parsed = try parseSources(std.testing.allocator, &sources);
    defer if (parsed.len > 0) std.testing.allocator.free(parsed);

    try std.testing.expectEqual(@as(usize, 1), parsed.len);
    const peers = TrustedPeers{ .enabled = true, .extra = parsed };
    try std.testing.expect(peers.contains(net.ip4(.{ 127, 9, 8, 7 }, 1234)));
    try std.testing.expect(peers.contains(net.ip4(.{ 10, 200, 200, 1 }, 54321)));
    try std.testing.expect(!peers.contains(net.ip4(.{ 10, 200, 200, 2 }, 54321)));
}

test "PROXY v2 round trip preserves the IPv4 client address" {
    const src = net.ip4(.{ 203, 0, 113, 7 }, 45678);
    const dst = net.ip4(.{ 127, 0, 0, 1 }, 8444);
    var buf: [64]u8 = undefined;
    const header = buildProxyV2(&buf, src, dst);
    const parsed = parseProxyV2(header);
    try std.testing.expect(parsed == .ok);
    try std.testing.expectEqual(header.len, parsed.ok.consumed);
    const parsed_src = parsed.ok.src.?;
    try std.testing.expect(net.Address.eql(&src, &parsed_src));
}

test "PROXY v2 preserves IPv6 client and maps an IPv4 destination" {
    const src = net.ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 }, 45678, 0, 0);
    const dst = net.ip4(.{ 127, 0, 0, 1 }, 8444);
    const mapped_dst = std.Io.net.Ip6Address.fromAny(dst);
    var buf: [64]u8 = undefined;
    const header = buildProxyV2(&buf, src, dst);
    try std.testing.expectEqual(@as(usize, 52), header.len);
    try std.testing.expectEqualSlices(u8, &src.ip6.bytes, header[16..32]);
    try std.testing.expectEqualSlices(u8, &mapped_dst.bytes, header[32..48]);
    try std.testing.expectEqual(@as(u16, 45678), std.mem.readInt(u16, header[48..50], .big));
    try std.testing.expectEqual(@as(u16, 8444), std.mem.readInt(u16, header[50..52], .big));
    const parsed = parseProxyV2(header);
    try std.testing.expect(parsed == .ok);
    try std.testing.expect(net.exactAddressEql(src, parsed.ok.src.?));
}
