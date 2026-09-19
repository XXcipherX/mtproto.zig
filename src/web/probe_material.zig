//! Ephemeral material for the installer end-to-end WEB probe.
//!
//! TLS and WebSocket protocol handling live in a standard-library-only Python helper.
//! Permanent access secrets never leave this process: stdout contains only a derived
//! bridge capability and one-use cryptographic material fed to the helper over stdin.
const std = @import("std");
const config = @import("../config.zig");
const capability = @import("capability.zig");

const Probe = struct {
    request: [108]u8,
    response_key: [512]u8,
};

fn activeSecret(cfg: *const config.Config) ?[16]u8 {
    var users = @constCast(&cfg.users).iterator();
    const user = users.next() orelse return null;
    return user.value_ptr.*;
}

fn makeProbe(secret: [16]u8, initial: [64]u8, nonce: [16]u8, seconds: u64) Probe {
    var clear: [108]u8 = [_]u8{0} ** 108;
    defer std.crypto.secureZero(u8, &clear);
    @memcpy(clear[0..64], &initial);
    @memset(clear[56..60], 0xdd);
    std.mem.writeInt(i16, clear[60..62], 2, .little);
    std.mem.writeInt(u32, clear[64..68], 40, .little);
    std.mem.writeInt(u64, clear[76..84], seconds << 32, .little);
    std.mem.writeInt(u32, clear[84..88], 20, .little);
    std.mem.writeInt(u32, clear[88..92], 0xbe7e8ef1, .little); // req_pq_multi
    @memcpy(clear[92..108], &nonce);

    var material: [48]u8 = undefined;
    @memcpy(material[0..32], clear[8..40]);
    @memcpy(material[32..48], &secret);
    var encrypt_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &encrypt_key, .{});
    var reversed: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &reversed);
    for (&reversed, 0..) |*byte, index| byte.* = clear[55 - index];
    @memcpy(material[0..32], reversed[0..32]);
    var decrypt_key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material, &decrypt_key, .{});
    defer std.crypto.secureZero(u8, &material);
    defer std.crypto.secureZero(u8, &encrypt_key);
    defer std.crypto.secureZero(u8, &decrypt_key);

    var result: Probe = undefined;
    const encrypt = std.crypto.core.aes.Aes256.initEnc(encrypt_key);
    std.crypto.core.modes.ctr(@TypeOf(encrypt), encrypt, &result.request, &clear, clear[40..56].*, .big);
    @memcpy(result.request[0..56], clear[0..56]);
    const decrypt = std.crypto.core.aes.Aes256.initEnc(decrypt_key);
    const zeros = [_]u8{0} ** 512;
    std.crypto.core.modes.ctr(@TypeOf(decrypt), decrypt, &result.response_key, &zeros, reversed[32..48].*, .big);
    return result;
}

fn effectivePath(allocator: std.mem.Allocator, base_path: []const u8, suffix: []const u8, trailing_slash: bool) ![]u8 {
    if (base_path.len == 0) return allocator.dupe(u8, suffix);
    return if (trailing_slash)
        std.fmt.allocPrint(allocator, "/{s}/", .{base_path})
    else
        std.fmt.allocPrint(allocator, "/{s}{s}", .{ base_path, suffix });
}

/// Return sensitive, caller-owned JSON. The caller must write it only to the probe's
/// stdin and zero it before freeing.
pub fn render(allocator: std.mem.Allocator, cfg: *const config.Config) ![]u8 {
    const raw_domain = cfg.web.domain orelse return error.MissingDomain;
    var domain_buf: [capability.max_host_len]u8 = undefined;
    const domain = try capability.normalizeHost(raw_domain, &domain_buf);
    const base_path = cfg.web.effectiveBasePath();
    const bridge_path = try effectivePath(allocator, base_path, "/", true);
    defer allocator.free(bridge_path);
    const ws_path = try effectivePath(allocator, base_path, cfg.web.effectiveWsPath(), false);
    defer allocator.free(ws_path);

    var secret = activeSecret(cfg) orelse return error.NoActiveUsers;
    defer std.crypto.secureZero(u8, &secret);
    var bridge_capability = capability.deriveForPaddedSecret(domain, base_path, secret);
    defer std.crypto.secureZero(u8, &bridge_capability);
    const io = std.Io.Threaded.global_single_threaded.io();
    const seconds: u64 = @intCast(@max(0, std.Io.Clock.real.now(io).toSeconds()));
    var initial: [64]u8 = undefined;
    try std.Io.randomSecure(io, &initial);
    defer std.crypto.secureZero(u8, &initial);
    // Stay outside the reserved HTTP/TLS/transport signatures.
    initial[0] = 0x55;
    initial[4] = 0x55;
    var nonce: [16]u8 = undefined;
    try std.Io.randomSecure(io, &nonce);
    defer std.crypto.secureZero(u8, &nonce);
    var probe = makeProbe(secret, initial, nonce, seconds);
    defer std.crypto.secureZero(u8, &probe.request);
    defer std.crypto.secureZero(u8, &probe.response_key);

    var request_hex = std.fmt.bytesToHex(probe.request, .lower);
    defer std.crypto.secureZero(u8, &request_hex);
    var response_hex = std.fmt.bytesToHex(probe.response_key, .lower);
    defer std.crypto.secureZero(u8, &response_hex);
    var nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    defer std.crypto.secureZero(u8, &nonce_hex);
    var json: std.Io.Writer.Allocating = .init(allocator);
    defer {
        std.crypto.secureZero(u8, json.written());
        json.deinit();
    }
    try std.json.Stringify.value(.{
        .domain = domain,
        .bridge_path = bridge_path,
        .ws_path = ws_path,
        .capability = &bridge_capability,
        .request = &request_hex,
        .response_key = &response_hex,
        .nonce = &nonce_hex,
    }, .{}, &json.writer);
    return allocator.dupe(u8, json.written());
}

test "req_pq wire bytes and response key match the upstream independent vector" {
    var initial: [64]u8 = undefined;
    for (&initial, 1..) |*byte, index| byte.* = @intCast(index);
    var nonce: [16]u8 = undefined;
    for (&nonce, 0..) |*byte, index| byte.* = @intCast(index);
    const probe = makeProbe([_]u8{0x11} ** 16, initial, nonce, 1700000000);
    var expected: [108]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738fa994dc688e58644f6df46d7a17f438b1168566826f172a3bc770868794270d81b763e816ec6381ef8f6dd717296ca1b91149ee9");
    try std.testing.expectEqualSlices(u8, &expected, &probe.request);
    var expected_response: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_response, "7726db6e707a15c5ae6d2554e0b12fd729bef3d40840f58506daf8b14517554aa3d2bd4d597514940bf80d7c66ad5e15452ecba27b1bfa58164ff2ca83022692");
    try std.testing.expectEqualSlices(u8, &expected_response, probe.response_key[0..64]);
}
