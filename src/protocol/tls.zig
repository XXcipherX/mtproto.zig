//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

/// Re-export for convenience
pub const UserSecret = obfuscation.UserSecret;

// ============= TLS Validation Result =============

pub const TlsValidation = struct {
    /// Username that validated
    user: []const u8,
    /// Session ID from ClientHello
    session_id: []const u8,
    /// Client digest for response generation
    digest: [constants.tls_digest_len]u8,
    /// Timestamp extracted from digest
    timestamp: u32,
    /// The 16-byte user secret that matched (needed for ServerHello HMAC)
    secret: [16]u8,
};

// ============= Public Functions =============

/// Validate a TLS ClientHello against user secrets.
/// Returns validation result if a matching user is found.
pub fn validateTlsHandshake(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    ignore_time_skew: bool,
) !?TlsValidation {
    const min_len = constants.tls_digest_pos + constants.tls_digest_len + 1;
    if (handshake.len < min_len) return null;

    // Extract digest
    const digest: [constants.tls_digest_len]u8 = handshake[constants.tls_digest_pos..][0..constants.tls_digest_len].*;

    // Extract session ID
    const session_id_len_pos = constants.tls_digest_pos + constants.tls_digest_len;
    if (session_id_len_pos >= handshake.len) return null;
    const session_id_len: usize = handshake[session_id_len_pos];
    if (session_id_len > 32) return null;

    const session_id_start = session_id_len_pos + 1;
    if (handshake.len < session_id_start + session_id_len) return null;

    // Build message with zeroed digest for HMAC
    const msg = try allocator.alloc(u8, handshake.len);
    defer allocator.free(msg);
    @memcpy(msg, handshake);
    @memset(msg[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    const now: i64 = if (!ignore_time_skew)
        @intCast(std.time.timestamp())
    else
        0;

    for (secrets) |entry| {
        const computed = crypto.sha256Hmac(&entry.secret, msg);

        // Constant-time comparison of first 28 bytes using stdlib
        if (!std.crypto.timing_safe.eql([28]u8, digest[0..28].*, computed[0..28].*)) continue;

        // Extract timestamp from last 4 bytes (XOR)
        const timestamp = std.mem.readInt(u32, &[4]u8{
            digest[28] ^ computed[28],
            digest[29] ^ computed[29],
            digest[30] ^ computed[30],
            digest[31] ^ computed[31],
        }, .little);

        if (!ignore_time_skew) {
            const time_diff = now - @as(i64, @intCast(timestamp));
            if (time_diff < constants.time_skew_min or time_diff > constants.time_skew_max) {
                continue;
            }
        }

        return .{
            .user = entry.name,
            .session_id = handshake[session_id_start .. session_id_start + session_id_len],
            .digest = digest,
            .timestamp = timestamp,
            .secret = entry.secret,
        };
    }

    return null;
}

/// Build a fake TLS ServerHello response.
///
/// Includes ServerHello record, Change Cipher Spec, and a fake
/// Application Data record (mimicking encrypted certificates).
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    fake_cert_len: usize,
) ![]u8 {
    const cert_len = @max(64, @min(fake_cert_len, constants.max_tls_ciphertext_size));

    // Generate random X25519-like key (just random bytes for fake TLS)
    var x25519_key: [32]u8 = undefined;
    crypto.randomBytes(&x25519_key);

    const session_id_len: u8 = @intCast(session_id.len);

    // Extensions: key_share (x25519) + supported_versions (TLS 1.3)
    const key_share_ext = buildKeyShareExt(&x25519_key);
    const supported_versions_ext = [_]u8{
        0x00, 0x2b, // supported_versions
        0x00, 0x02, // length
        0x03, 0x04, // TLS 1.3
    };
    const extensions_len: u16 = @intCast(key_share_ext.len + supported_versions_ext.len);

    const body_len: u24 = @intCast(2 + // version
        32 + // random
        1 + session_id.len + // session_id
        2 + // cipher suite
        1 + // compression
        2 + key_share_ext.len + supported_versions_ext.len // extensions
    );

    // Pre-calculate total response size
    const record_len: u16 = @intCast(@as(u32, body_len) + 4);
    const server_hello_len = 5 + @as(usize, record_len);
    const ccs_len: usize = 6;
    const app_data_len = 5 + cert_len;
    const total_len = server_hello_len + ccs_len + app_data_len;

    const response = try allocator.alloc(u8, total_len);
    errdefer allocator.free(response);
    var pos: usize = 0;

    // --- ServerHello record ---
    // Record header
    response[pos] = constants.tls_record_handshake;
    pos += 1;
    @memcpy(response[pos..][0..2], &constants.tls_version);
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], record_len, .big);
    pos += 2;

    // Handshake header
    response[pos] = 0x02; // ServerHello type
    pos += 1;
    response[pos] = @intCast((body_len >> 16) & 0xff);
    response[pos + 1] = @intCast((body_len >> 8) & 0xff);
    response[pos + 2] = @intCast(body_len & 0xff);
    pos += 3;

    // Version (TLS 1.2 in header)
    @memcpy(response[pos..][0..2], &constants.tls_version);
    pos += 2;

    // Random (32 bytes placeholder — will be replaced with HMAC digest)
    const random_pos = pos;
    @memset(response[pos..][0..32], 0);
    pos += 32;

    // Session ID
    response[pos] = session_id_len;
    pos += 1;
    @memcpy(response[pos..][0..session_id.len], session_id);
    pos += session_id.len;

    // Cipher suite: TLS_AES_128_GCM_SHA256
    response[pos] = 0x13;
    response[pos + 1] = 0x01;
    pos += 2;

    // Compression: none
    response[pos] = 0x00;
    pos += 1;

    // Extensions
    std.mem.writeInt(u16, response[pos..][0..2], extensions_len, .big);
    pos += 2;
    @memcpy(response[pos..][0..key_share_ext.len], &key_share_ext);
    pos += key_share_ext.len;
    @memcpy(response[pos..][0..supported_versions_ext.len], &supported_versions_ext);
    pos += supported_versions_ext.len;

    // --- Change Cipher Spec record ---
    response[pos] = constants.tls_record_change_cipher;
    response[pos + 1] = constants.tls_version[0];
    response[pos + 2] = constants.tls_version[1];
    response[pos + 3] = 0x00;
    response[pos + 4] = 0x01;
    response[pos + 5] = 0x01;
    pos += 6;

    // --- Fake Application Data record ---
    response[pos] = constants.tls_record_application;
    pos += 1;
    @memcpy(response[pos..][0..2], &constants.tls_version);
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], @intCast(cert_len), .big);
    pos += 2;
    crypto.randomBytes(response[pos..][0..cert_len]);
    pos += cert_len;

    std.debug.assert(pos == total_len);

    // Compute HMAC for the response
    // hmac_input = client_digest || response
    const hmac_input = try allocator.alloc(u8, constants.tls_digest_len + total_len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], client_digest);
    @memcpy(hmac_input[constants.tls_digest_len..], response);
    const response_digest = crypto.sha256Hmac(secret, hmac_input);

    // Insert digest into ServerHello random field
    @memcpy(response[random_pos..][0..32], &response_digest);

    return response;
}

fn buildKeyShareExt(public_key: *const [32]u8) [40]u8 {
    var ext: [40]u8 = undefined;
    ext[0] = 0x00;
    ext[1] = 0x33; // key_share
    ext[2] = 0x00;
    ext[3] = 0x24; // length = 36
    ext[4] = 0x00;
    ext[5] = 0x1d; // x25519
    ext[6] = 0x00;
    ext[7] = 0x20; // key length = 32
    @memcpy(ext[8..40], public_key);
    return ext;
}

/// Check if bytes look like a TLS ClientHello.
pub fn isTlsHandshake(first_bytes: []const u8) bool {
    if (first_bytes.len < 3) return false;
    return first_bytes[0] == constants.tls_record_handshake and
        first_bytes[1] == 0x03 and
        (first_bytes[2] == 0x01 or first_bytes[2] == 0x03);
}

/// Extract SNI from a TLS ClientHello.
pub fn extractSni(handshake: []const u8) ?[]const u8 {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return null;

    const record_len = std.mem.readInt(u16, handshake[3..5], .big);
    if (handshake.len < @as(usize, 5) + record_len) return null;

    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return null; // not ClientHello

    pos += 4; // type + 3-byte length
    pos += 2 + 32; // version + random

    if (pos + 1 > handshake.len) return null;
    const session_id_len: usize = handshake[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > handshake.len) return null;
    const cipher_suites_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2 + cipher_suites_len;

    if (pos + 1 > handshake.len) return null;
    const comp_len: usize = handshake[pos];
    pos += 1 + comp_len;

    if (pos + 2 > handshake.len) return null;
    const ext_total_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total_len;
    if (ext_end > handshake.len) return null;

    // Walk extensions
    while (pos + 4 <= ext_end) {
        const etype = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        const elen = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + elen > ext_end) break;

        if (etype == 0x0000 and elen >= 5) {
            // server_name extension
            var sn_pos = pos + 2; // skip list_len
            const sn_end = @min(pos + elen, ext_end);
            while (sn_pos + 3 <= sn_end) {
                const name_type = handshake[sn_pos];
                const name_len = std.mem.readInt(u16, handshake[sn_pos + 1 ..][0..2], .big);
                sn_pos += 3;
                if (sn_pos + name_len > sn_end) break;
                if (name_type == 0 and name_len > 0) {
                    return handshake[sn_pos .. sn_pos + name_len];
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    return null;
}

// ============= Tests =============

test "isTlsHandshake" {
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x01 }));
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x16, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x17, 0x03, 0x03 }));
}

test "timing_safe.eql" {
    const a = [_]u8{ 1, 2, 3 };
    const b = [_]u8{ 1, 2, 3 };
    const c = [_]u8{ 1, 2, 4 };
    try std.testing.expect(std.crypto.timing_safe.eql([3]u8, a, b));
    try std.testing.expect(!std.crypto.timing_safe.eql([3]u8, a, c));
}

test "buildServerHello produces valid structure" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0x42} ** 32;
    const session_id = [_]u8{0x01} ** 32;

    const response = try buildServerHello(
        allocator,
        &digest,
        &digest,
        &session_id,
        256,
    );
    defer allocator.free(response);

    // Should start with TLS record handshake
    try std.testing.expectEqual(@as(u8, constants.tls_record_handshake), response[0]);
    // Version bytes
    try std.testing.expectEqual(@as(u8, 0x03), response[1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[2]);
    // Should have CCS record somewhere
    try std.testing.expect(response.len > 50);
}
