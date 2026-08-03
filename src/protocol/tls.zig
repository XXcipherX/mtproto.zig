//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const compat = @import("../compat.zig");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

/// Re-export for convenience
pub const UserSecret = obfuscation.UserSecret;

// ============= TLS Validation Result =============

pub const TlsValidation = struct {
    /// Username that validated
    user: []const u8,
    /// Session ID copied from ClientHello.
    session_id: [32]u8,
    /// Client digest for response generation
    digest: [constants.tls_digest_len]u8,
    /// Canonical HMAC before timestamp XOR masking (for replay protection)
    canonical_hmac: [constants.tls_digest_len]u8,
    /// Timestamp extracted from digest
    timestamp: u32,
    /// The 16-byte user secret that matched (needed for ServerHello HMAC)
    secret: [16]u8,

    /// Wipe copied authentication material without overwriting the borrowed
    /// username pointer with an invalid pointer representation.
    pub fn wipe(self: *TlsValidation) void {
        std.crypto.secureZero(u8, &self.session_id);
        std.crypto.secureZero(u8, &self.digest);
        std.crypto.secureZero(u8, &self.canonical_hmac);
        std.crypto.secureZero(u8, &self.secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.timestamp));
    }
};

const ParsedClientHello = struct {
    digest: []const u8,
    session_id: []const u8,
    sni: ?[]const u8,
    first_tls13_cipher: ?u16,
    offers_pq_key_share: bool,
};

/// Parse the ClientHello record once and enforce all nested outer lengths.
/// Feature-specific readers below consume only slices produced by this parser.
fn parseClientHello(handshake: []const u8) ?ParsedClientHello {
    if (handshake.len < 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2) return null;
    if (handshake[0] != constants.tls_record_handshake) return null;
    if (handshake[1] != 0x03 or (handshake[2] != 0x01 and handshake[2] != 0x03)) return null;

    const record_len: usize = std.mem.readInt(u16, handshake[3..5], .big);
    if (record_len != handshake.len - 5) return null;
    if (handshake[5] != 0x01) return null;
    const hello_len: usize = std.mem.readInt(u24, handshake[6..9], .big);
    if (hello_len != record_len - 4) return null;

    var pos: usize = 9;
    if (2 + 32 > handshake.len - pos) return null;
    pos += 2;
    const digest = handshake[pos .. pos + 32];
    pos += 32;

    if (pos >= handshake.len) return null;
    const session_id_len: usize = handshake[pos];
    pos += 1;
    if (session_id_len > 32 or session_id_len > handshake.len - pos) return null;
    const session_id = handshake[pos .. pos + session_id_len];
    pos += session_id_len;

    if (2 > handshake.len - pos) return null;
    const cipher_suites_len: usize = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (cipher_suites_len < 2 or cipher_suites_len % 2 != 0 or cipher_suites_len > handshake.len - pos) return null;
    const cipher_suites = handshake[pos .. pos + cipher_suites_len];
    pos += cipher_suites_len;

    var first_tls13_cipher: ?u16 = null;
    var cipher_pos: usize = 0;
    while (cipher_pos < cipher_suites.len) : (cipher_pos += 2) {
        const suite = std.mem.readInt(u16, cipher_suites[cipher_pos..][0..2], .big);
        if ((suite & 0x0f0f) == 0x0a0a) continue;
        if (suite == 0x1301 or suite == 0x1302 or suite == 0x1303) {
            first_tls13_cipher = suite;
            break;
        }
    }

    if (pos >= handshake.len) return null;
    const compression_len: usize = handshake[pos];
    pos += 1;
    if (compression_len == 0 or compression_len > handshake.len - pos) return null;
    pos += compression_len;

    if (2 > handshake.len - pos) return null;
    const extensions_len: usize = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (extensions_len != handshake.len - pos) return null;
    const extensions = handshake[pos..];

    var ext_pos: usize = 0;
    var sni: ?[]const u8 = null;
    var seen_sni = false;
    var seen_key_share = false;
    var offers_pq_key_share = false;
    while (ext_pos < extensions.len) {
        if (extensions.len - ext_pos < 4) return null;
        const ext_type = std.mem.readInt(u16, extensions[ext_pos..][0..2], .big);
        const ext_len: usize = std.mem.readInt(u16, extensions[ext_pos + 2 ..][0..2], .big);
        ext_pos += 4;
        if (ext_len > extensions.len - ext_pos) return null;
        const payload = extensions[ext_pos .. ext_pos + ext_len];

        if (ext_type == 0x0000) {
            if (seen_sni or payload.len < 2) return null;
            seen_sni = true;
            const names_len: usize = std.mem.readInt(u16, payload[0..2], .big);
            if (names_len != payload.len - 2) return null;
            var name_pos: usize = 2;
            while (name_pos < payload.len) {
                if (payload.len - name_pos < 3) return null;
                const name_type = payload[name_pos];
                const name_len: usize = std.mem.readInt(u16, payload[name_pos + 1 ..][0..2], .big);
                name_pos += 3;
                if (name_len > payload.len - name_pos) return null;
                if (name_type == 0) {
                    if (name_len == 0 or sni != null) return null;
                    sni = payload[name_pos .. name_pos + name_len];
                }
                name_pos += name_len;
            }
        } else if (ext_type == 0x0033) {
            if (seen_key_share or payload.len < 2) return null;
            seen_key_share = true;
            const shares_len: usize = std.mem.readInt(u16, payload[0..2], .big);
            if (shares_len != payload.len - 2) return null;
            var share_pos: usize = 2;
            while (share_pos < payload.len) {
                if (payload.len - share_pos < 4) return null;
                const group = std.mem.readInt(u16, payload[share_pos..][0..2], .big);
                const key_len: usize = std.mem.readInt(u16, payload[share_pos + 2 ..][0..2], .big);
                share_pos += 4;
                if (key_len == 0 or key_len > payload.len - share_pos) return null;
                if (group == pq_named_group) {
                    if (key_len != pq_client_key_share_len or offers_pq_key_share) return null;
                    offers_pq_key_share = true;
                } else if (group == 0x001d and key_len != 32) {
                    return null;
                }
                share_pos += key_len;
            }
        }
        ext_pos += ext_len;
    }

    return .{
        .digest = digest,
        .session_id = session_id,
        .sni = sni,
        .first_tls13_cipher = first_tls13_cipher,
        .offers_pq_key_share = offers_pq_key_share,
    };
}

// ============= Public Functions =============

/// Validate a TLS ClientHello against user secrets.
/// Returns validation result if a matching user is found.
pub fn validateTlsHandshake(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    ignore_time_skew: bool,
) !?TlsValidation {
    _ = allocator;

    const parsed = parseClientHello(handshake) orelse return null;
    if (parsed.digest.ptr != handshake[constants.tls_digest_pos..].ptr) return null;
    if (parsed.session_id.len != 32) return null;
    var digest: [constants.tls_digest_len]u8 = parsed.digest[0..constants.tls_digest_len].*;
    defer std.crypto.secureZero(u8, &digest);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const zero_digest = [_]u8{0} ** constants.tls_digest_len;

    const now: i64 = if (!ignore_time_skew)
        compat.timestamp()
    else
        0;

    for (secrets) |*entry| {
        var hmac = HmacSha256.init(&entry.secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
        hmac.update(handshake[0..constants.tls_digest_pos]);
        hmac.update(zero_digest[0..]);
        hmac.update(handshake[constants.tls_digest_pos + constants.tls_digest_len ..]);
        var computed: [constants.tls_digest_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &computed);
        hmac.final(&computed);

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
            .session_id = parsed.session_id[0..32].*,
            .digest = digest,
            .canonical_hmac = computed,
            .timestamp = timestamp,
            .secret = entry.secret,
        };
    }

    return null;
}

/// Build a fake TLS ServerHello response using a pre-built TLS 1.3 server template.
///
/// The response consists of three TLS records that the client validates:
/// 1. ServerHello record (type 0x16) — contains the HMAC digest in the `random` field
/// 2. Change Cipher Spec record (type 0x14) — fixed 6 bytes
/// 3. Fake Application Data record (type 0x17) — fixed-size body simulating encrypted cert
///
/// Template approach: use a comptime-built normal TLS 1.3 ServerHello shape:
/// - Extensions in common server order: supported_versions THEN key_share
/// - Fixed AppData size (consistent like a real certificate, not random)
/// - Deterministic pseudo-random AppData body (high entropy, same every time)
///
/// Only three fields are patched at runtime:
/// - Server Random (offset 11..43): HMAC-SHA256 digest
/// - Session ID (offset 44..76): echoed from ClientHello
/// - X25519 key (offset 95..127): fresh random key
///
/// The client (ConnectionSocket.cpp) validates the response by:
/// - Checking for `\x16\x03\x03` prefix (ServerHello record)
/// - Reading len1 (ServerHello record payload length)
/// - Checking for `\x14\x03\x03\x00\x01\x01\x17\x03\x03` after the ServerHello record
/// - Reading len2 (Application Data payload length)
/// - Waiting for all `len1 + 5 + 11 + len2` bytes
/// - Saving bytes at offset 11..43 (the random field), zeroing them
/// - Computing HMAC-SHA256(secret, client_digest || entire_response_with_zeroed_random)
/// - Comparing the HMAC to the saved random field (straight 32-byte compare, no XOR)
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
) ![]u8 {
    return buildServerHelloWithTemplate(allocator, &server_template, secret, client_digest, session_id);
}

pub fn buildServerHelloWithTemplate(
    allocator: std.mem.Allocator,
    template: []const u8,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
) ![]u8 {
    return buildServerHelloWithTemplateCipher(allocator, template, secret, client_digest, session_id, null);
}

pub fn buildServerHelloWithTemplateCipher(
    allocator: std.mem.Allocator,
    template: []const u8,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
) ![]u8 {
    const cert_payload_size = templateFakeCertPayloadSize(template) orelse return error.BadServerHelloTemplate;
    if (session_id.len != 32) return error.InvalidSessionIdLength;

    // 1. Copy the pre-built template (random and session_id are zeroed in template)
    const response = try allocator.alloc(u8, template.len);
    errdefer allocator.free(response);
    @memcpy(response, template);
    @memset(response[tmpl_random_offset..][0..32], 0);

    // 1b. Echo a client-offered TLS 1.3 cipher when known. Real servers negotiate
    // one of the offered suites; a hard-coded suite is a passive ServerHello tell.
    if (cipher) |cs| {
        std.mem.writeInt(u16, response[tmpl_cipher_offset..][0..2], cs, .big);
    }

    // 2. Patch Session ID (echo from client). Template assumes 32-byte session ID.
    @memcpy(response[tmpl_session_id_offset..][0..32], session_id);

    // 3. Patch a canonical X25519 public key. Arbitrary random bytes are not a
    // valid encoding distribution and expose a passive high-bit fingerprint.
    const x25519_key = try randomX25519PublicKey();
    @memcpy(response[tmpl_x25519_key_offset..][0..32], &x25519_key);

    // 3b. Randomize fake encrypted-certificate AppData per connection. TLS 1.3
    // certificate bytes are encrypted under fresh ECDHE keys, so identical
    // ciphertext across connections is a fingerprint.
    crypto.randomBytes(response[server_hello_prefix_len..][0..cert_payload_size]);

    // 4. Compute HMAC over the full response with the random field explicitly
    // zeroed. Correctness does not depend on caller-provided template contents.
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
    hmac.update(client_digest[0..]);
    hmac.update(response);
    var response_digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_digest);
    hmac.final(&response_digest);

    // 5. Insert HMAC digest into Server Random field
    @memcpy(response[tmpl_random_offset..][0..32], &response_digest);

    return response;
}

// ============= Post-quantum X25519MLKEM768 ServerHello =============
//
// Modern Telegram Desktop/Android ClientHellos can offer X25519MLKEM768
// (named group 0x11ec). Answering such a flow with plain x25519 (0x001d)
// is a passive group-downgrade tell, so when the client provided a 0x11ec
// key_share we emit a 0x11ec ServerHello key_share of the correct wire size.
//
// The ML-KEM ciphertext bytes are intentionally high-entropy placeholders,
// not a real encapsulation; the X25519 suffix is a canonical derived public
// key. MTProto FakeTLS clients validate framing plus the server-random HMAC.

pub const pq_named_group: u16 = 0x11ec;
/// X25519MLKEM768 client share: ML-KEM-768 public key (1184) || X25519 (32).
const pq_client_key_share_len: usize = 1216;
const pq_mlkem_ciphertext_len: usize = 1088;
/// X25519MLKEM768 server share: ML-KEM-768 ciphertext (1088) || X25519 (32).
const pq_key_share_len: usize = 1120;
/// PQ ServerHello record length: 5(rec hdr)+4(hs hdr)+2(ver)+32(rand)+1+32(sid)
/// +2(cipher)+1(comp)+2(extlen)+6(supported_versions)+4(ks ext hdr)
/// +2(group)+2(keylen)+1120(key) = 1215.
const pq_server_hello_record_len: usize = 95 + pq_key_share_len;
/// Full PQ response: ServerHello + CCS(6) + AppData(5 + cert payload).
pub const pq_server_hello_len: usize = pq_server_hello_record_len + 6 + 5 + fake_cert_payload_size;
/// Offset of the 1120-byte PQ key_share inside the response.
const pq_key_offset: usize = 95;
/// Offset of the fake AppData body inside the PQ response.
const pq_appdata_offset: usize = pq_server_hello_record_len + 6 + 5;

/// Return true when the ClientHello carries a key_share entry for X25519MLKEM768.
pub fn clientOffersPqKeyShare(handshake: []const u8) bool {
    return (parseClientHello(handshake) orelse return false).offers_pq_key_share;
}

/// Build a ServerHello that answers an X25519MLKEM768-offering client with a
/// 0x11ec key_share. Same HMAC-in-server-random construction as the x25519 path.
pub fn buildServerHelloPq(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
    cert_payload_size: usize,
) ![]u8 {
    if (session_id.len != 32) return error.InvalidSessionIdLength;
    if (!validFakeCertPayloadSize(cert_payload_size)) return error.InvalidFakeCertSize;

    const response_len = pqResponseLen(cert_payload_size);
    const response = try allocator.alloc(u8, response_len);
    errdefer allocator.free(response);
    @memset(response, 0);

    // Record 1: ServerHello with a 0x11ec key_share.
    response[0] = constants.tls_record_handshake;
    response[1] = 0x03;
    response[2] = 0x03;
    std.mem.writeInt(u16, response[3..][0..2], @intCast(pq_server_hello_record_len - 5), .big);
    response[5] = 0x02;
    std.mem.writeInt(u24, response[6..][0..3], @intCast(pq_server_hello_record_len - 9), .big);
    response[9] = 0x03;
    response[10] = 0x03;
    response[43] = 0x20;
    @memcpy(response[tmpl_session_id_offset..][0..32], session_id);
    std.mem.writeInt(u16, response[tmpl_cipher_offset..][0..2], cipher orelse 0x1301, .big);
    response[78] = 0x00;
    std.mem.writeInt(u16, response[79..][0..2], @intCast(6 + 4 + 4 + pq_key_share_len), .big);

    // supported_versions (0x002b) first, matching OpenSSL TLS 1.3 ordering.
    response[81] = 0x00;
    response[82] = 0x2b;
    response[83] = 0x00;
    response[84] = 0x02;
    response[85] = 0x03;
    response[86] = 0x04;

    // key_share (0x0033), group 0x11ec, key length 1120.
    response[87] = 0x00;
    response[88] = 0x33;
    std.mem.writeInt(u16, response[89..][0..2], @intCast(4 + pq_key_share_len), .big);
    std.mem.writeInt(u16, response[91..][0..2], pq_named_group, .big);
    std.mem.writeInt(u16, response[93..][0..2], @intCast(pq_key_share_len), .big);
    crypto.randomBytes(response[pq_key_offset..][0..pq_mlkem_ciphertext_len]);
    const x25519_key = try randomX25519PublicKey();
    @memcpy(response[pq_key_offset + pq_mlkem_ciphertext_len ..][0..32], &x25519_key);

    // Record 2: Change Cipher Spec.
    const ccs = pq_server_hello_record_len;
    response[ccs] = constants.tls_record_change_cipher;
    response[ccs + 1] = 0x03;
    response[ccs + 2] = 0x03;
    response[ccs + 3] = 0x00;
    response[ccs + 4] = 0x01;
    response[ccs + 5] = 0x01;

    // Record 3: fake encrypted certificate AppData.
    const app = ccs + 6;
    response[app] = constants.tls_record_application;
    response[app + 1] = 0x03;
    response[app + 2] = 0x03;
    std.mem.writeInt(u16, response[app + 3 ..][0..2], @intCast(cert_payload_size), .big);
    crypto.randomBytes(response[pq_appdata_offset..][0..cert_payload_size]);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
    hmac.update(client_digest[0..]);
    hmac.update(response);
    var response_digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_digest);
    hmac.final(&response_digest);
    @memcpy(response[tmpl_random_offset..][0..32], &response_digest);

    return response;
}

// ============= Static TLS 1.3 ServerHello Template =============
//
// Pre-built at comptime to match a normal TLS 1.3 server shape.
// Structure: ServerHello (127 bytes) + CCS (6 bytes) + AppData (5 + 2878 bytes)
//
// Key differences from naive FakeTLS that DPI detects:
// 1. Extension ordering: supported_versions (0x002b) BEFORE key_share (0x0033)
// 2. AppData size: fixed 2878 bytes (realistic Let's Encrypt ECDSA cert chain),
//    NOT random in [1024,4096) which is an entropy fingerprint
// 3. AppData body: deterministic pseudo-random (same across connections, like a real cert)

/// Offset of Server Random field (32 bytes) — patched with HMAC at runtime
const tmpl_random_offset: usize = 11;
/// Offset of Session ID (32 bytes) — echoed from client at runtime
const tmpl_session_id_offset: usize = 44;
/// Offset of the 2-byte cipher suite, immediately after the 32-byte session_id.
const tmpl_cipher_offset: usize = tmpl_session_id_offset + 32;
/// Offset of X25519 public key (32 bytes) — filled canonically at runtime
const tmpl_x25519_key_offset: usize = 95;

fn randomX25519PublicKey() ![32]u8 {
    var secret_key: [32]u8 = undefined;
    crypto.randomBytes(&secret_key);
    defer std.crypto.secureZero(u8, &secret_key);
    return std.crypto.dh.X25519.recoverPublicKey(secret_key);
}

/// Fake encrypted certificate payload size.
/// 2878 bytes matches a typical Let's Encrypt ECDSA P-256 cert chain:
///   EncryptedExtensions (~20) + Certificate (~2400) + CertificateVerify (~100) +
///   Finished (~36) + AEAD tags (~50) + record layer overhead.
/// Fixed size eliminates the random-range fingerprint that ТСПУ detects.
const fake_cert_payload_len: u16 = 2878;
const fake_cert_payload_size: usize = @as(usize, fake_cert_payload_len);
pub const default_fake_cert_size: usize = fake_cert_payload_size;
pub const min_fake_cert_size: usize = 256;
pub const max_fake_cert_size: usize = 16 * 1024;

/// Total template size: ServerHello(127) + CCS(6) + AppData(5 + 2878)
const server_template_len: usize = 127 + 6 + 5 + fake_cert_payload_size;
pub const server_hello_template_len: usize = server_template_len;
/// Fixed ServerHello+CCS+AppData-header prefix length.
const tmpl_appdata_offset: usize = server_template_len - fake_cert_payload_size;
pub const server_hello_prefix_len: usize = tmpl_appdata_offset;

const default_template_seed: u64 = 0x5365_7276_546C_7331;

/// The pre-built template, constructed at comptime.
const server_template: [server_template_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    break :blk buildStaticServerTemplate(default_template_seed);
};

pub fn buildServerHelloTemplate(seed: ?u64) [server_template_len]u8 {
    const actual_seed = seed orelse crypto.randomInt(u64);
    return buildStaticServerTemplate(actual_seed);
}

pub fn effectiveFakeCertSize(configured: u32) usize {
    if (configured == 0) return default_fake_cert_size;
    return @min(max_fake_cert_size, @max(min_fake_cert_size, @as(usize, configured)));
}

pub fn buildServerHelloTemplateAlloc(
    allocator: std.mem.Allocator,
    seed: ?u64,
    cert_payload_size: usize,
) ![]u8 {
    if (!validFakeCertPayloadSize(cert_payload_size)) return error.InvalidFakeCertSize;

    const actual_seed = seed orelse crypto.randomInt(u64);
    const template = try allocator.alloc(u8, server_hello_prefix_len + cert_payload_size);
    errdefer allocator.free(template);
    try fillServerHelloTemplate(template, actual_seed, cert_payload_size);
    return template;
}

pub fn firstAppDataRecordLen(records: []const u8) ?usize {
    var pos: usize = 0;
    while (pos + 5 <= records.len) {
        const typ = records[pos];
        const len = std.mem.readInt(u16, records[pos + 3 ..][0..2], .big);
        const body_start = pos + 5;
        const next = body_start + @as(usize, len);
        if (next > records.len) return null;
        if (typ == constants.tls_record_application) return @as(usize, len);
        pos = next;
    }
    return null;
}

pub fn pqResponseLen(cert_payload_size: usize) usize {
    return pq_server_hello_record_len + 6 + 5 + cert_payload_size;
}

fn validFakeCertPayloadSize(cert_payload_size: usize) bool {
    return cert_payload_size >= min_fake_cert_size and
        cert_payload_size <= max_fake_cert_size and
        cert_payload_size <= std.math.maxInt(u16);
}

fn templateFakeCertPayloadSize(template: []const u8) ?usize {
    if (template.len < server_hello_prefix_len) return null;
    const cert_payload_size = template.len - server_hello_prefix_len;
    if (!validFakeCertPayloadSize(cert_payload_size)) return null;
    if (firstAppDataRecordLen(template)) |record_len| {
        if (record_len == cert_payload_size) return cert_payload_size;
    }
    return null;
}

fn buildStaticServerTemplate(seed: u64) [server_template_len]u8 {
    var t: [server_template_len]u8 = undefined;
    fillServerHelloTemplate(t[0..], seed, fake_cert_payload_size) catch unreachable;
    return t;
}

fn fillServerHelloTemplate(t: []u8, seed: u64, cert_payload_size: usize) !void {
    if (t.len != server_hello_prefix_len + cert_payload_size) return error.BadServerHelloTemplate;
    if (!validFakeCertPayloadSize(cert_payload_size)) return error.InvalidFakeCertSize;

    var pos: usize = 0;

    // ── Record 1: ServerHello ──────────────────────────────────
    // Record header: type(1) + version(2) + length(2) = 5 bytes
    t[pos] = 0x16; // Handshake
    pos += 1;
    t[pos] = 0x03;
    t[pos + 1] = 0x03; // TLS 1.2 compat
    pos += 2;
    t[pos] = 0x00;
    t[pos + 1] = 0x7A; // Record payload length = 122
    pos += 2;

    // Handshake header: type(1) + length(3) = 4 bytes
    t[pos] = 0x02; // ServerHello
    pos += 1;
    t[pos] = 0x00;
    t[pos + 1] = 0x00;
    t[pos + 2] = 0x76; // Handshake body length = 118
    pos += 3;

    // Server version: TLS 1.2 (legacy, per RFC 8446)
    t[pos] = 0x03;
    t[pos + 1] = 0x03;
    pos += 2;

    // Server Random: 32 zero bytes (PLACEHOLDER — patched with HMAC at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // Session ID length: 32 (TLS 1.3 compatibility mode)
    t[pos] = 0x20;
    pos += 1;

    // Session ID: 32 zero bytes (PLACEHOLDER — echoed from client at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // Cipher suite: TLS_AES_128_GCM_SHA256 (0x1301), common TLS 1.3 default.
    t[pos] = 0x13;
    t[pos + 1] = 0x01;
    pos += 2;

    // Compression: none
    t[pos] = 0x00;
    pos += 1;

    // Extensions length: 46 bytes (supported_versions: 6 + key_share: 40)
    t[pos] = 0x00;
    t[pos + 1] = 0x2E;
    pos += 2;

    // Extension: supported_versions (0x002b) — OpenSSL sends this FIRST
    t[pos] = 0x00;
    t[pos + 1] = 0x2B;
    t[pos + 2] = 0x00;
    t[pos + 3] = 0x02; // length
    t[pos + 4] = 0x03;
    t[pos + 5] = 0x04; // TLS 1.3
    pos += 6;

    // Extension: key_share (0x0033) — x25519
    t[pos] = 0x00;
    t[pos + 1] = 0x33;
    t[pos + 2] = 0x00;
    t[pos + 3] = 0x24; // length = 36
    t[pos + 4] = 0x00;
    t[pos + 5] = 0x1D; // x25519 group
    t[pos + 6] = 0x00;
    t[pos + 7] = 0x20; // key length = 32
    pos += 8;

    // X25519 public key: 32 zero bytes (placeholder — derived at runtime)
    for (0..32) |i| {
        t[pos + i] = 0x00;
    }
    pos += 32;

    // ── Record 2: Change Cipher Spec ──────────────────────────
    t[pos] = 0x14; // CCS type
    t[pos + 1] = 0x03;
    t[pos + 2] = 0x03; // TLS 1.2
    t[pos + 3] = 0x00;
    t[pos + 4] = 0x01; // length = 1
    t[pos + 5] = 0x01; // CCS byte
    pos += 6;

    // ── Record 3: Fake Application Data (encrypted certificate) ─
    t[pos] = 0x17; // Application Data type
    t[pos + 1] = 0x03;
    t[pos + 2] = 0x03; // TLS 1.2
    std.mem.writeInt(u16, t[pos + 3 ..][0..2], @intCast(cert_payload_size), .big);
    pos += 5;

    // Fill with deterministic pseudo-random bytes (SplitMix64).
    // Looks like encrypted data to DPI, same every time like a real cert.
    var prng_state: u64 = seed;
    for (0..cert_payload_size) |i| {
        prng_state +%= 0x9E3779B97F4A7C15;
        var z = prng_state;
        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
        z = z ^ (z >> 31);
        t[pos + i] = @intCast((z >> 24) & 0xFF);
    }
    pos += cert_payload_size;

    if (pos != t.len) return error.BadServerHelloTemplate;
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
    return (parseClientHello(handshake) orelse return null).sni;
}

/// Return the first non-GREASE TLS 1.3 cipher suite offered by the client.
/// Used to make the synthetic ServerHello track the ClientHello like a real server.
pub fn extractFirstTls13Cipher(handshake: []const u8) ?u16 {
    return (parseClientHello(handshake) orelse return null).first_tls13_cipher;
}

// ============= Tests =============

fn buildTestClientHello(comptime session_id_len: usize, session_fill: u8) [52 + session_id_len]u8 {
    var hello = [_]u8{0} ** (52 + session_id_len);
    hello[0] = constants.tls_record_handshake;
    hello[1] = 0x03;
    hello[2] = 0x01;
    std.mem.writeInt(u16, hello[3..5], @intCast(hello.len - 5), .big);
    hello[5] = 0x01;
    std.mem.writeInt(u24, hello[6..9], @intCast(hello.len - 9), .big);
    hello[9] = 0x03;
    hello[10] = 0x03;
    hello[43] = @intCast(session_id_len);
    @memset(hello[44..][0..session_id_len], session_fill);
    var pos: usize = 44 + session_id_len;
    std.mem.writeInt(u16, hello[pos..][0..2], 2, .big);
    pos += 2;
    std.mem.writeInt(u16, hello[pos..][0..2], 0x1301, .big);
    pos += 2;
    hello[pos] = 1;
    hello[pos + 1] = 0;
    pos += 2;
    std.mem.writeInt(u16, hello[pos..][0..2], 0, .big);
    return hello;
}

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

test "buildServerHello produces valid three-record server template structure" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0x42} ** 32;
    const session_id = [_]u8{0x01} ** 32;

    const response = try buildServerHello(
        allocator,
        &digest,
        &digest,
        &session_id,
    );
    defer allocator.free(response);

    // Template produces fixed-size response
    try std.testing.expectEqual(server_template_len, response.len);

    // Record 1: ServerHello (\x16\x03\x03)
    try std.testing.expectEqual(@as(u8, constants.tls_record_handshake), response[0]);
    try std.testing.expectEqual(@as(u8, 0x03), response[1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[2]);

    const len1 = std.mem.readInt(u16, response[3..5], .big);
    try std.testing.expectEqual(@as(u16, 122), len1); // Fixed ServerHello payload
    const ccs_start = 5 + @as(usize, len1);

    // Record 2: Change Cipher Spec (\x14\x03\x03\x00\x01\x01)
    try std.testing.expect(response.len > ccs_start + 6);
    try std.testing.expectEqual(@as(u8, constants.tls_record_change_cipher), response[ccs_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 2]);
    try std.testing.expectEqual(@as(u8, 0x00), response[ccs_start + 3]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 4]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 5]);

    // Record 3: Application Data (\x17\x03\x03)
    const app_start = ccs_start + 6;
    try std.testing.expect(response.len > app_start + 5);
    try std.testing.expectEqual(@as(u8, constants.tls_record_application), response[app_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 2]);

    const len2 = std.mem.readInt(u16, response[app_start + 3 ..][0..2], .big);
    // AppData is fixed-size by default, not random-length.
    try std.testing.expectEqual(fake_cert_payload_len, len2);

    // Total response length should match all three records
    try std.testing.expectEqual(5 + @as(usize, len1) + 6 + 5 + @as(usize, len2), response.len);

    // Extension ordering: supported_versions (0x002b) BEFORE key_share (0x0033)
    // Extensions start at offset 81
    try std.testing.expectEqual(@as(u8, 0x00), response[81]); // supported_versions ext type hi
    try std.testing.expectEqual(@as(u8, 0x2B), response[82]); // supported_versions ext type lo
    try std.testing.expectEqual(@as(u8, 0x00), response[87]); // key_share ext type hi
    try std.testing.expectEqual(@as(u8, 0x33), response[88]); // key_share ext type lo

    // Session ID was echoed correctly
    try std.testing.expectEqualSlices(u8, &session_id, response[tmpl_session_id_offset..][0..32]);

    // HMAC digest is at offset 11 (tls_digest_pos) in the response
    // Verify it by recomputing: HMAC(secret, client_digest || response_with_zeroed_random)
    var zeroed = try allocator.alloc(u8, response.len);
    defer allocator.free(zeroed);
    @memcpy(zeroed, response);
    @memset(zeroed[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    var hmac_input = try allocator.alloc(u8, constants.tls_digest_len + response.len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], &digest);
    @memcpy(hmac_input[constants.tls_digest_len..], zeroed);

    const expected_hmac = crypto.sha256Hmac(&digest, hmac_input);
    try std.testing.expect(std.crypto.timing_safe.eql(
        [32]u8,
        response[constants.tls_digest_pos..][0..32].*,
        expected_hmac,
    ));
}

test "buildServerHello AppData: fixed length, per-connection-random body" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;

    // Build two responses: size stays fixed, encrypted-cert bytes vary per connection.
    const r1 = try buildServerHello(allocator, &digest, &digest, &session_id);
    defer allocator.free(r1);
    const r2 = try buildServerHello(allocator, &digest, &digest, &session_id);
    defer allocator.free(r2);

    // Same total size (fixed template)
    try std.testing.expectEqual(r1.len, r2.len);

    const app_offset = server_hello_prefix_len; // after ServerHello + CCS + AppData header
    try std.testing.expect(!std.mem.eql(u8, r1[app_offset..], r2[app_offset..]));
}

test "buildServerHelloTemplate depends on seed" {
    const t1 = buildServerHelloTemplate(0x1111_2222_3333_4444);
    const t2 = buildServerHelloTemplate(0x5555_6666_7777_8888);

    const app_offset = server_hello_prefix_len;
    try std.testing.expect(!std.mem.eql(u8, t1[app_offset..], t2[app_offset..]));
}

test "buildServerHelloTemplateAlloc supports custom fake cert size" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;
    const cert_size: usize = 4096;

    const template = try buildServerHelloTemplateAlloc(allocator, 0x1111_2222_3333_4444, cert_size);
    defer allocator.free(template);
    try std.testing.expectEqual(server_hello_prefix_len + cert_size, template.len);
    try std.testing.expectEqual(@as(?usize, cert_size), firstAppDataRecordLen(template));

    const resp = try buildServerHelloWithTemplateCipher(allocator, template, &digest, &digest, &session_id, 0x1302);
    defer allocator.free(resp);
    try std.testing.expectEqual(server_hello_prefix_len + cert_size, resp.len);
    try std.testing.expectEqual(@as(?usize, cert_size), firstAppDataRecordLen(resp));
    try std.testing.expectEqual(@as(u16, 0x1302), std.mem.readInt(u16, resp[tmpl_cipher_offset..][0..2], .big));
}

test "effectiveFakeCertSize clamps explicit values and keeps zero default" {
    try std.testing.expectEqual(default_fake_cert_size, effectiveFakeCertSize(0));
    try std.testing.expectEqual(min_fake_cert_size, effectiveFakeCertSize(1));
    try std.testing.expectEqual(@as(usize, 4096), effectiveFakeCertSize(4096));
    try std.testing.expectEqual(max_fake_cert_size, effectiveFakeCertSize(99999));
}

test "firstAppDataRecordLen rejects truncated records" {
    const template = buildServerHelloTemplate(0x1111_2222_3333_4444);
    try std.testing.expectEqual(@as(?usize, default_fake_cert_size), firstAppDataRecordLen(template[0..]));
    try std.testing.expect(firstAppDataRecordLen(template[0 .. template.len - 1]) == null);
}

test "validateTlsHandshake - valid handshake" {
    const allocator = std.testing.allocator;

    // Create mock secrets
    var secrets = [_]UserSecret{
        .{ .name = "alice", .secret = [_]u8{0x1A} ** 16 },
        .{ .name = "bob", .secret = [_]u8{0x2B} ** 16 },
    };

    // Client hello mock with 32-byte session_id, matching the ServerHello template contract.
    var handshake = buildTestClientHello(32, 0xaa);
    // Set timestamp (say 123456789 = 0x075BCD15)
    // Wait, the client sends digest WITH timestamp XOR'd in the last 4 bytes.
    // If ignore_time_skew = true, the proxy doesn't care what timestamp is.
    // Proxy calculates HMAC on handshake with zeroed digest, then expects it to match (up to 28 bytes) the given digest.

    const hmac_input = buildTestClientHello(32, 0xaa);

    // Compute HMAC
    const computed_mac = crypto.sha256Hmac(&secrets[1].secret, &hmac_input);

    // Create the actual handshake by copying hmac_input and setting the digest with some timestamp
    @memcpy(&handshake, &hmac_input);
    @memcpy(handshake[constants.tls_digest_pos..][0..28], computed_mac[0..28]);

    // XOR timestamp into the last 4 bytes of digest
    const timestamp: u32 = 0x12345678;
    const ts_bytes = std.mem.toBytes(timestamp);
    handshake[constants.tls_digest_pos + 28] = computed_mac[28] ^ ts_bytes[0];
    handshake[constants.tls_digest_pos + 29] = computed_mac[29] ^ ts_bytes[1];
    handshake[constants.tls_digest_pos + 30] = computed_mac[30] ^ ts_bytes[2];
    handshake[constants.tls_digest_pos + 31] = computed_mac[31] ^ ts_bytes[3];

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result != null);
    const validation = result.?;
    try std.testing.expectEqualStrings("bob", validation.user);
    try std.testing.expectEqual(@as(u32, 0x12345678), validation.timestamp);
    try std.testing.expectEqualSlices(u8, handshake[44..76], validation.session_id[0..]);
    handshake[44] = 0x55;
    try std.testing.expectEqual(@as(u8, 0xaa), validation.session_id[0]);
}

test "validateTlsHandshake - invalid user" {
    const allocator = std.testing.allocator;
    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = [_]u8{0xAA} ** 64; // random junk

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result == null);
}

test "extractSni - malformed returns null" {
    // Too short
    try std.testing.expect(extractSni(&[_]u8{ 0x16, 0x03, 0x01, 0x00 }) == null);
    // Not a handshake type
    try std.testing.expect(extractSni(&[_]u8{ 0x17, 0x03, 0x01, 0x00, 0x00 }) == null);
}

test "all ClientHello readers share strict record framing" {
    const domain = "example.com";
    var ch = [_]u8{0} ** 72;
    const base = buildTestClientHello(0, 0);
    @memcpy(ch[0..50], base[0..50]);
    std.mem.writeInt(u16, ch[3..5], @intCast(ch.len - 5), .big);
    std.mem.writeInt(u24, ch[6..9], @intCast(ch.len - 9), .big);
    std.mem.writeInt(u16, ch[50..52], 20, .big);
    std.mem.writeInt(u16, ch[52..54], 0x0000, .big);
    std.mem.writeInt(u16, ch[54..56], 16, .big);
    std.mem.writeInt(u16, ch[56..58], 14, .big);
    ch[58] = 0;
    std.mem.writeInt(u16, ch[59..61], @intCast(domain.len), .big);
    @memcpy(ch[61..72], domain);

    try std.testing.expectEqualStrings(domain, extractSni(&ch).?);
    try std.testing.expectEqual(@as(?u16, 0x1301), extractFirstTls13Cipher(&ch));
    try std.testing.expect(!clientOffersPqKeyShare(&ch));

    // A truncated nested extension is rejected consistently by every reader.
    std.mem.writeInt(u16, ch[54..56], 17, .big);
    try std.testing.expect(extractSni(&ch) == null);
    try std.testing.expect(extractFirstTls13Cipher(&ch) == null);
    try std.testing.expect(!clientOffersPqKeyShare(&ch));
}

test "extractFirstTls13Cipher returns first non-GREASE TLS1.3 suite" {
    var ch: [56]u8 = undefined;
    ch[0] = constants.tls_record_handshake;
    ch[1] = 0x03;
    ch[2] = 0x01;
    ch[3] = 0x00;
    ch[4] = 0x33;
    ch[5] = 0x01;
    ch[6] = 0x00;
    ch[7] = 0x00;
    ch[8] = 0x2f;
    ch[9] = 0x03;
    ch[10] = 0x03;
    @memset(ch[11..43], 0xAB);
    ch[43] = 0x00;
    ch[44] = 0x00;
    ch[45] = 0x06;
    ch[46] = 0x0a;
    ch[47] = 0x0a;
    ch[48] = 0x13;
    ch[49] = 0x03;
    ch[50] = 0x13;
    ch[51] = 0x01;
    ch[52] = 0x01;
    ch[53] = 0x00;
    ch[54] = 0x00;
    ch[55] = 0x00;

    try std.testing.expectEqual(@as(?u16, 0x1303), extractFirstTls13Cipher(&ch));
    try std.testing.expect(extractFirstTls13Cipher(ch[0..40]) == null);
}

test "buildServerHelloWithTemplateCipher echoes chosen cipher" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0xAA} ** 32;
    const session_id = [_]u8{0xBB} ** 32;

    const resp = try buildServerHelloWithTemplateCipher(allocator, &server_template, &digest, &digest, &session_id, 0x1303);
    defer allocator.free(resp);

    try std.testing.expectEqual(@as(u16, 0x1303), std.mem.readInt(u16, resp[tmpl_cipher_offset..][0..2], .big));
}

test "clientOffersPqKeyShare detects a complete 0x11ec key_share entry" {
    var ch: [1400]u8 = undefined;
    var n: usize = 0;
    const W = struct {
        fn b(buf: []u8, pos: *usize, v: u8) void {
            buf[pos.*] = v;
            pos.* += 1;
        }
        fn h(buf: []u8, pos: *usize, v: u16) void {
            std.mem.writeInt(u16, buf[pos.*..][0..2], v, .big);
            pos.* += 2;
        }
    };

    W.b(&ch, &n, constants.tls_record_handshake);
    W.h(&ch, &n, 0x0301);
    const record_len_at = n;
    W.h(&ch, &n, 0);
    W.b(&ch, &n, 0x01);
    const hello_len_at = n;
    W.b(&ch, &n, 0);
    W.h(&ch, &n, 0);
    W.h(&ch, &n, 0x0303);
    @memset(ch[n..][0..32], 0xAA);
    n += 32;
    W.b(&ch, &n, 0);
    W.h(&ch, &n, 2);
    W.h(&ch, &n, 0x1301);
    W.b(&ch, &n, 1);
    W.b(&ch, &n, 0);
    const ext_total_at = n;
    W.h(&ch, &n, 0);
    const ext_start = n;
    W.h(&ch, &n, 0x0033);
    const ext_len_at = n;
    W.h(&ch, &n, 0);
    const ext_payload_start = n;
    const list_len_at = n;
    W.h(&ch, &n, 0);
    const shares_start = n;
    W.h(&ch, &n, pq_named_group);
    W.h(&ch, &n, @intCast(pq_client_key_share_len));
    @memset(ch[n..][0..pq_client_key_share_len], 0xCC);
    n += pq_client_key_share_len;
    std.mem.writeInt(u16, ch[list_len_at..][0..2], @intCast(n - shares_start), .big);
    std.mem.writeInt(u16, ch[ext_len_at..][0..2], @intCast(n - ext_payload_start), .big);
    std.mem.writeInt(u16, ch[ext_total_at..][0..2], @intCast(n - ext_start), .big);
    std.mem.writeInt(u16, ch[record_len_at..][0..2], @intCast(n - 5), .big);
    std.mem.writeInt(u24, ch[hello_len_at..][0..3], @intCast(n - 9), .big);

    try std.testing.expect(clientOffersPqKeyShare(ch[0..n]));
    std.mem.writeInt(u16, ch[shares_start + 2 ..][0..2], 4, .big);
    try std.testing.expect(!clientOffersPqKeyShare(ch[0..n]));
}

test "buildServerHelloPq emits a 0x11ec key_share with correct framing + HMAC" {
    const allocator = std.testing.allocator;
    const digest = [_]u8{0} ** constants.tls_digest_len;
    const sid = [_]u8{0x33} ** 32;
    const secret = [_]u8{0x42} ** 16;

    const resp = try buildServerHelloPq(allocator, &secret, &digest, &sid, 0x1303, default_fake_cert_size);
    defer allocator.free(resp);

    try std.testing.expectEqual(pq_server_hello_len, resp.len);
    try std.testing.expectEqual(@as(u8, constants.tls_record_handshake), resp[0]);
    try std.testing.expectEqual(@as(u16, @intCast(pq_server_hello_record_len - 5)), std.mem.readInt(u16, resp[3..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 0x1303), std.mem.readInt(u16, resp[tmpl_cipher_offset..][0..2], .big));
    try std.testing.expectEqualSlices(u8, &sid, resp[tmpl_session_id_offset..][0..32]);
    try std.testing.expectEqual(@as(u16, 0x0033), std.mem.readInt(u16, resp[87..][0..2], .big));
    try std.testing.expectEqual(pq_named_group, std.mem.readInt(u16, resp[91..][0..2], .big));
    try std.testing.expectEqual(@as(u16, @intCast(pq_key_share_len)), std.mem.readInt(u16, resp[93..][0..2], .big));
    try std.testing.expectEqual(@as(u8, constants.tls_record_change_cipher), resp[pq_server_hello_record_len]);
    try std.testing.expectEqual(@as(u8, constants.tls_record_application), resp[pq_server_hello_record_len + 6]);
    try std.testing.expectEqual(@as(?usize, default_fake_cert_size), firstAppDataRecordLen(resp));

    const check = try allocator.dupe(u8, resp);
    defer allocator.free(check);
    @memset(check[tmpl_random_offset..][0..32], 0);
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(&secret);
    hmac.update(&digest);
    hmac.update(check);
    var expected: [32]u8 = undefined;
    hmac.final(&expected);
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, expected, resp[tmpl_random_offset..][0..32].*));
}

test "buildServerHelloPq supports custom fake cert size" {
    const allocator = std.testing.allocator;
    const digest = [_]u8{0} ** constants.tls_digest_len;
    const sid = [_]u8{0x33} ** 32;
    const secret = [_]u8{0x42} ** 16;
    const cert_size: usize = 4096;

    const resp = try buildServerHelloPq(allocator, &secret, &digest, &sid, 0x1301, cert_size);
    defer allocator.free(resp);

    try std.testing.expectEqual(pqResponseLen(cert_size), resp.len);
    try std.testing.expectEqual(@as(?usize, cert_size), firstAppDataRecordLen(resp));
    try std.testing.expectEqual(@as(u16, 0x1301), std.mem.readInt(u16, resp[tmpl_cipher_offset..][0..2], .big));
}

test "validateTlsHandshake returns canonical_hmac" {
    const allocator = std.testing.allocator;

    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = buildTestClientHello(32, 0xaa);

    const hmac_input = buildTestClientHello(32, 0xaa);

    const computed_mac = crypto.sha256Hmac(&secrets[0].secret, &hmac_input);
    @memcpy(&handshake, &hmac_input);
    @memcpy(handshake[constants.tls_digest_pos..][0..28], computed_mac[0..28]);

    const timestamp: u32 = 0x01020304;
    const ts_bytes = std.mem.toBytes(timestamp);
    handshake[constants.tls_digest_pos + 28] = computed_mac[28] ^ ts_bytes[0];
    handshake[constants.tls_digest_pos + 29] = computed_mac[29] ^ ts_bytes[1];
    handshake[constants.tls_digest_pos + 30] = computed_mac[30] ^ ts_bytes[2];
    handshake[constants.tls_digest_pos + 31] = computed_mac[31] ^ ts_bytes[3];

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &computed_mac, &result.?.canonical_hmac);
}

test "validateTlsHandshake rejects non-32 session id" {
    const allocator = std.testing.allocator;

    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var handshake = buildTestClientHello(4, 0xaa);
    const hmac_input = buildTestClientHello(4, 0xaa);

    const computed_mac = crypto.sha256Hmac(&secrets[0].secret, &hmac_input);
    @memcpy(&handshake, &hmac_input);
    @memcpy(handshake[constants.tls_digest_pos..][0..28], computed_mac[0..28]);

    const timestamp: u32 = 0x01020304;
    const ts_bytes = std.mem.toBytes(timestamp);
    handshake[constants.tls_digest_pos + 28] = computed_mac[28] ^ ts_bytes[0];
    handshake[constants.tls_digest_pos + 29] = computed_mac[29] ^ ts_bytes[1];
    handshake[constants.tls_digest_pos + 30] = computed_mac[30] ^ ts_bytes[2];
    handshake[constants.tls_digest_pos + 31] = computed_mac[31] ^ ts_bytes[3];

    const result = try validateTlsHandshake(allocator, &handshake, &secrets, true);
    try std.testing.expect(result == null);
}
