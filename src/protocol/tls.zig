//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const runtime_time = @import("../runtime/time.zig");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

/// Re-export for convenience
pub const UserSecret = obfuscation.UserSecret;
pub const PreparedHmacState = std.crypto.auth.hmac.sha2.HmacSha256;

/// Authentication work is bounded independently of the TLS record/read limit.
/// Includes the five-byte record header; PQ + X25519 ClientHellos fit below 2 KiB.
pub const max_authenticated_hello_len: usize = 4096;

// ============= TLS Validation Result =============

pub const ClientKeyShare = enum { x25519, x25519_mlkem768 };

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
    /// ServerHello selection from the authenticated parse, with PQ priority.
    key_share: ClientKeyShare,
    first_tls13_cipher: ?u16,

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

pub const TlsValidationFailure = enum {
    oversized_client_hello,
    malformed_client_hello,
    invalid_session_id,
    unsupported_key_share,
    secret_mismatch,
    timestamp_skew,
};

pub const TlsValidationDiagnostic = struct {
    failure: TlsValidationFailure = .malformed_client_hello,
    /// Server wall clock minus the authenticated client timestamp, in seconds.
    /// Populated only when `failure == .timestamp_skew`.
    timestamp_skew_s: ?i64 = null,
};

const ParsedClientHello = struct {
    digest: []const u8,
    session_id: []const u8,
    sni: ?[]const u8,
    first_tls13_cipher: ?u16,
    offers_pq_key_share: bool,
    offers_x25519_key_share: bool,
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
    var offers_x25519_key_share = false;
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
                } else if (group == 0x001d) {
                    if (key_len != 32) return null;
                    offers_x25519_key_share = true;
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
        .offers_x25519_key_share = offers_x25519_key_share,
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
    var ignored_diagnostic: TlsValidationDiagnostic = .{};
    return validateTlsHandshakeDetailed(
        allocator,
        handshake,
        secrets,
        ignore_time_skew,
        &ignored_diagnostic,
    );
}

/// Validate a TLS ClientHello and retain the reason for an authentication
/// failure. The normal wrapper above deliberately preserves its optional API.
pub fn validateTlsHandshakeDetailed(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    ignore_time_skew: bool,
    diagnostic: *TlsValidationDiagnostic,
) !?TlsValidation {
    return validateTlsHandshakeImpl(allocator, handshake, secrets, null, ignore_time_skew, diagnostic);
}

/// The immutable startup snapshot owns these keyed contexts in secret order.
/// Zig 0.16 HmacSha256/Sha256 contain only by-value arrays and integer state.
pub fn validateTlsHandshakePrepared(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    prepared_hmacs: []const PreparedHmacState,
    ignore_time_skew: bool,
    diagnostic: *TlsValidationDiagnostic,
) !?TlsValidation {
    if (prepared_hmacs.len != secrets.len) return error.InvalidPreparedSecrets;
    return validateTlsHandshakeImpl(allocator, handshake, secrets, prepared_hmacs, ignore_time_skew, diagnostic);
}

fn validateTlsHandshakeImpl(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    prepared_hmacs: ?[]const PreparedHmacState,
    ignore_time_skew: bool,
    diagnostic: *TlsValidationDiagnostic,
) !?TlsValidation {
    _ = allocator;

    diagnostic.* = .{};
    if (handshake.len > max_authenticated_hello_len) {
        diagnostic.failure = .oversized_client_hello;
        return null;
    }
    const parsed = parseClientHello(handshake) orelse return null;
    if (parsed.digest.ptr != handshake[constants.tls_digest_pos..].ptr) return null;
    if (parsed.session_id.len != 32) {
        diagnostic.failure = .invalid_session_id;
        return null;
    }
    const key_share: ClientKeyShare = if (parsed.offers_pq_key_share)
        .x25519_mlkem768
    else if (parsed.offers_x25519_key_share)
        .x25519
    else {
        diagnostic.failure = .unsupported_key_share;
        return null;
    };
    var digest: [constants.tls_digest_len]u8 = parsed.digest[0..constants.tls_digest_len].*;
    defer std.crypto.secureZero(u8, &digest);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const zero_digest = [_]u8{0} ** constants.tls_digest_len;

    const now: i64 = if (!ignore_time_skew)
        runtime_time.realtimeSeconds()
    else
        0;

    var saw_matching_hmac = false;
    for (secrets, 0..) |*entry, i| {
        var hmac = if (prepared_hmacs) |contexts| contexts[i] else HmacSha256.init(&entry.secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
        hmac.update(handshake[0..constants.tls_digest_pos]);
        hmac.update(zero_digest[0..]);
        hmac.update(handshake[constants.tls_digest_pos + constants.tls_digest_len ..]);
        var computed: [constants.tls_digest_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &computed);
        hmac.final(&computed);

        // Constant-time comparison of first 28 bytes using stdlib
        if (!std.crypto.timing_safe.eql([28]u8, digest[0..28].*, computed[0..28].*)) continue;
        saw_matching_hmac = true;

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
                diagnostic.failure = .timestamp_skew;
                diagnostic.timestamp_skew_s = time_diff;
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
            .key_share = key_share,
            .first_tls13_cipher = parsed.first_tls13_cipher,
        };
    }

    if (!saw_matching_hmac) diagnostic.failure = .secret_mismatch;
    return null;
}

/// Build a fake TLS ServerHello response using a pre-built TLS 1.3 server template.
///
/// The response consists of three TLS records that the client validates:
/// 1. ServerHello record (type 0x16) — contains the HMAC digest in the `random` field
/// 2. Change Cipher Spec record (type 0x14) — fixed 6 bytes
/// 3. Fake Application Data record (type 0x17) — body simulating encrypted cert
///
/// Template approach: use a comptime-built normal TLS 1.3 ServerHello shape:
/// - Extensions in common server order: supported_versions THEN key_share
/// - AppData size comes from the template; production chooses it once at startup
/// - AppData body is filled with fresh random bytes for each response
///
/// Fields patched at runtime (the offered cipher is selected by the cipher builder):
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
    _ = templateFakeCertPayloadSize(template) orelse return error.BadServerHelloTemplate;
    if (session_id.len != 32) return error.InvalidSessionIdLength;
    const response = try allocator.alloc(u8, template.len);
    errdefer allocator.free(response);
    return buildServerHelloWithTemplateInto(response, template, secret, client_digest, session_id, cipher);
}

/// Build in caller-owned storage without allocation or retaining pointers.
/// The returned borrowed slice excludes spare capacity.
pub fn buildServerHelloWithTemplateInto(
    output: []u8,
    template: []const u8,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
) ![]u8 {
    const cert_payload_size = templateFakeCertPayloadSize(template) orelse return error.BadServerHelloTemplate;
    if (session_id.len != 32) return error.InvalidSessionIdLength;
    if (output.len < template.len) return error.NoSpaceLeft;
    const response = output[0..template.len];

    // AppData is filled with fresh randomness below; copy only the wire prefix.
    @memcpy(response[0..server_hello_prefix_len], template[0..server_hello_prefix_len]);
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
    return buildServerHelloPqInto(response, secret, client_digest, session_id, cipher, cert_payload_size);
}

pub fn buildServerHelloPqInto(
    output: []u8,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
    cipher: ?u16,
    cert_payload_size: usize,
) ![]u8 {
    if (session_id.len != 32) return error.InvalidSessionIdLength;
    if (!validFakeCertPayloadSize(cert_payload_size)) return error.InvalidFakeCertSize;
    const response_len = pqResponseLen(cert_payload_size);
    if (output.len < response_len) return error.NoSpaceLeft;
    const response = output[0..response_len];
    // Every other byte is assigned below before hashing. Only server_random
    // must start at zero for the FakeTLS HMAC construction.
    @memset(response[tmpl_random_offset..][0..32], 0);

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
// This legacy static shape is used by the fixed-size helper and test fixtures.
// Production builds a variable-size process template, retaining extension order
// (supported_versions before key_share). Builders randomize AppData per response;
// neither the static size nor the random fallback proves a cover-origin match.

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

/// Legacy static-template size; production resolves its size separately at startup.
const fake_cert_payload_len: u16 = 2878;
const fake_cert_payload_size: usize = @as(usize, fake_cert_payload_len);
pub const default_fake_cert_size: usize = fake_cert_payload_size;
pub const min_fake_cert_size: usize = 256;
pub const max_fake_cert_size: usize = 16 * 1024;
/// Fallback heuristic when the operator has not supplied a certificate size.
pub const default_fake_cert_min_size: usize = 2400;
pub const default_fake_cert_max_size: usize = 3600;

comptime {
    std.debug.assert(min_fake_cert_size <= default_fake_cert_min_size);
    std.debug.assert(default_fake_cert_min_size <= default_fake_cert_max_size);
    std.debug.assert(default_fake_cert_max_size <= max_fake_cert_size);
}

/// Total template size: ServerHello(127) + CCS(6) + AppData(5 + 2878)
const server_template_len: usize = 127 + 6 + 5 + fake_cert_payload_size;
pub const server_hello_template_len: usize = server_template_len;
/// Fixed ServerHello+CCS+AppData-header prefix length.
const tmpl_appdata_offset: usize = server_template_len - fake_cert_payload_size;
pub const server_hello_prefix_len: usize = tmpl_appdata_offset;
/// Largest supported response, including the larger PQ prefix and maximum cert.
pub const max_server_hello_len: usize = @max(server_hello_prefix_len, pq_appdata_offset) + max_fake_cert_size;

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

/// Resolve once when creating the process template, never per connection.
/// Nonzero operator/profile sizes take priority over the random fallback.
pub fn effectiveFakeCertSize(configured: u32) usize {
    if (configured == 0) return default_fake_cert_min_size +
        crypto.randomRange(usize, default_fake_cert_max_size - default_fake_cert_min_size + 1);
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
    // Template filler only; response builders replace it with fresh random bytes.
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

pub const SniInspection = union(enum) {
    found: []const u8,
    missing,
    malformed,
};

/// Inspect SNI for listener routing without applying FakeTLS-specific policy to
/// unrelated extensions. Authentication still uses parseClientHello(), whose
/// cipher and key-share checks intentionally remain strict.
pub fn inspectSni(handshake: []const u8) SniInspection {
    if (handshake.len < 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2) return .malformed;
    if (handshake[0] != constants.tls_record_handshake) return .malformed;
    if (handshake[1] != 0x03 or (handshake[2] != 0x01 and handshake[2] != 0x03)) return .malformed;

    const record_len: usize = std.mem.readInt(u16, handshake[3..5], .big);
    if (record_len != handshake.len - 5) return .malformed;
    if (handshake[5] != 0x01) return .malformed;
    const hello_len: usize = std.mem.readInt(u24, handshake[6..9], .big);
    if (hello_len != record_len - 4) return .malformed;

    var pos: usize = 9;
    if (2 + 32 > handshake.len - pos) return .malformed;
    pos += 2 + 32;

    if (pos >= handshake.len) return .malformed;
    const session_id_len: usize = handshake[pos];
    pos += 1;
    if (session_id_len > 32 or session_id_len > handshake.len - pos) return .malformed;
    pos += session_id_len;

    if (2 > handshake.len - pos) return .malformed;
    const cipher_suites_len: usize = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (cipher_suites_len < 2 or cipher_suites_len % 2 != 0 or cipher_suites_len > handshake.len - pos) return .malformed;
    pos += cipher_suites_len;

    if (pos >= handshake.len) return .malformed;
    const compression_len: usize = handshake[pos];
    pos += 1;
    if (compression_len == 0 or compression_len > handshake.len - pos) return .malformed;
    pos += compression_len;

    if (2 > handshake.len - pos) return .malformed;
    const extensions_len: usize = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    if (extensions_len != handshake.len - pos) return .malformed;
    const extensions = handshake[pos..];

    var ext_pos: usize = 0;
    var sni: ?[]const u8 = null;
    var seen_sni = false;
    while (ext_pos < extensions.len) {
        if (extensions.len - ext_pos < 4) return .malformed;
        const ext_type = std.mem.readInt(u16, extensions[ext_pos..][0..2], .big);
        const ext_len: usize = std.mem.readInt(u16, extensions[ext_pos + 2 ..][0..2], .big);
        ext_pos += 4;
        if (ext_len > extensions.len - ext_pos) return .malformed;
        const payload = extensions[ext_pos .. ext_pos + ext_len];

        if (ext_type == 0x0000) {
            if (seen_sni or payload.len < 2) return .malformed;
            seen_sni = true;
            const names_len: usize = std.mem.readInt(u16, payload[0..2], .big);
            if (names_len != payload.len - 2) return .malformed;
            var name_pos: usize = 2;
            while (name_pos < payload.len) {
                if (payload.len - name_pos < 3) return .malformed;
                const name_type = payload[name_pos];
                const name_len: usize = std.mem.readInt(u16, payload[name_pos + 1 ..][0..2], .big);
                name_pos += 3;
                if (name_len > payload.len - name_pos) return .malformed;
                if (name_type == 0) {
                    if (name_len == 0 or sni != null) return .malformed;
                    sni = payload[name_pos .. name_pos + name_len];
                }
                name_pos += name_len;
            }
        }
        ext_pos += ext_len;
    }

    if (sni) |value| return .{ .found = value };
    return .missing;
}

pub fn extractSni(handshake: []const u8) ?[]const u8 {
    return switch (inspectSni(handshake)) {
        .found => |sni| sni,
        .missing, .malformed => null,
    };
}

/// Return the first non-GREASE TLS 1.3 cipher suite offered by the client.
/// Used to make the synthetic ServerHello track the ClientHello like a real server.
pub fn extractFirstTls13Cipher(handshake: []const u8) ?u16 {
    return (parseClientHello(handshake) orelse return null).first_tls13_cipher;
}

// ============= Tests =============

fn buildTestClientHello(comptime session_id_len: usize, session_fill: u8) [94 + session_id_len]u8 {
    var hello = [_]u8{0} ** (94 + session_id_len);
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
    std.mem.writeInt(u16, hello[pos..][0..2], 42, .big);
    pos += 2;
    @memcpy(hello[pos..][0..10], &[_]u8{ 0, 0x33, 0, 38, 0, 36, 0, 0x1d, 0, 32 });
    @memset(hello[pos + 10 ..][0..32], 0x42);
    return hello;
}

fn buildSizedTestClientHello(buffer: []u8, pq: bool, x25519: bool, secret: *const [16]u8) []u8 {
    const with_share = buildTestClientHello(32, 0xaa);
    const base = with_share[0..84];
    const hostname = "example.org";
    const shares_len: usize = (if (pq) @as(usize, 4 + pq_client_key_share_len) else 0) +
        (if (x25519) @as(usize, 4 + 32) else 0);
    std.debug.assert(buffer.len >= base.len + 9 + hostname.len + 6 + shares_len + 4);
    @memset(buffer, 0);
    @memcpy(buffer[0..base.len], base);
    std.mem.writeInt(u16, buffer[3..5], @intCast(buffer.len - 5), .big);
    std.mem.writeInt(u24, buffer[6..9], @intCast(buffer.len - 9), .big);
    std.mem.writeInt(u16, buffer[base.len - 2 ..][0..2], @intCast(buffer.len - base.len), .big);
    var pos: usize = base.len;
    std.mem.writeInt(u16, buffer[pos..][0..2], 0, .big);
    std.mem.writeInt(u16, buffer[pos + 2 ..][0..2], @intCast(5 + hostname.len), .big);
    std.mem.writeInt(u16, buffer[pos + 4 ..][0..2], @intCast(3 + hostname.len), .big);
    buffer[pos + 6] = 0;
    std.mem.writeInt(u16, buffer[pos + 7 ..][0..2], @intCast(hostname.len), .big);
    @memcpy(buffer[pos + 9 ..][0..hostname.len], hostname);
    pos += 9 + hostname.len;
    std.mem.writeInt(u16, buffer[pos..][0..2], 0x0033, .big);
    std.mem.writeInt(u16, buffer[pos + 2 ..][0..2], @intCast(2 + shares_len), .big);
    std.mem.writeInt(u16, buffer[pos + 4 ..][0..2], @intCast(shares_len), .big);
    pos += 6;
    for ([_]struct { offered: bool, group: u16, len: usize }{
        .{ .offered = pq, .group = pq_named_group, .len = pq_client_key_share_len },
        .{ .offered = x25519, .group = 0x001d, .len = 32 },
    }) |share| {
        if (!share.offered) continue;
        std.mem.writeInt(u16, buffer[pos..][0..2], share.group, .big);
        std.mem.writeInt(u16, buffer[pos + 2 ..][0..2], @intCast(share.len), .big);
        @memset(buffer[pos + 4 ..][0..share.len], 0x42);
        pos += 4 + share.len;
    }
    std.mem.writeInt(u16, buffer[pos..][0..2], 0x0015, .big); // padding
    std.mem.writeInt(u16, buffer[pos + 2 ..][0..2], @intCast(buffer.len - pos - 4), .big);
    const digest = crypto.sha256Hmac(secret, buffer);
    @memcpy(buffer[constants.tls_digest_pos..][0..constants.tls_digest_len], &digest);
    return buffer;
}

test "prepared FakeTLS HMAC snapshots preserve cold validation and remain reusable" {
    const secrets = [_]UserSecret{
        .{ .name = "alice", .secret = [_]u8{0x11} ** 16 },
        .{ .name = "bob", .secret = [_]u8{0x22} ** 16 },
        .{ .name = "carol", .secret = [_]u8{0x33} ** 16 },
    };
    var prepared: [secrets.len]PreparedHmacState = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&prepared));
    for (&secrets, &prepared) |*secret, *context| context.* = PreparedHmacState.init(&secret.secret);
    var no_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = no_alloc.allocator();
    var storage: [max_authenticated_hello_len]u8 = undefined;
    for ([_]struct { len: usize, pq: bool, x25519: bool }{
        .{ .len = 512, .pq = false, .x25519 = true },
        .{ .len = 1600, .pq = true, .x25519 = false },
        .{ .len = max_authenticated_hello_len, .pq = true, .x25519 = true },
    }) |fixture| {
        const hello = buildSizedTestClientHello(storage[0..fixture.len], fixture.pq, fixture.x25519, &secrets[2].secret);
        var cold_diagnostic: TlsValidationDiagnostic = .{};
        var cached_diagnostic: TlsValidationDiagnostic = .{};
        // The last key forces all three trials; reuse must not advance a shared state.
        for (0..2) |_| {
            var cold = try validateTlsHandshakeDetailed(allocator, hello, &secrets, true, &cold_diagnostic);
            defer if (cold) |*value| value.wipe();
            var cached = try validateTlsHandshakePrepared(allocator, hello, &secrets, &prepared, true, &cached_diagnostic);
            defer if (cached) |*value| value.wipe();
            try std.testing.expect(cold != null and cached != null);
            try std.testing.expectEqualDeep(cold.?, cached.?);
            try std.testing.expectEqualStrings("carol", cached.?.user);
            try std.testing.expectEqualDeep(cold_diagnostic, cached_diagnostic);
        }

        // The fixture signs timestamp zero: both paths must reject it as stale.
        try std.testing.expect(try validateTlsHandshakeDetailed(allocator, hello, &secrets, false, &cold_diagnostic) == null);
        try std.testing.expect(try validateTlsHandshakePrepared(allocator, hello, &secrets, &prepared, false, &cached_diagnostic) == null);
        try std.testing.expectEqual(TlsValidationFailure.timestamp_skew, cold_diagnostic.failure);
        try std.testing.expectEqual(cold_diagnostic.failure, cached_diagnostic.failure);
        try std.testing.expect(cached_diagnostic.timestamp_skew_s.? > constants.time_skew_max);

        var timestamp: [4]u8 = undefined;
        std.mem.writeInt(u32, &timestamp, @intCast(runtime_time.realtimeSeconds()), .little);
        for (hello[constants.tls_digest_pos + 28 ..][0..4], timestamp) |*byte, stamp| byte.* ^= stamp;
        var cold = try validateTlsHandshakeDetailed(allocator, hello, &secrets, false, &cold_diagnostic);
        defer if (cold) |*value| value.wipe();
        var cached = try validateTlsHandshakePrepared(allocator, hello, &secrets, &prepared, false, &cached_diagnostic);
        defer if (cached) |*value| value.wipe();
        try std.testing.expect(cold != null and cached != null);
        try std.testing.expectEqualDeep(cold.?, cached.?);

        hello[hello.len - 1] ^= 1; // Valid padding framing, invalid authentication.
        try std.testing.expect(try validateTlsHandshakeDetailed(allocator, hello, &secrets, true, &cold_diagnostic) == null);
        try std.testing.expect(try validateTlsHandshakePrepared(allocator, hello, &secrets, &prepared, true, &cached_diagnostic) == null);
        try std.testing.expectEqual(TlsValidationFailure.secret_mismatch, cold_diagnostic.failure);
        try std.testing.expectEqualDeep(cold_diagnostic, cached_diagnostic);
    }

    var diagnostic: TlsValidationDiagnostic = .{};
    try std.testing.expectError(error.InvalidPreparedSecrets, validateTlsHandshakePrepared(allocator, &storage, &secrets, prepared[0..2], true, &diagnostic));
    try std.testing.expectEqual(@as(usize, 0), no_alloc.allocations);
    try std.testing.expect(!no_alloc.has_induced_failure);

    // A restarted user configuration prepares a new snapshot, independent of the old one.
    const replacement = [_]UserSecret{.{ .name = "carol", .secret = [_]u8{0x44} ** 16 }};
    var replacement_contexts = [_]PreparedHmacState{PreparedHmacState.init(&replacement[0].secret)};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&replacement_contexts));
    const old_hello = buildSizedTestClientHello(&storage, true, true, &secrets[2].secret);
    try std.testing.expect(try validateTlsHandshakePrepared(allocator, old_hello, &replacement, &replacement_contexts, true, &diagnostic) == null);
    var old_result = try validateTlsHandshakePrepared(allocator, old_hello, &secrets, &prepared, true, &diagnostic);
    defer if (old_result) |*value| value.wipe();
    try std.testing.expect(old_result != null);
    const new_hello = buildSizedTestClientHello(&storage, true, true, &replacement[0].secret);
    var new_result = try validateTlsHandshakePrepared(allocator, new_hello, &replacement, &replacement_contexts, true, &diagnostic);
    defer if (new_result) |*value| value.wipe();
    try std.testing.expect(new_result != null);
    try std.testing.expect(try validateTlsHandshakePrepared(allocator, new_hello, &secrets, &prepared, true, &diagnostic) == null);
}

test "FakeTLS authentication bounds input without lowering the TLS parser limit" {
    const secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1a} ** 16 }};
    var storage: [constants.max_tls_plaintext_size + 5]u8 = undefined;
    for ([_]struct { pq: bool, x25519: bool, len: usize }{
        .{ .pq = false, .x25519 = true, .len = 256 },
        .{ .pq = true, .x25519 = false, .len = 1500 },
        .{ .pq = true, .x25519 = true, .len = 1600 },
        .{ .pq = true, .x25519 = true, .len = max_authenticated_hello_len },
        .{ .pq = true, .x25519 = true, .len = max_authenticated_hello_len + 1 },
        .{ .pq = true, .x25519 = true, .len = storage.len },
    }) |fixture| {
        const hello = buildSizedTestClientHello(storage[0..fixture.len], fixture.pq, fixture.x25519, &secrets[0].secret);
        try std.testing.expectEqualStrings("example.org", extractSni(hello).?);
        try std.testing.expectEqual(fixture.pq, clientOffersPqKeyShare(hello));
        var diagnostic = TlsValidationDiagnostic{ .failure = .timestamp_skew, .timestamp_skew_s = 123 };
        var result = try validateTlsHandshakeDetailed(std.testing.allocator, hello, &secrets, true, &diagnostic);
        defer if (result) |*value| value.wipe();
        if (fixture.len <= max_authenticated_hello_len) {
            try std.testing.expect(result != null);
            try std.testing.expectEqualStrings("alice", result.?.user);
        } else {
            // A correctly signed input would authenticate if the HMAC scan ran.
            try std.testing.expect(result == null);
            try std.testing.expectEqual(TlsValidationFailure.oversized_client_hello, diagnostic.failure);
            try std.testing.expect(diagnostic.timestamp_skew_s == null);
        }
    }
    // The size gate also precedes structural parsing and cannot inspect secrets.
    @memset(&storage, 0xff);
    var diagnostic: TlsValidationDiagnostic = .{};
    try std.testing.expect(try validateTlsHandshakeDetailed(std.testing.allocator, &storage, &.{}, false, &diagnostic) == null);
    try std.testing.expectEqual(TlsValidationFailure.oversized_client_hello, diagnostic.failure);
}

test "FakeTLS requires a supported share and returns PQ priority and cipher from validation" {
    const secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1a} ** 16 }};
    var storage: [1600]u8 = undefined;
    for ([_]struct { pq: bool, x25519: bool, selected: ?ClientKeyShare }{
        .{ .pq = true, .x25519 = false, .selected = .x25519_mlkem768 },
        .{ .pq = false, .x25519 = true, .selected = .x25519 },
        .{ .pq = true, .x25519 = true, .selected = .x25519_mlkem768 },
        .{ .pq = false, .x25519 = false, .selected = null },
    }) |fixture| {
        const hello = buildSizedTestClientHello(&storage, fixture.pq, fixture.x25519, &secrets[0].secret);
        var diagnostic: TlsValidationDiagnostic = .{};
        var result = try validateTlsHandshakeDetailed(std.testing.allocator, hello, &secrets, true, &diagnostic);
        defer if (result) |*value| value.wipe();
        if (fixture.selected) |selected| {
            try std.testing.expect(result != null);
            try std.testing.expectEqual(selected, result.?.key_share);
            try std.testing.expectEqual(@as(?u16, 0x1301), result.?.first_tls13_cipher);
        } else {
            try std.testing.expect(result == null);
            try std.testing.expectEqual(TlsValidationFailure.unsupported_key_share, diagnostic.failure);
        }
    }
    const share_pos: usize = 84 + 9 + "example.org".len + 6;
    for ([_]bool{ false, true }) |pq| {
        const hello = buildSizedTestClientHello(&storage, pq, !pq, &secrets[0].secret);
        std.mem.writeInt(u16, hello[share_pos + 2 ..][0..2], @intCast(if (pq) pq_client_key_share_len - 1 else 33), .big);
        var diagnostic: TlsValidationDiagnostic = .{};
        try std.testing.expect(try validateTlsHandshakeDetailed(std.testing.allocator, hello, &secrets, true, &diagnostic) == null);
        try std.testing.expectEqual(TlsValidationFailure.malformed_client_hello, diagnostic.failure);
    }
    for ([_]u16{ 0x0017, 0x0015 }) |replacement| {
        const hello = buildSizedTestClientHello(&storage, false, true, &secrets[0].secret);
        // Unknown group or no key_share extension, both still structurally valid.
        const pos = if (replacement == 0x0017) share_pos else share_pos - 6;
        std.mem.writeInt(u16, hello[pos..][0..2], replacement, .big);
        @memset(hello[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);
        const digest = crypto.sha256Hmac(&secrets[0].secret, hello);
        @memcpy(hello[constants.tls_digest_pos..][0..constants.tls_digest_len], &digest);
        var diagnostic: TlsValidationDiagnostic = .{};
        try std.testing.expect(try validateTlsHandshakeDetailed(std.testing.allocator, hello, &secrets, true, &diagnostic) == null);
        try std.testing.expectEqual(TlsValidationFailure.unsupported_key_share, diagnostic.failure);
    }
}

test "FakeTLS retains duplicate key-share extension and group policies" {
    const secret = [_]u8{0x1a} ** 16;
    var storage: [3000]u8 = undefined;
    const share_pos: usize = 84 + 9 + "example.org".len + 6;
    for ([_]bool{ false, true }) |pq| {
        const hello = buildSizedTestClientHello(&storage, pq, !pq, &secret);
        const entry_len: usize = 4 + (if (pq) pq_client_key_share_len else 32);
        @memcpy(hello[share_pos + entry_len ..][0..entry_len], hello[share_pos..][0..entry_len]);
        std.mem.writeInt(u16, hello[share_pos - 4 ..][0..2], @intCast(2 + 2 * entry_len), .big);
        std.mem.writeInt(u16, hello[share_pos - 2 ..][0..2], @intCast(2 * entry_len), .big);
        const padding_pos = share_pos + 2 * entry_len;
        std.mem.writeInt(u16, hello[padding_pos..][0..2], 0x0015, .big);
        std.mem.writeInt(u16, hello[padding_pos + 2 ..][0..2], @intCast(hello.len - padding_pos - 4), .big);
        // Duplicate PQ entries are rejected; duplicate valid X25519 entries
        // retain the fork's existing permissive behavior.
        try std.testing.expectEqual(!pq, parseClientHello(hello) != null);
    }
    const hello = buildSizedTestClientHello(&storage, false, true, &secret);
    const padding_pos = share_pos + 4 + 32;
    std.mem.writeInt(u16, hello[padding_pos..][0..2], 0x0033, .big);
    try std.testing.expect(parseClientHello(hello) == null);
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

fn expectServerHelloTestHmac(response: []const u8, secret: []const u8, digest: *const [32]u8) !void {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(digest);
    hmac.update(response[0..tmpl_random_offset]);
    hmac.update(&([_]u8{0} ** 32));
    hmac.update(response[tmpl_random_offset + 32 ..]);
    var expected: [32]u8 = undefined;
    hmac.final(&expected);
    try std.testing.expectEqualSlices(u8, &expected, response[tmpl_random_offset..][0..32]);
}

test "ServerHello into builders preserve allocated wire invariants at every cert size" {
    const allocator = std.testing.allocator;
    const secret = [_]u8{0x42} ** 16;
    const digest = [_]u8{0x71} ** 32;
    const sid = [_]u8{0x39} ** 32;
    for ([_]usize{ min_fake_cert_size, default_fake_cert_size, 4096, max_fake_cert_size }) |cert_size| {
        const template = try buildServerHelloTemplateAlloc(allocator, 42, cert_size);
        defer allocator.free(template);
        for ([_]bool{ false, true }) |pq| {
            var scratch = [_]u8{0xa5} ** (max_server_hello_len + 1);
            const response = if (pq)
                try buildServerHelloPqInto(&scratch, &secret, &digest, &sid, 0x1303, cert_size)
            else
                try buildServerHelloWithTemplateInto(&scratch, template, &secret, &digest, &sid, 0x1303);
            const allocated = if (pq)
                try buildServerHelloPq(allocator, &secret, &digest, &sid, 0x1303, cert_size)
            else
                try buildServerHelloWithTemplateCipher(allocator, template, &secret, &digest, &sid, 0x1303);
            defer allocator.free(allocated);
            const key_start = if (pq) pq_key_offset else tmpl_x25519_key_offset;
            const key_len = if (pq) pq_key_share_len else 32;
            const prefix_len = if (pq) pq_appdata_offset else server_hello_prefix_len;
            try std.testing.expect(response.ptr == scratch[0..].ptr);
            try std.testing.expectEqual(prefix_len + cert_size, response.len);
            try std.testing.expectEqual(allocated.len, response.len);
            try std.testing.expectEqualSlices(u8, allocated[0..11], response[0..11]);
            try std.testing.expectEqualSlices(u8, allocated[43..key_start], response[43..key_start]);
            try std.testing.expectEqualSlices(u8, allocated[key_start + key_len .. prefix_len], response[key_start + key_len .. prefix_len]);
            // Independent legacy wire reference, supplied with this response's
            // fresh public-key/certificate randomness. Compare every wire byte.
            var legacy: [max_server_hello_len]u8 = undefined;
            const expected = legacy[0..response.len];
            if (pq) {
                @memset(expected, 0);
                @memcpy(expected[0..95], template[0..95]);
                std.mem.writeInt(u16, expected[3..5], 1210, .big);
                std.mem.writeInt(u24, expected[6..9], 1206, .big);
                std.mem.writeInt(u16, expected[79..81], 1134, .big);
                std.mem.writeInt(u16, expected[89..91], 1124, .big);
                std.mem.writeInt(u16, expected[91..93], 0x11ec, .big);
                std.mem.writeInt(u16, expected[93..95], 1120, .big);
                @memcpy(expected[1215..1226], template[127..138]);
            } else {
                @memcpy(expected, template);
            }
            @memcpy(expected[11..43], response[11..43]);
            @memcpy(expected[44..76], &sid);
            std.mem.writeInt(u16, expected[76..78], 0x1303, .big);
            @memcpy(expected[key_start..][0..key_len], response[key_start..][0..key_len]);
            @memcpy(expected[prefix_len..], response[prefix_len..]);
            try std.testing.expectEqualSlices(u8, expected, response);
            try std.testing.expectEqualSlices(u8, &sid, response[tmpl_session_id_offset..][0..32]);
            try std.testing.expectEqual(@as(?usize, cert_size), firstAppDataRecordLen(response));
            try std.testing.expectEqual(@as(u8, 0), response[key_start + key_len - 1] & 0x80);
            try std.testing.expect(!std.mem.eql(u8, allocated[prefix_len..], response[prefix_len..]));
            try expectServerHelloTestHmac(response, &secret, &digest);
            try expectServerHelloTestHmac(allocated, &secret, &digest);
            try std.testing.expectEqual(@as(u8, 0xa5), scratch[response.len]);
            try std.testing.expectError(error.NoSpaceLeft, if (pq)
                buildServerHelloPqInto(scratch[0 .. response.len - 1], &secret, &digest, &sid, 0x1303, cert_size)
            else
                buildServerHelloWithTemplateInto(scratch[0 .. response.len - 1], template, &secret, &digest, &sid, 0x1303));
        }
    }
    try std.testing.expectEqual(pqResponseLen(max_fake_cert_size), max_server_hello_len);
}

test "effectiveFakeCertSize uses a bounded fallback and preserves explicit sizes" {
    for (0..32) |_| {
        const size = effectiveFakeCertSize(0);
        try std.testing.expect(size >= default_fake_cert_min_size);
        try std.testing.expect(size <= default_fake_cert_max_size);
    }
    try std.testing.expectEqual(min_fake_cert_size, effectiveFakeCertSize(1));
    try std.testing.expectEqual(min_fake_cert_size, effectiveFakeCertSize(@intCast(min_fake_cert_size)));
    try std.testing.expectEqual(@as(usize, 4096), effectiveFakeCertSize(4096));
    try std.testing.expectEqual(max_fake_cert_size, effectiveFakeCertSize(@intCast(max_fake_cert_size)));
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

test "validateTlsHandshakeDetailed classifies authentication failures" {
    const allocator = std.testing.allocator;
    var secrets = [_]UserSecret{.{ .name = "alice", .secret = [_]u8{0x1A} ** 16 }};
    var diagnostic: TlsValidationDiagnostic = undefined;

    const bad_secret = buildTestClientHello(32, 0xaa);
    const bad_secret_result = try validateTlsHandshakeDetailed(
        allocator,
        &bad_secret,
        &secrets,
        true,
        &diagnostic,
    );
    try std.testing.expect(bad_secret_result == null);
    try std.testing.expectEqual(TlsValidationFailure.secret_mismatch, diagnostic.failure);
    try std.testing.expect(diagnostic.timestamp_skew_s == null);

    const bad_session = buildTestClientHello(4, 0xaa);
    const bad_session_result = try validateTlsHandshakeDetailed(
        allocator,
        &bad_session,
        &secrets,
        true,
        &diagnostic,
    );
    try std.testing.expect(bad_session_result == null);
    try std.testing.expectEqual(TlsValidationFailure.invalid_session_id, diagnostic.failure);
    try std.testing.expect(diagnostic.timestamp_skew_s == null);

    var stale = buildTestClientHello(32, 0xaa);
    const stale_hmac = crypto.sha256Hmac(&secrets[0].secret, &stale);
    @memcpy(stale[constants.tls_digest_pos..][0..constants.tls_digest_len], stale_hmac[0..]);
    const stale_result = try validateTlsHandshakeDetailed(
        allocator,
        &stale,
        &secrets,
        false,
        &diagnostic,
    );
    try std.testing.expect(stale_result == null);
    try std.testing.expectEqual(TlsValidationFailure.timestamp_skew, diagnostic.failure);
    try std.testing.expect(diagnostic.timestamp_skew_s != null);
    try std.testing.expect(diagnostic.timestamp_skew_s.? > constants.time_skew_max);
}

test "extractSni - malformed returns null" {
    // Too short
    const short = [_]u8{ 0x16, 0x03, 0x01, 0x00 };
    try std.testing.expect(extractSni(&short) == null);
    try std.testing.expect(switch (inspectSni(&short)) {
        .malformed => true,
        else => false,
    });
    // Not a handshake type
    try std.testing.expect(extractSni(&[_]u8{ 0x17, 0x03, 0x01, 0x00, 0x00 }) == null);

    const without_sni = buildTestClientHello(32, 0xaa);
    try std.testing.expect(switch (inspectSni(&without_sni)) {
        .missing => true,
        else => false,
    });
}

test "ClientHello readers reject malformed record framing" {
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

test "SNI routing ignores unrelated FakeTLS key-share policy" {
    const domain = "example.com";
    var ch = [_]u8{0} ** 83;
    const base = buildTestClientHello(0, 0);
    @memcpy(ch[0..50], base[0..50]);
    std.mem.writeInt(u16, ch[3..5], @intCast(ch.len - 5), .big);
    std.mem.writeInt(u24, ch[6..9], @intCast(ch.len - 9), .big);
    std.mem.writeInt(u16, ch[50..52], 31, .big);

    // A valid SNI extension followed by a structurally framed but noncanonical
    // X25519 key share. Listener routing must still find the WEB hostname; the
    // strict FakeTLS readers must continue rejecting the key share.
    std.mem.writeInt(u16, ch[52..54], 0x0000, .big);
    std.mem.writeInt(u16, ch[54..56], 16, .big);
    std.mem.writeInt(u16, ch[56..58], 14, .big);
    ch[58] = 0;
    std.mem.writeInt(u16, ch[59..61], @intCast(domain.len), .big);
    @memcpy(ch[61..72], domain);

    std.mem.writeInt(u16, ch[72..74], 0x0033, .big);
    std.mem.writeInt(u16, ch[74..76], 7, .big);
    std.mem.writeInt(u16, ch[76..78], 5, .big);
    std.mem.writeInt(u16, ch[78..80], 0x001d, .big);
    std.mem.writeInt(u16, ch[80..82], 1, .big);
    ch[82] = 0xaa;

    try std.testing.expectEqualStrings(domain, extractSni(&ch).?);
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

test "fuzz FakeTLS ClientHello parsing and validation" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var storage: [4096]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];
            const secrets = [_]UserSecret{.{
                .name = "fuzz-user",
                .secret = [_]u8{0x5a} ** 16,
            }};

            _ = isTlsHandshake(input);
            _ = extractSni(input);
            _ = extractFirstTls13Cipher(input);
            _ = clientOffersPqKeyShare(input);
            _ = validateTlsHandshake(std.testing.allocator, input, &secrets, true) catch null;
        }
    }.testOne, .{});
}
