//! Bridge capability derivation and WEB-proxy hostname rules.
//!
//! Telegram Desktop never hands the MTProxy secret to JavaScript. Instead it derives a
//! domain-separated bearer token from `(hostname, secret)` and puts *that* in the page
//! URL it navigates the hidden WebView to:
//!
//!     context = base_path.len == 0
//!         ? "tdesktop-web-proxy-bridge-v1\n" + host
//!         : "tdesktop-web-proxy-bridge-v2\n" + host + "\n" + base_path
//!     bridge  = base64url-no-padding(HMAC-SHA256(key = secret_bytes, message = context))
//!     base    = base_path.len == 0 ? "/" : "/" + base_path + "/"
//!     url     = "https://" + host + base + "?bridge=" + bridge
//!
//! `secret_bytes` is the decoded MTProxy secret *including* its leading `dd` byte when
//! the link used the random-padding form — which ours always does, because tdesktop
//! rejects `ee` (FakeTLS) secrets for WEB proxies outright.
//!
//! Two things follow, and both are load-bearing for us:
//!
//!  1. Because we know every configured user secret, we can recompute the capability
//!     and learn *which user* is behind a bridge request without ever seeing the
//!     MTProto stream. Capabilities are a startup snapshot; restart the relay as well
//!     as the data plane when changing access users.
//!  2. A visitor who cannot present a capability derived from a real secret never sees
//!     the bridge page at all — they get the same empty 404 as the ordinary MTProto
//!     masking hostname.
//!
//! Reference: tdesktop `Telegram/SourceFiles/mtproto/mtproto_proxy_data.cpp`
//! (`ComputeWebProxyBridgeCapability`, `NormalizeWebProxyHost`, `LastLabelIsNumeric`).

const std = @import("std");

/// Domain-separation prefixes. The trailing newlines are part of the contexts.
pub const context_prefix_v1 = "tdesktop-web-proxy-bridge-v1\n";
pub const context_prefix_v2 = "tdesktop-web-proxy-bridge-v2\n";

/// base64url of a 32-byte HMAC with padding omitted.
pub const capability_len: usize = 43;

/// tdesktop's `dd` random-padding secret marker. WEB links must use this form (or a
/// bare 16-byte secret); `ee` FakeTLS secrets are reported as `Status::Unsupported`.
pub const padded_marker: u8 = 0xdd;

/// Marks a base-path WEB-link secret. Clients that understand the marker strip it
/// and retain the complete following MTProxy secret. Older clients reject the
/// otherwise non-canonical length instead of accepting a pathless empty host.
pub const path_secret_marker: u8 = 0x70;

/// Longest canonical WEB base path, excluding its surrounding slashes.
pub const max_base_path_len: usize = 128;

/// Longest hostname `NormalizeWebProxyHost` will accept.
pub const max_host_len: usize = 253;

pub const Capability = [capability_len]u8;

pub const BasePathError = error{
    TooLong,
    NonCanonical,
};

/// Validate the exact client/server base-path grammar. The empty string means the
/// historical host root. Non-empty paths contain slash-separated segments matching
/// `[A-Za-z0-9][A-Za-z0-9_-]*`, with no leading or trailing slash.
pub fn validateBasePath(path: []const u8) BasePathError!void {
    if (path.len == 0) return;
    if (path.len > max_base_path_len) return error.TooLong;
    if (path[0] == '/' or path[path.len - 1] == '/') return error.NonCanonical;

    var segment_start = true;
    for (path) |byte| {
        if (byte == '/') {
            if (segment_start) return error.NonCanonical;
            segment_start = true;
            continue;
        }
        const alpha_num = std.ascii.isAlphanumeric(byte);
        if (!alpha_num and (segment_start or (byte != '-' and byte != '_'))) {
            return error.NonCanonical;
        }
        segment_start = false;
    }
}

/// Derive the bridge capability for a normalized `host`, canonical `base_path`, and
/// raw `secret` bytes. The empty path preserves the frozen v1 context byte-for-byte.
pub fn derive(host: []const u8, base_path: []const u8, secret: []const u8) Capability {
    var mac_state = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    if (base_path.len == 0) {
        mac_state.update(context_prefix_v1);
        mac_state.update(host);
    } else {
        mac_state.update(context_prefix_v2);
        mac_state.update(host);
        mac_state.update("\n");
        mac_state.update(base_path);
    }
    var mac: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &mac);
    mac_state.final(&mac);

    var out: Capability = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&out, &mac);
    std.debug.assert(encoded.len == capability_len);
    return out;
}

/// Derive the capability for a 16-byte user secret carried in a `dd…` WEB link.
pub fn deriveForPaddedSecret(host: []const u8, base_path: []const u8, secret: [16]u8) Capability {
    var key: [17]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    key[0] = padded_marker;
    @memcpy(key[1..], &secret);
    return derive(host, base_path, &key);
}

/// Encode `0x70 || 0xdd || secret` for a base-path `tg://webproxy` link.
/// Eighteen input bytes encode to exactly 24 unpadded base64url characters.
pub fn encodeMarkedPaddedSecret(secret: [16]u8) [24]u8 {
    var marked: [18]u8 = undefined;
    defer std.crypto.secureZero(u8, &marked);
    marked[0] = path_secret_marker;
    marked[1] = padded_marker;
    @memcpy(marked[2..], &secret);

    var out: [24]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&out, &marked);
    std.debug.assert(encoded.len == out.len);
    return out;
}

/// Constant-time comparison of a presented capability against an expected one.
///
/// Presented capabilities come from an untrusted query string; comparing them in
/// constant time keeps the relay from leaking a per-user oracle through timing.
pub fn matches(presented: []const u8, expected: Capability) bool {
    if (presented.len != capability_len) return false;
    return std.crypto.timing_safe.eql([capability_len]u8, presented[0..capability_len].*, expected);
}

// ── hostname normalization ────────────────────────────────────────────────────

pub const HostError = error{
    /// Empty, or longer than 253 bytes.
    BadLength,
    /// Contains `:` `/` `?` `#` `@`, or a trailing dot.
    BadCharacters,
    /// Non-ASCII input. tdesktop maps Unicode hosts with whatever IDNA profile the Qt
    /// version it shipped uses, and the profiles disagree on deviation characters
    /// (`ß`, `ς`, ZWJ/ZWNJ) — a mismatch there silently changes the capability on some
    /// platforms. Operators must publish the ACE (`xn--…`) form, so we require it.
    NonAscii,
    /// A label was empty, over 63 bytes, hyphen-anchored, or held an illegal byte.
    BadLabel,
    /// Single-label name (no dot) — rejected by tdesktop.
    NotFullyQualified,
    /// An IP address or a WHATWG "ends in a number" shorthand (`127.1`, `0x7f.1`).
    IpLiteral,
};

/// Normalize and validate a WEB-proxy hostname exactly like `NormalizeWebProxyHost`,
/// writing the lowercase A-label form into `out` and returning that slice.
///
/// `out` must be at least `max_host_len` bytes.
pub fn normalizeHost(input: []const u8, out: []u8) HostError![]const u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > max_host_len) return error.BadLength;
    if (trimmed[trimmed.len - 1] == '.') return error.BadCharacters;
    for (trimmed) |c| {
        switch (c) {
            ':', '/', '?', '#', '@' => return error.BadCharacters,
            else => {},
        }
        if (c >= 0x80) return error.NonAscii;
        if (c < 0x20 or c == 0x7f) return error.BadCharacters;
    }
    if (out.len < trimmed.len) return error.BadLength;

    for (trimmed, 0..) |c, i| out[i] = std.ascii.toLower(c);
    const host = out[0..trimmed.len];

    if (std.mem.indexOfScalar(u8, host, '.') == null) return error.NotFullyQualified;

    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadLabel;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.BadLabel;
        for (label) |c| {
            const alnum = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
            if (!alnum and c != '-') return error.BadLabel;
        }
    }

    if (lastLabelIsNumeric(host)) return error.IpLiteral;
    return host;
}

/// The WHATWG URL "ends in a number" rule: a final label of ASCII digits, or a
/// `0x`-prefixed hex label, means the host is really an IPv4 address in some
/// shorthand (`127.1`, `0x7f.1`, `0177.0.0.1`).
fn lastLabelIsNumeric(host: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, host, '.');
    const label = if (dot) |d| host[d + 1 ..] else host;
    if (label.len == 0) return false;
    const hex = label.len >= 2 and label[0] == '0' and label[1] == 'x';
    const digits = if (hex) label[2..] else label;
    for (digits) |c| {
        const decimal = c >= '0' and c <= '9';
        const alpha = c >= 'a' and c <= 'f';
        if (!decimal and !(hex and alpha)) return false;
    }
    return true;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test "bridge capability matches the normative tdesktop vectors" {
    // tproxy-server BASE_PATH.md §1 and Telegram Desktop's own tests.
    const plain = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    try std.testing.expectEqualStrings(
        "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk",
        &derive("proxy.example.com", "", &plain),
    );
    try std.testing.expectEqualStrings(
        "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA",
        &deriveForPaddedSecret("proxy.example.com", "", plain),
    );
    try std.testing.expectEqualStrings(
        "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ",
        &derive("proxy.example.com", "dobry-cola-super-app", &plain),
    );
    try std.testing.expectEqualStrings(
        "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo",
        &deriveForPaddedSecret("proxy.example.com", "dobry-cola-super-app", plain),
    );
}

test "base path validation accepts only the canonical shared grammar" {
    for ([_][]const u8{ "", "a", "MixedCase", "two/segments", "a/b/c9_x-y" }) |path| {
        try validateBasePath(path);
    }
    for ([_][]const u8{ "/leading", "trailing/", "empty//segment", "-lead", "_lead", "a/-lead", "dot.ted", "..", "with space", "per%20cent", "unicode-é" }) |path| {
        try std.testing.expectError(error.NonCanonical, validateBasePath(path));
    }
    try validateBasePath("a" ** max_base_path_len);
    try std.testing.expectError(error.TooLong, validateBasePath("a" ** (max_base_path_len + 1)));
}

test "base path link marker wraps the complete padded MTProxy secret" {
    const plain = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    try std.testing.expectEqualStrings("cN0AAQIDBAUGBwgJCgsMDQ4P", &encodeMarkedPaddedSecret(plain));
}

test "capability comparison is length-checked" {
    const secret = [_]u8{0xab} ** 16;
    const cap = deriveForPaddedSecret("proxy.example.com", "", secret);
    try std.testing.expect(matches(&cap, cap));
    try std.testing.expect(!matches(cap[0 .. capability_len - 1], cap));
    try std.testing.expect(!matches("", cap));
    var wrong = cap;
    wrong[0] = if (wrong[0] == 'A') 'B' else 'A';
    try std.testing.expect(!matches(&wrong, cap));
}

test "host normalization accepts and lowercases a real hostname" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "proxy.example.com",
        try normalizeHost(" Proxy.Example.COM ", &buf),
    );
    try std.testing.expectEqualStrings(
        "xn--strae-oqa.example",
        try normalizeHost("xn--strae-oqa.example", &buf),
    );
}

test "host normalization rejects what tdesktop rejects" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectError(error.NotFullyQualified, normalizeHost("localhost", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("127.0.0.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("127.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("0x7f.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("0177.0.0.1", &buf));
    try std.testing.expectError(error.IpLiteral, normalizeHost("1.2.3", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("site.example:443", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("site.example.", &buf));
    try std.testing.expectError(error.BadCharacters, normalizeHost("https://site.example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("site..example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("-site.example", &buf));
    try std.testing.expectError(error.BadLabel, normalizeHost("site-.example", &buf));
    try std.testing.expectError(error.BadLength, normalizeHost("   ", &buf));
    try std.testing.expectError(error.NonAscii, normalizeHost("bücher.example", &buf));
}

test "host normalization keeps a hex-looking label that is not last" {
    var buf: [max_host_len]u8 = undefined;
    try std.testing.expectEqualStrings("0x7f.example", try normalizeHost("0x7f.example", &buf));
}

test "capability changes with the hostname" {
    const secret = [_]u8{0x11} ** 16;
    const a = deriveForPaddedSecret("a.example", "", secret);
    const b = deriveForPaddedSecret("b.example", "", secret);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "capability changes with the base path" {
    const secret = [_]u8{0x22} ** 16;
    const root = deriveForPaddedSecret("proxy.example", "", secret);
    const one = deriveForPaddedSecret("proxy.example", "one", secret);
    const two = deriveForPaddedSecret("proxy.example", "two", secret);
    try std.testing.expect(!std.mem.eql(u8, &root, &one));
    try std.testing.expect(!std.mem.eql(u8, &one, &two));
}
