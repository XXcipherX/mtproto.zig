//! Minimal HTTP/1.1 request parsing for the WEB proxy relay.
//!
//! The relay serves one capability-gated bridge page, its token-authenticated WebSocket
//! upgrade, and an optional startup-loaded public site. Without that site, ordinary
//! HTTP routes retain the fork's bodyless 404. It never proxies HTTP, never reads a
//! request body, and only ever answers `GET`/`HEAD`. Body-bearing requests force
//! Connection: close and cannot upgrade or become a second request. Ambiguous framing
//! (Transfer-Encoding with Content-Length or duplicate length headers) is rejected.
//!
//! `src/monitoring.zig` already serves `/metrics` with prefix matching and a single
//! 2 KiB read. That is fine for a loopback endpoint but cannot extract
//! `Sec-WebSocket-Key`, so the relay needs real header parsing — kept here, separate
//! from the event loop, so it is exhaustively unit-testable.

const std = @import("std");

/// Largest request head we will buffer. tdesktop bounds its own loopback HTTP boundary
/// at the same 16 KiB; browsers never send more for a plain GET.
pub const max_head_bytes: usize = 16 * 1024;

/// Headers beyond this are a client we do not want to talk to.
pub const max_headers: usize = 48;

pub const Method = enum { get, head, other };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const ParseError = error{
    /// Malformed request line, bad version, illegal header, a body, or too many headers.
    Malformed,
    /// The head exceeded `max_head_bytes` before `\r\n\r\n` appeared.
    HeadTooLarge,
};

pub const Request = struct {
    method: Method,
    /// Request target as sent, e.g. `/?bridge=abc`.
    target: []const u8,
    /// Authentication selectors accept only the canonical origin-form request target.
    /// Absolute-form targets remain parseable as ordinary HTTP but cannot authenticate.
    origin_form: bool = true,
    /// Bytes the complete head occupies, including the terminating blank line.
    head_len: usize,
    /// HTTP/1.0 request — different keep-alive default.
    http_1_0: bool,
    headers_buf: [max_headers]Header,
    headers_len: usize,
    has_body: bool = false,

    pub fn headers(self: *const Request) []const Header {
        return self.headers_buf[0..self.headers_len];
    }

    /// First header matching `name` (ASCII case-insensitive), or null.
    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Number of field lines matching `name` (ASCII case-insensitive).
    ///
    /// The browser emits one line for each WebSocket handshake field. Rejecting
    /// duplicates keeps the authenticated carrier request canonical instead of letting
    /// an intermediary and the relay disagree about which value is authoritative.
    pub fn headerCount(self: *const Request, name: []const u8) usize {
        var count: usize = 0;
        for (self.headers()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) count += 1;
        }
        return count;
    }

    /// **Last** header matching `name` (ASCII case-insensitive), or null.
    ///
    /// RFC 9110 §5.2 makes repeated field lines equivalent to one comma-joined value, in
    /// order, so any rule that reads the right-most entry of a list has to read the last
    /// line. A terminator that *appends* its own `X-Forwarded-For` line instead of
    /// replacing ours (a CDN, or an operator's own front) would otherwise hand
    /// `header()`'s first match — the line the client wrote — to `forwardedForClient`,
    /// and a hostile client would pick the address Telegram is told.
    pub fn lastHeader(self: *const Request, name: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        for (self.headers()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) found = h.value;
        }
        return found;
    }

    /// True when a comma-separated list header contains `token` (case-insensitive).
    /// `Connection: keep-alive, Upgrade` must match `Upgrade`, so a plain equality
    /// check on the whole value is not enough.
    pub fn headerHasToken(self: *const Request, name: []const u8, token: []const u8) bool {
        const value = self.header(name) orelse return false;
        return listHasToken(value, token);
    }

    /// Path portion of the target (everything before `?`).
    pub fn path(self: *const Request) []const u8 {
        return pathOf(self.target);
    }

    /// Raw (still percent-encoded) value of query parameter `key`, or null.
    pub fn query(self: *const Request, key: []const u8) ?[]const u8 {
        return queryValue(self.target, key);
    }

    /// Whether the connection may be reused after this response. HTTP/1.1 defaults to
    /// keep-alive and HTTP/1.0 to close; the relay honours both for bridge and empty
    /// masking responses.
    pub fn keepAlive(self: *const Request) bool {
        if (self.has_body) return false;
        if (self.headerHasToken("connection", "close")) return false;
        if (self.http_1_0) return self.headerHasToken("connection", "keep-alive");
        return true;
    }
};

pub fn listHasToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

pub fn pathOf(target: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    if (q == 0) return "/";
    return target[0..q];
}

pub fn queryValue(target: []const u8, key: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Offset just past `\r\n\r\n`, or null while the head is still incomplete.
pub fn headEnd(buf: []const u8) ?usize {
    const idx = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    return idx + 4;
}

/// Parse a complete request head. `buf` must contain at least one `\r\n\r\n`.
pub fn parse(buf: []const u8) ParseError!Request {
    const end = headEnd(buf) orelse {
        return if (buf.len >= max_head_bytes) error.HeadTooLarge else error.Malformed;
    };
    if (end > max_head_bytes) return error.HeadTooLarge;

    const head = buf[0 .. end - 4]; // everything before the terminating blank line
    var lines = std.mem.splitSequence(u8, head, "\r\n");

    const request_line = lines.next() orelse return error.Malformed;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_text = parts.next() orelse return error.Malformed;
    const raw_target = parts.next() orelse return error.Malformed;
    var target = raw_target;
    if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://")) {
        const scheme_len: usize = if (target[4] == ':') 7 else 8;
        const authority_end = std.mem.indexOfAnyPos(u8, target, scheme_len, "/?") orelse target.len;
        if (authority_end == scheme_len) return error.Malformed;
        target = if (authority_end == target.len) "/" else target[authority_end..];
    }
    const version = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;
    const http_1_0 = std.mem.eql(u8, version, "HTTP/1.0");
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !http_1_0) return error.Malformed;
    if (target.len == 0 or (target[0] != '/' and target[0] != '?')) return error.Malformed;
    for (raw_target) |c| {
        if (c <= 0x20 or c == 0x7f) return error.Malformed;
    }

    const method: Method = if (std.mem.eql(u8, method_text, "GET"))
        .get
    else if (std.mem.eql(u8, method_text, "HEAD"))
        .head
    else
        .other;

    var request = Request{
        .method = method,
        .target = target,
        .origin_form = raw_target.len > 0 and raw_target[0] == '/',
        .head_len = end,
        .http_1_0 = http_1_0,
        .headers_buf = undefined,
        .headers_len = 0,
    };

    while (lines.next()) |line| {
        if (line.len == 0) return error.Malformed; // an empty line inside the head
        // Obsolete line folding is a smuggling primitive; refuse it.
        if (line[0] == ' ' or line[0] == '\t') return error.Malformed;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
        const name = line[0..colon];
        if (name.len == 0) return error.Malformed;
        for (name) |c| {
            // RFC 9110 field-name: no spaces, no controls, no separators we care about.
            if (c <= 0x20 or c == 0x7f or c == ':') return error.Malformed;
        }
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (value) |c| {
            if (c < 0x20 and c != '\t') return error.Malformed;
        }
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked") or request.header("transfer-encoding") != null or request.header("content-length") != null) return error.Malformed;
            request.has_body = true;
        }
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (value.len == 0 or request.header("content-length") != null or request.header("transfer-encoding") != null) return error.Malformed;
            for (value) |c| if (!std.ascii.isDigit(c)) return error.Malformed;
            const length = std.fmt.parseInt(u64, value, 10) catch return error.Malformed;
            request.has_body = length != 0;
        }
        if (request.headers_len >= max_headers) return error.Malformed;
        request.headers_buf[request.headers_len] = .{ .name = name, .value = value };
        request.headers_len += 1;
    }

    return request;
}

/// Upgrade envelope authenticated before the WebSocket key is interpreted. Keeping the
/// key out of this predicate lets a valid short-lived token receive a truthful 400 for a
/// missing or malformed key without exposing that distinction to unauthenticated traffic.
fn hasWebSocketUpgradeEnvelope(req: *const Request) bool {
    if (req.method != .get or req.has_body) return false;
    if (req.headerCount("upgrade") != 1 or req.headerCount("connection") != 1) return false;
    if (req.headerCount("sec-websocket-version") != 1) return false;
    if (!req.headerHasToken("upgrade", "websocket")) return false;
    if (!req.headerHasToken("connection", "upgrade")) return false;
    const version = req.header("sec-websocket-version") orelse return false;
    return std.mem.eql(u8, version, "13");
}

/// True when the request carries the complete canonical RFC 6455 upgrade envelope.
/// Key syntax itself is checked by the WebSocket implementation after token matching.
pub fn isWebSocketUpgrade(req: *const Request) bool {
    return hasWebSocketUpgradeEnvelope(req) and req.headerCount("sec-websocket-key") == 1;
}

/// The **right-most** entry of a forwarded-for list.
///
/// The left-most entry is the one everybody reaches for, and it is the one an attacker
/// controls: a proxy that appends with `$proxy_add_x_forwarded_for` keeps whatever the
/// client sent and adds the address it observed, so `X-Forwarded-For: 1.2.3.4` from a
/// hostile client becomes `1.2.3.4, <real address>` and the left-most read hands the
/// attacker an arbitrary identity.
///
/// The right-most entry is always written by the hop directly in front of us — ours —
/// and cannot be forged. With a terminator that overwrites rather than appends (which is
/// what our own vhost does) the list has exactly one entry and the two readings agree.
/// A single-value header such as `CF-Connecting-IP` also lands here unchanged.
///
/// Repeated header *lines* are one and the same list (RFC 9110 §5.2), so the value fed
/// in here must come from `Request.lastHeader`, never `Request.header`.
pub fn forwardedForClient(value: []const u8) ?[]const u8 {
    var it = std.mem.splitBackwardsScalar(u8, value, ',');
    const last = std.mem.trim(u8, it.next() orelse return null, " \t");
    return if (last.len == 0) null else last;
}

// ── tests ─────────────────────────────────────────────────────────────────────

const sample_get =
    "GET /?bridge=abc HTTP/1.1\r\n" ++
    "Host: proxy.example.com\r\n" ++
    "User-Agent: test\r\n" ++
    "Accept: */*\r\n" ++
    "\r\n";

test "absolute-form targets route as origin-form without accepting ambiguous framing" {
    const req = try parse("GET https://example.com/path?bridge=abc HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try std.testing.expectEqualStrings("/path", req.path());
    try std.testing.expectEqualStrings("abc", req.query("bridge").?);
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"));
}

test "parses a plain GET" {
    const req = try parse(sample_get);
    try std.testing.expectEqual(Method.get, req.method);
    try std.testing.expectEqualStrings("/?bridge=abc", req.target);
    try std.testing.expectEqualStrings("/", req.path());
    try std.testing.expectEqualStrings("abc", req.query("bridge").?);
    try std.testing.expectEqual(@as(?[]const u8, null), req.query("nope"));
    try std.testing.expectEqualStrings("proxy.example.com", req.header("HOST").?);
    try std.testing.expectEqual(@as(usize, 3), req.headers_len);
    try std.testing.expectEqual(sample_get.len, req.head_len);
    try std.testing.expect(req.keepAlive());
}

test "head boundary detection ignores an incomplete head" {
    try std.testing.expectEqual(@as(?usize, null), headEnd("GET / HTTP/1.1\r\nHost: x\r\n"));
    try std.testing.expectEqual(@as(?usize, 27), headEnd("GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"));
}

test "recognises a WebSocket upgrade and its variations" {
    const upgrade =
        "GET /api/v1/socket HTTP/1.1\r\n" ++
        "Host: proxy.example.com\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Upgrade: WebSocket\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Origin: https://proxy.example.com\r\n" ++
        "\r\n";
    const req = try parse(upgrade);
    try std.testing.expect(isWebSocketUpgrade(&req));
    try std.testing.expectEqualStrings("/api/v1/socket", req.path());
    try std.testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", req.header("sec-websocket-key").?);
}

test "an upgrade missing version 13 is not an upgrade" {
    const bad =
        "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" ++
        "Sec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const req = try parse(bad);
    try std.testing.expect(!isWebSocketUpgrade(&req));
}

test "duplicate WebSocket handshake fields are not canonical" {
    const duplicate_key = try parse(
        "GET /api/v1/socket HTTP/1.1\r\n" ++
            "Host: proxy.example.com\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    );
    try std.testing.expectEqual(@as(usize, 2), duplicate_key.headerCount("sec-websocket-key"));
    try std.testing.expect(!isWebSocketUpgrade(&duplicate_key));
}

test "an empty body declaration is accepted, the way a static host would" {
    // Refusing this is a one-request, secret-less way to tell the relay apart from any
    // ordinary web server, including the Caddy 404 masking endpoint in front of it.
    const req = try parse("GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n");
    try std.testing.expectEqualStrings("/", req.path());
    try std.testing.expectEqual(@as(usize, 2), req.headers_len);
}

test "a duplicated content-length is still refused" {
    const dup = "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expectError(error.Malformed, parse(dup));
}

test "body requests force connection close and folded headers are refused" {
    const with_len = "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    const body = try parse(with_len);
    try std.testing.expect(!body.keepAlive());
    try std.testing.expect(!isWebSocketUpgrade(&body));
    const chunked = "GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    const chunks = try parse(chunked);
    try std.testing.expect(!chunks.keepAlive());
    const folded = "GET / HTTP/1.1\r\nHost: h\r\n  continued\r\n\r\n";
    try std.testing.expectError(error.Malformed, parse(folded));
}

test "malformed request lines are refused" {
    try std.testing.expectError(error.Malformed, parse("GET /\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/2.0\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET http:/// HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1 extra\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nnovalue\r\n\r\n"));
}

test "non-GET methods parse but are classified as other" {
    const req = try parse("POST / HTTP/1.1\r\nHost: h\r\n\r\n");
    try std.testing.expectEqual(Method.other, req.method);
}

test "connection close is honoured, and HTTP/1.0 defaults to close" {
    const closed = try parse("GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n");
    try std.testing.expect(!closed.keepAlive());
    const old = try parse("GET / HTTP/1.0\r\nHost: h\r\n\r\n");
    try std.testing.expect(!old.keepAlive());
    const old_keep = try parse("GET / HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n");
    try std.testing.expect(old_keep.keepAlive());
}

test "too many headers is refused" {
    var buf: [max_head_bytes]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("GET / HTTP/1.1\r\n");
    for (0..max_headers + 1) |i| try w.print("X-{d}: v\r\n", .{i});
    try w.writeAll("\r\n");
    try std.testing.expectError(error.Malformed, parse(w.buffered()));
}

test "forwarded-for takes the right-most entry, which the client cannot forge" {
    // "1.2.3.4" here is what a hostile client sent; "10.0.0.1" is what our own hop saw.
    try std.testing.expectEqualStrings("10.0.0.1", forwardedForClient("1.2.3.4, 10.0.0.1").?);
    try std.testing.expectEqualStrings("203.0.113.7", forwardedForClient("203.0.113.7").?);
    try std.testing.expectEqualStrings("2001:db8::1", forwardedForClient(" 2001:db8::1 ").?);
    try std.testing.expectEqual(@as(?[]const u8, null), forwardedForClient(""));
    try std.testing.expectEqual(@as(?[]const u8, null), forwardedForClient("1.2.3.4, "));

    // Two header LINES are one comma-joined list, so the right-most entry lives on the
    // last line. Reading the first one hands the address the client typed to the proxy
    // — and from there to RPC_PROXY_REQ.remote_ip_port and the per-user IP quota.
    const two_lines =
        "GET / HTTP/1.1\r\n" ++
        "Host: relay.example.com\r\n" ++
        "X-Forwarded-For: 9.9.9.9\r\n" ++
        "X-Forwarded-For: 203.0.113.7\r\n" ++
        "\r\n";
    const req = try parse(two_lines);
    try std.testing.expectEqualStrings("9.9.9.9", req.header("x-forwarded-for").?);
    try std.testing.expectEqualStrings("203.0.113.7", req.lastHeader("X-Forwarded-For").?);
    try std.testing.expectEqualStrings("203.0.113.7", forwardedForClient(req.lastHeader("x-forwarded-for").?).?);
    // One line still reads the same through both accessors.
    const one_line = try parse("GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.2.3.4, 10.0.0.1\r\n\r\n");
    try std.testing.expectEqualStrings("10.0.0.1", forwardedForClient(one_line.lastHeader("x-forwarded-for").?).?);
    try std.testing.expectEqual(@as(?[]const u8, null), one_line.lastHeader("cf-connecting-ip"));
}

test "token list matching is case-insensitive and comma aware" {
    try std.testing.expect(listHasToken("keep-alive, Upgrade", "upgrade"));
    try std.testing.expect(listHasToken("Upgrade", "UPGRADE"));
    try std.testing.expect(!listHasToken("upgraded", "upgrade"));
}

/// Only the exact origin-form bridge GET is authenticated. `bridge_path` is `/` for
/// root deployments and the effective `/<base_path>/` route otherwise.
pub fn bridgeValue(request: *const Request, bridge_path: []const u8, host: []const u8) ?[]const u8 {
    if (request.method != .get or request.has_body or !request.origin_form or !hostMatches(request, host)) return null;
    if (!std.mem.startsWith(u8, request.target, bridge_path)) return null;
    const rest = request.target[bridge_path.len..];
    const prefix = "?bridge=";
    if (rest.len != prefix.len + 43 or !std.mem.startsWith(u8, rest, prefix)) return null;
    const value = rest[prefix.len..];
    if (!canonicalToken(value)) return null;
    return value;
}

pub fn singleHeader(request: *const Request, name: []const u8) ?[]const u8 {
    var result: ?[]const u8 = null;
    for (request.headers()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, name)) continue;
        if (result != null) return null;
        result = h.value;
    }
    return result;
}

pub fn hostMatches(request: *const Request, expected: []const u8) bool {
    const host = singleHeader(request, "host") orelse return false;
    return std.mem.eql(u8, host, expected) or
        (host.len == expected.len + 4 and std.mem.startsWith(u8, host, expected) and std.mem.endsWith(u8, host, ":443"));
}

/// Return the short-lived carrier token only for the exact carrier route, upgrade
/// envelope and single canonical subprotocol value. No query string is accepted.
/// Sec-WebSocket-Key is deliberately validated after token authentication.
pub fn carrierToken(request: *const Request, path: []const u8, host: []const u8) ?[]const u8 {
    if (!request.origin_form or !std.mem.eql(u8, request.target, path) or !hostMatches(request, host) or !hasWebSocketUpgradeEnvelope(request)) return null;
    const protocol = singleHeader(request, "sec-websocket-protocol") orelse return null;
    const prefix = "tproxy-v1.";
    if (protocol.len != prefix.len + 43 or !std.mem.startsWith(u8, protocol, prefix)) return null;
    const token = protocol[prefix.len..];
    if (!canonicalToken(token)) return null;
    return token;
}

fn canonicalToken(value: []const u8) bool {
    if (value.len != 43) return false;
    for (value) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    // 32 bytes encode to 43 base64url characters. The last symbol contains only four
    // significant bits, so its two unused low bits must be zero.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = std.mem.indexOfScalar(u8, alphabet, value[42]) orelse return false;
    return (last & 3) == 0;
}

test "canonical bridge selector supports root and base path and rejects aliases" {
    const token = "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA";
    const root = try parse("GET /?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n");
    try std.testing.expectEqualStrings(token, bridgeValue(&root, "/", "proxy.example.com").?);
    const based = try parse("GET /relay/Path_1/?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com:443\r\n\r\n");
    try std.testing.expectEqualStrings(token, bridgeValue(&based, "/relay/Path_1/", "proxy.example.com").?);

    const cases = [_][]const u8{
        "GET /?bridge=" ++ token ++ "&x=1 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
        "GET /?bridge=" ++ token ++ "&bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
        "HEAD /?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
        "GET /?b=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
        "GET /?bridge=" ++ token ++ " HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
        "GET /?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\nHost: proxy.example.com\r\n\r\n",
        "GET https://proxy.example.com/?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
        "GET /?bridge=" ++ token ++ " HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Length: 1\r\n\r\n",
    };
    for (cases) |raw| {
        const req = try parse(raw);
        try std.testing.expect(bridgeValue(&req, "/", "proxy.example.com") == null);
    }
}

test "carrier selector requires exact path host and unique canonical subprotocol" {
    const token = "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA";
    const headers =
        " HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    const valid = try parse("GET /relay/api/v1/socket" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expectEqualStrings(token, carrierToken(&valid, "/relay/api/v1/socket", "proxy.example.com").?);

    const no_key_headers =
        " HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const missing_key = try parse("GET /relay/api/v1/socket" ++ no_key_headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(!isWebSocketUpgrade(&missing_key));
    try std.testing.expectEqualStrings(token, carrierToken(&missing_key, "/relay/api/v1/socket", "proxy.example.com").?);
    const invalid_key = try parse("GET /relay/api/v1/socket" ++ no_key_headers ++ "Sec-WebSocket-Key: invalid\r\nSec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expectEqualStrings(token, carrierToken(&invalid_key, "/relay/api/v1/socket", "proxy.example.com").?);

    const old_query = try parse("GET /relay/api/v1/socket?b=" ++ token ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&old_query, "/relay/api/v1/socket", "proxy.example.com") == null);
    const extra_query = try parse("GET /relay/api/v1/socket?x=1" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&extra_query, "/relay/api/v1/socket", "proxy.example.com") == null);
    const wrong_path = try parse("GET /relay/api/v1/other" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&wrong_path, "/relay/api/v1/socket", "proxy.example.com") == null);
    const duplicate = try parse("GET /relay/api/v1/socket" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\nSec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&duplicate, "/relay/api/v1/socket", "proxy.example.com") == null);
    const bad_host = try parse("GET /relay/api/v1/socket HTTP/1.1\r\nHost: other.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&bad_host, "/relay/api/v1/socket", "proxy.example.com") == null);
    const duplicate_host = try parse("GET /relay/api/v1/socket" ++ headers ++ "Host: proxy.example.com\r\nSec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&duplicate_host, "/relay/api/v1/socket", "proxy.example.com") == null);
    const malformed = try parse("GET /relay/api/v1/socket" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&malformed, "/relay/api/v1/socket", "proxy.example.com") == null);
    const absolute = try parse("GET https://proxy.example.com/relay/api/v1/socket" ++ headers ++ "Sec-WebSocket-Protocol: tproxy-v1." ++ token ++ "\r\n\r\n");
    try std.testing.expect(carrierToken(&absolute, "/relay/api/v1/socket", "proxy.example.com") == null);
}

test "fuzz HTTP request parsing" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var storage: [max_head_bytes + 64]u8 = undefined;
            const input = storage[0..smith.slice(&storage)];

            _ = headEnd(input);
            if (parse(input)) |request| {
                try std.testing.expect(request.head_len <= input.len);
                try std.testing.expect(request.headers_len <= max_headers);
                _ = request.path();
                _ = request.query("bridge");
                _ = request.keepAlive();
                _ = isWebSocketUpgrade(&request);
            } else |_| {}
        }
    }.testOne, .{});
}
