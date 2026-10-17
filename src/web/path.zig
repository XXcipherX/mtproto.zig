//! Carrier paths must survive the browser URL parser byte-for-byte: relay route
//! matching is exact. See https://url.spec.whatwg.org/#path-state.
const std = @import("std");

pub fn isCanonicalWsPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or std.mem.startsWith(u8, path, "//")) return false;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        const byte = path[i];
        if (byte <= ' ' or byte >= 0x7f) return false;
        switch (byte) {
            // Path percent-encode set, query/fragment delimiters, and the
            // special-scheme backslash separator.
            '"', '<', '>', '^', '`', '{', '}', '?', '#', '\\' => return false,
            '%' => {
                if (path.len - i < 3 or !std.ascii.isHex(path[i + 1]) or !std.ascii.isHex(path[i + 2])) return false;
                i += 2;
            },
            else => {},
        }
    }
    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        for ([_][]const u8{ ".", "..", "%2e", ".%2e", "%2e.", "%2e%2e" }) |dot| {
            if (std.ascii.eqlIgnoreCase(segment, dot)) return false;
        }
    }
    return true;
}

test "carrier paths reject browser normalization and preserve canonical escapes" {
    for ([_][]const u8{
        "",          "socket",      "//socket",     "/a\\b", "/a b",  "/a\nb",  "/a\x7f",
        "/путь",
        "/a?b",      "/a#b",        "/a<b",         "/a>b",  "/a\"b", "/a`b",   "/a^b",
        "/a{b}",     "/a/./socket", "/a/../socket", "/.",    "/..",   "/%2e/",  "/a/%2E",
        "/a/.%2E/b", "/a/%2e./b",   "/a/%2E%2e/b",  "/a/%",  "/a/%2", "/a/%gg",
    }) |path| try std.testing.expect(!isCanonicalWsPath(path));
    for ([_][]const u8{
        "/",      "/api/v1/socket", "/relay/Path_1/api/v1/socket", "/a.b/.../socket",
        "/a//b/", "/a&b'c",         "/%20/%23/%2f/%5C/%25/%D0%BF", "/.%2e-x/%2Ex",
    }) |path| try std.testing.expect(isCanonicalWsPath(path));
}
