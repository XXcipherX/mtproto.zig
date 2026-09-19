//! Operator-owned static public files, loaded once so the network loop never reads disk.
const std = @import("std");
const io = std.Io.Threaded.global_single_threaded.io();
const max_files: usize = 256;
const max_file_bytes: usize = 2 * 1024 * 1024;
const max_total_bytes: usize = 16 * 1024 * 1024;

const Entry = struct {
    path: []u8,
    body: []u8,
    mime: []const u8,
    etag: [64]u8,
};

pub const Site = struct {
    entries: std.ArrayList(Entry) = .empty,

    pub fn deinit(self: *Site, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            allocator.free(entry.path);
            allocator.free(entry.body);
        }
        self.entries.deinit(allocator);
    }

    pub fn load(allocator: std.mem.Allocator, path: ?[]const u8) !Site {
        if (path == null) return .{};
        var dir = try std.Io.Dir.cwd().openDir(io, path.?, .{ .iterate = true });
        defer dir.close(io);
        return fromDir(allocator, dir);
    }

    pub fn fromDir(allocator: std.mem.Allocator, dir: std.Io.Dir) !Site {
        var opened = try dir.openDir(io, ".", .{ .iterate = true });
        defer opened.close(io);
        var walker = try opened.walk(allocator);
        defer {
            while (walker.inner.stack.items.len > 1) walker.leave(io);
            walker.deinit();
        }

        var self = Site{};
        errdefer self.deinit(allocator);
        var bytes: usize = 0;
        while (try walker.next(io)) |file| {
            if (file.kind == .directory) {
                if (file.depth() > 8 or file.basename[0] == '.') walker.leave(io);
                continue;
            }
            // The walker does not follow symlinks. Only regular, non-hidden files
            // become routes.
            if (file.kind != .file) continue;
            if (self.entries.items.len >= max_files or file.path.len > 1024) return error.PublicSiteTooLarge;
            var parts = std.mem.splitScalar(u8, file.path, '/');
            var hidden = false;
            while (parts.next()) |part| {
                if (part.len > 0 and part[0] == '.') hidden = true;
            }
            if (hidden) continue;

            const body = try file.dir.readFileAlloc(io, file.basename, allocator, .limited(max_file_bytes));
            errdefer allocator.free(body);
            bytes += body.len;
            if (bytes > max_total_bytes) return error.PublicSiteTooLarge;
            const name = try allocator.dupe(u8, file.path);
            errdefer allocator.free(name);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
            try self.entries.append(allocator, .{
                .path = name,
                .body = body,
                .mime = mime(file.path),
                .etag = std.fmt.bytesToHex(digest, .lower),
            });
        }
        return self;
    }

    pub fn find(self: *const Site, target: []const u8) ?*const Entry {
        if (target.len == 0 or target[0] != '/') return null;
        const path = if (std.mem.eql(u8, target, "/")) "index.html" else target[1..];
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, path, entry.path)) return entry;
        }
        return null;
    }
};

test "public files retain operator bytes and exact routes without generated cover" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    try dir.dir.writeFile(io, .{ .sub_path = "index.html", .data = "My real website" });
    try dir.dir.writeFile(io, .{ .sub_path = "style.css", .data = "body{}" });
    try dir.dir.writeFile(io, .{ .sub_path = ".secret", .data = "never public" });
    var site = try Site.fromDir(std.testing.allocator, dir.dir);
    defer site.deinit(std.testing.allocator);

    try std.testing.expect(site.find("/") != null);
    try std.testing.expectEqualStrings("My real website", site.find("/").?.body);
    try std.testing.expectEqualStrings("text/css; charset=utf-8", site.find("/style.css").?.mime);
    try std.testing.expectEqual(@as(usize, 64), site.find("/").?.etag.len);
    try std.testing.expect(site.find("/.secret") == null);
    try std.testing.expect(site.find("/missing") == null);
    try std.testing.expect(site.find("/../index.html") == null);
    try std.testing.expect(site.find("/%2e%2e/index.html") == null);
}

test "public site file count is bounded" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var name_buf: [32]u8 = undefined;
    for (0..max_files + 1) |index| {
        const name = try std.fmt.bufPrint(&name_buf, "asset-{d}.txt", .{index});
        try dir.dir.writeFile(io, .{ .sub_path = name, .data = "" });
    }
    try std.testing.expectError(error.PublicSiteTooLarge, Site.fromDir(std.testing.allocator, dir.dir));
}

test "public site rejects a file above the per-file limit" {
    const allocator = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const oversized = try allocator.alloc(u8, max_file_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');
    try dir.dir.writeFile(io, .{ .sub_path = "oversized.bin", .data = oversized });

    var rejected = false;
    var site = Site.fromDir(allocator, dir.dir) catch blk: {
        rejected = true;
        break :blk Site{};
    };
    defer site.deinit(allocator);
    try std.testing.expect(rejected);
}

test "public site total loaded bytes are bounded" {
    const allocator = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    const chunk = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    var name_buf: [32]u8 = undefined;
    for (0..17) |index| {
        const name = try std.fmt.bufPrint(&name_buf, "chunk-{d}.bin", .{index});
        try dir.dir.writeFile(io, .{ .sub_path = name, .data = chunk });
    }
    try std.testing.expectError(error.PublicSiteTooLarge, Site.fromDir(allocator, dir.dir));
}

test "no configured public directory creates no deployment fingerprint" {
    var site = try Site.load(std.testing.allocator, null);
    defer site.deinit(std.testing.allocator);
    try std.testing.expect(site.find("/") == null);
}

fn mime(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const types = .{
        .{ ".html", "text/html; charset=utf-8" },     .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" }, .{ ".json", "application/json" },
        .{ ".txt", "text/plain; charset=utf-8" },     .{ ".svg", "image/svg+xml" },
        .{ ".png", "image/png" },                     .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },                   .{ ".ico", "image/x-icon" },
        .{ ".webp", "image/webp" },                   .{ ".woff2", "font/woff2" },
    };
    inline for (types) |pair| {
        if (std.ascii.eqlIgnoreCase(ext, pair[0])) return pair[1];
    }
    return "application/octet-stream";
}
