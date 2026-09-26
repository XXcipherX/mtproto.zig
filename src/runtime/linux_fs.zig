//! Bounded reads for Linux procfs/cgroup pseudo-files.
//! Zig 0.16's convenient allocRemaining path can trust a zero stat.size for
//! these files and return empty data; read the stream until EOF instead.

const std = @import("std");
const builtin = @import("builtin");

pub fn readPseudoFileAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buf);
    return readRemainingBounded(&reader.interface, allocator, max_bytes);
}

fn readRemainingBounded(reader: *std.Io.Reader, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (result.items.len < max_bytes) {
        const n = try reader.readSliceShort(buffer[0..@min(buffer.len, max_bytes - result.items.len)]);
        if (n == 0) return result.toOwnedSlice(allocator);
        try result.appendSlice(allocator, buffer[0..n]);
    }
    if (try reader.readSliceShort(buffer[0..1]) != 0) return error.StreamTooLong;
    return result.toOwnedSlice(allocator);
}

test "bounded pseudo-file reading handles empty exact and oversized input" {
    const allocator = std.testing.allocator;
    var empty = std.Io.Reader.fixed("");
    const empty_result = try readRemainingBounded(&empty, allocator, 0);
    defer allocator.free(empty_result);
    try std.testing.expectEqual(@as(usize, 0), empty_result.len);
    var exact = std.Io.Reader.fixed("abc");
    const result = try readRemainingBounded(&exact, allocator, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("abc", result);
    var oversized = std.Io.Reader.fixed("abcd");
    try std.testing.expectError(error.StreamTooLong, readRemainingBounded(&oversized, allocator, 3));
    var zero_limit = std.Io.Reader.fixed("a");
    try std.testing.expectError(error.StreamTooLong, readRemainingBounded(&zero_limit, allocator, 0));
}

test "procfs status is not empty despite zero stat size" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const content = try readPseudoFileAlloc(std.testing.allocator, "/proc/self/status", 64 * 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "Name:") != null);
}
