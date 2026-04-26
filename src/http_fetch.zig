const std = @import("std");
const posix = std.posix;

pub const default_timeout_sec: u32 = 10;

pub const FetchOptions = struct {
    max_response_bytes: usize,
    timeout_sec: u32 = default_timeout_sec,
    max_redirects: u8 = 3,
};

fn setSocketTimeouts(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch return;
}

fn setConnectionTimeouts(connection: anytype, timeout_sec: u32) void {
    // Keep std.http transport access localized; the public timeout policy above
    // should not depend on call sites knowing the current stream_reader shape.
    setSocketTimeouts(connection.stream_reader.getStream().handle, timeout_sec);
}

pub fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8, options: FetchOptions) ![]u8 {
    const uri = try std.Uri.parse(url);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.GET, uri, .{
        .redirect_behavior = @enumFromInt(options.max_redirects),
        .keep_alive = false,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer req.deinit();

    if (req.connection) |connection| {
        setConnectionTimeouts(connection, options.timeout_sec);
    }

    try req.sendBodiless();

    // Some std.http paths establish the socket lazily on send.
    if (req.connection) |connection| {
        setConnectionTimeouts(connection, options.timeout_sec);
    }

    var redirect_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status.class() != .success) return error.HttpRequestFailed;

    var transfer_buf: [4 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    return reader.allocRemaining(allocator, .limited(options.max_response_bytes));
}
