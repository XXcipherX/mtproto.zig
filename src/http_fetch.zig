const std = @import("std");
const compat = @import("compat.zig");

pub const default_timeout_sec: u32 = 10;

pub const FetchOptions = struct {
    max_response_bytes: usize,
    timeout_sec: u32 = default_timeout_sec,
    max_redirects: u8 = 3,
};

const FetchEvent = enum {
    fetch,
    timeout,
};

const FetchTask = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
    io: std.Io,
    queue: *std.Io.Queue(FetchEvent),
};

pub fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8, options: FetchOptions) ![]u8 {
    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();

    const io = threaded_io.io();
    if (options.timeout_sec == 0) return fetchUrlBytesWithIo(allocator, url, options, io);

    const worker_allocator = std.heap.page_allocator;
    const url_copy = try worker_allocator.dupe(u8, url);
    defer worker_allocator.free(url_copy);

    var event_storage: [2]FetchEvent = undefined;
    var event_queue: std.Io.Queue(FetchEvent) = .init(&event_storage);

    var fetch_future = try io.concurrent(fetchUrlBytesSignaled, .{FetchTask{
        .allocator = worker_allocator,
        .url = url_copy,
        .options = options,
        .io = io,
        .queue = &event_queue,
    }});
    var timeout_future = io.concurrent(fetchTimeoutSignaled, .{
        io,
        options.timeout_sec,
        &event_queue,
    }) catch |err| {
        discardFetchResult(fetch_future.cancel(io));
        return err;
    };

    const selected = event_queue.getOneUncancelable(io) catch |err| {
        discardFetchResult(fetch_future.cancel(io));
        timeout_future.cancel(io) catch {};
        return err;
    };

    switch (selected) {
        .fetch => {
            const result = fetch_future.await(io);
            timeout_future.cancel(io) catch {};
            return finishFetchResult(allocator, result);
        },
        .timeout => {
            timeout_future.await(io) catch |err| {
                discardFetchResult(fetch_future.cancel(io));
                return err;
            };
            discardFetchResult(fetch_future.cancel(io));
            return error.HttpRequestTimedOut;
        },
    }
}

fn fetchUrlBytesSignaled(task: FetchTask) ![]u8 {
    const result = fetchUrlBytesWithIo(
        task.allocator,
        task.url,
        task.options,
        task.io,
    );
    task.queue.putOneUncancelable(task.io, .fetch) catch {};
    return result;
}

fn fetchTimeoutSignaled(
    io: std.Io,
    timeout_sec: u32,
    queue: *std.Io.Queue(FetchEvent),
) !void {
    const result = fetchTimeout(io, timeout_sec);
    queue.putOneUncancelable(io, .timeout) catch {};
    return result;
}

fn finishFetchResult(allocator: std.mem.Allocator, result: anyerror![]u8) ![]u8 {
    if (result) |bytes| {
        defer std.heap.page_allocator.free(bytes);
        return allocator.dupe(u8, bytes);
    } else |err| {
        return err;
    }
}

fn discardFetchResult(result: anyerror![]u8) void {
    if (result) |bytes| {
        std.heap.page_allocator.free(bytes);
    } else |_| {}
}

fn fetchTimeout(io: std.Io, timeout_sec: u32) !void {
    const timeout_ns: u64 = @as(u64, timeout_sec) * std.time.ns_per_s;
    try std.Io.sleep(
        io,
        .{ .nanoseconds = @intCast(timeout_ns) },
        .awake,
    );
}

fn fetchUrlBytesWithIo(
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
    io: std.Io,
) ![]u8 {
    const uri = try std.Uri.parse(url);
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
    };
    defer client.deinit();

    var req = try client.request(.GET, uri, .{
        .redirect_behavior = @enumFromInt(options.max_redirects),
        .keep_alive = false,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buf: [8 * 1024]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (response.head.status.class() != .success) return error.HttpRequestFailed;

    var transfer_buf: [4 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    return reader.allocRemaining(allocator, .limited(options.max_response_bytes));
}
