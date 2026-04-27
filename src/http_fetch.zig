const std = @import("std");
const posix = std.posix;

pub const default_timeout_sec: u32 = 10;

pub const FetchOptions = struct {
    max_response_bytes: usize,
    timeout_sec: u32 = default_timeout_sec,
    max_redirects: u8 = 3,
};

const FetchWorkerState = struct {
    url: []u8,
    options: FetchOptions,
    mutex: std.Thread.Mutex = .{},
    done: bool = false,
    detached: bool = false,
    result: anyerror![]u8 = error.HttpRequestTimedOut,
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
    if (options.timeout_sec == 0) return fetchUrlBytesBlocking(allocator, url, options);

    // std.http can block before a socket exists (notably DNS), so the public
    // timeout wraps the whole request instead of only socket I/O.
    const worker_allocator = std.heap.page_allocator;
    const url_copy = try worker_allocator.dupe(u8, url);
    const state = worker_allocator.create(FetchWorkerState) catch |err| {
        worker_allocator.free(url_copy);
        return err;
    };
    state.* = .{
        .url = url_copy,
        .options = options,
    };

    const thread = std.Thread.spawn(.{}, fetchUrlBytesWorker, .{state}) catch |err| {
        freeFetchWorkerState(state);
        return err;
    };

    const deadline_ns = std.time.nanoTimestamp() + @as(i128, options.timeout_sec) * std.time.ns_per_s;
    const poll_interval_ns: u64 = 10 * std.time.ns_per_ms;
    while (!isFetchWorkerDone(state)) {
        if (std.time.nanoTimestamp() >= deadline_ns) {
            if (markFetchWorkerDetached(state)) {
                thread.join();
                return finishJoinedFetchWorker(allocator, state);
            }
            thread.detach();
            return error.HttpRequestTimedOut;
        }
        std.Thread.sleep(poll_interval_ns);
    }

    thread.join();
    return finishJoinedFetchWorker(allocator, state);
}

fn fetchUrlBytesWorker(state: *FetchWorkerState) void {
    const worker_allocator = std.heap.page_allocator;
    const result = fetchUrlBytesBlocking(worker_allocator, state.url, state.options);

    state.mutex.lock();
    state.result = result;
    state.done = true;
    const should_cleanup = state.detached;
    state.mutex.unlock();

    if (should_cleanup) {
        if (result) |bytes| {
            worker_allocator.free(bytes);
        } else |_| {}
        freeFetchWorkerState(state);
    }
}

fn isFetchWorkerDone(state: *FetchWorkerState) bool {
    state.mutex.lock();
    defer state.mutex.unlock();
    return state.done;
}

fn markFetchWorkerDetached(state: *FetchWorkerState) bool {
    state.mutex.lock();
    defer state.mutex.unlock();
    if (state.done) return true;
    state.detached = true;
    return false;
}

fn finishJoinedFetchWorker(allocator: std.mem.Allocator, state: *FetchWorkerState) ![]u8 {
    if (state.result) |bytes| {
        defer std.heap.page_allocator.free(bytes);
        defer freeFetchWorkerState(state);
        return allocator.dupe(u8, bytes);
    } else |err| {
        freeFetchWorkerState(state);
        return err;
    }
}

fn freeFetchWorkerState(state: *FetchWorkerState) void {
    const worker_allocator = std.heap.page_allocator;
    worker_allocator.free(state.url);
    worker_allocator.destroy(state);
}

fn fetchUrlBytesBlocking(allocator: std.mem.Allocator, url: []const u8, options: FetchOptions) ![]u8 {
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
