const std = @import("std");
const compat = @import("compat.zig");
const net = @import("net_compat.zig");

const log = std.log.scoped(.http_fetch);

pub const default_timeout_sec: u32 = 10;

pub const FetchOptions = struct {
    max_response_bytes: usize,
    timeout_sec: u32 = default_timeout_sec,
    max_redirects: u8 = 3,
    stop: ?*const std.atomic.Value(bool) = null,
};

const FetchEvent = union(enum) {
    fetch: anyerror![]u8,
    timeout: anyerror!void,
    stop: anyerror!void,
};

pub fn fetchUrlBytes(allocator: std.mem.Allocator, url: []const u8, options: FetchOptions) ![]u8 {
    if (options.stop) |stop| {
        if (stop.load(.acquire)) return error.UpdateCancelled;
    }

    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const worker_allocator = std.heap.page_allocator;
    const url_copy = try worker_allocator.dupe(u8, url);
    defer worker_allocator.free(url_copy);

    var event_storage: [3]FetchEvent = undefined;
    var select = std.Io.Select(FetchEvent).init(io, &event_storage);
    try select.concurrent(.fetch, fetchUrlBytesWithFallback, .{
        worker_allocator,
        url_copy,
        options,
        io,
    });
    if (options.timeout_sec != 0) {
        select.concurrent(.timeout, fetchTimeout, .{
            io,
            options.timeout_sec,
        }) catch |err| {
            drainFetchSelect(&select);
            return err;
        };
    }
    if (options.stop) |stop| {
        select.concurrent(.stop, waitForFetchStop, .{ io, stop }) catch |err| {
            drainFetchSelect(&select);
            return err;
        };
    }

    const selected = select.await() catch |err| {
        drainFetchSelect(&select);
        return err;
    };
    defer drainFetchSelect(&select);

    switch (selected) {
        .fetch => |result| {
            if (options.stop) |stop| {
                if (stop.load(.acquire)) {
                    discardFetchResult(result);
                    return error.UpdateCancelled;
                }
            }
            return finishFetchResult(allocator, result);
        },
        .timeout => |result| {
            try result;
            if (options.stop) |stop| {
                if (stop.load(.acquire)) return error.UpdateCancelled;
            }
            return error.HttpRequestTimedOut;
        },
        .stop => |result| {
            try result;
            return error.UpdateCancelled;
        },
    }
}

fn fetchUrlBytesWithFallback(
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
    io: std.Io,
) ![]u8 {
    return fetchUrlBytesWithIo(allocator, url, options, io) catch |err| {
        if (std.mem.eql(u8, @errorName(err), "ResolvConfParseFailed") or
            std.mem.eql(u8, @errorName(err), "UnsafeResolverConfiguration"))
        {
            log.warn("std.http resolver rejected the system configuration for {s}: {s}; retrying via curl", .{
                url,
                @errorName(err),
            });
            return runCurlFetch(allocator, url, options, io);
        }
        return err;
    };
}

fn finishFetchResult(allocator: std.mem.Allocator, result: anyerror![]u8) ![]u8 {
    if (result) |bytes| {
        defer std.heap.page_allocator.free(bytes);
        return allocator.dupe(u8, bytes);
    } else |err| {
        return err;
    }
}

fn drainFetchSelect(select: *std.Io.Select(FetchEvent)) void {
    while (select.cancel()) |event| switch (event) {
        .fetch => |result| discardFetchResult(result),
        .timeout, .stop => |result| result catch {},
    };
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

fn waitForFetchStop(io: std.Io, stop: *const std.atomic.Value(bool)) !void {
    while (!stop.load(.acquire)) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = 100 * std.time.ns_per_ms },
            .awake,
        );
    }
}

fn fetchUrlBytesWithIo(
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
    io: std.Io,
) ![]u8 {
    var client: std.http.Client = .{
        .allocator = allocator,
        .io = io,
    };
    defer client.deinit();

    var current_url = try allocator.dupe(u8, url);
    defer allocator.free(current_url);
    var redirects_followed: u8 = 0;

    while (true) {
        const step = try fetchUrlStep(
            allocator,
            &client,
            current_url,
            options.max_response_bytes,
        );
        switch (step) {
            .body => |body| return body,
            .redirect => |next_url| {
                if (redirects_followed >= options.max_redirects) {
                    allocator.free(next_url);
                    return error.TooManyHttpRedirects;
                }
                redirects_followed += 1;
                allocator.free(current_url);
                current_url = next_url;
            },
        }
    }
}

const FetchStep = union(enum) {
    body: []u8,
    redirect: []u8,
};

fn fetchUrlStep(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    url: []const u8,
    max_response_bytes: usize,
) !FetchStep {
    var uri = try std.Uri.parse(url);
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureHttpUrl;
    uri.scheme = "https";

    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = try uri.getHost(&host_buf);
    try net.validateSystemResolverForHost(allocator, client.io, host.bytes);

    var req = try client.request(.GET, uri, .{
        // Redirects must be inspected before another connection is opened:
        // Zig's automatic path also accepts plain HTTP targets.
        .redirect_behavior = .unhandled,
        .keep_alive = false,
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
        },
    });
    defer req.deinit();

    try req.sendBodiless();

    var unused_redirect_buf: [0]u8 = .{};
    var response = try req.receiveHead(&unused_redirect_buf);
    if (response.head.status.class() == .redirect and
        response.head.status != .not_modified)
    {
        const location = response.head.location orelse return error.HttpRedirectLocationMissing;
        return .{ .redirect = try resolveHttpsRedirect(allocator, uri, location) };
    }
    if (response.head.status.class() != .success) return error.HttpRequestFailed;

    var transfer_buf: [4 * 1024]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    const body = reader.allocRemaining(
        allocator,
        .limited(max_response_bytes),
    ) catch |err| switch (err) {
        // The generic reader erases transport errors; preserve Canceled so a
        // Select cancellation is acknowledged by the fetch task.
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        else => |e| return e,
    };
    return .{ .body = body };
}

fn resolveHttpsRedirect(
    allocator: std.mem.Allocator,
    base_uri: std.Uri,
    location: []const u8,
) ![]u8 {
    var redirect_buf: [8 * 1024]u8 = undefined;
    if (location.len > redirect_buf.len) return error.HttpRedirectLocationOversize;
    @memcpy(redirect_buf[0..location.len], location);

    var remaining: []u8 = redirect_buf[0..];
    var uri = base_uri.resolveInPlace(location.len, &remaining) catch |err| switch (err) {
        error.NoSpaceLeft => return error.HttpRedirectLocationOversize,
        else => return error.HttpRedirectLocationInvalid,
    };
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureHttpRedirect;
    uri.scheme = "https";
    return std.fmt.allocPrint(allocator, "{f}", .{std.Uri.fmt(&uri, .all)});
}

fn runCurlFetch(
    allocator: std.mem.Allocator,
    url: []const u8,
    options: FetchOptions,
    io: std.Io,
) ![]u8 {
    var timeout_buf: [16]u8 = undefined;
    var max_redirects_buf: [4]u8 = undefined;
    const timeout = if (options.timeout_sec == 0) default_timeout_sec else options.timeout_sec;
    const timeout_arg = try std.fmt.bufPrint(&timeout_buf, "{d}", .{timeout});
    const max_redirects_arg = try std.fmt.bufPrint(&max_redirects_buf, "{d}", .{options.max_redirects});

    const argv = [_][]const u8{
        "curl",
        "--silent",
        "--fail",
        "--show-error",
        "--location",
        "--max-redirs",
        max_redirects_arg,
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        timeout_arg,
        url,
    };

    const result = std.process.run(allocator, io, .{
        .argv = &argv,
        .stdout_limit = std.Io.Limit.limited(options.max_response_bytes),
        .stderr_limit = std.Io.Limit.limited(1 * 1024 * 1024),
    }) catch |err| {
        log.warn("curl fetch failed to start for {s}: {any}", .{ url, err });
        return err;
    };
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                log.warn("curl fetch {s} exited with {d}: {s}", .{
                    url,
                    code,
                    std.mem.trim(u8, result.stderr, " \t\r\n"),
                });
                allocator.free(result.stdout);
                return error.HttpRequestFailed;
            }
        },
        else => {
            log.warn("curl fetch {s} terminated abnormally", .{url});
            allocator.free(result.stdout);
            return error.HttpRequestFailed;
        },
    }

    return result.stdout;
}

test "redirect resolver rejects HTTPS downgrade before the next request" {
    const base = try std.Uri.parse("https://example.com/path/index");
    try std.testing.expectError(
        error.InsecureHttpRedirect,
        resolveHttpsRedirect(std.testing.allocator, base, "http://example.com/plain"),
    );
}

test "redirect resolver preserves HTTPS for relative and network paths" {
    const base = try std.Uri.parse("https://example.com/path/index");

    const relative = try resolveHttpsRedirect(std.testing.allocator, base, "../next");
    defer std.testing.allocator.free(relative);
    try std.testing.expectEqualStrings("https://example.com/next", relative);

    const network = try resolveHttpsRedirect(std.testing.allocator, base, "//cdn.example.com/file");
    defer std.testing.allocator.free(network);
    try std.testing.expectEqualStrings("https://cdn.example.com/file", network);

    const uppercase = try std.Uri.parse("HTTPS://example.com/start");
    const same_scheme = try resolveHttpsRedirect(std.testing.allocator, uppercase, "/next");
    defer std.testing.allocator.free(same_scheme);
    try std.testing.expect(std.ascii.eqlIgnoreCase(
        (try std.Uri.parse(same_scheme)).scheme,
        "https",
    ));
}
