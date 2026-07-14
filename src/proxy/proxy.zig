//! Proxy core — single-threaded Linux epoll event loop.
//!
//! This replaces the thread-per-connection model with a pre-allocated
//! connection pool and non-blocking state machine.

const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_compat.zig");
const posix = std.posix;
const linux = std.os.linux;

const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const compat = @import("../compat.zig");
const http_fetch = @import("../http_fetch.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;

const log = std.log.scoped(.proxy);

const tls_header_len = 5;
// Bound epoll sleep by the shortest timer cadence. Longer sleeps make the
// 3-5 ms desynchronization deadlines observationally meaningless.
const event_loop_wait_ms = 5;
const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
const accept_batch_limit: usize = 256;
const stats_log_interval_s: i64 = 10;
const stats_log_interval_ns: i128 = @as(i128, stats_log_interval_s) * std.time.ns_per_s;
const nofile_fd_overhead: usize = 512;
const middle_proxy_config_url = "https://core.telegram.org/getProxyConfig";
const middle_proxy_secret_url = "https://core.telegram.org/getProxySecret";
// Telegram can rotate MiddleProxy endpoints/secrets within a day. Hourly
// best-effort refresh bounds stale metadata without adding meaningful load.
const middle_proxy_update_period_ns: u64 = 60 * 60 * std.time.ns_per_s;
const middle_proxy_reactive_cooldown_ns: u64 = 60 * std.time.ns_per_s;
const middle_proxy_update_stop_poll_ns: u64 = std.time.ns_per_s;
const tunnel_mask_gateway_ip = "10.200.200.1";
const min_nofile_soft: usize = 65535;
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = 4096;
const pre_first_byte_timeout_ms: i64 = 10 * std.time.ms_per_s;
const middle_proxy_stage_timeout_ms: i64 = 5 * std.time.ms_per_s;
const tls_control_record_budget: usize = 8;
const tls_control_byte_budget: usize = 64 * 1024;

const invalid_fd: posix.fd_t = switch (builtin.os.tag) {
    .windows => std.os.windows.INVALID_HANDLE_VALUE,
    else => -1,
};

fn isInvalidFd(fd: posix.fd_t) bool {
    return fd == invalid_fd;
}

fn fakeFd(value: usize) posix.fd_t {
    return switch (builtin.os.tag) {
        .windows => @ptrFromInt(value),
        else => @intCast(value),
    };
}

fn closeFd(fd: posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = linux.close(fd);
    } else if (builtin.os.tag == .windows) {
        std.os.windows.CloseHandle(fd);
    }
}

fn acceptFd(fd: posix.fd_t, addr: *posix.sockaddr, len: *posix.socklen_t) !posix.fd_t {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.accept4(fd, addr, len, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .CONNABORTED => error.ConnectionAborted,
        .CONNRESET => error.ConnectionResetByPeer,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

fn socketTcpNonblocking(family: posix.sa_family_t) !posix.fd_t {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.socket(
        @intCast(family),
        linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
        linux.IPPROTO.TCP,
    );
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.PermissionDenied,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

fn connectFd(fd: posix.fd_t, addr: *const posix.sockaddr, len: posix.socklen_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.connect(fd, addr, @intCast(len));
    switch (posix.errno(rc)) {
        .SUCCESS, .ISCONN => {},
        .AGAIN => return error.WouldBlock,
        .INPROGRESS, .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => return error.Unexpected,
    }
}

fn getpeernameFd(fd: posix.fd_t, addr: *posix.sockaddr, len: *posix.socklen_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.getpeername(fd, addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
}

fn getsocknameFd(fd: posix.fd_t, addr: *posix.sockaddr, len: *posix.socklen_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.getsockname(fd, addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
}

fn getsockoptErrorFd(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    if (err_code == 0) return;

    const err: @TypeOf(posix.errno(rc)) = @enumFromInt(err_code);
    switch (err) {
        .CONNREFUSED => return error.ConnectionRefused,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => return error.Unexpected,
    }
}

fn writeFd(fd: posix.fd_t, data: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    if (data.len == 0) return 0;

    while (true) {
        const rc = linux.write(fd, data.ptr, data.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .PIPE => return error.BrokenPipe,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

fn writevFd(fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    if (iovecs.len == 0) return 0;

    while (true) {
        const rc = linux.writev(fd, iovecs.ptr, iovecs.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .PIPE => return error.BrokenPipe,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

fn setSockOptBytes(fd: posix.fd_t, level: i32, optname: u32, bytes: []const u8) void {
    if (builtin.os.tag != .linux) return;

    const rc = linux.setsockopt(fd, level, optname, bytes.ptr, @intCast(bytes.len));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return,
    }
}

fn seekFdToStart(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.lseek(fd, 0, linux.SEEK.SET);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .SPIPE => return error.Unseekable,
        else => return error.Unexpected,
    }
}

/// Per-/24 (IPv4) or /48 (IPv6) subnet rate limiter.
/// Fixed-size open-addressed hash table — zero heap allocation.
/// Token bucket per subnet: each second refills up to max_per_sec tokens.
const SubnetRateLimit = struct {
    const BUCKETS = 65536;
    const MAX_PROBES = 8;
    const stale_after_s: i64 = 60;

    // Keep naturally aligned fields first: EventLoop embeds this fixed table,
    // so padding multiplied by BUCKETS directly increases its stack frame.
    const Entry = struct {
        subnet_key: u64 = 0,
        last_refill_s: i64 = 0,
        used: bool = false,
        tokens: u8 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() SubnetRateLimit {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    fn indexFor(self: *const SubnetRateLimit, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    fn findEntry(self: *SubnetRateLimit, key: u64) ?*Entry {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];
            if (!e.used) return null;
            if (e.subnet_key == key) return e;
        }
        return null;
    }

    /// Returns true if the connection is allowed, false if rate-limited.
    fn check(self: *SubnetRateLimit, addr: net.Address, max_per_sec: u8) bool {
        if (max_per_sec == 0) return true;
        const key = subnetKey(addr);
        const now_s = @divTrunc(compat.monotonicMilliTimestamp(), 1000);

        const start = self.indexFor(key);
        var first_stale_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];

            if (!e.used) {
                e.* = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
                return true;
            }

            if (e.subnet_key == key) {
                // Refill tokens based on elapsed seconds
                const elapsed = now_s - e.last_refill_s;
                if (elapsed > 0) {
                    const refill: u16 = @intCast(@min(elapsed, 255));
                    const topped = @as(u16, e.tokens) + refill * @as(u16, max_per_sec);
                    e.tokens = @intCast(@min(@as(u16, max_per_sec), topped));
                    e.last_refill_s = now_s;
                }

                if (e.tokens > 0) {
                    e.tokens -= 1;
                    return true;
                }
                return false;
            }

            if (now_s - e.last_refill_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
        }

        if (first_stale_idx) |victim_idx| {
            self.entries[victim_idx] = .{ .used = true, .subnet_key = key, .tokens = max_per_sec -| 1, .last_refill_s = now_s };
            return true;
        }

        // The probed window is occupied by live buckets; reject this connection
        // instead of evicting an active subnet and resetting its limiter state.
        return false;
    }

    fn subnetKey(addr: net.Address) u64 {
        if (addr.any.family == posix.AF.INET) {
            // /24 subnet: mask off last octet
            const ip_bytes = std.mem.asBytes(&addr.in.sa.addr);
            return @as(u64, ip_bytes[0]) << 16 | @as(u64, ip_bytes[1]) << 8 | @as(u64, ip_bytes[2]);
        } else if (addr.any.family == posix.AF.INET6) {
            const ip6 = &addr.in6.sa.addr;

            const is_ipv4_mapped = std.mem.eql(u8, ip6[0..10], &[_]u8{0} ** 10) and
                ip6[10] == 0xff and ip6[11] == 0xff;
            if (is_ipv4_mapped) {
                return @as(u64, ip6[12]) << 16 | @as(u64, ip6[13]) << 8 | @as(u64, ip6[14]);
            }

            // Preserve all /48 bits and reserve the high bit as an IPv6 namespace
            // marker so unrelated prefixes cannot collide before table hashing.
            return @as(u64, 1) << 63 |
                @as(u64, ip6[0]) << 40 |
                @as(u64, ip6[1]) << 32 |
                @as(u64, ip6[2]) << 24 |
                @as(u64, ip6[3]) << 16 |
                @as(u64, ip6[4]) << 8 |
                @as(u64, ip6[5]);
        }
        return 0;
    }
};

const MsgBlockClass = enum(u2) {
    tiny = 0,
    small = 1,
    standard = 2,
};

const tiny_block_size: usize = 64;
const small_block_size: usize = 512;
const standard_block_size: usize = 2048;

const MsgBlock = struct {
    class: MsgBlockClass,
    len: usize,
};

const TinyMsgBlock = struct {
    header: MsgBlock = .{ .class = .tiny, .len = 0 },
    data: [tiny_block_size]u8 = undefined,
};

const SmallMsgBlock = struct {
    header: MsgBlock = .{ .class = .small, .len = 0 },
    data: [small_block_size]u8 = undefined,
};

const StandardMsgBlock = struct {
    header: MsgBlock = .{ .class = .standard, .len = 0 },
    data: [standard_block_size]u8 = undefined,
};

const max_scatter_parts: usize = 64;

fn hasFatalEpollHangup(events: u32) bool {
    return (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) != 0;
}

fn hasGracefulEpollRdhup(events: u32) bool {
    return (events & linux.EPOLL.RDHUP) != 0 and
        (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) == 0;
}

fn classCapacity(class: MsgBlockClass) usize {
    return switch (class) {
        .tiny => tiny_block_size,
        .small => small_block_size,
        .standard => standard_block_size,
    };
}

fn chooseClass(size: usize) MsgBlockClass {
    if (size <= tiny_block_size) return .tiny;
    if (size <= small_block_size) return .small;
    return .standard;
}

fn blockStorage(blk: *MsgBlock) []u8 {
    return switch (blk.class) {
        .tiny => blk: {
            const tiny: *TinyMsgBlock = @fieldParentPtr("header", blk);
            break :blk tiny.data[0..];
        },
        .small => blk: {
            const small: *SmallMsgBlock = @fieldParentPtr("header", blk);
            break :blk small.data[0..];
        },
        .standard => blk: {
            const standard: *StandardMsgBlock = @fieldParentPtr("header", blk);
            break :blk standard.data[0..];
        },
    };
}

fn blockStorageConst(blk: *const MsgBlock) []const u8 {
    return switch (blk.class) {
        .tiny => blk: {
            const tiny: *const TinyMsgBlock = @fieldParentPtr("header", blk);
            break :blk tiny.data[0..];
        },
        .small => blk: {
            const small: *const SmallMsgBlock = @fieldParentPtr("header", blk);
            break :blk small.data[0..];
        },
        .standard => blk: {
            const standard: *const StandardMsgBlock = @fieldParentPtr("header", blk);
            break :blk standard.data[0..];
        },
    };
}

const MessageQueue = struct {
    const max_pending_bytes: usize = 4 * 1024 * 1024;
    const max_free_tiny_blocks: usize = 128;
    const max_free_small_blocks: usize = 96;
    const max_free_standard_blocks: usize = 128;

    allocator: std.mem.Allocator,
    tiny_free: std.ArrayList(*MsgBlock) = .empty,
    small_free: std.ArrayList(*MsgBlock) = .empty,
    std_free: std.ArrayList(*MsgBlock) = .empty,
    blocks: std.ArrayList(*MsgBlock) = .empty,
    head_idx: usize = 0,
    offset: usize = 0,
    total_len: usize = 0,

    fn deinit(self: *MessageQueue) void {
        self.clear();

        for (self.tiny_free.items) |blk| self.destroyBlock(blk);
        for (self.small_free.items) |blk| self.destroyBlock(blk);
        for (self.std_free.items) |blk| self.destroyBlock(blk);

        self.tiny_free.deinit(self.allocator);
        self.small_free.deinit(self.allocator);
        self.std_free.deinit(self.allocator);
        self.blocks.deinit(self.allocator);
    }

    fn clear(self: *MessageQueue) void {
        for (self.blocks.items[self.head_idx..]) |blk| {
            self.recycleBlock(blk) catch {
                self.destroyBlock(blk);
            };
        }
        self.blocks.clearRetainingCapacity();
        self.head_idx = 0;
        self.offset = 0;
        self.total_len = 0;
    }

    fn isEmpty(self: *const MessageQueue) bool {
        return self.total_len == 0;
    }

    fn appendCopy(self: *MessageQueue, data: []const u8) !void {
        if (data.len == 0) return;
        try self.ensureCanAppend(data.len);

        var off: usize = 0;
        while (off < data.len) {
            const rem = data.len - off;
            const class = chooseClass(rem);
            const cap = classCapacity(class);
            const take = @min(rem, cap);

            var blk = try self.acquireBlock(class);
            blk.len = take;
            @memcpy(blockStorage(blk)[0..take], data[off .. off + take]);
            self.blocks.append(self.allocator, blk) catch |err| {
                self.recycleBlock(blk) catch self.destroyBlock(blk);
                return err;
            };
            self.total_len += take;
            off += take;
        }
    }

    fn ensureCanAppend(self: *const MessageQueue, additional_len: usize) !void {
        if (additional_len > max_pending_bytes or self.total_len > max_pending_bytes - additional_len) {
            return error.PendingQueueOverflow;
        }
    }

    fn prepareIovecs(self: *const MessageQueue, out: []posix.iovec_const) usize {
        if (self.head_idx >= self.blocks.items.len) return 0;

        var count: usize = 0;
        var local_off = self.offset;
        for (self.blocks.items[self.head_idx..]) |blk| {
            if (count >= out.len) break;

            if (local_off >= blk.len) {
                local_off -= blk.len;
                continue;
            }

            const storage = blockStorageConst(blk);
            out[count] = .{ .base = storage[local_off..blk.len].ptr, .len = blk.len - local_off };
            count += 1;
            local_off = 0;
        }
        return count;
    }

    fn consume(self: *MessageQueue, bytes: usize) !void {
        if (bytes == 0 or self.total_len == 0) return;

        var remaining = @min(bytes, self.total_len);
        self.total_len -= remaining;

        while (remaining > 0 and self.head_idx < self.blocks.items.len) {
            const blk = self.blocks.items[self.head_idx];
            const blk_left = blk.len - self.offset;

            if (remaining < blk_left) {
                self.offset += remaining;
                remaining = 0;
                break;
            }

            remaining -= blk_left;
            self.offset = 0;
            self.head_idx += 1;
            self.recycleBlock(blk) catch {
                self.destroyBlock(blk);
            };
        }

        if (self.head_idx > 0 and (self.head_idx >= self.blocks.items.len or self.head_idx >= 64)) {
            const rem = self.blocks.items.len - self.head_idx;
            if (rem > 0) {
                std.mem.copyForwards(*MsgBlock, self.blocks.items[0..rem], self.blocks.items[self.head_idx..]);
            }
            self.blocks.shrinkRetainingCapacity(rem);
            self.head_idx = 0;
        }

        if (self.total_len == 0) {
            self.head_idx = 0;
            self.offset = 0;
        }
    }

    fn acquireBlock(self: *MessageQueue, class: MsgBlockClass) !*MsgBlock {
        const list = switch (class) {
            .tiny => &self.tiny_free,
            .small => &self.small_free,
            .standard => &self.std_free,
        };

        if (list.items.len > 0) {
            return list.pop().?;
        }

        return switch (class) {
            .tiny => blk: {
                const tiny = try self.allocator.create(TinyMsgBlock);
                tiny.* = .{};
                break :blk &tiny.header;
            },
            .small => blk: {
                const small = try self.allocator.create(SmallMsgBlock);
                small.* = .{};
                break :blk &small.header;
            },
            .standard => blk: {
                const standard = try self.allocator.create(StandardMsgBlock);
                standard.* = .{};
                break :blk &standard.header;
            },
        };
    }

    fn recycleBlock(self: *MessageQueue, blk: *MsgBlock) !void {
        std.crypto.secureZero(u8, blockStorage(blk));
        blk.len = 0;
        const list = switch (blk.class) {
            .tiny => &self.tiny_free,
            .small => &self.small_free,
            .standard => &self.std_free,
        };
        if (list.items.len >= freeListLimit(blk.class)) {
            self.destroyBlock(blk);
            return;
        }
        try list.append(self.allocator, blk);
    }

    fn freeListLimit(class: MsgBlockClass) usize {
        return switch (class) {
            .tiny => max_free_tiny_blocks,
            .small => max_free_small_blocks,
            .standard => max_free_standard_blocks,
        };
    }

    fn destroyBlock(self: *MessageQueue, blk: *MsgBlock) void {
        std.crypto.secureZero(u8, blockStorage(blk));
        switch (blk.class) {
            .tiny => {
                const tiny: *TinyMsgBlock = @fieldParentPtr("header", blk);
                self.allocator.destroy(tiny);
            },
            .small => {
                const small: *SmallMsgBlock = @fieldParentPtr("header", blk);
                self.allocator.destroy(small);
            },
            .standard => {
                const standard: *StandardMsgBlock = @fieldParentPtr("header", blk);
                self.allocator.destroy(standard);
            },
        }
    }
};

const UpstreamKind = enum {
    none,
    dc,
    mask,
};

const ConnectionPhase = enum {
    idle,
    reading_tls_header,
    reading_client_hello_body,
    writing_server_hello_first,
    desync_wait,
    writing_server_hello_rest,
    reading_mtproto_tls_header,
    reading_mtproto_tls_body,
    connecting_upstream,
    writing_dc_nonce,
    middle_proxy_handshake,
    relaying,
    mask_relaying,
    closing,
};

fn shouldCloseOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    if (phase == .idle) return false;

    // During connecting_upstream, EPOLLERR on upstream fd is expected and
    // handled via onUpstreamWritable -> onUpstreamConnectComplete.
    return !(phase == .connecting_upstream and event_fd == upstream_fd);
}

fn shouldFallbackMiddleProxyOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    return phase == .middle_proxy_handshake and event_fd == upstream_fd;
}

const MiddleProxyHandshakeStep = enum {
    none,
    sending_rpc_nonce,
    waiting_rpc_nonce_response,
    sending_rpc_handshake,
    waiting_rpc_handshake_response,
    done,

    fn awaitingMiddleProxy(self: MiddleProxyHandshakeStep) bool {
        return switch (self) {
            .sending_rpc_nonce,
            .waiting_rpc_nonce_response,
            .sending_rpc_handshake,
            .waiting_rpc_handshake_response,
            => true,
            .none, .done => false,
        };
    }
};

const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

test "MiddleProxyHandshakeStep.awaitingMiddleProxy gates reactive refresh" {
    try std.testing.expect(!MiddleProxyHandshakeStep.none.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_nonce.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_nonce_response.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.sending_rpc_handshake.awaitingMiddleProxy());
    try std.testing.expect(MiddleProxyHandshakeStep.waiting_rpc_handshake_response.awaitingMiddleProxy());
    try std.testing.expect(!MiddleProxyHandshakeStep.done.awaitingMiddleProxy());
}

const DcConnectPlan = struct {
    candidates: [16]net.Address = undefined,
    count: usize = 0,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,
    direct_fallback: ?net.Address = null,
};

const MiddleProxyLock = struct {
    mutex: compat.BlockingMutex = .{},

    fn lock(self: *MiddleProxyLock) void {
        self.mutex.lock();
    }

    fn unlock(self: *MiddleProxyLock) void {
        self.mutex.unlock();
    }

    fn lockShared(self: *MiddleProxyLock) void {
        self.lock();
    }

    fn unlockShared(self: *MiddleProxyLock) void {
        self.unlock();
    }
};

const DynamicRecordSizer = struct {
    current_size: usize,
    records_sent: u32,
    bytes_sent: u64,
    enabled: bool,

    const initial_size: usize = 1369;
    const full_size: usize = constants.max_tls_plaintext_size;
    const ramp_record_threshold: u32 = 8;
    const ramp_byte_threshold: u64 = 128 * 1024;

    fn init(enabled: bool) DynamicRecordSizer {
        return .{
            .current_size = if (enabled) initial_size else full_size,
            .records_sent = 0,
            .bytes_sent = 0,
            .enabled = enabled,
        };
    }

    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        if (!self.enabled or self.current_size == full_size) return;
        self.records_sent +|= 1;
        self.bytes_sent +|= @as(u64, @intCast(payload_len));
        if (self.current_size == initial_size and
            (self.records_sent >= ramp_record_threshold or self.bytes_sent >= ramp_byte_threshold))
        {
            self.current_size = full_size;
        }
    }
};

const ReplayCache = struct {
    const BUCKETS = 8192;
    const MAX_PROBES = 8;
    const stale_after_s: i64 = 60 * 60;

    const Entry = struct {
        used: bool = false,
        key: u64 = 0,
        digest: [32]u8 = [_]u8{0} ** 32,
        last_seen_s: i64 = 0,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() ReplayCache {
        return .{
            .hash_seed = crypto.randomInt(u64),
        };
    }

    fn digestKey(digest: *const [32]u8) u64 {
        return std.mem.readInt(u64, digest[0..8], .little);
    }

    fn indexFor(self: *const ReplayCache, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    pub fn checkAndInsert(self: *ReplayCache, digest: *const [32]u8) bool {
        const key = digestKey(digest);
        const now_s = @divTrunc(compat.monotonicMilliTimestamp(), 1000);
        const start = self.indexFor(key);

        var first_stale_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const e = &self.entries[idx];

            if (!e.used) {
                e.* = .{ .used = true, .key = key, .digest = digest.*, .last_seen_s = now_s };
                return false;
            }

            if (e.key == key and std.crypto.timing_safe.eql([32]u8, e.digest, digest.*)) {
                e.last_seen_s = now_s;
                return true;
            }

            if (now_s - e.last_seen_s > stale_after_s and first_stale_idx == null) {
                first_stale_idx = idx;
            }
        }

        const victim_idx = first_stale_idx orelse return true;
        self.entries[victim_idx] = .{ .used = true, .key = key, .digest = digest.*, .last_seen_s = now_s };
        return false;
    }
};

/// Bounds unauthenticated connections per IPv4 /24 or IPv6 /48. The charge is
/// taken after a pool slot is acquired and released only after authentication
/// succeeds (or the slot closes), so silent and one-byte clients share one
/// finite allowance without penalizing established relays behind large NATs.
const SubnetHandshakeLimit = struct {
    const BUCKETS = 16384;
    const MAX_PROBES = 8;

    // Field order is intentional for the same fixed-table layout reason above.
    const Entry = struct {
        subnet_key: u64 = 0,
        inflight: u16 = 0,
        used: bool = false,
    };

    hash_seed: u64 = 0,
    entries: [BUCKETS]Entry = [_]Entry{.{}} ** BUCKETS,

    fn init() SubnetHandshakeLimit {
        return .{ .hash_seed = crypto.randomInt(u64) };
    }

    fn indexFor(self: *const SubnetHandshakeLimit, key: u64) usize {
        var x = self.hash_seed ^ key;
        x +%= 0x9E3779B97F4A7C15;
        x ^= x >> 30;
        x *%= 0xBF58476D1CE4E5B9;
        x ^= x >> 27;
        x *%= 0x94D049BB133111EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (BUCKETS - 1)));
    }

    fn reserve(self: *SubnetHandshakeLimit, key: u64, limit: u16) bool {
        const start = self.indexFor(key);
        var free_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const idx = (start + probe) & (BUCKETS - 1);
            const entry = &self.entries[idx];
            if (entry.used and entry.subnet_key == key) {
                if (entry.inflight >= limit) return false;
                entry.inflight += 1;
                return true;
            }
            if ((!entry.used or entry.inflight == 0) and free_idx == null) free_idx = idx;
        }

        const idx = free_idx orelse return false;
        self.entries[idx] = .{ .used = true, .subnet_key = key, .inflight = 1 };
        return true;
    }

    fn release(self: *SubnetHandshakeLimit, key: u64) void {
        const start = self.indexFor(key);
        var probe: usize = 0;
        while (probe < MAX_PROBES) : (probe += 1) {
            const entry = &self.entries[(start + probe) & (BUCKETS - 1)];
            if (!entry.used or entry.subnet_key != key) continue;
            if (entry.inflight > 0) entry.inflight -= 1;
            if (entry.inflight == 0) entry.used = false;
            return;
        }
    }
};

fn subnetHandshakeLimit(max_connections: u32) u16 {
    return @intCast(@min(@as(u32, 128), @max(@as(u32, 16), max_connections / 8)));
}

const middle_proxy_connect_cooldown_ms: i64 = 60 * std.time.ms_per_s;
const middle_proxy_cooldown_slots = 32;

const MiddleProxyCooldown = struct {
    active: bool = false,
    addr: net.Address = undefined,
    until_ms: i64 = 0,
};

const ConnectionSlot = struct {
    index: u32 = 0,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = invalid_fd,
    upstream_fd: posix.fd_t = invalid_fd,
    upstream_kind: UpstreamKind = .none,
    peer_addr: net.Address = undefined,

    phase: ConnectionPhase = .idle,
    active_reserved: bool = false,
    /// Set after the first client byte reserves a handshake-budget slot.
    /// Silent pre-warmed TCP sessions deliberately do not consume this budget.
    hs_counted: bool = false,
    subnet_key: u64 = 0,
    subnet_hs_counted: bool = false,

    created_at_ms: i64 = 0,
    first_byte_at_ms: i64 = 0,
    /// Timestamp for the current upstream connect attempt. Reset per candidate.
    upstream_connect_started_ms: i64 = 0,
    /// Fixed deadline for the current upstream connect attempt.
    upstream_connect_deadline_ms: i64 = 0,
    last_activity_ms: i64 = 0,
    /// Last relayed payload time in each direction. If the server spoke more
    /// recently than the client, the server reply is unanswered.
    last_client_byte_ms: i64 = 0,
    last_server_byte_ms: i64 = 0,
    desync_deadline_ns: i128 = 0,

    // Initial TLS handshake reassembly
    tls_hdr_buf: [tls_header_len]u8 = undefined,
    tls_hdr_pos: u8 = 0,
    tls_body_len: u16 = 0,
    tls_body_pos: u16 = 0,
    tls_record_type: u8 = 0,

    client_hello_inline: [client_hello_inline_size]u8 = undefined,
    client_hello_heap: ?[]u8 = null,
    client_hello_len: usize = 0,

    validation_secret: [16]u8 = [_]u8{0} ** 16,
    validation_digest: [32]u8 = [_]u8{0} ** 32,
    validation_session_id: [32]u8 = [_]u8{0} ** 32,
    validation_session_id_len: u8 = 0,
    validation_user: [32]u8 = [_]u8{0} ** 32,
    validation_user_len: u8 = 0,
    validation_force_direct: bool = false,

    server_hello: ?[]u8 = null,
    server_hello_off: usize = 0,

    // 64-byte MTProto handshake assembly from TLS appdata records
    handshake_buf: [constants.handshake_len]u8 = undefined,
    handshake_pos: u8 = 0,
    pipelined_data: ?[]u8 = null,
    pipelined_len: usize = 0,

    // Obfuscation / relay crypto state
    obf_params: ?obfuscation.ObfuscationParams = null,
    client_encryptor: ?crypto.AesCtr = null,
    client_decryptor: ?crypto.AesCtr = null,
    tg_encryptor: ?crypto.AesCtr = null,
    tg_decryptor: ?crypto.AesCtr = null,
    middle_ctx: ?middleproxy.MiddleProxyContext = null,

    dc_idx: i16 = 0,
    dc_abs: u16 = 0,
    proto_tag: constants.ProtoTag = .intermediate,
    use_fast_mode: bool = false,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,

    upstream_candidates: ?[]net.Address = null,
    upstream_candidate_next: u8 = 0,
    direct_fallback_addr: ?net.Address = null,
    direct_fallback_used: bool = false,
    current_upstream_addr: ?net.Address = null,

    // Pending initial bytes for direct DC path (promotion tag)
    dc_initial_tail: ?[]u8 = null,

    // Relay parsing state (C2S TLS records)
    relay_tls_hdr: [tls_header_len]u8 = undefined,
    relay_tls_hdr_pos: u8 = 0,
    relay_tls_body_len: u16 = 0,
    relay_tls_body_pos: u16 = 0,
    relay_record_type: u8 = 0,

    drs: DynamicRecordSizer = DynamicRecordSizer{
        .current_size = DynamicRecordSizer.full_size,
        .records_sent = 0,
        .bytes_sent = 0,
        .enabled = false,
    },
    c2s_bytes: u64 = 0,
    s2c_bytes: u64 = 0,

    read_buf: ?[]u8 = null,

    // Non-blocking write queues (slab-like chain buffers)
    client_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },
    upstream_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },

    // Masking: bytes already read from client before deciding to mask
    mask_prebuffer: ?[]u8 = null,

    // Non-blocking MiddleProxy handshake state
    mp_step: MiddleProxyHandshakeStep = .none,
    mp_write_seq_no: i32 = -2,
    mp_read_seq_no: i32 = -2,
    mp_nonce: [16]u8 = [_]u8{0} ** 16,
    mp_timestamp: u32 = 0,
    mp_rpc_nonce_ans: [16]u8 = [_]u8{0} ** 16,
    mp_enc: ?crypto.AesCbc = null,
    mp_dec: ?crypto.AesCbc = null,
    mp_frame_buf: ?[]u8 = null,
    mp_frame_have: usize = 0,
    mp_frame_need: usize = 0,
    mp_frame_total_len: usize = 0,
    mp_frame_padded_len: usize = 0,
    mp_frame_encrypted: bool = false,
    mp_frame_first_decrypted: bool = false,
    mp_step_deadline_ms: i64 = 0,
    mp_secret: [256]u8 = [_]u8{0} ** 256,
    mp_secret_len: usize = 0,
    mp_nat_ip4: ?[4]u8 = null,

    // Current epoll interests
    client_interest_in: bool = false,
    client_interest_out: bool = false,
    upstream_interest_in: bool = false,
    upstream_interest_out: bool = false,
    relay_half_closed: bool = false,
    client_detached: bool = false,
    upstream_detached: bool = false,

    fn hasClientPending(self: *const ConnectionSlot) bool {
        return !self.client_queue.isEmpty();
    }

    fn hasUpstreamPending(self: *const ConnectionSlot) bool {
        return !self.upstream_queue.isEmpty();
    }

    fn handshakeInProgress(self: *const ConnectionSlot) bool {
        return switch (self.phase) {
            .reading_tls_header,
            .reading_client_hello_body,
            .writing_server_hello_first,
            .desync_wait,
            .writing_server_hello_rest,
            .reading_mtproto_tls_header,
            .reading_mtproto_tls_body,
            .connecting_upstream,
            .writing_dc_nonce,
            .middle_proxy_handshake,
            => true,
            else => false,
        };
    }

    fn resetOwnedBuffers(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        self.client_queue.deinit();
        self.upstream_queue.deinit();
        self.client_queue = .{ .allocator = allocator };
        self.upstream_queue = .{ .allocator = allocator };

        self.releaseClientHello(allocator);

        if (self.server_hello) |buf| secureFree(allocator, buf);
        self.server_hello = null;

        if (self.pipelined_data) |buf| secureFree(allocator, buf);
        self.pipelined_data = null;
        self.pipelined_len = 0;

        if (self.mask_prebuffer) |buf| secureFree(allocator, buf);
        self.mask_prebuffer = null;

        if (self.dc_initial_tail) |buf| secureFree(allocator, buf);
        self.dc_initial_tail = null;

        if (self.middle_ctx) |*mp| mp.deinit();
        self.middle_ctx = null;

        if (self.upstream_candidates) |buf| allocator.free(buf);
        self.upstream_candidates = null;
        self.upstream_candidate_next = 0;
        self.direct_fallback_addr = null;
        self.direct_fallback_used = false;
        self.current_upstream_addr = null;
        self.upstream_connect_started_ms = 0;
        self.upstream_connect_deadline_ms = 0;
        self.dc_abs = 0;
        self.is_media_path = false;

        if (self.read_buf) |buf| secureFree(allocator, buf);
        self.read_buf = null;

        if (self.mp_frame_buf) |buf| secureFree(allocator, buf);
        self.mp_frame_buf = null;

        if (self.obf_params) |*params| params.wipe();
        self.obf_params = null;

        if (self.client_encryptor) |*c| c.wipe();
        if (self.client_decryptor) |*c| c.wipe();
        if (self.tg_encryptor) |*c| c.wipe();
        if (self.tg_decryptor) |*c| c.wipe();
        if (self.mp_enc) |*c| c.wipe();
        if (self.mp_dec) |*c| c.wipe();

        self.client_encryptor = null;
        self.client_decryptor = null;
        self.tg_encryptor = null;
        self.tg_decryptor = null;
        self.mp_enc = null;
        self.mp_dec = null;
        std.crypto.secureZero(u8, &self.validation_secret);
        std.crypto.secureZero(u8, &self.validation_digest);
        std.crypto.secureZero(u8, &self.validation_session_id);
        std.crypto.secureZero(u8, &self.validation_user);
        std.crypto.secureZero(u8, &self.handshake_buf);
        std.crypto.secureZero(u8, &self.mp_nonce);
        std.crypto.secureZero(u8, &self.mp_rpc_nonce_ans);
        std.crypto.secureZero(u8, &self.mp_secret);
        self.validation_session_id_len = 0;
        self.validation_user_len = 0;
        self.validation_force_direct = false;
        self.handshake_pos = 0;
        self.mp_timestamp = 0;
        self.mp_secret_len = 0;
        self.mp_nat_ip4 = null;
    }

    fn releaseClientHello(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        if (self.client_hello_heap) |buf| {
            secureFree(allocator, buf);
            self.client_hello_heap = null;
        } else if (self.client_hello_len > 0) {
            std.crypto.secureZero(u8, self.client_hello_inline[0..self.client_hello_len]);
        }
        self.client_hello_len = 0;
    }

    fn clientHelloBuf(self: *ConnectionSlot) []u8 {
        if (self.client_hello_heap) |buf| return buf;
        return self.client_hello_inline[0..self.client_hello_len];
    }
};

const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    slots: []?*ConnectionSlot,
    free_stack: []u32,
    free_count: u32,
    active_hi: u32,
    fd_to_slot: std.AutoHashMapUnmanaged(posix.fd_t, u32) = .{},

    fn init(allocator: std.mem.Allocator, capacity: u32) !ConnectionPool {
        const slots = try allocator.alloc(?*ConnectionSlot, capacity);
        errdefer allocator.free(slots);

        const free_stack = try allocator.alloc(u32, capacity);
        errdefer allocator.free(free_stack);

        for (slots) |*slot| {
            slot.* = null;
        }

        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            free_stack[i] = @intCast(capacity - 1 - i);
        }

        var pool = ConnectionPool{
            .allocator = allocator,
            .slots = slots,
            .free_stack = free_stack,
            .free_count = capacity,
            .active_hi = 0,
            .fd_to_slot = .{},
        };
        try pool.fd_to_slot.ensureTotalCapacity(allocator, @as(u32, capacity * 2));
        return pool;
    }

    fn deinit(self: *ConnectionPool) void {
        for (self.slots) |slot_opt| {
            if (slot_opt) |slot_ptr| {
                slot_ptr.resetOwnedBuffers(self.allocator);
                self.allocator.destroy(slot_ptr);
            }
        }
        self.fd_to_slot.deinit(self.allocator);
        self.allocator.free(self.free_stack);
        self.allocator.free(self.slots);
    }

    fn acquire(self: *ConnectionPool) ?*ConnectionSlot {
        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const idx = self.free_stack[self.free_count];
        if (self.slots[idx] == null) {
            const fresh = self.allocator.create(ConnectionSlot) catch {
                self.free_stack[self.free_count] = idx;
                self.free_count += 1;
                return null;
            };
            fresh.* = .{};
            self.slots[idx] = fresh;
        }

        const slot = self.slots[idx].?;
        slot.* = .{};
        slot.index = idx;
        slot.client_queue.allocator = self.allocator;
        slot.upstream_queue.allocator = self.allocator;
        const active_hi = idx + 1;
        if (active_hi > self.active_hi) self.active_hi = active_hi;
        return slot;
    }

    fn release(self: *ConnectionPool, slot: *ConnectionSlot) void {
        self.free_stack[self.free_count] = slot.index;
        self.free_count += 1;
        slot.phase = .idle;
        if (slot.index + 1 == self.active_hi) {
            while (self.active_hi > 0) {
                const top = self.slots[self.active_hi - 1] orelse {
                    self.active_hi -= 1;
                    continue;
                };
                if (top.phase != .idle) break;
                self.active_hi -= 1;
            }
        }
    }

    fn mapFd(self: *ConnectionPool, fd: posix.fd_t, idx: u32) !void {
        try self.fd_to_slot.put(self.allocator, fd, idx);
    }

    fn unmapFd(self: *ConnectionPool, fd: posix.fd_t) void {
        _ = self.fd_to_slot.remove(fd);
    }

    fn getByFd(self: *ConnectionPool, fd: posix.fd_t) ?*ConnectionSlot {
        const idx = self.fd_to_slot.get(fd) orelse return null;
        return self.slots[idx];
    }
};

fn secureFree(allocator: std.mem.Allocator, buf: []u8) void {
    std.crypto.secureZero(u8, buf);
    allocator.free(buf);
}

fn freeUserSecrets(allocator: std.mem.Allocator, secrets: []obfuscation.UserSecret) void {
    for (secrets) |*secret| {
        std.crypto.secureZero(u8, &secret.secret);
        allocator.free(secret.name);
    }
    allocator.free(secrets);
}

fn slotCandidateCount(slot: *const ConnectionSlot) usize {
    if (slot.upstream_candidates) |c| return c.len;
    return 0;
}

pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    user_secrets: []obfuscation.UserSecret,
    connection_count: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    handshakes_inflight: std.atomic.Value(u32),
    mask_target: ?[]const u8,
    mask_addrs: []net.Address,
    replay_cache: ReplayCache,
    tls_server_hello_template: []u8,

    // Degradation counters (monotonic totals, delta'd in stats log)
    stats_dropped_cap: std.atomic.Value(u64),
    stats_dropped_saturation: std.atomic.Value(u64),
    stats_dropped_rate_limit: std.atomic.Value(u64),
    stats_dropped_hs_budget: std.atomic.Value(u64),
    stats_hs_timeout: std.atomic.Value(u64),
    stats_mp_fallback: std.atomic.Value(u64),

    middle_proxy_lock: MiddleProxyLock = .{},
    middle_proxy_addrs_primary: [5]net.Address,
    middle_proxy_addrs_media_primary: [5]net.Address,
    middle_proxy_addr_203: net.Address,
    middle_proxy_candidates: [5][16]net.Address,
    middle_proxy_candidate_lens: [5]usize,
    middle_proxy_media_candidates: [5][16]net.Address,
    middle_proxy_media_candidate_lens: [5]usize,
    middle_proxy_candidates_203: [16]net.Address,
    middle_proxy_candidates_203_len: usize,
    middle_proxy_cooldowns: [middle_proxy_cooldown_slots]MiddleProxyCooldown,
    middle_proxy_secret: [256]u8,
    middle_proxy_secret_len: usize,
    middle_proxy_nat_ip4: ?[4]u8,
    middle_proxy_updater_stop: std.atomic.Value(bool),
    middle_proxy_refresh_requested: std.atomic.Value(bool),
    middle_proxy_updater_thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !ProxyState {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        errdefer {
            for (secrets.items) |*secret| {
                std.crypto.secureZero(u8, &secret.secret);
                allocator.free(secret.name);
            }
            secrets.deinit(allocator);
        }
        var users = cfg.users;
        var it = users.iterator();
        while (it.next()) |entry| {
            const user_name = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(user_name);
            try secrets.append(allocator, .{
                .name = user_name,
                .secret = entry.value_ptr.*,
            });
        }
        const user_secrets = try secrets.toOwnedSlice(allocator);
        secrets = .empty;
        errdefer freeUserSecrets(allocator, user_secrets);

        const tls_template = try tls.buildServerHelloTemplateAlloc(
            allocator,
            null,
            tls.effectiveFakeCertSize(cfg.fake_cert_size),
        );
        errdefer allocator.free(tls_template);

        var mask_target: ?[]const u8 = null;
        var resolved_addrs: []net.Address = &.{};
        errdefer if (resolved_addrs.len > 0) allocator.free(resolved_addrs);
        if (cfg.mask) {
            mask_target = blk: {
                if (cfg.mask_port == 443) break :blk cfg.tls_domain;

                if (isRunningInNonInitNetns()) {
                    log.info(
                        "mask_port={d} with non-init netns detected, using host veth IP {s} for local masking",
                        .{ cfg.mask_port, tunnel_mask_gateway_ip },
                    );
                    break :blk tunnel_mask_gateway_ip;
                }

                break :blk "127.0.0.1";
            };
            if (std.Io.net.IpAddress.parse(mask_target.?, cfg.mask_port)) |_| {
                const list = try net.getAddressList(allocator, mask_target.?, cfg.mask_port);
                if (list.addrs.len > 0) {
                    resolved_addrs = list.addrs;
                    log.info("Using literal mask target '{s}:{d}'", .{ mask_target.?, cfg.mask_port });
                } else {
                    list.deinit();
                }
            } else |_| {
                log.info("Mask target '{s}:{d}' will be resolved in the background", .{ mask_target.?, cfg.mask_port });
            }
        }

        var default_middle_proxy_secret = [_]u8{0} ** 256;
        @memcpy(default_middle_proxy_secret[0..middleproxy.proxy_secret.len], middleproxy.proxy_secret[0..]);

        var detected_nat_ip4: ?[4]u8 = null;
        if (cfg.datacenter_override == null) {
            if (cfg.middle_proxy_nat_ip) |configured_nat_ip| {
                if (parseIpv4Literal(configured_nat_ip)) |parsed_ip| {
                    detected_nat_ip4 = parsed_ip;
                    var ip_buf: [16]u8 = undefined;
                    log.info("Using server.middle_proxy_nat_ip for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(parsed_ip, &ip_buf)});
                } else {
                    log.info("server.middle_proxy_nat_ip='{s}' is not an IPv4 literal; falling back to AWG/public detection", .{configured_nat_ip});
                }
            }

            if (detected_nat_ip4 == null) {
                if (cfg.public_ip) |configured_public_ip| {
                    if (parseIpv4Literal(configured_public_ip)) |parsed_ip| {
                        detected_nat_ip4 = parsed_ip;
                        var ip_buf: [16]u8 = undefined;
                        log.info("Using server.public_ip for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(parsed_ip, &ip_buf)});
                    } else {
                        log.info("server.public_ip='{s}' is not an IPv4 literal; middle-proxy NAT IP will be detected in the background", .{configured_public_ip});
                    }
                }
            }
        }

        return .{
            .allocator = allocator,
            .config = cfg,
            .user_secrets = user_secrets,
            .connection_count = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .handshakes_inflight = std.atomic.Value(u32).init(0),
            .mask_target = mask_target,
            .mask_addrs = resolved_addrs,
            .replay_cache = ReplayCache.init(),
            .tls_server_hello_template = tls_template,
            .stats_dropped_cap = std.atomic.Value(u64).init(0),
            .stats_dropped_saturation = std.atomic.Value(u64).init(0),
            .stats_dropped_rate_limit = std.atomic.Value(u64).init(0),
            .stats_dropped_hs_budget = std.atomic.Value(u64).init(0),
            .stats_hs_timeout = std.atomic.Value(u64).init(0),
            .stats_mp_fallback = std.atomic.Value(u64).init(0),
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addrs_media_primary = constants.tg_media_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.getDcAddressV4(203),
            .middle_proxy_candidates = defaultMiddleProxyCandidateLists(constants.tg_middle_proxies_v4),
            .middle_proxy_candidate_lens = [_]usize{1} ** 5,
            .middle_proxy_media_candidates = defaultMiddleProxyCandidateLists(constants.tg_media_middle_proxies_v4),
            .middle_proxy_media_candidate_lens = [_]usize{1} ** 5,
            .middle_proxy_candidates_203 = [_]net.Address{constants.getDcAddressV4(203)} ** 16,
            .middle_proxy_candidates_203_len = 1,
            .middle_proxy_cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots,
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
            .middle_proxy_nat_ip4 = detected_nat_ip4,
            .middle_proxy_updater_stop = std.atomic.Value(bool).init(false),
            .middle_proxy_refresh_requested = std.atomic.Value(bool).init(false),
            .middle_proxy_updater_thread = null,
        };
    }

    pub fn deinit(self: *ProxyState) void {
        self.stopMiddleProxyUpdater();
        self.middle_proxy_lock.lock();
        std.crypto.secureZero(u8, &self.middle_proxy_secret);
        self.middle_proxy_secret_len = 0;
        self.middle_proxy_lock.unlock();
        self.allocator.free(self.tls_server_hello_template);
        if (self.mask_addrs.len > 0) self.allocator.free(self.mask_addrs);
        freeUserSecrets(self.allocator, self.user_secrets);
    }

    pub fn run(self: *ProxyState) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

        const address = net.Address.initIp6(
            .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            self.config.port,
            0,
            0,
        );
        var ipv6_ok = true;
        var server = address.listen(.{
            .reuse_address = true,
            .kernel_backlog = @intCast(self.config.backlog),
        }) catch |err| blk: {
            if (err == error.AddressFamilyNotSupported) {
                ipv6_ok = false;
                log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
                const address_v4 = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.config.port);
                break :blk try address_v4.listen(.{
                    .reuse_address = true,
                    .kernel_backlog = @intCast(self.config.backlog),
                });
            }
            return err;
        };
        defer server.deinit();

        if (ipv6_ok) {
            log.info("Listening on [::]:{d} (epoll, single-thread)", .{self.config.port});
        } else {
            log.info("Listening on 0.0.0.0:{d} (epoll, single-thread)", .{self.config.port});
        }

        var middle_proxy_updater_started = false;
        defer {
            if (middle_proxy_updater_started) self.stopMiddleProxyUpdater();
        }

        if (self.config.datacenter_override == null and
            (self.config.usesAnyMiddleProxy() or (self.config.mask and self.mask_target != null)))
        {
            self.startMiddleProxyUpdater();
            middle_proxy_updater_started = self.middle_proxy_updater_thread != null;
        }

        if (getNofileSoftLimit()) |soft| {
            const configured_max = self.config.max_connections;
            const needed_fds = requiredFdsForConnections(configured_max);
            if (soft < needed_fds) {
                const clamped = maxConnectionsForNofile(soft);
                if (clamped == 0) {
                    log.err("RLIMIT_NOFILE soft={d} cannot support the minimum 32 connections (need at least {d})", .{
                        soft,
                        requiredFdsForConnections(32),
                    });
                    return error.InsufficientFileDescriptorLimit;
                }
                if (clamped < configured_max) {
                    self.config.max_connections = clamped;
                    log.warn("max_connections clamped from {d} to {d} due to RLIMIT_NOFILE soft={d}", .{
                        configured_max,
                        clamped,
                        soft,
                    });
                }
            }
        }

        const effective_needed_fds = requiredFdsForConnections(self.config.max_connections);
        checkNofileLimit(@max(effective_needed_fds, min_nofile_soft), self.config.max_connections);

        const loop = try EventLoop.init(self, server.stream.handle);
        defer {
            loop.deinit();
            self.allocator.destroy(loop);
        }
        try loop.run();
    }

    const MiddleProxySnapshot = struct {
        candidates: [5][16]net.Address,
        candidate_lens: [5]usize,
        media_candidates: [5][16]net.Address,
        media_candidate_lens: [5]usize,
        candidates_203: [16]net.Address,
        candidates_203_len: usize,
        secret: [256]u8,
        secret_len: usize,
        nat_ip4: ?[4]u8 = null,

        fn candidatesForDc(self: *const MiddleProxySnapshot, dc_abs: usize, media: bool) []const net.Address {
            if (dc_abs == 203) return self.candidates_203[0..self.candidates_203_len];
            if (dc_abs >= 1 and dc_abs <= self.candidates.len) {
                const index = dc_abs - 1;
                if (media) return self.media_candidates[index][0..self.media_candidate_lens[index]];
                return self.candidates[index][0..self.candidate_lens[index]];
            }
            return &.{};
        }
    };

    fn getMiddleProxySnapshot(self: *ProxyState) MiddleProxySnapshot {
        self.middle_proxy_lock.lockShared();
        defer self.middle_proxy_lock.unlockShared();

        var snapshot = MiddleProxySnapshot{
            .candidates = self.middle_proxy_candidates,
            .candidate_lens = self.middle_proxy_candidate_lens,
            .media_candidates = self.middle_proxy_media_candidates,
            .media_candidate_lens = self.middle_proxy_media_candidate_lens,
            .candidates_203 = self.middle_proxy_candidates_203,
            .candidates_203_len = self.middle_proxy_candidates_203_len,
            .secret = self.middle_proxy_secret,
            .secret_len = self.middle_proxy_secret_len,
            .nat_ip4 = self.middle_proxy_nat_ip4,
        };
        const now_ms = compat.monotonicMilliTimestamp();
        for (0..snapshot.candidates.len) |i| {
            prioritizeMiddleProxyCandidates(&snapshot.candidates[i], snapshot.candidate_lens[i], &self.middle_proxy_cooldowns, now_ms);
            prioritizeMiddleProxyCandidates(&snapshot.media_candidates[i], snapshot.media_candidate_lens[i], &self.middle_proxy_cooldowns, now_ms);
        }
        prioritizeMiddleProxyCandidates(&snapshot.candidates_203, snapshot.candidates_203_len, &self.middle_proxy_cooldowns, now_ms);
        return snapshot;
    }

    fn promoteMiddleProxyCandidate(self: *ProxyState, dc_abs: usize, media: bool, addr: net.Address) bool {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();

        self.clearMiddleProxyCooldownLocked(addr);

        if (dc_abs == 203) {
            return promoteMiddleProxyCandidateInList(
                &self.middle_proxy_candidates_203,
                self.middle_proxy_candidates_203_len,
                addr,
            );
        }
        if (dc_abs < 1 or dc_abs > self.middle_proxy_candidates.len) return false;

        const index = dc_abs - 1;
        if (media and promoteMiddleProxyCandidateInList(
            &self.middle_proxy_media_candidates[index],
            self.middle_proxy_media_candidate_lens[index],
            addr,
        )) return true;

        return promoteMiddleProxyCandidateInList(
            &self.middle_proxy_candidates[index],
            self.middle_proxy_candidate_lens[index],
            addr,
        );
    }

    fn cooldownMiddleProxyCandidate(self: *ProxyState, addr: net.Address) bool {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();

        const now_ms = compat.monotonicMilliTimestamp();
        var replacement_index: usize = 0;
        var replacement_until_ms: i64 = std.math.maxInt(i64);
        for (&self.middle_proxy_cooldowns, 0..) |*entry, i| {
            if (entry.active and isSameIpEndpoint(entry.addr, addr)) {
                entry.until_ms = now_ms + middle_proxy_connect_cooldown_ms;
                return false;
            }
            if (!entry.active or entry.until_ms <= now_ms) {
                replacement_index = i;
                break;
            }
            if (entry.until_ms < replacement_until_ms) {
                replacement_index = i;
                replacement_until_ms = entry.until_ms;
            }
        }

        self.middle_proxy_cooldowns[replacement_index] = .{
            .active = true,
            .addr = addr,
            .until_ms = now_ms + middle_proxy_connect_cooldown_ms,
        };
        return true;
    }

    fn clearMiddleProxyCooldownLocked(self: *ProxyState, addr: net.Address) void {
        for (&self.middle_proxy_cooldowns) |*entry| {
            if (entry.active and isSameIpEndpoint(entry.addr, addr)) {
                entry.active = false;
                entry.until_ms = 0;
                return;
            }
        }
    }

    fn startMiddleProxyUpdater(self: *ProxyState) void {
        if (self.middle_proxy_updater_thread != null) return;
        self.middle_proxy_updater_stop.store(false, .release);

        if (std.Thread.spawn(.{}, ProxyState.middleProxyUpdaterMain, .{self})) |updater| {
            self.middle_proxy_updater_thread = updater;
        } else |err| {
            log.warn("Middle-proxy updater thread failed to start: {any}", .{err});
        }
    }

    fn stopMiddleProxyUpdater(self: *ProxyState) void {
        self.middle_proxy_updater_stop.store(true, .release);
        if (self.middle_proxy_updater_thread) |thread| {
            thread.join();
            self.middle_proxy_updater_thread = null;
        }
    }

    fn requestMiddleProxyRefresh(self: *ProxyState) void {
        self.middle_proxy_refresh_requested.store(true, .release);
    }

    fn waitMiddleProxyUpdatePeriod(self: *ProxyState) bool {
        var slept_ns: u64 = 0;
        while (slept_ns < middle_proxy_update_period_ns) {
            if (self.middle_proxy_updater_stop.load(.acquire)) return false;
            if (slept_ns >= middle_proxy_reactive_cooldown_ns and
                self.middle_proxy_refresh_requested.swap(false, .acq_rel))
            {
                log.info("Middle-proxy reactive refresh: stalled handshake(s) suggest stale metadata", .{});
                return true;
            }
            const chunk = @min(middle_proxy_update_stop_poll_ns, middle_proxy_update_period_ns - slept_ns);
            compat.sleep(chunk);
            slept_ns += chunk;
        }
        return !self.middle_proxy_updater_stop.load(.acquire);
    }

    fn middleProxyUpdaterMain(self: *ProxyState) void {
        if (self.config.usesAnyMiddleProxy()) {
            self.ensureMiddleProxyNatIp();
            // Serve immediately with bundled fallback endpoints. Fetching metadata
            // in this worker keeps a censored or slow core.telegram.org from
            // delaying accepts after a proxy restart.
            self.refreshMiddleProxyInfo() catch |err| {
                if (err == error.UpdateCancelled or self.middle_proxy_updater_stop.load(.acquire)) return;
                log.warn("Initial middle-proxy refresh failed, using bundled defaults: {any}", .{err});
            };
        }
        self.refreshMaskAddresses();

        while (self.waitMiddleProxyUpdatePeriod()) {
            if (self.config.usesAnyMiddleProxy()) {
                self.ensureMiddleProxyNatIp();
                self.refreshMiddleProxyInfo() catch |err| {
                    if (err == error.UpdateCancelled or self.middle_proxy_updater_stop.load(.acquire)) return;
                    log.warn("Middle-proxy refresh failed: {any}", .{err});
                };
            }
            self.refreshMaskAddresses();
        }
    }

    fn ensureMiddleProxyNatIp(self: *ProxyState) void {
        self.middle_proxy_lock.lock();
        const already_known = self.middle_proxy_nat_ip4 != null;
        self.middle_proxy_lock.unlock();
        if (already_known or self.middle_proxy_updater_stop.load(.acquire)) return;

        var detected = detectAwgEndpointIpv4(self.allocator);
        if (detected == null and !self.middle_proxy_updater_stop.load(.acquire)) {
            detected = detectPublicIpv4(self.allocator);
        }
        const ip = detected orelse return;

        self.middle_proxy_lock.lock();
        if (self.middle_proxy_nat_ip4 == null) self.middle_proxy_nat_ip4 = ip;
        self.middle_proxy_lock.unlock();

        var ip_buf: [16]u8 = undefined;
        log.info("Detected IPv4 for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(ip, &ip_buf)});
    }

    fn refreshMaskAddresses(self: *ProxyState) void {
        const target = self.mask_target orelse return;
        if (self.middle_proxy_updater_stop.load(.acquire)) return;

        const list = net.getAddressList(self.allocator, target, self.config.mask_port) catch |err| {
            if (!self.middle_proxy_updater_stop.load(.acquire)) {
                log.warn("Failed to resolve mask target '{s}:{d}': {any}", .{ target, self.config.mask_port, err });
            }
            return;
        };
        if (list.addrs.len == 0) {
            list.deinit();
            return;
        }
        prioritizeIpv4Addresses(list.addrs);

        self.middle_proxy_lock.lock();
        const old_addrs = self.mask_addrs;
        self.mask_addrs = list.addrs;
        self.middle_proxy_lock.unlock();
        if (old_addrs.len > 0) self.allocator.free(old_addrs);

        log.info("Mask target '{s}:{d}' resolved to {d} candidate(s)", .{ target, self.config.mask_port, list.addrs.len });
    }

    fn fetchMiddleProxyMetadata(self: *ProxyState, label: []const u8, url: []const u8) ![]u8 {
        var attempt: u8 = 0;
        while (attempt < 2) : (attempt += 1) {
            if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;
            const bytes = http_fetch.fetchUrlBytes(
                self.allocator,
                url,
                .{ .max_response_bytes = 1 * 1024 * 1024 },
            ) catch |err| {
                if (err == error.HttpRequestTimedOut and attempt == 0) {
                    log.info("Middle-proxy {s} request timed out; retrying once in 1s", .{label});
                    var waited: u64 = 0;
                    while (waited < std.time.ns_per_s) : (waited += 100 * std.time.ns_per_ms) {
                        if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;
                        compat.sleep(100 * std.time.ns_per_ms);
                    }
                    continue;
                }
                if (err == error.HttpRequestTimedOut) {
                    log.info("Middle-proxy {s} request timed out after retry", .{label});
                }
                return err;
            };

            if (attempt > 0) {
                log.info("Middle-proxy {s} request succeeded on retry", .{label});
            }
            return bytes;
        }
        unreachable;
    }

    fn refreshMiddleProxyInfo(self: *ProxyState) !void {
        if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;
        const cfg_bytes = try self.fetchMiddleProxyMetadata("getProxyConfig", middle_proxy_config_url);
        defer secureFree(self.allocator, cfg_bytes);

        var next_primary: [5]?net.Address = [_]?net.Address{null} ** 5;
        var next_media_primary: [5]?net.Address = [_]?net.Address{null} ** 5;
        var next_candidates: [5][16]net.Address = undefined;
        var next_candidate_lens: [5]usize = [_]usize{0} ** 5;
        var next_media_candidates: [5][16]net.Address = undefined;
        var next_media_candidate_lens: [5]usize = [_]usize{0} ** 5;
        for (0..next_primary.len) |i| {
            if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;
            const dc_num: i16 = @intCast(i + 1);

            var candidates: [16]net.Address = undefined;
            const count = parseMiddleProxyAddressesForDc(cfg_bytes, dc_num, .positive_only, &candidates);
            const preferred = if (count == 0)
                null
            else if (i == 3)
                candidates[0]
            else if (trySelectReachableMiddleProxy(candidates[0..count], 1200, &self.middle_proxy_updater_stop)) |reachable|
                reachable
            else
                candidates[0];
            next_primary[i] = preferred;
            if (preferred) |addr| {
                next_candidate_lens[i] = copyMiddleProxyCandidates(&next_candidates[i], candidates[0..count], addr);
            }

            var media_candidates: [16]net.Address = undefined;
            const media_count = parseMiddleProxyAddressesForDc(cfg_bytes, dc_num, .negative_only, &media_candidates);
            const media_preferred = if (media_count == 0)
                null
            else if (i == 3)
                media_candidates[0]
            else if (trySelectReachableMiddleProxy(media_candidates[0..media_count], 1200, &self.middle_proxy_updater_stop)) |reachable|
                reachable
            else
                media_candidates[0];
            next_media_primary[i] = media_preferred;
            if (media_preferred) |addr| {
                next_media_candidate_lens[i] = copyMiddleProxyCandidates(&next_media_candidates[i], media_candidates[0..media_count], addr);
            }
        }

        var candidates_203: [16]net.Address = undefined;
        const count_203 = parseMiddleProxyAddressesForDc(cfg_bytes, 203, .any, &candidates_203);
        var next_203_candidates: [16]net.Address = undefined;
        var next_203_candidates_len: usize = 0;
        if (count_203 > 0) {
            next_203_candidates_len = copyMiddleProxyCandidates(&next_203_candidates, candidates_203[0..count_203], candidates_203[0]);
        }
        const next_addr_203 = if (count_203 == 0) null else candidates_203[0];

        if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;
        const next_secret = try self.fetchMiddleProxyMetadata("getProxySecret", middle_proxy_secret_url);
        defer secureFree(self.allocator, next_secret);

        if (next_secret.len < 16 or next_secret.len > self.middle_proxy_secret.len) {
            return error.BadMiddleProxySecret;
        }

        var changed = false;
        var changed_dc4: net.Address = undefined;
        var changed_dc203: net.Address = undefined;
        var changed_secret_len: usize = 0;

        {
            self.middle_proxy_lock.lock();
            defer self.middle_proxy_lock.unlock();

            for (0..next_primary.len) |i| {
                if (next_primary[i]) |addr| {
                    if (!self.middle_proxy_addrs_primary[i].eql(addr)) {
                        self.middle_proxy_addrs_primary[i] = addr;
                        changed = true;
                    }
                }
                if (next_media_primary[i]) |addr| {
                    if (!self.middle_proxy_addrs_media_primary[i].eql(addr)) {
                        self.middle_proxy_addrs_media_primary[i] = addr;
                        changed = true;
                    }
                }
            }

            if (next_addr_203) |addr| {
                if (!self.middle_proxy_addr_203.eql(addr)) {
                    self.middle_proxy_addr_203 = addr;
                    changed = true;
                }
            }

            for (0..next_candidate_lens.len) |i| {
                if (next_candidate_lens[i] > 0 and
                    (self.middle_proxy_candidate_lens[i] != next_candidate_lens[i] or
                        !addressesEqual(self.middle_proxy_candidates[i][0..next_candidate_lens[i]], next_candidates[i][0..next_candidate_lens[i]])))
                {
                    @memcpy(self.middle_proxy_candidates[i][0..next_candidate_lens[i]], next_candidates[i][0..next_candidate_lens[i]]);
                    self.middle_proxy_candidate_lens[i] = next_candidate_lens[i];
                    changed = true;
                }

                if (next_media_candidate_lens[i] > 0 and
                    (self.middle_proxy_media_candidate_lens[i] != next_media_candidate_lens[i] or
                        !addressesEqual(self.middle_proxy_media_candidates[i][0..next_media_candidate_lens[i]], next_media_candidates[i][0..next_media_candidate_lens[i]])))
                {
                    @memcpy(self.middle_proxy_media_candidates[i][0..next_media_candidate_lens[i]], next_media_candidates[i][0..next_media_candidate_lens[i]]);
                    self.middle_proxy_media_candidate_lens[i] = next_media_candidate_lens[i];
                    changed = true;
                }
            }

            if (next_203_candidates_len > 0) {
                if (self.middle_proxy_candidates_203_len != next_203_candidates_len or
                    !addressesEqual(self.middle_proxy_candidates_203[0..next_203_candidates_len], next_203_candidates[0..next_203_candidates_len]))
                {
                    @memcpy(self.middle_proxy_candidates_203[0..next_203_candidates_len], next_203_candidates[0..next_203_candidates_len]);
                    self.middle_proxy_candidates_203_len = next_203_candidates_len;
                    changed = true;
                }
            }

            if (self.middle_proxy_secret_len != next_secret.len or
                !std.mem.eql(u8, self.middle_proxy_secret[0..self.middle_proxy_secret_len], next_secret))
            {
                std.crypto.secureZero(u8, &self.middle_proxy_secret);
                @memcpy(self.middle_proxy_secret[0..next_secret.len], next_secret);
                self.middle_proxy_secret_len = next_secret.len;
                changed = true;
            }

            if (changed) {
                changed_dc4 = self.middle_proxy_addrs_primary[3];
                changed_dc203 = self.middle_proxy_addr_203;
                changed_secret_len = self.middle_proxy_secret_len;
            }
        }

        if (changed) {
            var dc4_buf: [64]u8 = undefined;
            var dc203_buf: [64]u8 = undefined;
            const dc4_str = formatAddress(changed_dc4, &dc4_buf);
            const dc203_str = formatAddress(changed_dc203, &dc203_buf);
            log.info("Middle-proxy cache updated: dc4={s} dc203={s} secret_len={d}", .{
                dc4_str,
                dc203_str,
                changed_secret_len,
            });
        }
    }
};

const EventLoop = struct {
    state: *ProxyState,
    epoll_fd: posix.fd_t,
    listen_fd: posix.fd_t,
    pool: ConnectionPool,
    accept_paused: bool,
    accept_resume_ns: i128,
    saturation_paused: bool,
    timer_scan_cursor: u32,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,
    subnet_limiter: SubnetRateLimit,
    subnet_handshakes: SubnetHandshakeLimit,
    // Snapshot of degradation counters for delta logging
    prev_dropped_cap: u64,
    prev_dropped_saturation: u64,
    prev_dropped_rate_limit: u64,
    prev_dropped_hs_budget: u64,
    prev_hs_timeout: u64,
    prev_mp_fallback: u64,
    mp_c2s_scratch: ?[]u8,
    mp_s2c_scratch: ?[]u8,
    pending_close_fds: std.ArrayList(posix.fd_t),

    fn init(state: *ProxyState, listen_fd: posix.fd_t) !*EventLoop {
        const epoll_fd = try epollCreate();
        errdefer closeFd(epoll_fd);

        const loop = try state.allocator.create(EventLoop);
        errdefer state.allocator.destroy(loop);

        loop.state = state;
        loop.epoll_fd = epoll_fd;
        loop.listen_fd = listen_fd;
        loop.pool = try ConnectionPool.init(state.allocator, state.config.max_connections);
        errdefer loop.pool.deinit();
        loop.accept_paused = false;
        loop.accept_resume_ns = 0;
        loop.saturation_paused = false;
        loop.timer_scan_cursor = 0;
        loop.stats_next_log_ns = compat.monotonicNanoTimestamp() + stats_log_interval_ns;
        loop.accepted_since_log = 0;
        loop.closed_since_log = 0;
        loop.subnet_limiter.hash_seed = crypto.randomInt(u64);
        for (&loop.subnet_limiter.entries) |*entry| entry.* = .{};
        loop.subnet_handshakes.hash_seed = crypto.randomInt(u64);
        for (&loop.subnet_handshakes.entries) |*entry| entry.* = .{};
        loop.prev_dropped_cap = 0;
        loop.prev_dropped_saturation = 0;
        loop.prev_dropped_rate_limit = 0;
        loop.prev_dropped_hs_budget = 0;
        loop.prev_hs_timeout = 0;
        loop.prev_mp_fallback = 0;
        loop.mp_c2s_scratch = null;
        loop.mp_s2c_scratch = null;
        loop.pending_close_fds = .empty;

        try loop.addFd(listen_fd, true, false);
        return loop;
    }

    fn deinit(self: *EventLoop) void {
        for (self.pool.slots) |slot_opt| {
            if (slot_opt) |slot| {
                if (slot.phase != .idle) {
                    self.closeSlot(slot, "shutdown");
                }
            }
        }

        if (self.mp_c2s_scratch) |buf| secureFree(self.state.allocator, buf);
        if (self.mp_s2c_scratch) |buf| secureFree(self.state.allocator, buf);

        self.drainPendingCloses();
        self.pending_close_fds.deinit(self.state.allocator);

        self.pool.deinit();
        closeFd(self.epoll_fd);
    }

    fn deferClose(self: *EventLoop, fd: posix.fd_t) void {
        self.pending_close_fds.append(self.state.allocator, fd) catch {
            closeFd(fd);
        };
    }

    fn drainPendingCloses(self: *EventLoop) void {
        for (self.pending_close_fds.items) |fd| closeFd(fd);
        self.pending_close_fds.clearRetainingCapacity();
    }

    fn run(self: *EventLoop) !void {
        var events: [256]linux.epoll_event = undefined;
        const timer_tick_ns: i128 = 5 * std.time.ns_per_ms;
        var next_timer_tick_ns: i128 = compat.monotonicNanoTimestamp();

        while (true) {
            self.drainPendingCloses();

            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), event_loop_wait_ms);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return posix.unexpectedErrno(err),
            }

            const n: usize = @intCast(rc);
            for (events[0..n]) |ev| {
                const fd = ev.data.fd;
                const ev_flags = ev.events;
                if (fd == self.listen_fd) {
                    self.acceptNewConnections() catch |err| {
                        log.err("accept loop error: {any}", .{err});
                    };
                    continue;
                }

                const slot = self.pool.getByFd(fd) orelse continue;
                self.processSlotEvent(slot, fd, ev_flags);
            }

            const now_ns = compat.monotonicNanoTimestamp();
            if (self.accept_paused and now_ns >= self.accept_resume_ns) {
                self.resumeAccepting();
            }
            // Saturation hysteresis: resume accepting when active drops below 80%
            if (self.saturation_paused) {
                const active = self.state.active_connections.load(.monotonic);
                const resume_threshold = (self.state.config.max_connections * 8) / 10;
                if (active <= resume_threshold) {
                    self.resumeSaturation();
                }
            }
            if (now_ns >= next_timer_tick_ns) {
                self.runTimers();
                next_timer_tick_ns = now_ns + timer_tick_ns;
            }
            if (now_ns >= self.stats_next_log_ns) {
                self.logPeriodicStats(now_ns);
            }
        }
    }

    fn processSlotEvent(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t, events: u32) void {
        if (slot.phase == .idle) return;
        if (fd != slot.client_fd and fd != slot.upstream_fd) return;
        if ((fd == slot.client_fd and slot.client_detached) or
            (fd == slot.upstream_fd and slot.upstream_detached))
        {
            return;
        }

        const graceful_rdhup = hasGracefulEpollRdhup(events);
        if (graceful_rdhup and (slot.phase == .relaying or slot.phase == .mask_relaying)) {
            self.drainRelayRdhup(slot, fd, events);
            return;
        }

        const fatal_hangup = hasFatalEpollHangup(events) or
            ((events & linux.EPOLL.RDHUP) != 0 and slot.phase != .relaying and slot.phase != .mask_relaying);

        if (fd == slot.client_fd) {
            if ((events & linux.EPOLL.OUT) != 0) {
                self.onClientWritable(slot);
            }
            if (slot.phase == .idle) return;
            if ((events & linux.EPOLL.IN) != 0) {
                self.onClientReadable(slot);
            }
        } else if (fd == slot.upstream_fd) {
            if ((events & linux.EPOLL.OUT) != 0 or (slot.phase == .connecting_upstream and fatal_hangup)) {
                self.onUpstreamWritable(slot);
            }
            if (slot.phase == .idle) return;
            if ((events & linux.EPOLL.IN) != 0) {
                self.onUpstreamReadable(slot);
            }
        }

        if (fd != slot.client_fd and fd != slot.upstream_fd) return;
        if ((fd == slot.client_fd and slot.client_detached) or
            (fd == slot.upstream_fd and slot.upstream_detached))
        {
            return;
        }

        if (fatal_hangup and shouldCloseOnFatalHangup(slot.phase, fd, slot.upstream_fd)) {
            if (self.tryBeginRelayHalfClose(slot, fd, events)) return;
            if (shouldFallbackMiddleProxyOnFatalHangup(slot.phase, fd, slot.upstream_fd) and
                self.fallbackFromMiddleProxyToDirect(slot))
            {
                return;
            }
            self.closeSlot(slot, "epoll hup/err");
            return;
        }

        if (slot.phase != .idle) {
            self.syncInterests(slot) catch |err| {
                log.debug("[{d}] interest sync error: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "interest sync error");
            };
        }
    }

    fn acceptNewConnections(self: *EventLoop) !void {
        // Saturation hysteresis: if active > 90% of max, stop accepting entirely.
        // Resume only when active drops below 80% (checked in run() loop).
        const active_now = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        if (active_now >= (max * 9) / 10) {
            if (!self.saturation_paused) {
                self.pauseSaturation();
            }
            _ = self.state.stats_dropped_saturation.fetchAdd(1, .monotonic);
            return;
        }

        var accepted_this_round: usize = 0;
        while (accepted_this_round < accept_batch_limit) {
            var client_addr: net.Address = undefined;
            var client_len: posix.socklen_t = @sizeOf(net.Address);
            const cfd = acceptFd(self.listen_fd, &client_addr.any, &client_len) catch |err| {
                switch (err) {
                    error.WouldBlock => return,
                    error.ConnectionAborted, error.ConnectionResetByPeer => continue,
                    error.ProcessFdQuotaExceeded,
                    error.SystemFdQuotaExceeded,
                    error.SystemResources,
                    => {
                        self.pauseAccepting(err);
                        return;
                    },
                    else => return err,
                }
            };
            accepted_this_round += 1;

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!self.subnet_limiter.check(client_addr, self.state.config.rate_limit_per_subnet)) {
                _ = self.state.stats_dropped_rate_limit.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            const active_before = self.state.active_connections.fetchAdd(1, .monotonic);
            if (active_before >= self.state.config.max_connections) {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                _ = self.state.stats_dropped_cap.fetchAdd(1, .monotonic);
                closeFd(cfd);
                continue;
            }

            const slot = self.pool.acquire() orelse {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                closeFd(cfd);
                continue;
            };

            const subnet_key = SubnetRateLimit.subnetKey(client_addr);
            if (!self.subnet_handshakes.reserve(subnet_key, subnetHandshakeLimit(max))) {
                _ = self.state.active_connections.fetchSub(1, .monotonic);
                _ = self.state.stats_dropped_hs_budget.fetchAdd(1, .monotonic);
                self.pool.release(slot);
                closeFd(cfd);
                continue;
            }

            slot.active_reserved = true;
            slot.hs_counted = false;
            slot.subnet_key = subnet_key;
            slot.subnet_hs_counted = true;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.phase = .reading_tls_header;
            slot.created_at_ms = compat.monotonicMilliTimestamp();
            slot.last_activity_ms = slot.created_at_ms;
            slot.last_client_byte_ms = 0;
            slot.last_server_byte_ms = 0;
            slot.drs = DynamicRecordSizer.init(self.state.config.drs);

            if (self.addFd(cfd, true, false)) |_| {
                slot.client_interest_in = true;
                slot.client_interest_out = false;
                self.pool.mapFd(cfd, slot.index) catch {
                    self.closeSlot(slot, "fd map failed");
                    continue;
                };
                self.accepted_since_log += 1;
            } else |_| {
                self.closeSlot(slot, "epoll add client failed");
                continue;
            }
        }
    }

    fn logPeriodicStats(self: *EventLoop, now_ns: i128) void {
        const active = self.state.active_connections.load(.monotonic);
        const hs = self.state.handshakes_inflight.load(.monotonic);
        const accepted_total = self.state.connection_count.load(.monotonic);

        // Snapshot degradation counters and compute deltas
        const cur_cap = self.state.stats_dropped_cap.load(.monotonic);
        const cur_sat = self.state.stats_dropped_saturation.load(.monotonic);
        const cur_rate = self.state.stats_dropped_rate_limit.load(.monotonic);
        const cur_hs = self.state.stats_dropped_hs_budget.load(.monotonic);
        const cur_hst = self.state.stats_hs_timeout.load(.monotonic);
        const cur_mpf = self.state.stats_mp_fallback.load(.monotonic);

        const d_cap = cur_cap - self.prev_dropped_cap;
        const d_sat = cur_sat - self.prev_dropped_saturation;
        const d_rate = cur_rate - self.prev_dropped_rate_limit;
        const d_hs = cur_hs - self.prev_dropped_hs_budget;
        const d_hst = cur_hst - self.prev_hs_timeout;
        const d_mpf = cur_mpf - self.prev_mp_fallback;

        self.prev_dropped_cap = cur_cap;
        self.prev_dropped_saturation = cur_sat;
        self.prev_dropped_rate_limit = cur_rate;
        self.prev_dropped_hs_budget = cur_hs;
        self.prev_hs_timeout = cur_hst;
        self.prev_mp_fallback = cur_mpf;

        const has_drops = d_cap + d_sat + d_rate + d_hs + d_hst + d_mpf > 0;

        log.info("conn stats: active={d}/{d} hs_inflight={d} accepted+={d} closed+={d} tracked_fds={d} total={d} paused={}/{}", .{
            active,
            self.state.config.max_connections,
            hs,
            self.accepted_since_log,
            self.closed_since_log,
            self.pool.fd_to_slot.count(),
            accepted_total,
            self.accept_paused,
            self.saturation_paused,
        });

        if (has_drops) {
            log.info("  drops: cap+={d} sat+={d} rate+={d} hs_budget+={d} hs_timeout+={d} mp_fallback+={d}", .{
                d_cap, d_sat, d_rate, d_hs, d_hst, d_mpf,
            });
        }

        self.accepted_since_log = 0;
        self.closed_since_log = 0;

        while (self.stats_next_log_ns <= now_ns) {
            self.stats_next_log_ns += stats_log_interval_ns;
        }
    }

    fn wantsAcceptInterest(self: *const EventLoop) bool {
        return shouldAcceptListen(self.accept_paused, self.saturation_paused);
    }

    fn syncAcceptInterest(self: *EventLoop) !void {
        try self.modFd(self.listen_fd, self.wantsAcceptInterest(), false);
    }

    fn pauseAccepting(self: *EventLoop, err: anyerror) void {
        self.accept_resume_ns = compat.monotonicNanoTimestamp() + accept_backoff_ns;
        if (self.accept_paused) return;

        self.accept_paused = true;
        self.syncAcceptInterest() catch |mod_err| {
            log.err("failed to pause accepts after fd quota error: {any}", .{mod_err});
        };

        const needed = requiredFdsForConnections(self.state.config.max_connections);
        log.warn("fd quota reached ({any}); pausing accepts for {d}ms (recommended LimitNOFILE >= {d})", .{
            err,
            accept_backoff_ms,
            needed,
        });
    }

    fn resumeAccepting(self: *EventLoop) void {
        if (!self.accept_paused) return;

        self.accept_paused = false;
        self.accept_resume_ns = 0;

        self.syncAcceptInterest() catch |err| {
            if (!self.saturation_paused) {
                self.accept_paused = true;
                self.accept_resume_ns = compat.monotonicNanoTimestamp() + accept_backoff_ns;
            }
            log.warn("failed to update accept interest after fd quota resume: {any}", .{err});
            return;
        };
    }

    fn pauseSaturation(self: *EventLoop) void {
        if (self.saturation_paused) return;

        self.saturation_paused = true;
        self.syncAcceptInterest() catch |mod_err| {
            log.err("failed to pause accepts for saturation: {any}", .{mod_err});
        };

        const active = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        log.warn(
            "connection saturation: active={d}/{d} (>{d}%); pausing new accepts. " ++
                "Will resume when active drops below {d} ({d}%). " ++
                "To handle more clients, increase max_connections or upgrade VPS RAM.",
            .{ active, max, @as(u32, 90), (max * 8) / 10, @as(u32, 80) },
        );
    }

    fn resumeSaturation(self: *EventLoop) void {
        if (!self.saturation_paused) return;

        self.saturation_paused = false;
        self.syncAcceptInterest() catch |err| {
            if (!self.accept_paused) {
                self.saturation_paused = true;
            }
            log.warn("failed to update accept interest after saturation ease: {any}", .{err});
            return;
        };

        const active = self.state.active_connections.load(.monotonic);
        if (self.wantsAcceptInterest()) {
            log.info("saturation eased: active={d}/{d}; resuming accepts", .{ active, self.state.config.max_connections });
        } else {
            log.info("saturation eased: active={d}/{d}; accepts remain paused for fd quota", .{ active, self.state.config.max_connections });
        }
    }

    fn onClientReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = compat.monotonicMilliTimestamp();

        switch (slot.phase) {
            .reading_tls_header => self.readTlsHeader(slot),
            .reading_client_hello_body => self.readClientHelloBody(slot),
            .reading_mtproto_tls_header, .reading_mtproto_tls_body => self.readMtprotoHandshake(slot),
            .relaying => self.relayClientToUpstream(slot),
            .mask_relaying => self.relayRawClientToUpstream(slot),
            else => {},
        }
    }

    fn onClientWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (flushClientPending(slot)) |written| {
            if (written > 0) slot.last_activity_ms = compat.monotonicMilliTimestamp();
        } else |err| {
            log.debug("[{d}] client flush error: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "client flush error");
            return;
        }
        if (slot.relay_half_closed and slot.upstream_detached and !slot.hasClientPending()) {
            self.closeSlot(slot, "relay drained after upstream half-close");
            return;
        }

        switch (slot.phase) {
            .writing_server_hello_first => {
                if (!slot.hasClientPending()) {
                    slot.phase = .desync_wait;
                    slot.desync_deadline_ns = self.desyncSplitDeadlineNs();
                }
            },
            .writing_server_hello_rest => {
                if (!slot.hasClientPending()) {
                    if (slot.server_hello) |buf| {
                        secureFree(self.state.allocator, buf);
                        slot.server_hello = null;
                    }
                    slot.phase = .reading_mtproto_tls_header;
                    slot.tls_hdr_pos = 0;
                    slot.tls_body_len = 0;
                    slot.tls_body_pos = 0;
                }
            },
            else => {},
        }
    }

    fn onUpstreamReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = compat.monotonicMilliTimestamp();

        switch (slot.phase) {
            .middle_proxy_handshake => self.middleProxyOnReadable(slot),
            .relaying => self.relayUpstreamToClient(slot),
            .mask_relaying => self.relayRawUpstreamToClient(slot),
            else => {},
        }
    }

    fn onUpstreamWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        switch (slot.phase) {
            .connecting_upstream => self.onUpstreamConnectComplete(slot),
            .writing_dc_nonce, .relaying, .mask_relaying, .middle_proxy_handshake => {
                if (flushUpstreamPending(slot)) |written| {
                    if (written > 0) slot.last_activity_ms = compat.monotonicMilliTimestamp();
                } else |err| {
                    log.debug("[{d}] upstream flush error: {any}", .{ slot.conn_id, err });
                    if (slot.phase == .middle_proxy_handshake and self.fallbackFromMiddleProxyToDirect(slot)) return;
                    self.closeSlot(slot, "upstream flush error");
                    return;
                }
                if (slot.relay_half_closed and slot.client_detached and !slot.hasUpstreamPending()) {
                    self.closeSlot(slot, "relay drained after client half-close");
                    return;
                }

                if (slot.phase == .writing_dc_nonce and !slot.hasUpstreamPending()) {
                    self.onDcNonceWritable(slot);
                    if (slot.phase == .idle) return;
                }

                if (slot.phase == .middle_proxy_handshake) {
                    self.middleProxyOnWritable(slot);
                }

                // If middle-proxy handshake failed and switched to fallback direct path,
                // immediately start direct DC nonce sequence on the same connected fd.
                if (slot.phase == .writing_dc_nonce and !slot.hasUpstreamPending()) {
                    self.onDcNonceWritable(slot);
                }
            },
            else => {},
        }
    }

    fn onDcNonceWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.dc_initial_tail) |tail| {
            if (queueUpstream(slot, tail)) |_| {
                secureFree(self.state.allocator, tail);
                slot.dc_initial_tail = null;
            } else |err| {
                log.debug("[{d}] dc tail write error: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "dc tail write error");
                return;
            }
        }

        if (!slot.hasUpstreamPending() and slot.dc_initial_tail == null) {
            self.startRelay(slot);
        }
    }

    /// Charge the bounded handshake budget only after a client actually starts
    /// sending data. This prevents silent TCP sessions from starving real
    /// handshakes while preserving the existing 30%-of-capacity churn limit.
    fn reserveHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) bool {
        if (slot.hs_counted) return true;

        const hs_inflight = self.state.handshakes_inflight.fetchAdd(1, .monotonic);
        const hs_max = (self.state.config.max_connections * 3) / 10;
        if (hs_max > 0 and hs_inflight >= hs_max) {
            _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
            _ = self.state.stats_dropped_hs_budget.fetchAdd(1, .monotonic);
            return false;
        }

        slot.hs_counted = true;
        return true;
    }

    /// Release a reserved handshake-budget slot exactly once. Relay and mask
    /// completion can release it early; all error paths funnel through closeSlot.
    fn releaseHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.hs_counted) return;
        _ = self.state.handshakes_inflight.fetchSub(1, .monotonic);
        slot.hs_counted = false;
    }

    fn releaseSubnetHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.subnet_hs_counted) return;
        self.subnet_handshakes.release(slot.subnet_key);
        slot.subnet_hs_counted = false;
        slot.subnet_key = 0;
    }

    fn readTlsHeader(self: *EventLoop, slot: *ConnectionSlot) void {
        while (slot.tls_hdr_pos < tls_header_len) {
            const n = posix.read(slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "tls header read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof before tls header");
                return;
            }
            if (slot.first_byte_at_ms == 0) {
                slot.first_byte_at_ms = compat.monotonicMilliTimestamp();
                if (!self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
        }

        if (!tls.isTlsHandshake(slot.tls_hdr_buf[0..])) {
            self.startMasking(slot, slot.tls_hdr_buf[0..]) catch {
                self.closeSlot(slot, "non-tls masked failed");
            };
            return;
        }

        const record_len = std.mem.readInt(u16, slot.tls_hdr_buf[3..5], .big);
        if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
            self.startMasking(slot, slot.tls_hdr_buf[0..]) catch {
                self.closeSlot(slot, "bad tls length");
            };
            return;
        }

        slot.client_hello_len = tls_header_len + record_len;
        if (slot.client_hello_len > slot.client_hello_inline.len) {
            slot.client_hello_heap = self.state.allocator.alloc(u8, slot.client_hello_len) catch {
                self.closeSlot(slot, "client_hello alloc failed");
                return;
            };
        }

        const hello_buf = slot.clientHelloBuf();
        @memcpy(hello_buf[0..tls_header_len], slot.tls_hdr_buf[0..]);
        slot.tls_body_len = @intCast(record_len);
        slot.tls_body_pos = 0;
        slot.phase = .reading_client_hello_body;
    }

    fn readClientHelloBody(self: *EventLoop, slot: *ConnectionSlot) void {
        const hello_buf = slot.clientHelloBuf();

        while (slot.tls_body_pos < slot.tls_body_len) {
            const off = tls_header_len + slot.tls_body_pos;
            const end = tls_header_len + slot.tls_body_len;
            const n = posix.read(slot.client_fd, hello_buf[off..end]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "client hello body read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof during client hello");
                return;
            }
            slot.tls_body_pos += @intCast(n);
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
        }

        const client_hello = hello_buf[0..slot.client_hello_len];

        const maybe_sni = tls.extractSni(client_hello);
        if (maybe_sni == null) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls missing sni");
            };
            return;
        }

        const sni = maybe_sni.?;
        if (!std.ascii.eqlIgnoreCase(sni, self.state.config.tls_domain)) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls sni mismatch");
            };
            return;
        }

        const validation = tls.validateTlsHandshake(
            self.state.allocator,
            client_hello,
            self.state.user_secrets,
            false,
        ) catch null;

        if (validation == null) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "tls validation failed");
            };
            return;
        }

        const v = validation.?;
        if (self.state.replay_cache.checkAndInsert(&v.canonical_hmac)) {
            self.startMasking(slot, client_hello) catch {
                self.closeSlot(slot, "replay detected, masking failed");
            };
            return;
        }

        slot.validation_secret = v.secret;
        slot.validation_digest = v.digest;
        slot.validation_session_id = v.session_id;
        slot.validation_session_id_len = @intCast(v.session_id.len);
        const ulen = @min(v.user.len, slot.validation_user.len);
        slot.validation_user_len = @intCast(ulen);
        @memcpy(slot.validation_user[0..ulen], v.user[0..ulen]);
        slot.validation_force_direct = self.state.config.userBypassesMiddleProxy(v.user);

        const offers_pq = tls.clientOffersPqKeyShare(client_hello);
        const echoed_cipher = tls.extractFirstTls13Cipher(client_hello);
        const cipher_label = if (echoed_cipher) |cs| switch (cs) {
            0x1301 => "0x1301",
            0x1302 => "0x1302",
            0x1303 => "0x1303",
            else => "unknown",
        } else "none";
        log.debug("[{d}] valid FakeTLS ClientHello: key_share={s} cipher={s}", .{
            slot.conn_id,
            if (offers_pq) "X25519MLKEM768(0x11ec)" else "x25519(0x001d)",
            cipher_label,
        });

        slot.server_hello = (if (offers_pq)
            tls.buildServerHelloPq(
                self.state.allocator,
                &slot.validation_secret,
                &slot.validation_digest,
                slot.validation_session_id[0..slot.validation_session_id_len],
                echoed_cipher,
                self.state.tls_server_hello_template.len - tls.server_hello_prefix_len,
            )
        else
            tls.buildServerHelloWithTemplateCipher(
                self.state.allocator,
                self.state.tls_server_hello_template,
                &slot.validation_secret,
                &slot.validation_digest,
                slot.validation_session_id[0..slot.validation_session_id_len],
                echoed_cipher,
            )) catch {
            self.closeSlot(slot, "build server hello failed");
            return;
        };
        slot.server_hello_off = 0;
        slot.releaseClientHello(self.state.allocator);

        if (self.state.config.desync and slot.server_hello.?.len > 1) {
            slot.phase = .writing_server_hello_first;
            const one = slot.server_hello.?[0..1];
            if (queueClient(slot, one)) |_| {} else |_| {
                self.closeSlot(slot, "queue first desync byte failed");
                return;
            }
            slot.server_hello_off = 1;
        } else {
            slot.phase = .writing_server_hello_rest;
            if (queueClient(slot, slot.server_hello.?)) |_| {} else |_| {
                self.closeSlot(slot, "queue server hello failed");
                return;
            }
            slot.server_hello_off = slot.server_hello.?.len;
        }
    }

    fn readMtprotoHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        // Phase pair: read TLS header then body, reusing tls_* fields.
        var control_records: usize = 0;
        var control_bytes: usize = 0;
        while (true) {
            if (slot.phase == .reading_mtproto_tls_header) {
                while (slot.tls_hdr_pos < tls_header_len) {
                    const n = posix.read(slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
                        if (err == error.WouldBlock) return;
                        self.closeSlot(slot, "mtproto tls hdr read error");
                        return;
                    };
                    if (n == 0) {
                        self.closeSlot(slot, "client eof waiting mtproto hdr");
                        return;
                    }
                    slot.tls_hdr_pos += @intCast(n);
                }

                slot.tls_record_type = slot.tls_hdr_buf[0];
                slot.tls_body_len = std.mem.readInt(u16, slot.tls_hdr_buf[3..5], .big);
                slot.tls_body_pos = 0;

                if (slot.tls_record_type == constants.tls_record_alert) {
                    self.closeSlot(slot, "tls alert during mtproto handshake");
                    return;
                }

                if (slot.tls_record_type != constants.tls_record_change_cipher and
                    slot.tls_record_type != constants.tls_record_application)
                {
                    self.closeSlot(slot, "unexpected tls record type in mtproto handshake");
                    return;
                }
                if (slot.tls_body_len == 0 or slot.tls_body_len > constants.max_tls_ciphertext_size) {
                    self.closeSlot(slot, "bad mtproto tls body size");
                    return;
                }

                slot.phase = .reading_mtproto_tls_body;
            }

            if (slot.phase != .reading_mtproto_tls_body) return;

            const remaining: usize = slot.tls_body_len - slot.tls_body_pos;
            if (remaining == 0) {
                slot.tls_hdr_pos = 0;
                slot.phase = .reading_mtproto_tls_header;
                if (slot.handshake_pos >= constants.handshake_len) {
                    self.finishClientHandshake(slot);
                    return;
                }
                continue;
            }

            const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
                self.closeSlot(slot, "alloc read buffer failed");
                return;
            };
            const want = @min(remaining, read_buf.len);
            const n = posix.read(slot.client_fd, read_buf[0..want]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "mtproto tls body read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof waiting mtproto body");
                return;
            }

            slot.tls_body_pos += @intCast(n);
            control_bytes += n;

            if (slot.tls_record_type == constants.tls_record_change_cipher) {
                // discard body
            } else {
                var off: usize = 0;
                while (off < n) {
                    if (slot.handshake_pos < constants.handshake_len) {
                        const need = constants.handshake_len - slot.handshake_pos;
                        const take = @min(need, n - off);
                        @memcpy(slot.handshake_buf[slot.handshake_pos .. slot.handshake_pos + take], read_buf[off .. off + take]);
                        slot.handshake_pos += @intCast(take);
                        off += take;
                    } else {
                        const extra = read_buf[off..n];
                        self.appendPipelined(slot, extra) catch {
                            self.closeSlot(slot, "pipelined append failed");
                            return;
                        };
                        off = n;
                    }
                }
            }

            if (slot.tls_body_pos == slot.tls_body_len) {
                if (slot.tls_record_type == constants.tls_record_change_cipher) {
                    control_records += 1;
                }
                slot.tls_hdr_pos = 0;
                slot.phase = .reading_mtproto_tls_header;
                if (slot.handshake_pos >= constants.handshake_len) {
                    self.finishClientHandshake(slot);
                    return;
                }
                if (control_records >= tls_control_record_budget or control_bytes >= tls_control_byte_budget) {
                    return;
                }
            }
        }
    }

    fn finishClientHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        const known_secret = [_]obfuscation.UserSecret{.{
            .name = slot.validation_user[0..slot.validation_user_len],
            .secret = slot.validation_secret,
        }};
        const result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, &known_secret) orelse {
            self.closeSlot(slot, "bad mtproto obfuscation handshake");
            return;
        };

        slot.obf_params = result.params;
        slot.proto_tag = result.params.proto_tag;
        slot.dc_idx = result.params.dc_idx;
        slot.client_decryptor = result.params.createDecryptor();
        slot.client_encryptor = result.params.createEncryptor();
        if (slot.client_decryptor) |*dec| dec.ctr +%= 4;

        const dc_idx_wide: i32 = slot.dc_idx;
        const dc_abs_wide = if (dc_idx_wide < 0) -dc_idx_wide else dc_idx_wide;
        if (dc_abs_wide == 0) {
            self.closeSlot(slot, "invalid dc index");
            return;
        }
        const dc_abs: usize = @intCast(dc_abs_wide);
        if (!constants.isKnownDcV4(dc_abs)) {
            self.closeSlot(slot, "unsupported datacenter index");
            return;
        }

        var snapshot = if (shouldUseMiddleProxySnapshot(&self.state.config, dc_abs, slot.dc_idx))
            self.state.getMiddleProxySnapshot()
        else
            null;
        defer if (snapshot) |*snap| std.crypto.secureZero(u8, &snap.secret);

        const plan = buildDcConnectPlan(&self.state.config, dc_abs, slot.dc_idx, if (snapshot) |*s| s else null, slot.validation_force_direct);
        if (plan.count == 0) {
            self.closeSlot(slot, "no upstream candidates");
            return;
        }

        slot.dc_abs = @intCast(dc_abs);
        slot.use_middle_proxy = plan.use_middle_proxy;
        slot.is_media_path = plan.is_media_path;
        slot.use_fast_mode = self.state.config.fast_mode and !slot.use_middle_proxy and (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
        slot.direct_fallback_addr = plan.direct_fallback;
        slot.direct_fallback_used = false;
        if (plan.use_middle_proxy) {
            const snap = if (snapshot) |*s| s else {
                self.closeSlot(slot, "missing middle-proxy snapshot");
                return;
            };
            if (snap.secret_len < 4 or snap.secret_len > slot.mp_secret.len) {
                self.closeSlot(slot, "invalid middle-proxy secret snapshot");
                return;
            }
            @memcpy(slot.mp_secret[0..snap.secret_len], snap.secret[0..snap.secret_len]);
            slot.mp_secret_len = snap.secret_len;
            slot.mp_nat_ip4 = snap.nat_ip4;
        }

        // Log DC routing decisions at debug level (enable with log_level = "debug" in config)
        if (plan.is_media_path) {
            var addr_buf: [64]u8 = undefined;
            const addr_str = formatAddress(plan.candidates[0], &addr_buf);
            log.debug("[{d}] route: dc_idx={d} dc_abs={d} media={} middle_proxy={} candidates={d} -> {s}", .{
                slot.conn_id,
                slot.dc_idx,
                dc_abs,
                plan.is_media_path,
                plan.use_middle_proxy,
                plan.count,
                addr_str,
            });
        }

        if (slot.upstream_candidates) |old| {
            self.state.allocator.free(old);
            slot.upstream_candidates = null;
        }

        slot.upstream_candidates = self.state.allocator.alloc(net.Address, plan.count) catch {
            self.closeSlot(slot, "alloc upstream candidate list failed");
            return;
        };
        const candidates = slot.upstream_candidates.?;
        var idx: usize = 0;
        while (idx < candidates.len) : (idx += 1) {
            candidates[idx] = plan.candidates[idx];
        }
        slot.upstream_candidate_next = 1;
        slot.current_upstream_addr = candidates[0];

        const first_addr = candidates[0];
        self.startConnectUpstream(slot, first_addr, .dc) catch |err| {
            if (self.tryNextDcEndpoint(slot, err, first_addr)) return;
            self.closeSlot(slot, "upstream connect start failed");
        };
    }

    fn startMasking(self: *EventLoop, slot: *ConnectionSlot, buffered: []const u8) !void {
        if (!self.state.config.mask) return error.MaskingDisabled;
        self.state.middle_proxy_lock.lock();
        const candidates = self.state.allocator.dupe(net.Address, self.state.mask_addrs) catch |err| {
            self.state.middle_proxy_lock.unlock();
            return err;
        };
        self.state.middle_proxy_lock.unlock();
        if (candidates.len == 0) {
            self.state.allocator.free(candidates);
            return error.NoMaskAddress;
        }

        const pre = self.state.allocator.alloc(u8, buffered.len) catch |err| {
            self.state.allocator.free(candidates);
            return err;
        };
        @memcpy(pre, buffered);
        slot.mask_prebuffer = pre;

        slot.upstream_candidates = candidates;
        slot.upstream_candidate_next = 1;
        const first = slot.upstream_candidates.?[0];
        self.startConnectUpstream(slot, first, .mask) catch |err| {
            if (self.tryNextMaskEndpoint(slot, err, first)) return;
            return err;
        };
    }

    fn upstreamConnectDeadlineMs(self: *EventLoop, slot: *const ConnectionSlot, started_at_ms: i64) i64 {
        const configured_timeout_ms = secondsToMs(self.state.config.dc_connect_timeout_sec);
        if (configured_timeout_ms <= 0) return 0;

        const candidate_count = if (slot.upstream_candidates) |candidates| blk: {
            const next_index = @min(@as(usize, @intCast(slot.upstream_candidate_next)), candidates.len);
            break :blk candidates.len - next_index + 1;
        } else 1;
        const attempt_timeout_ms = budgetedConnectTimeoutMs(
            configured_timeout_ms,
            slot.first_byte_at_ms,
            secondsToMs(self.state.config.handshake_timeout_sec),
            started_at_ms,
            candidate_count,
        );
        return started_at_ms + attempt_timeout_ms;
    }

    fn startConnectUpstream(self: *EventLoop, slot: *ConnectionSlot, addr: net.Address, kind: UpstreamKind) !void {
        const fd = try socketTcpNonblocking(addr.any.family);
        errdefer closeFd(fd);

        try self.addFd(fd, false, true);
        errdefer _ = self.delFd(fd) catch {};

        try self.pool.mapFd(fd, slot.index);
        errdefer self.pool.unmapFd(fd);

        slot.upstream_fd = fd;
        slot.upstream_interest_in = false;
        slot.upstream_interest_out = true;
        slot.upstream_kind = kind;
        slot.current_upstream_addr = addr;
        slot.phase = .connecting_upstream;
        slot.upstream_connect_started_ms = compat.monotonicMilliTimestamp();
        slot.upstream_connect_deadline_ms = self.upstreamConnectDeadlineMs(slot, slot.upstream_connect_started_ms);
        errdefer {
            slot.upstream_fd = invalid_fd;
            slot.upstream_kind = .none;
            slot.current_upstream_addr = null;
            slot.upstream_connect_started_ms = 0;
            slot.upstream_connect_deadline_ms = 0;
        }

        connectFd(fd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => return,
            else => return err,
        };

        self.onUpstreamConnectComplete(slot);
    }

    fn onUpstreamConnectComplete(self: *EventLoop, slot: *ConnectionSlot) void {
        if (getsockoptErrorFd(slot.upstream_fd)) |_| {} else |err| {
            const failed_kind = slot.upstream_kind;
            const failed_addr = slot.current_upstream_addr;
            self.cleanupFailedUpstreamConnect(slot);

            if (failed_kind == .dc and self.tryNextDcEndpoint(slot, err, failed_addr)) {
                return;
            }
            if (failed_kind == .mask and self.tryNextMaskEndpoint(slot, err, failed_addr)) {
                return;
            }

            log.debug("[{d}] connect completion failed: dc_idx={d} media={} err={any}", .{
                slot.conn_id,
                slot.dc_idx,
                slot.is_media_path,
                err,
            });
            self.closeSlot(slot, "connect failed");
            return;
        }

        configureRelaySocket(slot.client_fd);
        configureRelaySocket(slot.upstream_fd);
        slot.upstream_connect_started_ms = 0;
        slot.upstream_connect_deadline_ms = 0;

        if (slot.upstream_kind == .mask) {
            if (slot.mask_prebuffer) |pre| {
                if (queueUpstream(slot, pre)) |_| {
                    secureFree(self.state.allocator, pre);
                    slot.mask_prebuffer = null;
                } else |err| {
                    log.debug("[{d}] queue mask prebuffer failed: {any}", .{ slot.conn_id, err });
                    self.closeSlot(slot, "mask prebuffer failed");
                    return;
                }
            }
            // Handshake complete (mask path) — release from handshake budget.
            self.releaseHandshakeBudget(slot);
            slot.phase = .mask_relaying;
            return;
        }

        if (slot.use_middle_proxy) {
            self.middleProxyBegin(slot);
            return;
        }

        self.sendDcNonce(slot);
    }

    fn desyncSplitDeadlineNs(self: *EventLoop) i128 {
        var delay_ms: u64 = self.state.config.desync_split_delay_ms;
        const jitter_ms = self.state.config.desync_split_jitter_ms;
        if (jitter_ms > 0) {
            delay_ms += crypto.randomRange(u64, @as(u64, jitter_ms) + 1);
        }
        return compat.monotonicNanoTimestamp() + (@as(i128, @intCast(delay_ms)) * std.time.ns_per_ms);
    }

    fn cleanupFailedUpstreamConnect(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!isInvalidFd(slot.upstream_fd)) {
            const fd = slot.upstream_fd;
            _ = self.delFd(fd) catch {};
            self.pool.unmapFd(fd);
            self.deferClose(fd);
            slot.upstream_fd = invalid_fd;
        }
        slot.upstream_kind = .none;
        slot.current_upstream_addr = null;
        slot.upstream_connect_started_ms = 0;
        slot.upstream_connect_deadline_ms = 0;
        slot.upstream_detached = false;
        slot.upstream_interest_in = false;
        slot.upstream_interest_out = false;
        slot.upstream_queue.clear();
    }

    fn tryNextDcEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror, attempt_addr: ?net.Address) bool {
        const candidates = slot.upstream_candidates orelse return false;
        const candidate_count = slotCandidateCount(slot);

        if (slot.use_middle_proxy) {
            if (attempt_addr) |addr| {
                if (self.state.cooldownMiddleProxyCandidate(addr)) {
                    log.info("[{d}] cooling failed middle-proxy endpoint for {d}s: dc_idx={d}", .{
                        slot.conn_id,
                        60,
                        slot.dc_idx,
                    });
                }
            }
        }

        if (slot.upstream_candidate_next < candidates.len) {
            const next_idx = slot.upstream_candidate_next;
            const next_addr = candidates[next_idx];
            slot.upstream_candidate_next += 1;
            self.startConnectUpstream(slot, next_addr, .dc) catch |next_err| {
                log.warn("[{d}] dc connect candidate {d}/{d} failed immediately: {any}", .{
                    slot.conn_id,
                    next_idx + 1,
                    candidate_count,
                    next_err,
                });
                return self.tryNextDcEndpoint(slot, next_err, next_addr);
            };

            if (attempt_addr) |addr| {
                var prev_buf: [64]u8 = undefined;
                const prev_str = formatAddress(addr, &prev_buf);
                log.warn("[{d}] dc connect failed ({any}), retry candidate {d}/{d} after {s}", .{
                    slot.conn_id,
                    err,
                    next_idx + 1,
                    candidate_count,
                    prev_str,
                });
            }
            return true;
        }

        if (!slot.direct_fallback_used and slot.direct_fallback_addr != null and slot.use_middle_proxy) {
            slot.direct_fallback_used = true;
            slot.use_middle_proxy = false;
            const fallback = slot.direct_fallback_addr.?;
            slot.upstream_candidate_next = 1;

            if (slot.upstream_candidates) |old| {
                self.state.allocator.free(old);
                slot.upstream_candidates = null;
            }
            const one = self.state.allocator.alloc(net.Address, 1) catch {
                return false;
            };
            one[0] = fallback;
            slot.upstream_candidates = one;

            self.startConnectUpstream(slot, fallback, .dc) catch |fallback_err| {
                log.warn("[{d}] direct fallback connect failed: {any}", .{ slot.conn_id, fallback_err });
                return false;
            };

            var fb_buf: [64]u8 = undefined;
            const fb_str = formatAddress(fallback, &fb_buf);
            log.warn("[{d}] middle-proxy dc={d} exhausted after {d} candidate(s) ({any}), fallback to direct {s}", .{
                slot.conn_id,
                slot.dc_idx,
                candidate_count,
                err,
                fb_str,
            });
            return true;
        }

        if (slot.is_media_path) {
            log.warn("[{d}] media path connect failed after all candidates: {any}", .{ slot.conn_id, err });
        }
        return false;
    }

    fn tryNextMaskEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror, attempt_addr: ?net.Address) bool {
        const candidates = slot.upstream_candidates orelse return false;
        if (slot.upstream_candidate_next >= candidates.len) return false;

        const next_idx = slot.upstream_candidate_next;
        const next_addr = candidates[next_idx];
        slot.upstream_candidate_next += 1;
        self.startConnectUpstream(slot, next_addr, .mask) catch |next_err| {
            return self.tryNextMaskEndpoint(slot, next_err, next_addr);
        };

        if (attempt_addr) |addr| {
            var prev_buf: [64]u8 = undefined;
            log.debug("[{d}] mask connect failed ({any}), retry candidate {d}/{d} after {s}", .{
                slot.conn_id,
                err,
                next_idx + 1,
                candidates.len,
                formatAddress(addr, &prev_buf),
            });
        }
        return true;
    }

    fn sendDcNonce(self: *EventLoop, slot: *ConnectionSlot) void {
        const params = slot.obf_params orelse {
            self.closeSlot(slot, "missing obfuscation params");
            return;
        };

        var tg_nonce = obfuscation.generateNonce();
        defer std.crypto.secureZero(u8, &tg_nonce);

        if (slot.use_fast_mode) {
            var client_s2c_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &client_s2c_key_iv);
            @memcpy(client_s2c_key_iv[0..constants.key_len], &params.encrypt_key);
            std.mem.writeInt(u128, client_s2c_key_iv[constants.key_len..][0..constants.iv_len], params.encrypt_iv, .big);
            obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, &client_s2c_key_iv);
        } else {
            obfuscation.prepareTgNonce(&tg_nonce, params.proto_tag, null);
        }

        std.mem.writeInt(i16, tg_nonce[constants.dc_idx_pos..][0..2], params.dc_idx, .little);

        const tg_enc_key_iv = tg_nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len];
        var tg_enc_key: [constants.key_len]u8 = tg_enc_key_iv[0..constants.key_len].*;
        defer std.crypto.secureZero(u8, &tg_enc_key);
        var tg_enc_iv_bytes: [constants.iv_len]u8 = tg_enc_key_iv[constants.key_len..][0..constants.iv_len].*;
        defer std.crypto.secureZero(u8, &tg_enc_iv_bytes);
        const tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);

        var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &tg_dec_key_iv);
        for (0..tg_enc_key_iv.len) |i| {
            tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
        }
        var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
        defer std.crypto.secureZero(u8, &tg_dec_key);
        const tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);

        var tg_encryptor = crypto.AesCtr.init(&tg_enc_key, tg_enc_iv);
        defer tg_encryptor.wipe();
        var encrypted_nonce: [constants.handshake_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &encrypted_nonce);
        @memcpy(&encrypted_nonce, &tg_nonce);
        tg_encryptor.apply(&encrypted_nonce);

        var nonce_to_send: [constants.handshake_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &nonce_to_send);
        @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
        @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

        if (queueUpstream(slot, &nonce_to_send)) |_| {} else |err| {
            log.debug("[{d}] queue dc nonce failed: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "queue dc nonce failed");
            return;
        }

        // Promotion tag (optional), only for primary DC1..5
        if (self.state.config.tag) |tag| {
            const dc_abs: usize = slot.dc_abs;
            if (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len and dc_abs != 203) {
                var promote_buf: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &promote_buf);
                var packet_len: usize = 0;

                const rpc_id: u32 = 0xaeaf0c42;
                var rpc_payload: [20]u8 = undefined;
                defer std.crypto.secureZero(u8, &rpc_payload);
                std.mem.writeInt(u32, rpc_payload[0..4], rpc_id, .little);
                @memcpy(rpc_payload[4..20], &tag);

                switch (params.proto_tag) {
                    .abridged => {
                        promote_buf[0] = 5;
                        @memcpy(promote_buf[1..21], &rpc_payload);
                        packet_len = 21;
                    },
                    .intermediate, .secure => {
                        std.mem.writeInt(u32, promote_buf[0..4], 20, .little);
                        @memcpy(promote_buf[4..24], &rpc_payload);
                        packet_len = 24;
                    },
                }

                const tail = self.state.allocator.alloc(u8, packet_len) catch {
                    self.closeSlot(slot, "alloc promotion tail failed");
                    return;
                };
                @memcpy(tail, promote_buf[0..packet_len]);
                tg_encryptor.apply(tail);
                slot.dc_initial_tail = tail;
            }
        }

        slot.tg_encryptor = tg_encryptor;
        slot.tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
        slot.phase = .writing_dc_nonce;
    }

    fn startRelay(self: *EventLoop, slot: *ConnectionSlot) void {
        // Handshake complete — release from handshake budget.
        self.releaseHandshakeBudget(slot);
        self.releaseSubnetHandshake(slot);
        slot.phase = .relaying;

        if (slot.pipelined_data) |buf| {
            const data = buf[0..slot.pipelined_len];
            if (slot.client_decryptor) |*dec| dec.apply(data);

            if (slot.middle_ctx) |*mp| {
                const required = mp.requiredC2sScratchCapacity(data) catch |err| {
                    log.debug("[{d}] middleproxy pipelined scratch sizing failed: proto={s} pipelined={d} buffered={d} err={any}", .{
                        slot.conn_id,
                        @tagName(slot.proto_tag),
                        data.len,
                        mp.c2s_len,
                        err,
                    });
                    self.closeSlot(slot, "compute middleproxy pipelined scratch failed");
                    return;
                };
                const scratch = self.ensureMpC2sScratch(required) catch {
                    self.closeSlot(slot, "alloc middleproxy c2s scratch failed");
                    return;
                };
                const out_data = mp.encapsulateC2S(data, scratch) catch {
                    self.closeSlot(slot, "encapsulate pipelined middleproxy payload failed");
                    return;
                };
                if (out_data.len > 0) {
                    _ = queueUpstream(slot, out_data) catch {
                        self.closeSlot(slot, "queue pipelined middleproxy payload failed");
                        return;
                    };
                }
            } else if (slot.tg_encryptor) |*enc| {
                enc.apply(data);
                _ = queueUpstream(slot, data) catch {
                    self.closeSlot(slot, "queue pipelined direct payload failed");
                    return;
                };
            }

            slot.c2s_bytes += data.len;
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
            slot.last_client_byte_ms = slot.last_activity_ms;
            secureFree(self.state.allocator, buf);
            slot.pipelined_data = null;
            slot.pipelined_len = 0;
        }
    }

    fn relayClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const progress = relayClientToUpstreamStep(self, slot) catch |err| {
            if (slot.is_media_path) {
                log.debug("[{d}] relay c2s error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                    slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                });
            }
            self.closeSlot(slot, "relay c2s failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
            slot.last_client_byte_ms = slot.last_activity_ms;
        }
    }

    fn relayUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const progress = relayUpstreamToClientStep(self, slot) catch |err| {
            if (slot.is_media_path) {
                log.debug("[{d}] relay s2c error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                    slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                });
            }
            self.closeSlot(slot, "relay s2c failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
            slot.last_server_byte_ms = slot.last_activity_ms;
        }
    }

    fn relayRawClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "mask read buffer alloc failed");
            return;
        };

        const n = posix.read(slot.client_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "mask client read failed");
            return;
        };
        if (n == 0) {
            self.closeSlot(slot, "mask client eof");
            return;
        }

        _ = queueUpstream(slot, read_buf[0..n]) catch {
            self.closeSlot(slot, "mask queue upstream failed");
            return;
        };
    }

    fn relayRawUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "mask upstream read buffer alloc failed");
            return;
        };

        const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "mask upstream read failed");
            return;
        };
        if (n == 0) {
            self.closeSlot(slot, "mask upstream eof");
            return;
        }

        _ = queueClient(slot, read_buf[0..n]) catch {
            self.closeSlot(slot, "mask queue client failed");
            return;
        };
    }

    fn middleProxyBegin(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.phase = .middle_proxy_handshake;
        self.setMiddleProxyStep(slot, .sending_rpc_nonce);
        slot.mp_write_seq_no = -2;
        slot.mp_read_seq_no = -2;
        slot.mp_frame_have = 0;
        slot.mp_frame_need = 0;
        slot.mp_enc = null;
        slot.mp_dec = null;

        crypto.randomBytes(&slot.mp_nonce);
        const ts: u32 = @intCast(@mod(compat.timestamp(), 4294967296));
        slot.mp_timestamp = ts;

        var crypto_ts: [4]u8 = undefined;
        std.mem.writeInt(u32, &crypto_ts, ts, .little);

        var msg: [32]u8 = undefined;
        @memcpy(msg[0..4], &middleproxy.rpc_nonce_req);
        @memset(msg[4..8], 0);
        if (slot.mp_secret_len < 4) {
            if (!self.fallbackFromMiddleProxyToDirect(slot)) self.closeSlot(slot, "missing middle-proxy secret snapshot");
            return;
        }
        @memcpy(msg[4..8], slot.mp_secret[0..4]);
        @memcpy(msg[8..12], &middleproxy.rpc_crypto_aes);
        @memcpy(msg[12..16], &crypto_ts);
        @memcpy(msg[16..32], &slot.mp_nonce);

        self.mpWriteFrame(slot, msg[0..], false) catch {
            if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                self.closeSlot(slot, "mp send nonce failed");
            }
            return;
        };

        if (!slot.hasUpstreamPending()) {
            self.setMiddleProxyStep(slot, .waiting_rpc_nonce_response);
            mpReadReset(slot, false);
        }
    }

    fn middleProxyOnWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        switch (slot.mp_step) {
            .sending_rpc_nonce => {
                self.setMiddleProxyStep(slot, .waiting_rpc_nonce_response);
                mpReadReset(slot, false);
            },
            .sending_rpc_handshake => {
                self.setMiddleProxyStep(slot, .waiting_rpc_handshake_response);
                mpReadReset(slot, true);
            },
            else => {},
        }
    }

    fn middleProxyOnReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        switch (slot.mp_step) {
            .waiting_rpc_nonce_response => {
                const payload = self.mpTryReadFrame(slot, false) catch |err| {
                    log.debug("[{d}] mp nonce frame read failed: {any}", .{ slot.conn_id, err });
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp read nonce ans failed");
                    }
                    return;
                } orelse return;

                if (payload.len != 32) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad nonce ans len");
                    }
                    return;
                }
                if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_nonce_req)) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad nonce ans type");
                    }
                    return;
                }

                var enc_keys: struct { [32]u8, [16]u8 } = undefined;
                var dec_keys: struct { [32]u8, [16]u8 } = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&enc_keys));
                defer std.crypto.secureZero(u8, std.mem.asBytes(&dec_keys));
                var middle_local_addr: net.Address = undefined;
                const mp_handshake_error: ?[]const u8 = handshake: {
                    const key_sel = slot.mp_secret[0..4];
                    const secret_slice = slot.mp_secret[0..slot.mp_secret_len];
                    if (!std.mem.eql(u8, payload[4..8], key_sel)) {
                        break :handshake "mp key selector mismatch";
                    }
                    if (!std.mem.eql(u8, payload[8..12], &middleproxy.rpc_crypto_aes)) {
                        break :handshake "mp crypto schema mismatch";
                    }

                    slot.mp_rpc_nonce_ans = payload[16..32][0..16].*;

                    var ts_arr: [4]u8 = undefined;
                    std.mem.writeInt(u32, &ts_arr, slot.mp_timestamp, .little);

                    var peer_addr: net.Address = undefined;
                    var peer_len: posix.socklen_t = @sizeOf(net.Address);
                    getpeernameFd(slot.upstream_fd, &peer_addr.any, &peer_len) catch {
                        break :handshake "mp getpeername failed";
                    };

                    var local_addr: net.Address = undefined;
                    var local_len: posix.socklen_t = @sizeOf(net.Address);
                    getsocknameFd(slot.upstream_fd, &local_addr.any, &local_len) catch {
                        break :handshake "mp getsockname failed";
                    };
                    middle_local_addr = local_addr;

                    var tg_port: [2]u8 = undefined;
                    var my_port: [2]u8 = undefined;
                    var tg_ip_v4_opt: ?[4]u8 = null;
                    var my_ip_v4_opt: ?[4]u8 = null;
                    var tg_ip_v6_opt: ?[16]u8 = null;
                    var my_ip_v6_opt: ?[16]u8 = null;

                    if (peer_addr.any.family == posix.AF.INET and local_addr.any.family == posix.AF.INET) {
                        tg_ip_v4_opt = ipv4AddressBytesForMiddleProxyKdf(peer_addr);
                        var my_ip_v4 = ipv4AddressBytesForMiddleProxyKdf(local_addr);

                        if (slot.mp_nat_ip4) |nat_ip| {
                            my_ip_v4 = ipv4BytesForMiddleProxyKdf(nat_ip);
                            middle_local_addr = net.Address.initIp4(nat_ip, std.mem.bigToNative(u16, local_addr.in.sa.port));
                        }

                        my_ip_v4_opt = my_ip_v4;

                        std.mem.writeInt(u16, &tg_port, std.mem.bigToNative(u16, peer_addr.in.sa.port), .little);
                        std.mem.writeInt(u16, &my_port, std.mem.bigToNative(u16, local_addr.in.sa.port), .little);
                    } else if (peer_addr.any.family == posix.AF.INET6 and local_addr.any.family == posix.AF.INET6) {
                        var tg_ip_v6: [16]u8 = undefined;
                        @memcpy(&tg_ip_v6, &peer_addr.in6.sa.addr);
                        tg_ip_v6_opt = tg_ip_v6;

                        var my_ip_v6: [16]u8 = undefined;
                        @memcpy(&my_ip_v6, &local_addr.in6.sa.addr);
                        my_ip_v6_opt = my_ip_v6;

                        std.mem.writeInt(u16, &tg_port, std.mem.bigToNative(u16, peer_addr.in6.sa.port), .little);
                        std.mem.writeInt(u16, &my_port, std.mem.bigToNative(u16, local_addr.in6.sa.port), .little);
                    } else {
                        break :handshake "mp unsupported addr family";
                    }

                    const tg_ip_v4_ptr: ?*const [4]u8 = if (tg_ip_v4_opt) |*ip| ip else null;
                    const my_ip_v4_ptr: ?*const [4]u8 = if (my_ip_v4_opt) |*ip| ip else null;
                    const my_ip_v6_ptr: ?*const [16]u8 = if (my_ip_v6_opt) |*ip| ip else null;
                    const tg_ip_v6_ptr: ?*const [16]u8 = if (tg_ip_v6_opt) |*ip| ip else null;

                    enc_keys = middleproxy.getAesKeyAndIv(
                        &slot.mp_rpc_nonce_ans,
                        &slot.mp_nonce,
                        &ts_arr,
                        tg_ip_v4_ptr,
                        &my_port,
                        "CLIENT",
                        my_ip_v4_ptr,
                        &tg_port,
                        secret_slice,
                        my_ip_v6_ptr,
                        tg_ip_v6_ptr,
                    ) catch break :handshake "mp kdf input invalid";

                    dec_keys = middleproxy.getAesKeyAndIv(
                        &slot.mp_rpc_nonce_ans,
                        &slot.mp_nonce,
                        &ts_arr,
                        tg_ip_v4_ptr,
                        &my_port,
                        "SERVER",
                        my_ip_v4_ptr,
                        &tg_port,
                        secret_slice,
                        my_ip_v6_ptr,
                        tg_ip_v6_ptr,
                    ) catch break :handshake "mp kdf input invalid";

                    break :handshake null;
                };

                if (mp_handshake_error) |reason| {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, reason);
                    }
                    return;
                }

                slot.mp_enc = crypto.AesCbc.init(&enc_keys[0], &enc_keys[1]);
                slot.mp_dec = crypto.AesCbc.init(&dec_keys[0], &dec_keys[1]);

                var hs_msg: [32]u8 = undefined;
                @memcpy(hs_msg[0..4], &middleproxy.rpc_handshake);
                @memset(hs_msg[4..8], 0);
                @memcpy(hs_msg[8..20], "IPIPPRPDTIME");
                @memcpy(hs_msg[20..32], "IPIPPRPDTIME");

                self.mpWriteFrame(slot, hs_msg[0..], true) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp send handshake failed");
                    }
                    return;
                };

                self.setMiddleProxyStep(slot, if (slot.hasUpstreamPending()) .sending_rpc_handshake else .waiting_rpc_handshake_response);
                if (!slot.hasUpstreamPending()) {
                    mpReadReset(slot, true);
                }
            },

            .waiting_rpc_handshake_response => {
                const payload = self.mpTryReadFrame(slot, true) catch |err| {
                    log.debug("[{d}] mp handshake frame read failed: {any}", .{ slot.conn_id, err });
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp read handshake ans failed");
                    }
                    return;
                } orelse return;

                if (payload.len != 32) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake ans len");
                    }
                    return;
                }
                if (!std.mem.eql(u8, payload[0..4], &middleproxy.rpc_handshake)) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake ans type");
                    }
                    return;
                }
                if (!std.mem.eql(u8, payload[20..32], "IPIPPRPDTIME")) {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp bad handshake pid");
                    }
                    return;
                }

                var local_addr: net.Address = undefined;
                var local_len: posix.socklen_t = @sizeOf(net.Address);
                getsocknameFd(slot.upstream_fd, &local_addr.any, &local_len) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp getsockname failed");
                    }
                    return;
                };

                var middle_local_addr = local_addr;
                if (slot.mp_nat_ip4) |nat_ip| {
                    if (local_addr.any.family == posix.AF.INET) {
                        middle_local_addr = net.Address.initIp4(nat_ip, std.mem.bigToNative(u16, local_addr.in.sa.port));
                    }
                }

                var conn_id: [8]u8 = undefined;
                crypto.randomBytes(&conn_id);

                slot.middle_ctx = middleproxy.MiddleProxyContext.initWithBuffer(
                    self.state.allocator,
                    slot.mp_enc.?,
                    slot.mp_dec.?,
                    conn_id,
                    slot.mp_write_seq_no,
                    slot.peer_addr,
                    middle_local_addr,
                    slot.proto_tag,
                    self.state.config.tag,
                    self.state.config.middleProxyBufferBytes(),
                ) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp context init failed");
                    }
                    return;
                };

                self.setMiddleProxyStep(slot, .done);
                self.promoteSuccessfulMiddleProxyCandidate(slot);
                self.startRelay(slot);
            },
            else => {},
        }
    }

    fn promoteSuccessfulMiddleProxyCandidate(self: *EventLoop, slot: *const ConnectionSlot) void {
        if (!slot.use_middle_proxy or slot.upstream_candidate_next <= 1) return;
        const addr = slot.current_upstream_addr orelse return;

        if (self.state.promoteMiddleProxyCandidate(@intCast(slot.dc_abs), slot.is_media_path, addr)) {
            log.info("[{d}] promoted successful middle-proxy fallback candidate: dc_idx={d}", .{
                slot.conn_id,
                slot.dc_idx,
            });
        }
    }

    fn fallbackFromMiddleProxyToDirect(self: *EventLoop, slot: *ConnectionSlot) bool {
        if (slot.use_middle_proxy) {
            if (slot.current_upstream_addr) |addr| {
                if (self.state.cooldownMiddleProxyCandidate(addr)) {
                    log.info("[{d}] cooling failed middle-proxy endpoint after handshake failure: dc_idx={d}", .{
                        slot.conn_id,
                        slot.dc_idx,
                    });
                }
            }
        }
        if (slot.direct_fallback_addr == null or slot.direct_fallback_used) return false;

        _ = slot.obf_params orelse return false;
        slot.direct_fallback_used = true;
        _ = self.state.stats_mp_fallback.fetchAdd(1, .monotonic);
        slot.use_middle_proxy = false;
        std.crypto.secureZero(u8, &slot.mp_secret);
        slot.mp_secret_len = 0;
        slot.mp_nat_ip4 = null;
        self.setMiddleProxyStep(slot, .none);
        if (slot.mp_enc) |*enc| enc.wipe();
        if (slot.mp_dec) |*dec| dec.wipe();
        slot.mp_enc = null;
        slot.mp_dec = null;
        if (slot.middle_ctx) |*mp| mp.deinit();
        slot.middle_ctx = null;

        slot.use_fast_mode = self.state.config.fast_mode and
            (slot.dc_abs >= 1 and slot.dc_abs <= constants.tg_datacenters_v4.len);

        // Reset nonce path state to cleanly re-send direct nonce.
        if (slot.dc_initial_tail) |tail| {
            secureFree(self.state.allocator, tail);
            slot.dc_initial_tail = null;
        }
        if (slot.tg_encryptor) |*enc| enc.wipe();
        if (slot.tg_decryptor) |*dec| dec.wipe();
        slot.tg_encryptor = null;
        slot.tg_decryptor = null;

        const fallback = slot.direct_fallback_addr.?;
        self.cleanupFailedUpstreamConnect(slot);
        slot.upstream_candidate_next = 1;

        if (slot.upstream_candidates) |old| {
            self.state.allocator.free(old);
            slot.upstream_candidates = null;
        }
        const one = self.state.allocator.alloc(net.Address, 1) catch {
            return false;
        };
        one[0] = fallback;
        slot.upstream_candidates = one;

        self.startConnectUpstream(slot, fallback, .dc) catch |err| {
            log.warn("[{d}] direct fallback connect start failed: {any}", .{ slot.conn_id, err });
            return false;
        };

        var fb_buf: [64]u8 = undefined;
        const fb_str = formatAddress(fallback, &fb_buf);
        log.warn("[{d}] middle-proxy handshake failed, reconnecting direct to {s}", .{ slot.conn_id, fb_str });
        return true;
    }

    fn setMiddleProxyStep(self: *EventLoop, slot: *ConnectionSlot, step: MiddleProxyHandshakeStep) void {
        slot.mp_step = step;
        slot.mp_step_deadline_ms = switch (step) {
            .none, .done => 0,
            else => compat.monotonicMilliTimestamp() + @min(
                secondsToMs(self.state.config.handshake_timeout_sec),
                middle_proxy_stage_timeout_ms,
            ),
        };
    }

    fn mpWriteFrame(self: *EventLoop, slot: *ConnectionSlot, payload: []const u8, encrypted: bool) !void {
        _ = self;
        var plain: [mp_handshake_frame_buf_size]u8 = undefined;
        const total_len: usize = payload.len + 12;
        if (total_len > plain.len) return error.BadMiddleProxyFrameSize;

        std.mem.writeInt(u32, plain[0..4], @intCast(total_len), .little);
        std.mem.writeInt(i32, plain[4..8], slot.mp_write_seq_no, .little);
        slot.mp_write_seq_no = slot.mp_write_seq_no +% 1;

        @memcpy(plain[8 .. 8 + payload.len], payload);
        const checksum = middleproxy.crc32(plain[0 .. 8 + payload.len]);
        std.mem.writeInt(u32, plain[8 + payload.len ..][0..4], checksum, .little);

        var frame_len = total_len;
        if (encrypted) {
            const pad = (16 - (frame_len % 16)) % 16;
            if (frame_len + pad > plain.len) return error.BadMiddleProxyFrameSize;
            var i: usize = 0;
            while (i < pad) : (i += 4) {
                std.mem.writeInt(u32, plain[frame_len + i ..][0..4], 4, .little);
            }
            frame_len += pad;
            try slot.mp_enc.?.encryptInPlace(plain[0..frame_len]);
        }

        _ = try queueUpstream(slot, plain[0..frame_len]);
    }

    fn mpTryReadFrame(self: *EventLoop, slot: *ConnectionSlot, encrypted: bool) !?[]const u8 {
        const frame_buf = try ensureMpFrameBuf(slot, self.state.allocator);

        while (true) {
            if (slot.mp_frame_need == 0) {
                mpReadReset(slot, encrypted);
            }

            if (slot.mp_frame_have < slot.mp_frame_need) {
                const n = posix.read(slot.upstream_fd, frame_buf[slot.mp_frame_have..slot.mp_frame_need]) catch |err| {
                    if (err == error.WouldBlock) return null;
                    log.debug("[{d}] mp read error: step={s} encrypted={} have={d} need={d} err={any}", .{
                        slot.conn_id,
                        @tagName(slot.mp_step),
                        encrypted,
                        slot.mp_frame_have,
                        slot.mp_frame_need,
                        err,
                    });
                    return err;
                };
                if (n == 0) {
                    log.debug("[{d}] mp upstream eof: step={s} encrypted={} have={d} need={d}", .{
                        slot.conn_id,
                        @tagName(slot.mp_step),
                        encrypted,
                        slot.mp_frame_have,
                        slot.mp_frame_need,
                    });
                    return error.EndOfStream;
                }
                slot.mp_frame_have += n;
                if (slot.mp_frame_have < slot.mp_frame_need) return null;
            }

            if (!encrypted) {
                if (slot.mp_frame_total_len == 0) {
                    slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > frame_buf.len) {
                        log.debug("[{d}] mp plain frame size invalid: total_len={d} have={d} need={d}", .{
                            slot.conn_id,
                            slot.mp_frame_total_len,
                            slot.mp_frame_have,
                            slot.mp_frame_need,
                        });
                        return error.BadMiddleProxyFrameSize;
                    }
                    slot.mp_frame_need = slot.mp_frame_total_len;
                    continue;
                }
            } else {
                if (!slot.mp_frame_first_decrypted) {
                    slot.mp_dec.?.decryptInPlace(frame_buf[0..16]) catch |err| {
                        log.debug("[{d}] mp decrypt first block failed: step={s} err={any}", .{
                            slot.conn_id,
                            @tagName(slot.mp_step),
                            err,
                        });
                        return err;
                    };
                    slot.mp_frame_first_decrypted = true;
                    slot.mp_frame_total_len = std.mem.readInt(u32, frame_buf[0..4], .little);
                    if (slot.mp_frame_total_len < 12 or slot.mp_frame_total_len > (1 << 24)) {
                        const first4_le = std.mem.readInt(u32, frame_buf[0..4], .little);
                        const first4_be = std.mem.readInt(u32, frame_buf[0..4], .big);
                        log.debug("[{d}] mp encrypted frame size invalid: total_len={d} first4_le=0x{x} first4_be=0x{x}", .{
                            slot.conn_id,
                            slot.mp_frame_total_len,
                            first4_le,
                            first4_be,
                        });
                        return error.BadMiddleProxyFrameSize;
                    }
                    slot.mp_frame_padded_len = if (slot.mp_frame_total_len % 16 == 0)
                        slot.mp_frame_total_len
                    else
                        slot.mp_frame_total_len + (16 - (slot.mp_frame_total_len % 16));
                    if (slot.mp_frame_padded_len > frame_buf.len) {
                        log.debug("[{d}] mp encrypted padded size invalid: total_len={d} padded_len={d} frame_buf={d}", .{
                            slot.conn_id,
                            slot.mp_frame_total_len,
                            slot.mp_frame_padded_len,
                            frame_buf.len,
                        });
                        return error.BadMiddleProxyFrameSize;
                    }
                    slot.mp_frame_need = slot.mp_frame_padded_len;
                    if (slot.mp_frame_have < slot.mp_frame_need) return null;
                }

                if (slot.mp_frame_padded_len > 16) {
                    slot.mp_dec.?.decryptInPlace(frame_buf[16..slot.mp_frame_padded_len]) catch |err| {
                        log.debug("[{d}] mp decrypt payload failed: step={s} padded_len={d} err={any}", .{
                            slot.conn_id,
                            @tagName(slot.mp_step),
                            slot.mp_frame_padded_len,
                            err,
                        });
                        return err;
                    };
                }
            }

            const frame = frame_buf[0..slot.mp_frame_total_len];
            const msg_seq = std.mem.readInt(i32, frame[4..8], .little);
            if (msg_seq != slot.mp_read_seq_no) {
                log.debug("[{d}] mp seq mismatch: got={d} expected={d} step={s}", .{
                    slot.conn_id,
                    msg_seq,
                    slot.mp_read_seq_no,
                    @tagName(slot.mp_step),
                });
                return error.BadMiddleProxySeqNo;
            }
            slot.mp_read_seq_no = slot.mp_read_seq_no +% 1;

            const expected_checksum = std.mem.readInt(u32, frame[frame.len - 4 ..][0..4], .little);
            const computed_checksum = middleproxy.crc32(frame[0 .. frame.len - 4]);
            if (expected_checksum != computed_checksum) {
                log.debug("[{d}] mp checksum mismatch: expected=0x{x} computed=0x{x} frame_len={d}", .{
                    slot.conn_id,
                    expected_checksum,
                    computed_checksum,
                    frame.len,
                });
                return error.BadMiddleProxyChecksum;
            }

            // Copy payload into front of frame_buf so caller can consume before reset.
            const payload_len = frame.len - 12;
            std.mem.copyForwards(u8, frame_buf[0..payload_len], frame[8 .. frame.len - 4]);
            const payload = frame_buf[0..payload_len];

            mpReadReset(slot, encrypted);
            return payload;
        }
    }

    fn runTimers(self: *EventLoop) void {
        const now_ms = compat.monotonicMilliTimestamp();
        const now_ns = compat.monotonicNanoTimestamp();

        const hi: usize = @intCast(self.pool.active_hi);
        if (hi == 0) return;

        var idx: usize = @intCast(self.timer_scan_cursor);
        if (idx >= hi) idx = 0;

        var scanned: usize = 0;
        while (scanned < hi) : (scanned += 1) {
            const slot_opt = self.pool.slots[idx];
            idx += 1;
            if (idx >= hi) idx = 0;

            const slot = slot_opt orelse continue;
            if (slot.phase == .idle) continue;

            if (slot.phase == .desync_wait and now_ns >= slot.desync_deadline_ns) {
                slot.phase = .writing_server_hello_rest;
                if (slot.server_hello) |sh| {
                    if (slot.server_hello_off < sh.len) {
                        if (queueClient(slot, sh[slot.server_hello_off..])) |_| {} else |_| {
                            self.closeSlot(slot, "desync rest write failed");
                            continue;
                        }
                        slot.server_hello_off = sh.len;
                    }
                }
            }

            if (slot.phase == .closing) {
                self.closeSlot(slot, "closing phase");
                continue;
            }

            if (slot.phase == .connecting_upstream and
                slot.upstream_connect_deadline_ms > 0 and
                now_ms > slot.upstream_connect_deadline_ms)
            {
                const failed_kind = slot.upstream_kind;
                const failed_addr = slot.current_upstream_addr;
                self.cleanupFailedUpstreamConnect(slot);

                if (failed_kind == .dc and self.tryNextDcEndpoint(slot, error.ConnectionTimedOut, failed_addr)) {
                    continue;
                }
                if (failed_kind == .mask and self.tryNextMaskEndpoint(slot, error.ConnectionTimedOut, failed_addr)) {
                    continue;
                }

                self.closeSlot(slot, "dc connect timeout");
                continue;
            }

            if (slot.phase == .middle_proxy_handshake and
                slot.mp_step_deadline_ms > 0 and
                now_ms > slot.mp_step_deadline_ms)
            {
                self.state.requestMiddleProxyRefresh();
                if (self.fallbackFromMiddleProxyToDirect(slot)) continue;
                self.closeSlot(slot, "middle-proxy stage timeout");
                continue;
            }

            if (slot.handshakeInProgress()) {
                if (slot.first_byte_at_ms == 0) {
                    if (now_ms - slot.created_at_ms > @min(self.idleTimeoutMs(slot), pre_first_byte_timeout_ms)) {
                        self.closeSlot(slot, "idle pre-first-byte timeout");
                        continue;
                    }
                } else if (now_ms - slot.first_byte_at_ms > secondsToMs(self.state.config.handshake_timeout_sec)) {
                    _ = self.state.stats_hs_timeout.fetchAdd(1, .monotonic);
                    if (slot.phase == .middle_proxy_handshake and slot.mp_step.awaitingMiddleProxy()) {
                        self.state.requestMiddleProxyRefresh();
                        if (self.fallbackFromMiddleProxyToDirect(slot)) continue;
                    }
                    self.closeSlot(slot, "handshake timeout");
                    continue;
                }
            } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
                if (slot.phase == .mask_relaying and self.state.config.mask_relay_max_secs > 0 and
                    now_ms - slot.created_at_ms > secondsToMs(self.state.config.mask_relay_max_secs))
                {
                    self.closeSlot(slot, "mask relay max lifetime");
                    continue;
                }

                // Break an iOS MtProtoKit bad_salt wedge: after a server reply,
                // the client may stop sending until the DC closes the socket.
                if (slot.phase == .relaying and self.state.config.client_silence_close_sec > 0 and
                    slot.last_client_byte_ms > 0 and
                    slot.last_server_byte_ms > slot.last_client_byte_ms and
                    now_ms - slot.last_server_byte_ms > secondsToMs(self.state.config.client_silence_close_sec))
                {
                    log.info("[{d}] closing relay: server reply unanswered {d}s (iOS bad_salt wedge breaker)", .{ slot.conn_id, self.state.config.client_silence_close_sec });
                    self.closeSlot(slot, "client silence wedge breaker");
                    continue;
                }
                if (now_ms - slot.last_activity_ms > self.idleTimeoutMs(slot)) {
                    self.closeSlot(slot, "relay idle timeout");
                    continue;
                }
            }

            self.syncInterests(slot) catch |err| {
                log.debug("[{d}] syncInterests error in timer tick: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "sync interest error");
            };
        }

        self.timer_scan_cursor = @intCast(idx);
    }

    fn idleTimeoutMs(self: *const EventLoop, slot: *const ConnectionSlot) i64 {
        return jitteredIdleTimeoutMs(
            self.state.config.idle_timeout_sec,
            self.state.config.idle_timeout_jitter_pct,
            idleTimeoutSeed(slot),
        );
    }

    fn syncInterests(self: *EventLoop, slot: *ConnectionSlot) !void {
        var want_client_in = false;
        var want_client_out = slot.hasClientPending();
        var want_upstream_in = false;
        var want_upstream_out = slot.hasUpstreamPending();

        switch (slot.phase) {
            .reading_tls_header,
            .reading_client_hello_body,
            .reading_mtproto_tls_header,
            .reading_mtproto_tls_body,
            => {
                want_client_in = true;
            },

            .writing_server_hello_first,
            .writing_server_hello_rest,
            => {
                want_client_out = true;
            },

            .desync_wait => {
                // Wait for timer tick only; keeping EPOLLOUT enabled here can
                // cause a busy loop because writable sockets trigger continuously.
            },

            .connecting_upstream => {
                want_client_in = false;
                want_upstream_out = true;
            },

            .writing_dc_nonce => {
                want_client_in = false;
                want_upstream_out = true;
            },

            .middle_proxy_handshake => {
                want_upstream_out = want_upstream_out or
                    slot.mp_step == .sending_rpc_nonce or
                    slot.mp_step == .sending_rpc_handshake;
                want_upstream_in = slot.mp_step == .waiting_rpc_nonce_response or
                    slot.mp_step == .waiting_rpc_handshake_response;
            },

            .relaying, .mask_relaying => {
                if (slot.relay_half_closed) {
                    want_client_in = false;
                    want_upstream_in = false;
                } else {
                    want_client_in = !slot.hasUpstreamPending();
                    want_upstream_in = !slot.hasClientPending();
                }
            },

            else => {},
        }

        if (!isInvalidFd(slot.client_fd) and !slot.client_detached) {
            if (slot.client_interest_in != want_client_in or slot.client_interest_out != want_client_out) {
                try self.modFd(slot.client_fd, want_client_in, want_client_out);
                slot.client_interest_in = want_client_in;
                slot.client_interest_out = want_client_out;
            }
        }

        if (!isInvalidFd(slot.upstream_fd) and !slot.upstream_detached) {
            if (slot.upstream_interest_in != want_upstream_in or slot.upstream_interest_out != want_upstream_out) {
                try self.modFd(slot.upstream_fd, want_upstream_in, want_upstream_out);
                slot.upstream_interest_in = want_upstream_in;
                slot.upstream_interest_out = want_upstream_out;
            }
        }
    }

    fn ensureMpC2sScratch(self: *EventLoop, min_capacity: usize) ![]u8 {
        const target_capacity = @max(self.state.config.middleProxyC2sScratchBytes(), min_capacity);
        if (self.mp_c2s_scratch) |buf| {
            if (buf.len >= target_capacity) return buf;
        }

        const next = try self.state.allocator.alloc(u8, target_capacity);
        if (self.mp_c2s_scratch) |prev| secureFree(self.state.allocator, prev);
        self.mp_c2s_scratch = next;
        return next;
    }

    fn ensureMpS2cScratch(self: *EventLoop, min_capacity: usize) ![]u8 {
        const target_capacity = @max(self.state.config.middleProxyBufferBytes(), min_capacity);
        if (self.mp_s2c_scratch) |buf| {
            if (buf.len >= target_capacity) return buf;
        }

        const next = try self.state.allocator.alloc(u8, target_capacity);
        if (self.mp_s2c_scratch) |prev| secureFree(self.state.allocator, prev);
        self.mp_s2c_scratch = next;
        return next;
    }

    fn tryBeginRelayHalfClose(self: *EventLoop, slot: *ConnectionSlot, hung_fd: posix.fd_t, events: u32) bool {
        if (slot.relay_half_closed) return false;
        if (!hasGracefulEpollRdhup(events)) return false;
        if (slot.phase != .relaying and slot.phase != .mask_relaying) return false;

        const drain_to_upstream = hung_fd == slot.client_fd and slot.hasUpstreamPending();
        const drain_to_client = hung_fd == slot.upstream_fd and slot.hasClientPending();
        if (!drain_to_upstream and !drain_to_client) return false;

        _ = self.delFd(hung_fd) catch {};
        self.pool.unmapFd(hung_fd);
        if (hung_fd == slot.client_fd) {
            slot.client_detached = true;
            slot.client_interest_in = false;
            slot.client_interest_out = false;
        } else {
            slot.upstream_detached = true;
            slot.upstream_interest_in = false;
            slot.upstream_interest_out = false;
        }
        slot.relay_half_closed = true;
        slot.last_activity_ms = compat.monotonicMilliTimestamp();

        self.syncInterests(slot) catch {
            self.closeSlot(slot, "half-close interest sync failed");
            return true;
        };
        return true;
    }

    fn drainRelayRdhup(self: *EventLoop, slot: *ConnectionSlot, hung_fd: posix.fd_t, events: u32) void {
        const from_client = hung_fd == slot.client_fd;
        const from_upstream = hung_fd == slot.upstream_fd;
        if (!from_client and !from_upstream) return;

        var reached_eof = false;
        if (slot.phase == .relaying) {
            while (slot.phase == .relaying) {
                const progress = if (from_client)
                    relayClientToUpstreamStep(self, slot)
                else
                    relayUpstreamToClientStep(self, slot);

                const step = progress catch |err| {
                    if (err == error.EndOfStream) {
                        reached_eof = true;
                        break;
                    }
                    self.closeSlot(slot, if (from_client) "relay client rdhup drain failed" else "relay upstream rdhup drain failed");
                    return;
                };

                if (step == .none) break;
                const now_ms = compat.monotonicMilliTimestamp();
                slot.last_activity_ms = now_ms;
                if (from_client) {
                    slot.last_client_byte_ms = now_ms;
                } else {
                    slot.last_server_byte_ms = now_ms;
                }
            }
        } else {
            const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
                self.closeSlot(slot, "mask rdhup read buffer alloc failed");
                return;
            };
            while (slot.phase == .mask_relaying) {
                const n = posix.read(hung_fd, read_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    self.closeSlot(slot, "mask rdhup drain failed");
                    return;
                };
                if (n == 0) {
                    reached_eof = true;
                    break;
                }
                if (from_client) {
                    _ = queueUpstream(slot, read_buf[0..n]) catch {
                        self.closeSlot(slot, "mask rdhup queue upstream failed");
                        return;
                    };
                } else {
                    _ = queueClient(slot, read_buf[0..n]) catch {
                        self.closeSlot(slot, "mask rdhup queue client failed");
                        return;
                    };
                }
                slot.last_activity_ms = compat.monotonicMilliTimestamp();
            }
        }

        if (reached_eof) {
            if (self.tryBeginRelayHalfClose(slot, hung_fd, events)) return;
            self.closeSlot(slot, "relay peer eof");
            return;
        }

        self.syncInterests(slot) catch {
            self.closeSlot(slot, "rdhup interest sync failed");
        };
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        log.debug("[{d}] closing: dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d}", .{
            slot.conn_id,
            slot.dc_idx,
            slot.is_media_path,
            @tagName(slot.phase),
            reason,
            slot.c2s_bytes,
            slot.s2c_bytes,
        });

        if (!isInvalidFd(slot.client_fd)) {
            _ = self.delFd(slot.client_fd) catch {};
            self.pool.unmapFd(slot.client_fd);
            self.deferClose(slot.client_fd);
            slot.client_fd = invalid_fd;
        }

        if (!isInvalidFd(slot.upstream_fd)) {
            _ = self.delFd(slot.upstream_fd) catch {};
            self.pool.unmapFd(slot.upstream_fd);
            self.deferClose(slot.upstream_fd);
            slot.upstream_fd = invalid_fd;
        }

        self.releaseHandshakeBudget(slot);
        self.releaseSubnetHandshake(slot);
        slot.resetOwnedBuffers(self.state.allocator);

        if (slot.active_reserved) {
            _ = self.state.active_connections.fetchSub(1, .monotonic);
            slot.active_reserved = false;
            self.closed_since_log += 1;
        }

        slot.relay_half_closed = false;
        slot.client_detached = false;
        slot.upstream_detached = false;
        slot.phase = .idle;
        self.pool.release(slot);
    }

    fn addFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;

        var ev = linux.epoll_event{ .events = events, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn modFd(self: *EventLoop, fd: posix.fd_t, want_in: bool, want_out: bool) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;

        var ev = linux.epoll_event{ .events = events, .data = .{ .fd = fd } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn delFd(self: *EventLoop, fd: posix.fd_t) !void {
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null);
        switch (posix.errno(rc)) {
            // EPERM means the target fd type cannot be registered with epoll.
            // Cleanup is already complete from the event loop's perspective.
            .SUCCESS, .NOENT, .PERM => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn appendPipelined(self: *EventLoop, slot: *ConnectionSlot, extra: []const u8) !void {
        if (extra.len == 0) return;

        const next_len = try std.math.add(usize, slot.pipelined_len, extra.len);
        if (next_len > constants.max_tls_ciphertext_size) return error.PipelinedDataTooLarge;

        var buf = slot.pipelined_data orelse blk: {
            const initial_capacity = pipelinedCapacity(0, next_len);
            const allocated = try self.state.allocator.alloc(u8, initial_capacity);
            slot.pipelined_data = allocated;
            break :blk allocated;
        };

        if (buf.len < next_len) {
            const next_capacity = pipelinedCapacity(buf.len, next_len);
            const next = try self.state.allocator.alloc(u8, next_capacity);
            @memcpy(next[0..slot.pipelined_len], buf[0..slot.pipelined_len]);
            secureFree(self.state.allocator, buf);
            buf = next;
            slot.pipelined_data = buf;
        }

        @memcpy(buf[slot.pipelined_len..next_len], extra);
        slot.pipelined_len = next_len;
    }
};

fn pipelinedCapacity(current_capacity: usize, required_len: usize) usize {
    var next = if (current_capacity == 0)
        @min(@as(usize, read_buf_size), constants.max_tls_ciphertext_size)
    else
        current_capacity;

    while (next < required_len) {
        next = @min(next * 2, constants.max_tls_ciphertext_size);
    }

    return next;
}

fn relayClientToUpstreamStep(self: *EventLoop, slot: *ConnectionSlot) !RelayProgress {
    const allocator = self.state.allocator;
    const read_buf = try ensureReadBuf(slot, allocator);
    var consumed_any = false;

    while (true) {
        if (slot.relay_tls_hdr_pos < tls_header_len) {
            const n = posix.read(slot.client_fd, slot.relay_tls_hdr[slot.relay_tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
                return err;
            };
            if (n == 0) return error.EndOfStream;
            consumed_any = true;
            slot.relay_tls_hdr_pos += @intCast(n);

            if (slot.relay_tls_hdr_pos < tls_header_len) return .partial;

            slot.relay_record_type = slot.relay_tls_hdr[0];
            slot.relay_tls_body_len = std.mem.readInt(u16, slot.relay_tls_hdr[3..5], .big);
            slot.relay_tls_body_pos = 0;

            if (slot.relay_record_type == constants.tls_record_alert) return error.ConnectionReset;
            if (slot.relay_record_type != constants.tls_record_change_cipher and
                slot.relay_record_type != constants.tls_record_application)
            {
                return error.ConnectionReset;
            }
            if (slot.relay_tls_body_len == 0 or slot.relay_tls_body_len > constants.max_tls_ciphertext_size) {
                return error.ConnectionReset;
            }
        }

        const remaining = slot.relay_tls_body_len - slot.relay_tls_body_pos;
        if (remaining == 0) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            if (consumed_any) return .partial;
            continue;
        }

        const want = @min(@as(usize, remaining), read_buf.len);
        const n = posix.read(slot.client_fd, read_buf[0..want]) catch |err| {
            if (err == error.WouldBlock) return if (consumed_any) .partial else .none;
            return err;
        };
        if (n == 0) return error.EndOfStream;

        consumed_any = true;
        slot.relay_tls_body_pos += @intCast(n);

        if (slot.relay_record_type == constants.tls_record_change_cipher) {
            if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
                slot.relay_tls_hdr_pos = 0;
                slot.relay_tls_body_pos = 0;
                slot.relay_tls_body_len = 0;
            }
            return .partial;
        }

        const payload = read_buf[0..n];
        if (slot.client_decryptor) |*dec| dec.apply(payload);

        if (slot.middle_ctx) |*mp| {
            const required = try mp.requiredC2sScratchCapacity(payload);
            const scratch = try self.ensureMpC2sScratch(required);
            const out_data = try mp.encapsulateC2S(payload, scratch);
            if (out_data.len > 0) {
                _ = try queueUpstream(slot, out_data);
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(payload);
            _ = try queueUpstream(slot, payload);
        }

        slot.c2s_bytes += payload.len;

        if (slot.relay_tls_body_pos == slot.relay_tls_body_len) {
            slot.relay_tls_hdr_pos = 0;
            slot.relay_tls_body_pos = 0;
            slot.relay_tls_body_len = 0;
            return .forwarded;
        }

        return .partial;
    }
}

fn relayUpstreamToClientStep(self: *EventLoop, slot: *ConnectionSlot) !RelayProgress {
    const read_buf = try ensureReadBuf(slot, self.state.allocator);
    const n = posix.read(slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;

    const raw = read_buf[0..n];

    if (slot.middle_ctx) |*mp| {
        const required = try mp.requiredS2cScratchCapacity(raw);
        const scratch = try self.ensureMpS2cScratch(required);
        const payload = try mp.decapsulateS2C(raw, scratch);
        if (payload.len == 0) return .partial;
        if (slot.client_encryptor) |*enc| enc.apply(payload);
        try queueTlsAppRecords(slot, payload);
        slot.s2c_bytes += payload.len;
        return .forwarded;
    }

    if (!slot.use_fast_mode) {
        if (slot.tg_decryptor) |*dec| dec.apply(raw);
        if (slot.client_encryptor) |*enc| enc.apply(raw);
    }

    try queueTlsAppRecords(slot, raw);
    slot.s2c_bytes += raw.len;
    return .forwarded;
}

fn queueTlsAppRecords(slot: *ConnectionSlot, payload: []u8) !void {
    var off: usize = 0;
    var header: [tls_header_len]u8 = undefined;

    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, slot.drs.nextRecordSize());

        header[0] = constants.tls_record_application;
        header[1] = constants.tls_version[0];
        header[2] = constants.tls_version[1];
        std.mem.writeInt(u16, header[3..5], @intCast(chunk_len), .big);

        _ = try queueClientPair(slot, header[0..], payload[off .. off + chunk_len]);
        slot.drs.recordSent(chunk_len);
        off += chunk_len;
    }
}

fn epollCreate() !posix.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn requiredFdsForConnections(max_connections: u32) usize {
    return @as(usize, max_connections) * 2 + nofile_fd_overhead;
}

fn shouldAcceptListen(accept_paused: bool, saturation_paused: bool) bool {
    return !accept_paused and !saturation_paused;
}

fn maxConnectionsForNofile(soft_nofile: usize) u32 {
    if (soft_nofile < requiredFdsForConnections(32)) return 0;

    const cap = (soft_nofile - nofile_fd_overhead) / 2;
    const capped_u32: u32 = @intCast(@min(cap, @as(usize, std.math.maxInt(u32))));
    return capped_u32;
}

fn getNofileSoftLimit() ?usize {
    if (builtin.os.tag != .linux) return null;

    var lim: linux.rlimit = undefined;
    const rc = linux.getrlimit(.NOFILE, &lim);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }

    return @intCast(lim.cur);
}

fn checkNofileLimit(required: usize, max_connections: u32) void {
    const soft = getNofileSoftLimit() orelse return;

    if (soft >= required) return;

    log.warn("RLIMIT_NOFILE soft limit is {d}, recommended >= {d} for max_connections={d}", .{
        soft,
        required,
        max_connections,
    });
}

fn secondsToMs(sec: u32) i64 {
    return @as(i64, @intCast(sec)) * std.time.ms_per_s;
}

fn budgetedConnectTimeoutMs(
    configured_timeout_ms: i64,
    first_byte_at_ms: i64,
    handshake_timeout_ms: i64,
    started_at_ms: i64,
    candidate_count: usize,
) i64 {
    if (configured_timeout_ms <= 0 or first_byte_at_ms <= 0 or candidate_count <= 1) {
        return configured_timeout_ms;
    }

    const handshake_deadline_ms = first_byte_at_ms + handshake_timeout_ms;
    const remaining_handshake_ms = @max(@as(i64, 1), handshake_deadline_ms - started_at_ms);
    const fair_share_ms = @max(
        @as(i64, 1),
        @divTrunc(remaining_handshake_ms, @as(i64, @intCast(candidate_count))),
    );
    return @min(configured_timeout_ms, fair_share_ms);
}

fn idleTimeoutSeed(slot: *const ConnectionSlot) u64 {
    const created: u64 = if (slot.created_at_ms > 0) @intCast(slot.created_at_ms) else 0;
    var x = slot.conn_id ^ (created *% 0x9E37_79B9_7F4A_7C15);
    x +%= 0x9E37_79B9_7F4A_7C15;
    var z = x;
    z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
    z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
    return z ^ (z >> 31);
}

fn jitteredIdleTimeoutMs(base_sec: u32, jitter_pct: u8, seed: u64) i64 {
    const base_ms = secondsToMs(base_sec);
    if (jitter_pct == 0) return base_ms;

    const pct: i64 = @intCast(@min(@as(u8, 100), jitter_pct));
    const range = @divTrunc(base_ms * pct, 100);
    if (range <= 0) return base_ms;

    const span: u64 = @intCast(2 * range + 1);
    const offset = @as(i64, @intCast(seed % span)) - range;
    const floor_ms = @max(secondsToMs(5), @divTrunc(base_ms, 2));
    return @max(floor_ms, base_ms + offset);
}

fn setTcpUserTimeout(fd: posix.fd_t, timeout_ms: u32) void {
    const value: c_int = @intCast(timeout_ms);
    setSockOptBytes(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, std.mem.asBytes(&value));
}

fn setTcpKeepalive(fd: posix.fd_t) void {
    const sol_tcp: i32 = 6;

    const enable: c_int = 1;
    setSockOptBytes(fd, linux.SOL.SOCKET, linux.SO.KEEPALIVE, std.mem.asBytes(&enable));

    const idle: c_int = 60;
    setSockOptBytes(fd, sol_tcp, 4, std.mem.asBytes(&idle));

    const interval: c_int = 10;
    setSockOptBytes(fd, sol_tcp, 5, std.mem.asBytes(&interval));

    const count: c_int = 3;
    setSockOptBytes(fd, sol_tcp, 6, std.mem.asBytes(&count));
}

fn setTcpNoDelay(fd: posix.fd_t) void {
    const enable: c_int = 1;
    setSockOptBytes(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&enable));
}

fn configureRelaySocket(fd: posix.fd_t) void {
    setTcpNoDelay(fd);
    setTcpKeepalive(fd);
    setTcpUserTimeout(fd, 30 * std.time.ms_per_s);
}

fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    switch (addr.any.family) {
        posix.AF.INET => {
            return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch "?";
        },
        posix.AF.INET6 => {
            const bytes: *const [16]u8 = @ptrCast(&addr.in6.sa.addr);
            const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
                std.mem.eql(u8, bytes[10..12], &[_]u8{ 0xff, 0xff });

            if (is_ipv4_mapped) {
                return std.fmt.bufPrint(buf, "[ipv4]:{d}", .{
                    std.mem.bigToNative(u16, addr.in6.sa.port),
                }) catch "?";
            }
            return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                std.mem.bigToNative(u16, addr.in6.sa.port),
            }) catch "?";
        },
        else => return "?",
    }
}

fn ensureReadBuf(slot: *ConnectionSlot, allocator: std.mem.Allocator) ![]u8 {
    if (slot.read_buf) |buf| return buf;
    const buf = try allocator.alloc(u8, read_buf_size);
    slot.read_buf = buf;
    return buf;
}

fn ensureMpFrameBuf(slot: *ConnectionSlot, allocator: std.mem.Allocator) ![]u8 {
    if (slot.mp_frame_buf) |buf| return buf;
    const buf = try allocator.alloc(u8, mp_handshake_frame_buf_size);
    slot.mp_frame_buf = buf;
    return buf;
}

fn parseIpv4Literal(text: []const u8) ?[4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var ip: [4]u8 = undefined;
    var idx: usize = 0;

    while (parts.next()) |part| {
        if (idx >= ip.len or part.len == 0 or part.len > 3) return null;
        const octet = std.fmt.parseInt(u16, part, 10) catch return null;
        if (octet > 255) return null;
        ip[idx] = @intCast(octet);
        idx += 1;
    }

    if (idx != ip.len) return null;
    return ip;
}

fn isRunningInNonInitNetns() bool {
    if (builtin.os.tag != .linux) return false;

    var self_buf: [std.fs.max_path_bytes]u8 = undefined;
    var init_buf: [std.fs.max_path_bytes]u8 = undefined;

    var threaded_io = compat.initThreadedIo();
    defer threaded_io.deinit();
    const local_io = threaded_io.io();
    const self_len = std.Io.Dir.readLinkAbsolute(local_io, "/proc/self/ns/net", &self_buf) catch return false;
    const init_len = std.Io.Dir.readLinkAbsolute(local_io, "/proc/1/ns/net", &init_buf) catch return false;
    const self_ns = self_buf[0..self_len];
    const init_ns = init_buf[0..init_len];

    return !std.mem.eql(u8, self_ns, init_ns);
}

fn parseEndpointHost(endpoint: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, endpoint, &[_]u8{ ' ', '\t', '\r', '\n' });
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, trimmed, ']') orelse return null;
        const host = trimmed[1..close_idx];
        if (host.len == 0) return null;
        return host;
    }

    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |sep| {
        if (sep == 0) return null;
        return std.mem.trim(u8, trimmed[0..sep], &[_]u8{ ' ', '\t', '\r', '\n' });
    }

    return trimmed;
}

fn resolveHostnameIpv4(allocator: std.mem.Allocator, host: []const u8) ?[4]u8 {
    var list = net.getAddressList(allocator, host, 443) catch return null;
    defer list.deinit();

    for (list.addrs) |addr| {
        if (addr.any.family == posix.AF.INET) {
            var ip: [4]u8 = undefined;
            @memcpy(&ip, std.mem.asBytes(&addr.in.sa.addr));
            return ip;
        }
    }

    return null;
}

fn parseAwgEndpointIpv4FromConfig(allocator: std.mem.Allocator, content: []const u8) ?[4]u8 {
    var in_peer = false;
    var lines = std.mem.splitScalar(u8, content, '\n');

    while (lines.next()) |raw_line| {
        const line_no_cr = std.mem.trimEnd(u8, raw_line, "\r");
        const line = std.mem.trim(u8, line_no_cr, &[_]u8{ ' ', '\t' });
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

        if (line[0] == '[' and line[line.len - 1] == ']') {
            in_peer = std.ascii.eqlIgnoreCase(line, "[Peer]");
            continue;
        }
        if (!in_peer) continue;

        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
        if (!std.ascii.eqlIgnoreCase(key, "Endpoint")) continue;

        var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
        if (std.mem.indexOfScalar(u8, value, '#')) |idx| value = value[0..idx];
        if (std.mem.indexOfScalar(u8, value, ';')) |idx| value = value[0..idx];
        value = std.mem.trim(u8, value, &[_]u8{ ' ', '\t' });
        const host = parseEndpointHost(value) orelse continue;

        if (parseIpv4Literal(host)) |ip| return ip;
        if (resolveHostnameIpv4(allocator, host)) |resolved_ip| return resolved_ip;
    }

    return null;
}

fn detectAwgEndpointIpv4(allocator: std.mem.Allocator) ?[4]u8 {
    if (builtin.os.tag != .linux) return null;

    const paths = [_][]const u8{
        "/etc/amnezia/amneziawg/awg0.conf",
        "/etc/amnezia/amneziawg/wg0.conf",
        "/etc/wireguard/wg0.conf",
    };

    for (paths) |path| {
        const content = compat.readFileAbsoluteAlloc(allocator, path, 64 * 1024) catch continue;
        defer allocator.free(content);

        if (parseAwgEndpointIpv4FromConfig(allocator, content)) |ip| return ip;
    }

    return null;
}

fn detectPublicIpv4(allocator: std.mem.Allocator) ?[4]u8 {
    const services = [_][]const u8{
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://ipv4.icanhazip.com",
    };

    for (services) |url| {
        const stdout = http_fetch.fetchUrlBytes(
            allocator,
            url,
            .{ .max_response_bytes = 64 * 1024 },
        ) catch continue;
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        const parsed = parseIpv4Literal(trimmed);
        allocator.free(stdout);
        if (parsed) |ip| return ip;
    }

    return null;
}

fn formatIpv4Bytes(ip: [4]u8, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?.?.?.?";
}

fn ipv4BytesForMiddleProxyKdf(network_order_ip: [4]u8) [4]u8 {
    const value = std.mem.readInt(u32, &network_order_ip, .big);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, value, .little);
    return out;
}

fn ipv4AddressBytesForMiddleProxyKdf(addr: net.Address) [4]u8 {
    var network_order_ip: [4]u8 = undefined;
    @memcpy(&network_order_ip, std.mem.asBytes(&addr.in.sa.addr));
    return ipv4BytesForMiddleProxyKdf(network_order_ip);
}

fn isSameIpEndpoint(a: net.Address, b: net.Address) bool {
    if (a.any.family != b.any.family) return false;

    if (a.any.family == posix.AF.INET) {
        return a.in.sa.addr == b.in.sa.addr and a.in.sa.port == b.in.sa.port;
    }

    if (a.any.family == posix.AF.INET6) {
        return std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr) and a.in6.sa.port == b.in6.sa.port;
    }

    return false;
}

fn defaultMiddleProxyCandidateLists(primary: [5]net.Address) [5][16]net.Address {
    var lists: [5][16]net.Address = undefined;
    for (primary, 0..) |addr, i| {
        lists[i] = [_]net.Address{addr} ** 16;
    }
    return lists;
}

fn copyMiddleProxyCandidates(out: *[16]net.Address, candidates: []const net.Address, preferred: net.Address) usize {
    var count: usize = 0;
    appendUniqueAddress(out, &count, preferred);
    for (candidates) |addr| appendUniqueAddress(out, &count, addr);
    return count;
}

fn promoteMiddleProxyCandidateInList(candidates: *[16]net.Address, candidate_len: usize, addr: net.Address) bool {
    const len = @min(candidate_len, candidates.len);
    var index: usize = 0;
    while (index < len) : (index += 1) {
        if (!isSameIpEndpoint(candidates[index], addr)) continue;
        if (index == 0) return false;

        const promoted = candidates[index];
        while (index > 0) : (index -= 1) {
            candidates[index] = candidates[index - 1];
        }
        candidates[0] = promoted;
        return true;
    }

    return false;
}

fn prioritizeMiddleProxyCandidates(
    candidates: *[16]net.Address,
    candidate_len: usize,
    cooldowns: []const MiddleProxyCooldown,
    now_ms: i64,
) void {
    const len = @min(candidate_len, candidates.len);
    if (len < 2) return;

    const CooledCandidate = struct {
        addr: net.Address,
        until_ms: i64,
    };
    var reordered: [16]net.Address = undefined;
    var healthy_count: usize = 0;
    var cooled: [16]CooledCandidate = undefined;
    var cooled_count: usize = 0;
    for (candidates[0..len]) |addr| {
        if (middleProxyCooldownUntilMs(cooldowns, addr, now_ms)) |until_ms| {
            var insert_at = cooled_count;
            while (insert_at > 0 and cooled[insert_at - 1].until_ms > until_ms) : (insert_at -= 1) {
                cooled[insert_at] = cooled[insert_at - 1];
            }
            cooled[insert_at] = .{ .addr = addr, .until_ms = until_ms };
            cooled_count += 1;
        } else {
            reordered[healthy_count] = addr;
            healthy_count += 1;
        }
    }
    for (cooled[0..cooled_count], 0..) |entry, i| {
        reordered[healthy_count + i] = entry.addr;
    }
    @memcpy(candidates[0..len], reordered[0..len]);
}

fn middleProxyCooldownUntilMs(cooldowns: []const MiddleProxyCooldown, addr: net.Address, now_ms: i64) ?i64 {
    for (cooldowns) |entry| {
        if (entry.active and entry.until_ms > now_ms and isSameIpEndpoint(entry.addr, addr)) return entry.until_ms;
    }
    return null;
}

fn appendUniqueAddress(addrs: *[16]net.Address, count: *usize, addr: net.Address) void {
    if (count.* >= addrs.len) return;
    for (addrs[0..count.*]) |existing| {
        if (isSameIpEndpoint(existing, addr)) return;
    }
    addrs[count.*] = addr;
    count.* += 1;
}

fn prioritizeIpv4Addresses(addrs: []net.Address) void {
    var write: usize = 0;
    var read: usize = 0;
    while (read < addrs.len) : (read += 1) {
        if (addrs[read].any.family != posix.AF.INET) continue;
        if (read != write) {
            const ipv4 = addrs[read];
            std.mem.copyBackwards(net.Address, addrs[write + 1 .. read + 1], addrs[write..read]);
            addrs[write] = ipv4;
        }
        write += 1;
    }
}

fn shouldUseMiddleProxySnapshot(cfg: *const Config, dc_abs: usize, dc_idx: i16) bool {
    if (cfg.datacenter_override != null) return false;
    if (cfg.use_middle_proxy) return true;

    const is_media_path = (dc_idx < 0) or (dc_abs == 203);
    return cfg.force_media_middle_proxy and is_media_path;
}

fn directDcAddressV4(dc_abs: usize) net.Address {
    return constants.getDcAddressV4(dc_abs);
}

fn buildDcConnectPlan(
    cfg: *const Config,
    dc_abs: usize,
    dc_idx: i16,
    snapshot: ?*const ProxyState.MiddleProxySnapshot,
    bypass_middle_proxy: bool,
) DcConnectPlan {
    var plan = DcConnectPlan{};
    if (!constants.isKnownDcV4(dc_abs)) return plan;
    plan.is_media_path = (dc_idx < 0) or (dc_abs == 203);

    if (cfg.datacenter_override) |override| {
        plan.candidates[0] = override;
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    if (bypass_middle_proxy) {
        plan.candidates[0] = directDcAddressV4(dc_abs);
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    var middle_candidates: []const net.Address = &.{};
    if (snapshot) |snap| {
        middle_candidates = snap.candidatesForDc(dc_abs, plan.is_media_path);
        if (middle_candidates.len == 0 and plan.is_media_path) {
            middle_candidates = snap.candidatesForDc(dc_abs, false);
        }
    }
    const middle_addr = if (middle_candidates.len > 0) middle_candidates[0] else null;

    const force_media_middle_proxy = cfg.force_media_middle_proxy and plan.is_media_path and middle_addr != null;
    plan.use_middle_proxy = if (force_media_middle_proxy)
        true
    else
        cfg.use_middle_proxy and middle_addr != null;

    if (!plan.use_middle_proxy) {
        plan.candidates[0] = directDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    for (middle_candidates) |addr| {
        appendUniqueAddress(&plan.candidates, &plan.count, addr);
    }

    if (plan.count == 0 and middle_addr != null) {
        appendUniqueAddress(&plan.candidates, &plan.count, middle_addr.?);
    }

    if (plan.count == 0) {
        // Safety fallback: if cache has no middle-proxy endpoint for this DC,
        // avoid dropping valid users and go direct.
        plan.use_middle_proxy = false;
        plan.candidates[0] = directDcAddressV4(dc_abs);
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    // If middle-proxy connect/handshake fails, retry the same DC via direct mode.
    // This keeps media paths functional in environments where middle-proxy transport
    // itself is degraded (for example due to strict NAT behavior in upstream tunnels).
    plan.direct_fallback = directDcAddressV4(dc_abs);
    return plan;
}

const DcSignFilter = enum {
    any,
    positive_only,
    negative_only,
};

fn parseMiddleProxyAddressesForDc(config_text: []const u8, target_dc: i16, sign: DcSignFilter, out: []net.Address) usize {
    if (out.len == 0) return 0;

    var lines = std.mem.splitScalar(u8, config_text, '\n');
    var count: usize = 0;

    while (lines.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });
        if (line.len == 0 or line[0] == '#') continue;
        if (line[line.len - 1] == ';') line = line[0 .. line.len - 1];

        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const keyword = parts.next() orelse continue;
        if (!std.mem.eql(u8, keyword, "proxy_for")) continue;

        const dc_text = parts.next() orelse continue;
        const host_port = parts.next() orelse continue;

        const dc_idx = std.fmt.parseInt(i16, dc_text, 10) catch continue;
        const abs_target: i16 = if (target_dc < 0) -target_dc else target_dc;
        switch (sign) {
            .any => if (dc_idx != abs_target and dc_idx != -abs_target) continue,
            .positive_only => if (dc_idx != abs_target) continue,
            .negative_only => if (dc_idx != -abs_target) continue,
        }

        const parsed = net.Address.parseIpAndPort(host_port) catch continue;

        var dup = false;
        for (out[0..count]) |existing| {
            if (existing.eql(parsed)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        out[count] = parsed;
        count += 1;
        if (count == out.len) break;
    }

    return count;
}

fn trySelectReachableMiddleProxy(
    candidates: []const net.Address,
    timeout_ms: i32,
    stop: ?*const std.atomic.Value(bool),
) ?net.Address {
    for (candidates) |addr| {
        if (stop) |flag| {
            if (flag.load(.acquire)) return null;
        }
        if (isAddressReachable(addr, timeout_ms, stop)) return addr;
    }
    return null;
}

fn addressesEqual(a: []const net.Address, b: []const net.Address) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!lhs.eql(rhs)) return false;
    }
    return true;
}

fn isAddressReachable(address: net.Address, timeout_ms: i32, stop: ?*const std.atomic.Value(bool)) bool {
    if (builtin.os.tag != .linux) return false;

    const sock_flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const socket_rc = linux.socket(@intCast(address.any.family), sock_flags, linux.IPPROTO.TCP);
    const fd: linux.fd_t = switch (posix.errno(socket_rc)) {
        .SUCCESS => @intCast(socket_rc),
        else => return false,
    };
    defer _ = linux.close(fd);

    const connect_rc = linux.connect(fd, &address.any, @intCast(address.getOsSockLen()));
    switch (posix.errno(connect_rc)) {
        .SUCCESS => {},
        .AGAIN, .INPROGRESS => {},
        else => return false,
    }

    var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    var remaining_ms = @max(timeout_ms, 0);
    while (true) {
        if (stop) |flag| {
            if (flag.load(.acquire)) return false;
        }
        const chunk_ms = @min(remaining_ms, 100);
        fds[0].revents = 0;
        const poll_rc = linux.poll(&fds, fds.len, chunk_ms);
        const ready = switch (posix.errno(poll_rc)) {
            .SUCCESS => poll_rc,
            .INTR => continue,
            else => return false,
        };
        if (ready > 0) break;
        if (remaining_ms <= chunk_ms) return false;
        remaining_ms -= chunk_ms;
    }

    const revents = fds[0].revents;
    if ((revents & linux.POLL.OUT) == 0) return false;
    if ((revents & (linux.POLL.ERR | linux.POLL.HUP | linux.POLL.NVAL)) != 0) return false;

    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const opt_rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    switch (posix.errno(opt_rc)) {
        .SUCCESS => {},
        else => return false,
    }
    return err_code == 0;
}

fn parseMiddleProxyAddressForDc(config_text: []const u8, target_dc: i16) ?net.Address {
    var one: [1]net.Address = undefined;
    const sign: DcSignFilter = if (target_dc < 0) .negative_only else .positive_only;
    const n = parseMiddleProxyAddressesForDc(config_text, target_dc, sign, &one);
    if (n == 0) return null;
    return one[0];
}

fn queueOrWriteMsg(fd: posix.fd_t, queue: *MessageQueue, data: []const u8) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = writeFd(fd, data) catch |err| {
            if (err == error.WouldBlock) {
                try queue.appendCopy(data);
                return false;
            }
            return err;
        };

        if (n == data.len) return true;
        try queue.appendCopy(data[n..]);
        return false;
    }

    try queue.appendCopy(data);
    return false;
}

fn queueOrWriteMsgPair(fd: posix.fd_t, queue: *MessageQueue, first: []const u8, second: []const u8) !bool {
    if (first.len == 0 and second.len == 0) return true;

    if (queue.isEmpty()) {
        var iovecs: [2]posix.iovec_const = undefined;
        var n_iov: usize = 0;
        if (first.len > 0) {
            iovecs[n_iov] = .{ .base = first.ptr, .len = first.len };
            n_iov += 1;
        }
        if (second.len > 0) {
            iovecs[n_iov] = .{ .base = second.ptr, .len = second.len };
            n_iov += 1;
        }

        const total_len = first.len + second.len;
        const n = writevFd(fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) {
                try queue.ensureCanAppend(total_len);
                try queue.appendCopy(first);
                try queue.appendCopy(second);
                return false;
            }
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        if (n == total_len) return true;

        if (n < first.len) {
            try queue.ensureCanAppend(first.len - n + second.len);
            try queue.appendCopy(first[n..]);
            try queue.appendCopy(second);
            return false;
        }

        const consumed_second = n - first.len;
        if (consumed_second < second.len) {
            try queue.appendCopy(second[consumed_second..]);
        }
        return false;
    }

    try queue.ensureCanAppend(first.len + second.len);
    try queue.appendCopy(first);
    try queue.appendCopy(second);
    return false;
}

fn flushQueue(fd: posix.fd_t, queue: *MessageQueue) !usize {
    if (queue.isEmpty()) return 0;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;
    var total_written: usize = 0;

    while (!queue.isEmpty()) {
        const n_iov = queue.prepareIovecs(iovecs[0..]);
        if (n_iov == 0) return total_written;

        const n = writevFd(fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) return total_written;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        try queue.consume(n);
        total_written += n;

        if (n < iovecs[0].len) return total_written;
    }

    return total_written;
}

fn queueClient(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot.client_fd, &slot.client_queue, data);
}

fn queueClientPair(slot: *ConnectionSlot, first: []const u8, second: []const u8) !bool {
    return queueOrWriteMsgPair(slot.client_fd, &slot.client_queue, first, second);
}

fn queueUpstream(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot.upstream_fd, &slot.upstream_queue, data);
}

fn flushClientPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot.client_fd, &slot.client_queue);
}

fn flushUpstreamPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot.upstream_fd, &slot.upstream_queue);
}

fn mpReadReset(slot: *ConnectionSlot, encrypted: bool) void {
    slot.mp_frame_have = 0;
    slot.mp_frame_total_len = 0;
    slot.mp_frame_padded_len = 0;
    slot.mp_frame_encrypted = encrypted;
    slot.mp_frame_first_decrypted = false;
    slot.mp_frame_need = if (encrypted) 16 else 4;
}

fn writePlainMiddleProxyTestFrame(fd: posix.fd_t, seq_no: i32, payload: []const u8) !void {
    var frame: [mp_handshake_frame_buf_size]u8 = undefined;
    const total_len = payload.len + 12;
    if (total_len > frame.len) return error.BadMiddleProxyFrameSize;

    std.mem.writeInt(u32, frame[0..4], @intCast(total_len), .little);
    std.mem.writeInt(i32, frame[4..8], seq_no, .little);
    @memcpy(frame[8 .. 8 + payload.len], payload);
    const checksum = middleproxy.crc32(frame[0 .. 8 + payload.len]);
    std.mem.writeInt(u32, frame[8 + payload.len ..][0..4], checksum, .little);

    const written = try writeFd(fd, frame[0..total_len]);
    try std.testing.expectEqual(total_len, written);
}

test "parse middle proxy address for dc203" {
    const cfg =
        "# force_probability 10 10\n" ++
        "default 2;\n" ++
        "proxy_for 1 149.154.175.50:8888;\n" ++
        "proxy_for 203 91.105.192.110:443;\n" ++
        "proxy_for -203 91.105.192.110:443;\n";

    const addr = parseMiddleProxyAddressForDc(cfg, 203) orelse return error.TestExpectedEqual;
    try std.testing.expect(addr.any.family == posix.AF.INET);
    try std.testing.expectEqual(@as(u16, 443), std.mem.bigToNative(u16, addr.in.sa.port));
}

test "middle proxy nonce response failures fall back to direct path" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .datacenter_override = net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tmp_io_state = compat.initThreadedIo();
    defer tmp_io_state.deinit();
    const tmp_io = tmp_io_state.io();

    var upstream_file = try tmp.dir.createFile(tmp_io, "middle-proxy-upstream", .{ .read = true });
    var upstream_file_owned = true;
    defer if (upstream_file_owned) upstream_file.close(tmp_io);

    const epoll_fd = try epollCreate();
    defer closeFd(epoll_fd);

    var loop = EventLoop{
        .state = &state,
        .epoll_fd = epoll_fd,
        .listen_fd = invalid_fd,
        .pool = try ConnectionPool.init(std.testing.allocator, 4),
        .accept_paused = false,
        .accept_resume_ns = 0,
        .saturation_paused = false,
        .timer_scan_cursor = 0,
        .stats_next_log_ns = 0,
        .accepted_since_log = 0,
        .closed_since_log = 0,
        .subnet_limiter = SubnetRateLimit.init(),
        .subnet_handshakes = SubnetHandshakeLimit.init(),
        .prev_dropped_cap = 0,
        .prev_dropped_saturation = 0,
        .prev_dropped_rate_limit = 0,
        .prev_dropped_hs_budget = 0,
        .prev_hs_timeout = 0,
        .prev_mp_fallback = 0,
        .mp_c2s_scratch = null,
        .mp_s2c_scratch = null,
        .pending_close_fds = .empty,
    };
    defer {
        loop.drainPendingCloses();
        loop.pending_close_fds.deinit(std.testing.allocator);
        loop.pool.deinit();
    }

    const slot = loop.pool.acquire() orelse return error.TestExpectedEqual;
    defer {
        if (slot.phase != .idle) {
            if (!isInvalidFd(slot.upstream_fd)) {
                closeFd(slot.upstream_fd);
                slot.upstream_fd = invalid_fd;
            }
            slot.resetOwnedBuffers(state.allocator);
            loop.pool.release(slot);
        }
    }

    var fallback_server = try net.Address.initIp4(.{ 127, 0, 0, 1 }, 0).listen(.{
        .reuse_address = true,
        .kernel_backlog = 1,
    });
    defer fallback_server.deinit();

    var fallback_addr: net.Address = undefined;
    var fallback_len: posix.socklen_t = @sizeOf(net.Address);
    try getsocknameFd(fallback_server.stream.handle, &fallback_addr.any, &fallback_len);

    slot.conn_id = 42;
    slot.upstream_fd = upstream_file.handle;
    upstream_file_owned = false;
    slot.phase = .middle_proxy_handshake;
    slot.mp_step = .waiting_rpc_nonce_response;
    slot.mp_read_seq_no = -2;
    slot.use_middle_proxy = true;
    slot.direct_fallback_addr = fallback_addr;
    slot.current_upstream_addr = fallback_addr;
    slot.dc_abs = 4;
    slot.obf_params = .{
        .decrypt_key = [_]u8{0} ** constants.key_len,
        .decrypt_iv = 0,
        .encrypt_key = [_]u8{0} ** constants.key_len,
        .encrypt_iv = 0,
        .proto_tag = .intermediate,
        .dc_idx = 4,
    };
    mpReadReset(slot, false);

    var bad_nonce_payload = [_]u8{0} ** 32;
    @memcpy(bad_nonce_payload[0..4], &middleproxy.rpc_proxy_ans);
    try writePlainMiddleProxyTestFrame(upstream_file.handle, -2, &bad_nonce_payload);
    try seekFdToStart(upstream_file.handle);

    loop.middleProxyOnReadable(slot);

    try std.testing.expect(slot.direct_fallback_used);
    try std.testing.expect(!slot.use_middle_proxy);
    try std.testing.expectEqual(MiddleProxyHandshakeStep.none, slot.mp_step);
    try std.testing.expectEqual(UpstreamKind.dc, slot.upstream_kind);
    try std.testing.expect(slot.upstream_candidates != null);
    try std.testing.expect(slot.current_upstream_addr.?.eql(fallback_addr));
    try std.testing.expect(slot.phase == .connecting_upstream or slot.phase == .writing_dc_nonce);
    try std.testing.expectEqual(@as(u64, 1), state.stats_mp_fallback.load(.monotonic));
}

fn initProxyStateAndDeinit(allocator: std.mem.Allocator, cfg: Config) !void {
    var state = try ProxyState.init(allocator, cfg);
    defer state.deinit();
}

test "proxy state init propagates user secret allocation failures" {
    const cfg_text =
        \\[general]
        \\use_middle_proxy = false
        \\force_media_middle_proxy = false
        \\[server]
        \\public_ip = "127.0.0.1"
        \\[censorship]
        \\mask = false
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, cfg_text);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, initProxyStateAndDeinit, .{cfg});
}

test "media-only middle-proxy mode requests metadata for negative media DCs" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    cfg.use_middle_proxy = false;
    cfg.force_media_middle_proxy = true;

    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 4, -4));
    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 203, -203));
    try std.testing.expect(!shouldUseMiddleProxySnapshot(&cfg, 4, 4));

    cfg.force_media_middle_proxy = false;
    try std.testing.expect(!shouldUseMiddleProxySnapshot(&cfg, 4, -4));

    cfg.use_middle_proxy = true;
    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 4, 4));

    cfg.datacenter_override = net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    try std.testing.expect(!shouldUseMiddleProxySnapshot(&cfg, 4, -4));
}

test "middle proxy updater stop joins sleeping thread" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    cfg.use_middle_proxy = false;
    cfg.force_media_middle_proxy = false;
    cfg.mask = false;
    cfg.datacenter_override = net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);

    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    state.startMiddleProxyUpdater();
    try std.testing.expect(state.middle_proxy_updater_thread != null);
    state.stopMiddleProxyUpdater();
    try std.testing.expect(state.middle_proxy_updater_thread == null);
}

test "direct users bypass middle-proxy routing" {
    const cfg_text =
        \\[general]
        \\use_middle_proxy = true
        \\[access.users]
        \\admin = "00112233445566778899aabbccddeeff"
        \\regular = "ffeeddccbbaa99887766554433221100"
        \\[access.direct_users]
        \\admin = true
    ;

    var cfg = try Config.parse(std.testing.allocator, cfg_text);
    defer cfg.deinit(std.testing.allocator);

    const mp_dc4 = net.Address.initIp4(.{ 11, 11, 11, 11 }, 443);
    const mp_dc203 = net.Address.initIp4(.{ 12, 12, 12, 12 }, 443);
    const mp_media_dc5_secondary = net.Address.initIp4(.{ 13, 13, 13, 13 }, 443);
    var media_candidates = defaultMiddleProxyCandidateLists(constants.tg_media_middle_proxies_v4);
    media_candidates[4][1] = mp_media_dc5_secondary;
    const snapshot = ProxyState.MiddleProxySnapshot{
        .candidates = defaultMiddleProxyCandidateLists(.{
            constants.tg_middle_proxies_v4[0],
            constants.tg_middle_proxies_v4[1],
            constants.tg_middle_proxies_v4[2],
            mp_dc4,
            constants.tg_middle_proxies_v4[4],
        }),
        .candidate_lens = [_]usize{1} ** 5,
        .media_candidates = media_candidates,
        .media_candidate_lens = .{ 1, 1, 1, 1, 2 },
        .candidates_203 = [_]net.Address{mp_dc203} ** 16,
        .candidates_203_len = 1,
        .secret = [_]u8{0} ** 256,
        .secret_len = 16,
    };

    const regular_plan = buildDcConnectPlan(&cfg, 4, 4, &snapshot, false);
    try std.testing.expect(regular_plan.use_middle_proxy);
    try std.testing.expect(regular_plan.direct_fallback != null);
    try std.testing.expect(regular_plan.candidates[0].eql(mp_dc4));

    const admin_plan = buildDcConnectPlan(&cfg, 4, 4, &snapshot, true);
    try std.testing.expect(!admin_plan.use_middle_proxy);
    try std.testing.expect(admin_plan.direct_fallback == null);
    try std.testing.expect(admin_plan.candidates[0].eql(constants.getDcAddressV4(4)));

    const regular_media = buildDcConnectPlan(&cfg, 203, -203, &snapshot, false);
    try std.testing.expect(regular_media.use_middle_proxy);
    try std.testing.expect(regular_media.candidates[0].eql(mp_dc203));

    const regular_media_dc5 = buildDcConnectPlan(&cfg, 5, -5, &snapshot, false);
    try std.testing.expectEqual(@as(usize, 2), regular_media_dc5.count);
    try std.testing.expect(regular_media_dc5.candidates[1].eql(mp_media_dc5_secondary));

    const admin_media = buildDcConnectPlan(&cfg, 203, -203, &snapshot, true);
    try std.testing.expect(!admin_media.use_middle_proxy);
    try std.testing.expect(admin_media.candidates[0].eql(constants.getDcAddressV4(203)));
}

test "unknown datacenter indices produce no connect plan" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    const plan = buildDcConnectPlan(&cfg, 6, 6, null, false);
    try std.testing.expectEqual(@as(usize, 0), plan.count);
    try std.testing.expect(!plan.use_middle_proxy);
    try std.testing.expect(plan.direct_fallback == null);
}

test "DRS disabled skips ramp and uses full TLS record size" {
    var drs = DynamicRecordSizer.init(false);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
    for (0..32) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "DRS enabled ramps" {
    var drs = DynamicRecordSizer.init(true);
    for (0..8) |_| drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
    const records_at_ramp = drs.records_sent;
    const bytes_at_ramp = drs.bytes_sent;
    drs.recordSent(std.math.maxInt(usize));
    try std.testing.expectEqual(records_at_ramp, drs.records_sent);
    try std.testing.expectEqual(bytes_at_ramp, drs.bytes_sent);
}

test "message queue consume is stable" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    try q.appendCopy("defg");
    try std.testing.expectEqual(@as(usize, 7), q.total_len);

    try q.consume(2);
    try std.testing.expectEqual(@as(usize, 5), q.total_len);

    var iov: [8]posix.iovec_const = undefined;
    const n = q.prepareIovecs(iov[0..]);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 'c'), iov[0].base[0]);

    try q.consume(5);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.offset);
    try std.testing.expectEqual(@as(usize, 0), q.head_idx);
}

test "message queue uses compact block storage per class" {
    try std.testing.expect(@sizeOf(TinyMsgBlock) < @sizeOf(StandardMsgBlock));
    try std.testing.expect(@sizeOf(SmallMsgBlock) < @sizeOf(StandardMsgBlock));

    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    var tiny_payload: [tiny_block_size]u8 = [_]u8{0} ** tiny_block_size;
    try q.appendCopy(&tiny_payload);
    try std.testing.expectEqual(MsgBlockClass.tiny, q.blocks.items[0].class);
    try std.testing.expectEqual(@as(usize, tiny_block_size), blockStorageConst(q.blocks.items[0]).len);
    q.clear();

    var small_payload: [small_block_size]u8 = [_]u8{1} ** small_block_size;
    try q.appendCopy(&small_payload);
    try std.testing.expectEqual(MsgBlockClass.small, q.blocks.items[0].class);
    try std.testing.expectEqual(@as(usize, small_block_size), blockStorageConst(q.blocks.items[0]).len);
    q.clear();

    var standard_payload: [small_block_size + 1]u8 = [_]u8{2} ** (small_block_size + 1);
    try q.appendCopy(&standard_payload);
    try std.testing.expectEqual(MsgBlockClass.standard, q.blocks.items[0].class);
    try std.testing.expectEqual(@as(usize, standard_block_size), blockStorageConst(q.blocks.items[0]).len);
}

test "message queue rejects pending byte overflow" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    q.total_len = MessageQueue.max_pending_bytes;
    try std.testing.expectError(error.PendingQueueOverflow, q.ensureCanAppend(1));
    q.total_len = 0;
}

test "message queue trims retained standard free blocks after traffic spike" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    const payload_len = (MessageQueue.max_free_standard_blocks + 8) * standard_block_size;
    const payload = try std.testing.allocator.alloc(u8, payload_len);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0xA5);

    try q.appendCopy(payload);
    try q.consume(payload.len);

    try std.testing.expect(q.isEmpty());
    try std.testing.expect(q.std_free.items.len <= MessageQueue.max_free_standard_blocks);
}

test "epoll hangup helper" {
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.HUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.ERR));
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.IN));
    try std.testing.expect(hasGracefulEpollRdhup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasGracefulEpollRdhup(linux.EPOLL.RDHUP | linux.EPOLL.IN));
    try std.testing.expect(!hasGracefulEpollRdhup(linux.EPOLL.RDHUP | linux.EPOLL.HUP));
    try std.testing.expect(!hasGracefulEpollRdhup(linux.EPOLL.RDHUP | linux.EPOLL.ERR));
}

test "fatal hangup close policy distinguishes client/upstream while connecting" {
    const client_fd = fakeFd(41);
    const upstream_fd = fakeFd(42);

    try std.testing.expect(shouldCloseOnFatalHangup(.connecting_upstream, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.reading_tls_header, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.idle, client_fd, upstream_fd));
}

test "fatal middle-proxy upstream hangup is fallback eligible" {
    const client_fd = fakeFd(41);
    const upstream_fd = fakeFd(42);

    try std.testing.expect(shouldFallbackMiddleProxyOnFatalHangup(.middle_proxy_handshake, upstream_fd, upstream_fd));
    try std.testing.expect(!shouldFallbackMiddleProxyOnFatalHangup(.middle_proxy_handshake, client_fd, upstream_fd));
    try std.testing.expect(!shouldFallbackMiddleProxyOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.middle_proxy_handshake, upstream_fd, upstream_fd));
}

test "jittered idle timeout keeps zero jitter exact" {
    try std.testing.expectEqual(secondsToMs(120), jitteredIdleTimeoutMs(120, 0, 12345));
}

test "connect timeout shares handshake budget across candidates" {
    try std.testing.expectEqual(
        @as(i64, 7000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 2_000, 2),
    );
    try std.testing.expectEqual(
        @as(i64, 10_000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 2_000, 1),
    );
    try std.testing.expectEqual(
        @as(i64, 0),
        budgetedConnectTimeoutMs(0, 1_000, 15_000, 2_000, 2),
    );
}

test "successful middle-proxy fallback candidate is promoted" {
    const first = net.Address.initIp4(.{ 11, 11, 11, 11 }, 443);
    const second = net.Address.initIp4(.{ 12, 12, 12, 12 }, 443);
    const third = net.Address.initIp4(.{ 13, 13, 13, 13 }, 443);
    var candidates = [_]net.Address{ first, second, third } ++ ([_]net.Address{first} ** 13);

    try std.testing.expect(promoteMiddleProxyCandidateInList(&candidates, 3, second));
    try std.testing.expect(candidates[0].eql(second));
    try std.testing.expect(candidates[1].eql(first));
    try std.testing.expect(candidates[2].eql(third));
    try std.testing.expect(!promoteMiddleProxyCandidateInList(&candidates, 3, second));
}

test "middle-proxy cooldown prioritizes healthy candidates" {
    const first = net.Address.initIp4(.{ 11, 11, 11, 11 }, 443);
    const second = net.Address.initIp4(.{ 12, 12, 12, 12 }, 443);
    var candidates = [_]net.Address{ first, second } ++ ([_]net.Address{first} ** 14);
    var cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots;
    cooldowns[0] = .{ .active = true, .addr = first, .until_ms = 200 };

    prioritizeMiddleProxyCandidates(&candidates, 2, &cooldowns, 100);
    try std.testing.expect(candidates[0].eql(second));
    try std.testing.expect(candidates[1].eql(first));
}

test "middle-proxy cooldown tries earliest recovery first when all cooled" {
    const first = net.Address.initIp4(.{ 11, 11, 11, 11 }, 443);
    const second = net.Address.initIp4(.{ 12, 12, 12, 12 }, 443);
    const third = net.Address.initIp4(.{ 13, 13, 13, 13 }, 443);
    var candidates = [_]net.Address{ first, second, third } ++ ([_]net.Address{first} ** 13);
    var cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots;
    cooldowns[0] = .{ .active = true, .addr = first, .until_ms = 300 };
    cooldowns[1] = .{ .active = true, .addr = second, .until_ms = 200 };
    cooldowns[2] = .{ .active = true, .addr = third, .until_ms = 250 };

    prioritizeMiddleProxyCandidates(&candidates, 3, &cooldowns, 100);
    try std.testing.expect(candidates[0].eql(second));
    try std.testing.expect(candidates[1].eql(third));
    try std.testing.expect(candidates[2].eql(first));
}

test "jittered idle timeout stays bounded" {
    const base_ms = secondsToMs(120);
    const range_ms = @divTrunc(base_ms * 15, 100);

    var seed: u64 = 0;
    while (seed < 128) : (seed += 1) {
        const value = jitteredIdleTimeoutMs(120, 15, seed *% 0x9E37_79B9_7F4A_7C15);
        try std.testing.expect(value >= base_ms - range_ms);
        try std.testing.expect(value <= base_ms + range_ms);
    }

    try std.testing.expectEqual(secondsToMs(5), jitteredIdleTimeoutMs(5, 100, 0));
}

test "fd requirement helpers" {
    try std.testing.expectEqual(@as(usize, 131582), requiredFdsForConnections(65535));
    try std.testing.expectEqual(@as(u32, 65535), maxConnectionsForNofile(131582));
    try std.testing.expectEqual(@as(u32, 32511), maxConnectionsForNofile(65535));
    try std.testing.expectEqual(@as(u32, 32), maxConnectionsForNofile(requiredFdsForConnections(32)));
    try std.testing.expectEqual(@as(u32, 0), maxConnectionsForNofile(requiredFdsForConnections(32) - 1));
}

test "accept listen interest stays disabled while any pause reason is active" {
    try std.testing.expect(shouldAcceptListen(false, false));
    try std.testing.expect(!shouldAcceptListen(true, false));
    try std.testing.expect(!shouldAcceptListen(false, true));
    try std.testing.expect(!shouldAcceptListen(true, true));
}

test "parse ipv4 literal" {
    const parsed = parseIpv4Literal("179.43.141.146") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
    try std.testing.expect(parseIpv4Literal("179.43.141") == null);
    try std.testing.expect(parseIpv4Literal("179.43.141.999") == null);
}

test "middle proxy ipv4 kdf bytes are endian explicit" {
    try std.testing.expectEqual([4]u8{ 146, 141, 43, 179 }, ipv4BytesForMiddleProxyKdf(.{ 179, 43, 141, 146 }));
}

test "parse endpoint host" {
    try std.testing.expectEqualStrings("179.43.141.146", parseEndpointHost("179.43.141.146:41182").?);
    try std.testing.expectEqualStrings("vpn.example.com", parseEndpointHost("vpn.example.com:51820").?);
    try std.testing.expectEqualStrings("2001:db8::1", parseEndpointHost("[2001:db8::1]:41182").?);
}

test "parse awg endpoint ipv4 from config" {
    const content =
        \\[Interface]
        \\Address = 100.83.12.60/32
        \\
        \\[Peer]
        \\PublicKey = x
        \\Endpoint = 179.43.141.146:41182
    ;

    const parsed = parseAwgEndpointIpv4FromConfig(std.testing.allocator, content) orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
}

test "subnet rate limit - subnet key groups /24 IPv4" {
    // 10.0.1.5 and 10.0.1.200 should have the same /24 key
    const addr1 = net.Address.initIp4(.{ 10, 0, 1, 5 }, 443);
    const addr2 = net.Address.initIp4(.{ 10, 0, 1, 200 }, 443);
    const addr3 = net.Address.initIp4(.{ 10, 0, 2, 5 }, 443);

    const key1 = SubnetRateLimit.subnetKey(addr1);
    const key2 = SubnetRateLimit.subnetKey(addr2);
    const key3 = SubnetRateLimit.subnetKey(addr3);

    try std.testing.expectEqual(key1, key2); // same /24
    try std.testing.expect(key1 != key3); // different /24
}

test "subnet rate limit - IPv4-mapped IPv6 keys match native IPv4 /24" {
    const native_v4 = net.Address.initIp4(.{ 203, 0, 113, 42 }, 443);

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 42 };
    const mapped = net.Address.initIp6(mapped_bytes, 443, 0, 0);

    const native_key = SubnetRateLimit.subnetKey(native_v4);
    const mapped_key = SubnetRateLimit.subnetKey(mapped);
    try std.testing.expectEqual(native_key, mapped_key);

    const mapped_other_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 198, 51, 100, 1 };
    const mapped_other = net.Address.initIp6(mapped_other_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(mapped_other) != mapped_key);

    const native6_bytes = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const native6 = net.Address.initIp6(native6_bytes, 443, 0, 0);
    try std.testing.expect(SubnetRateLimit.subnetKey(native6) != mapped_key);
}

test "subnet rate limit - preserves every IPv6 /48 prefix bit" {
    const prefix_a = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00 } ++ [_]u8{0} ** 10;
    const prefix_b = [_]u8{ 0x20, 0x01, 0x0d, 0xb9, 0x00, 0x01 } ++ [_]u8{0} ** 10;
    const addr_a = net.Address.initIp6(prefix_a, 443, 0, 0);
    const addr_b = net.Address.initIp6(prefix_b, 443, 0, 0);

    try std.testing.expect(SubnetRateLimit.subnetKey(addr_a) != SubnetRateLimit.subnetKey(addr_b));
}

test "subnet rate limit - allows up to max then blocks" {
    var limiter = SubnetRateLimit{};
    const addr = net.Address.initIp4(.{ 192, 168, 1, 100 }, 443);

    // max_per_sec = 3 → should allow 3 then block
    // First call resets entry with tokens = max-1 = 2, returns true
    try std.testing.expect(limiter.check(addr, 3));
    // Two more with existing tokens
    try std.testing.expect(limiter.check(addr, 3));
    try std.testing.expect(limiter.check(addr, 3));
    // Now should be blocked
    try std.testing.expect(!limiter.check(addr, 3));
    try std.testing.expect(!limiter.check(addr, 3));
}

test "subnet rate limit - disabled when max_per_sec is 0" {
    var limiter = SubnetRateLimit{};
    const addr = net.Address.initIp4(.{ 1, 2, 3, 4 }, 443);

    // With max_per_sec = 0, always allows
    for (0..100) |_| {
        try std.testing.expect(limiter.check(addr, 0));
    }
}

test "subnet rate limit - stale entry resets" {
    var limiter = SubnetRateLimit{};
    const addr = net.Address.initIp4(.{ 10, 20, 30, 40 }, 443);

    // Drain tokens
    _ = limiter.check(addr, 1);
    try std.testing.expect(!limiter.check(addr, 1));

    // Make entry stale (>60s old)
    const key = SubnetRateLimit.subnetKey(addr);
    const entry = limiter.findEntry(key) orelse return error.TestExpectedEqual;
    entry.last_refill_s -= SubnetRateLimit.stale_after_s + 1;

    // Should reset and allow again
    try std.testing.expect(limiter.check(addr, 1));
}

test "subnet rate limit - live probe window is not evicted" {
    var limiter = SubnetRateLimit{};
    const addr = net.Address.initIp4(.{ 203, 0, 113, 42 }, 443);
    const key = SubnetRateLimit.subnetKey(addr);
    const start = limiter.indexFor(key);
    const now_s = @divTrunc(compat.monotonicMilliTimestamp(), 1000);

    var probe: usize = 0;
    while (probe < SubnetRateLimit.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (SubnetRateLimit.BUCKETS - 1);
        limiter.entries[idx] = .{
            .used = true,
            .subnet_key = 0x80000000 + @as(u64, @intCast(probe)),
            .tokens = 1,
            .last_refill_s = now_s,
        };
    }

    try std.testing.expect(!limiter.check(addr, 1));

    probe = 0;
    while (probe < SubnetRateLimit.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (SubnetRateLimit.BUCKETS - 1);
        try std.testing.expectEqual(0x80000000 + @as(u64, @intCast(probe)), limiter.entries[idx].subnet_key);
    }
}

test "subnet rate limit - different subnets are independent" {
    var limiter = SubnetRateLimit{};
    const addr_a = net.Address.initIp4(.{ 10, 0, 1, 100 }, 443);
    const addr_b = net.Address.initIp4(.{ 10, 0, 2, 100 }, 443);

    // Drain subnet A
    _ = limiter.check(addr_a, 1);
    try std.testing.expect(!limiter.check(addr_a, 1));

    // Subnet B should still work
    try std.testing.expect(limiter.check(addr_b, 1));
}

test "replay cache detects duplicate digest" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0xAB} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest));
    try std.testing.expect(cache.checkAndInsert(&digest));
}

test "replay cache accepts distinct digests" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    const digest_b = [_]u8{0x22} ** 32;

    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
}

test "replay cache compares full digest on key collision" {
    var cache = ReplayCache.init();
    const digest_a = [_]u8{0x11} ** 32;
    var digest_b = digest_a;
    digest_b[31] ^= 0xff;

    try std.testing.expectEqual(ReplayCache.digestKey(&digest_a), ReplayCache.digestKey(&digest_b));
    try std.testing.expect(!cache.checkAndInsert(&digest_a));
    try std.testing.expect(!cache.checkAndInsert(&digest_b));
    try std.testing.expect(cache.checkAndInsert(&digest_a));
    try std.testing.expect(cache.checkAndInsert(&digest_b));
}

test "replay cache never evicts a live probe window" {
    var cache = ReplayCache.init();
    const digest = [_]u8{0x5a} ** 32;
    const start = cache.indexFor(ReplayCache.digestKey(&digest));
    const now_s = @divTrunc(compat.monotonicMilliTimestamp(), 1000);

    var probe: usize = 0;
    while (probe < ReplayCache.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (ReplayCache.BUCKETS - 1);
        var occupied_digest = [_]u8{0} ** 32;
        @memset(&occupied_digest, @intCast(probe + 1));
        cache.entries[idx] = .{
            .used = true,
            .key = @as(u64, @intCast(probe + 1)),
            .digest = occupied_digest,
            .last_seen_s = now_s,
        };
    }

    // A saturated live window fails closed instead of weakening replay protection.
    try std.testing.expect(cache.checkAndInsert(&digest));
    probe = 0;
    while (probe < ReplayCache.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (ReplayCache.BUCKETS - 1);
        try std.testing.expectEqual(@as(u64, @intCast(probe + 1)), cache.entries[idx].key);
    }
}

test "handshakeInProgress - phases" {
    var slot: ConnectionSlot = undefined;

    const hs_phases = [_]ConnectionPhase{
        .reading_tls_header,
        .reading_client_hello_body,
        .writing_server_hello_first,
        .desync_wait,
        .writing_server_hello_rest,
        .reading_mtproto_tls_header,
        .reading_mtproto_tls_body,
        .connecting_upstream,
        .writing_dc_nonce,
        .middle_proxy_handshake,
    };
    for (hs_phases) |phase| {
        slot.phase = phase;
        try std.testing.expect(slot.handshakeInProgress());
    }

    // Non-handshake phases
    slot.phase = .idle;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .mask_relaying;
    try std.testing.expect(!slot.handshakeInProgress());
    slot.phase = .closing;
    try std.testing.expect(!slot.handshakeInProgress());
}

test "handshake budget is charged once after the first client byte" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 10,
        .mask = false,
        .datacenter_override = net.Address.initIp4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    var loop = EventLoop{
        .state = &state,
        .epoll_fd = invalid_fd,
        .listen_fd = invalid_fd,
        .pool = try ConnectionPool.init(std.testing.allocator, 1),
        .accept_paused = false,
        .accept_resume_ns = 0,
        .saturation_paused = false,
        .timer_scan_cursor = 0,
        .stats_next_log_ns = 0,
        .accepted_since_log = 0,
        .closed_since_log = 0,
        .subnet_limiter = SubnetRateLimit.init(),
        .subnet_handshakes = SubnetHandshakeLimit.init(),
        .prev_dropped_cap = 0,
        .prev_dropped_saturation = 0,
        .prev_dropped_rate_limit = 0,
        .prev_dropped_hs_budget = 0,
        .prev_hs_timeout = 0,
        .prev_mp_fallback = 0,
        .mp_c2s_scratch = null,
        .mp_s2c_scratch = null,
        .pending_close_fds = .empty,
    };
    defer {
        loop.pending_close_fds.deinit(std.testing.allocator);
        loop.pool.deinit();
    }

    const slot = loop.pool.acquire() orelse return error.TestExpectedEqual;
    defer loop.pool.release(slot);

    try std.testing.expectEqual(@as(u32, 0), state.handshakes_inflight.load(.monotonic));
    try std.testing.expect(loop.reserveHandshakeBudget(slot));
    try std.testing.expect(slot.hs_counted);
    try std.testing.expectEqual(@as(u32, 1), state.handshakes_inflight.load(.monotonic));

    try std.testing.expect(loop.reserveHandshakeBudget(slot));
    try std.testing.expectEqual(@as(u32, 1), state.handshakes_inflight.load(.monotonic));

    loop.releaseHandshakeBudget(slot);
    loop.releaseHandshakeBudget(slot);
    try std.testing.expect(!slot.hs_counted);
    try std.testing.expectEqual(@as(u32, 0), state.handshakes_inflight.load(.monotonic));
}

test "subnet handshake limit bounds and releases unauthenticated slots" {
    var limiter = SubnetHandshakeLimit.init();
    limiter.hash_seed = 0;
    const key: u64 = 0x010203;

    try std.testing.expect(limiter.reserve(key, 2));
    try std.testing.expect(limiter.reserve(key, 2));
    try std.testing.expect(!limiter.reserve(key, 2));

    limiter.release(key);
    try std.testing.expect(limiter.reserve(key, 2));
    limiter.release(key);
    limiter.release(key);
}

test "subnet handshake limit scales within defensive bounds" {
    try std.testing.expectEqual(@as(u16, 16), subnetHandshakeLimit(32));
    try std.testing.expectEqual(@as(u16, 64), subnetHandshakeLimit(512));
    try std.testing.expectEqual(@as(u16, 128), subnetHandshakeLimit(100_000));
}
