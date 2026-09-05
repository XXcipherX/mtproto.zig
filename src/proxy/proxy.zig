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
const web_support = @import("web_support.zig");

const log = std.log.scoped(.proxy);

const tls_header_len = 5;
const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
const event_io_byte_budget: usize = 256 * 1024;
const event_io_operation_budget: usize = 64;
const queue_flush_operation_budget: usize = 8;
const accept_batch_limit: usize = event_io_operation_budget;
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

/// WEB-only serves the data plane only to peers trusted at accept(2) time.
/// The accepted address is deliberately used instead of a later PROXY-protocol
/// address, which is supplied by the client-facing relay.
fn webOnlyMasksPeer(web_only: bool, trusted_peer: bool) bool {
    return web_only and !trusted_peer;
}

const tunnel_mask_gateway_ip = "10.200.200.1";
const min_nofile_soft: usize = 65535;
const client_hello_inline_size: usize = 512;
const mp_handshake_frame_buf_size: usize = 2048;
const read_buf_size: usize = 4096;
pub const default_managed_buffer_limit_bytes: u64 = 64 * 1024 * 1024;
const pre_first_byte_timeout_ms: i64 = 10 * std.time.ms_per_s;
const middle_proxy_stage_timeout_ms: i64 = 5 * std.time.ms_per_s;
// Telegram iOS arms a 12-second response watchdog for requests that expect a
// reply. A later server push is not strong enough evidence to arm the wedge
// breaker, so only responses inside the same window are considered.
const client_response_window_ms: i64 = 12 * std.time.ms_per_s;
// A relay becomes a high-confidence recovery candidate only after it has
// survived long enough to complete a healthy request/reply continuation.
const wedge_proof_maturity_ms: i64 = 30 * std.time.ms_per_s;
// Low-confidence recovery is allowed only for the first exchange of a fresh
// generic relay. Every recovery close shares a per-real-client/access-user/DC
// budget of three waves at T/2T/4T; later candidates use ordinary idle timeout
// for a cooldown anchored to the most recent actual breaker close.
const wedge_gate_cooldown_ms: i64 = 30 * 60 * std.time.ms_per_s;
const wedge_gate_entry_stale_ms: i64 = wedge_gate_cooldown_ms;
const tls_control_record_budget: usize = 8;
const tls_control_byte_budget: usize = 64 * 1024;
const no_timer_heap_index = std.math.maxInt(u32);

const invalid_fd: posix.fd_t = switch (builtin.os.tag) {
    .windows => std.os.windows.INVALID_HANDLE_VALUE,
    else => -1,
};

const epoll_listener_token: u64 = 0;
const epoll_timer_token: u64 = 1;
const epoll_shutdown_token: u64 = 2;
const max_slot_generation: u32 = 0x7fff_ffff;

const SlotFdRole = enum(u1) {
    client = 0,
    upstream = 1,
};

const SlotEventToken = struct {
    index: u32,
    generation: u32,
    role: SlotFdRole,
};

fn nextSlotGeneration(current: u32) u32 {
    const next = (current +% 1) & max_slot_generation;
    return if (next == 0) 1 else next;
}

fn encodeSlotEventToken(slot: *const ConnectionSlot, role: SlotFdRole) u64 {
    const generation = switch (role) {
        .client => slot.client_event_generation,
        .upstream => slot.upstream_event_generation,
    };
    return @as(u64, slot.index) |
        (@as(u64, generation) << 32) |
        (@as(u64, @intFromEnum(role)) << 63);
}

fn decodeSlotEventToken(token: u64) ?SlotEventToken {
    const generation: u32 = @intCast((token >> 32) & @as(u64, max_slot_generation));
    if (generation == 0) return null;
    return .{
        .index = @truncate(token),
        .generation = generation,
        .role = @enumFromInt(@as(u1, @truncate(token >> 63))),
    };
}

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

fn createTimerFd() !posix.fd_t {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const rc = linux.timerfd_create(.MONOTONIC, .{ .NONBLOCK = true, .CLOEXEC = true });
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn armTimerFd(fd: posix.fd_t, deadline_ns: ?i128) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const value = deadline_ns orelse 0;
    const spec = linux.itimerspec{
        .it_interval = .{ .sec = 0, .nsec = 0 },
        .it_value = if (value <= 0)
            .{ .sec = 0, .nsec = 0 }
        else
            .{
                .sec = @intCast(@divTrunc(value, std.time.ns_per_s)),
                .nsec = @intCast(@mod(value, std.time.ns_per_s)),
            },
    };
    const rc = linux.timerfd_settime(fd, .{ .ABSTIME = true }, &spec, null);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn drainTimerFd(fd: posix.fd_t) void {
    var expirations: u64 = 0;
    while (true) {
        const bytes = std.mem.asBytes(&expirations);
        const rc = linux.read(fd, bytes.ptr, bytes.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return,
            else => return,
        }
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

const msg_block_header_size: usize = @sizeOf(?*anyopaque) + @sizeOf(usize);
const msg_block_payload_size: usize = std.heap.page_size_min - msg_block_header_size;

const MsgBlock = struct {
    next: ?*@This() = null,
    len: usize = 0,
    data: [msg_block_payload_size]u8 = undefined,
};

comptime {
    if (@sizeOf(MsgBlock) != std.heap.page_size_min) {
        @compileError("MsgBlock must occupy exactly one minimum target page");
    }
}

const max_scatter_parts: usize = 64;

fn hasFatalEpollHangup(events: u32) bool {
    return (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) != 0;
}

fn hasGracefulEpollRdhup(events: u32) bool {
    return (events & linux.EPOLL.RDHUP) != 0 and
        (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) == 0;
}

fn clientRelayAtFrameBoundary(slot: *const ConnectionSlot) bool {
    if (slot.phase == .mask_relaying) return true;
    if (slot.phase != .relaying) return false;
    if (slot.client_transport == .direct_obfuscated) {
        if (slot.middle_ctx) |*mp| return mp.c2sAtFrameBoundary();
        return true;
    }
    if (slot.relay_tls_hdr_pos != 0 or
        slot.relay_tls_body_len != 0 or
        slot.relay_tls_body_pos != 0)
    {
        return false;
    }
    if (slot.middle_ctx) |*mp| return mp.c2sAtFrameBoundary();
    return true;
}

fn upstreamRelayAtFrameBoundary(slot: *const ConnectionSlot) bool {
    if (slot.phase == .mask_relaying) return true;
    if (slot.phase != .relaying) return false;
    if (slot.middle_ctx) |*mp| return mp.s2cAtFrameBoundary();
    return true;
}

fn relayHalfCloseComplete(slot: *const ConnectionSlot) bool {
    return slot.client_read_closed and
        slot.upstream_read_closed and
        slot.client_write_shutdown and
        slot.upstream_write_shutdown and
        !slot.hasClientPending() and
        !slot.hasUpstreamPending();
}

fn shutdownWriteFd(fd: posix.fd_t) !void {
    while (true) {
        const rc = posix.system.shutdown(fd, posix.SHUT.WR);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .NOTCONN => return error.SocketUnconnected,
            .BADF, .INVAL, .NOTSOCK => unreachable,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn blockStorage(blk: *MsgBlock) []u8 {
    return blk.data[0..];
}

fn blockStorageConst(blk: *const MsgBlock) []const u8 {
    return blk.data[0..];
}

fn allocateMsgBlock(allocator: std.mem.Allocator) !*MsgBlock {
    const blk = try allocator.create(MsgBlock);
    blk.* = .{};
    return blk;
}

fn wipeMsgBlock(blk: *MsgBlock) void {
    std.crypto.secureZero(u8, blockStorage(blk));
    blk.len = 0;
}

fn destroyMsgBlock(allocator: std.mem.Allocator, blk: *MsgBlock) void {
    wipeMsgBlock(blk);
    blk.next = null;
    allocator.destroy(blk);
}

/// Exact process-local budget for dynamic relay and MiddleProxy storage.
///
/// The epoll loop is single-threaded, so the accounting deliberately avoids
/// atomics. `remap` is refused: `Allocator.realloc` then allocates the new
/// region before releasing the old one, which makes transient growth count
/// against the limit instead of hiding a temporary RSS spike.
const ManagedBufferAllocator = struct {
    child: std.mem.Allocator,
    limit_bytes: usize,
    used_bytes: usize = 0,
    peak_bytes: usize = 0,
    denied_allocations: u64 = 0,

    fn init(child: std.mem.Allocator, limit_bytes: usize) ManagedBufferAllocator {
        return .{
            .child = child,
            .limit_bytes = limit_bytes,
        };
    }

    fn allocator(self: *ManagedBufferAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn reserve(self: *ManagedBufferAllocator, len: usize) bool {
        const next = std.math.add(usize, self.used_bytes, len) catch {
            self.denied_allocations +|= 1;
            return false;
        };
        if (next > self.limit_bytes) {
            self.denied_allocations +|= 1;
            return false;
        }
        self.used_bytes = next;
        self.peak_bytes = @max(self.peak_bytes, next);
        return true;
    }

    fn release(self: *ManagedBufferAllocator, len: usize) void {
        std.debug.assert(self.used_bytes >= len);
        self.used_bytes -= len;
    }

    fn fromContext(ctx: *anyopaque) *ManagedBufferAllocator {
        return @ptrCast(@alignCast(ctx));
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self = fromContext(ctx);
        if (!self.reserve(len)) return null;
        return self.child.rawAlloc(len, alignment, ret_addr) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self = fromContext(ctx);
        if (new_len == memory.len) return true;

        if (new_len > memory.len) {
            const extra = new_len - memory.len;
            if (!self.reserve(extra)) return false;
            if (self.child.rawResize(memory, alignment, new_len, ret_addr)) return true;
            self.release(extra);
            return false;
        }

        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.release(memory.len - new_len);
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self = fromContext(ctx);
        self.child.rawFree(memory, alignment, ret_addr);
        self.release(memory.len);
    }
};

const MessageBlockPool = struct {
    const max_free_blocks: usize = 1024;

    allocator: std.mem.Allocator,
    free_head: ?*MsgBlock = null,
    free_count: usize = 0,

    fn deinit(self: *MessageBlockPool) void {
        var current = self.free_head;
        while (current) |blk| {
            const next = blk.next;
            destroyMsgBlock(self.allocator, blk);
            current = next;
        }
        self.free_head = null;
        self.free_count = 0;
    }

    fn acquire(self: *MessageBlockPool) !*MsgBlock {
        const blk = self.free_head orelse return allocateMsgBlock(self.allocator);
        self.free_head = blk.next;
        self.free_count -= 1;
        blk.next = null;
        blk.len = 0;
        return blk;
    }

    fn recycle(self: *MessageBlockPool, blk: *MsgBlock) void {
        if (self.free_count >= max_free_blocks) {
            destroyMsgBlock(self.allocator, blk);
            return;
        }
        wipeMsgBlock(blk);
        blk.next = self.free_head;
        self.free_head = blk;
        self.free_count += 1;
    }
};

const MessageQueue = struct {
    const max_pending_bytes: usize = Config.relay_queue_max_pending_bytes;

    allocator: std.mem.Allocator,
    pool: ?*MessageBlockPool = null,
    head: ?*MsgBlock = null,
    tail: ?*MsgBlock = null,
    offset: usize = 0,
    total_len: usize = 0,

    fn deinit(self: *MessageQueue) void {
        self.clear();
    }

    fn clear(self: *MessageQueue) void {
        var current = self.head;
        while (current) |blk| {
            const next = blk.next;
            self.recycleBlock(blk);
            current = next;
        }
        self.head = null;
        self.tail = null;
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
        if (self.tail) |tail| {
            const available = blockStorage(tail).len - tail.len;
            const take = @min(data.len, available);
            if (take > 0) {
                @memcpy(
                    blockStorage(tail)[tail.len .. tail.len + take],
                    data[0..take],
                );
                tail.len += take;
                self.total_len += take;
                off = take;
            }
        }

        while (off < data.len) {
            const take = @min(data.len - off, msg_block_payload_size);
            const blk = try self.acquireBlock();
            blk.len = take;
            blk.next = null;
            @memcpy(blockStorage(blk)[0..take], data[off .. off + take]);

            if (self.tail) |tail| {
                tail.next = blk;
            } else {
                self.head = blk;
            }
            self.tail = blk;
            self.total_len += take;
            off += take;
        }
    }

    fn ensureCanAppend(self: *const MessageQueue, additional_len: usize) !void {
        if (additional_len > max_pending_bytes or self.total_len > max_pending_bytes - additional_len) {
            return error.PendingQueueOverflow;
        }
    }

    fn prepareIovecs(self: *const MessageQueue, out: []posix.iovec_const, max_bytes: usize) usize {
        if (self.head == null or max_bytes == 0) return 0;

        var count: usize = 0;
        var prepared: usize = 0;
        var local_off = self.offset;
        var current = self.head;
        while (current) |blk| {
            if (count >= out.len or prepared >= max_bytes) break;

            if (local_off >= blk.len) {
                local_off -= blk.len;
                current = blk.next;
                continue;
            }

            const storage = blockStorageConst(blk);
            const take = @min(blk.len - local_off, max_bytes - prepared);
            out[count] = .{ .base = storage[local_off..blk.len].ptr, .len = take };
            count += 1;
            prepared += take;
            local_off = 0;
            current = blk.next;
        }
        return count;
    }

    fn consume(self: *MessageQueue, bytes: usize) !void {
        if (bytes == 0 or self.total_len == 0) return;

        var remaining = @min(bytes, self.total_len);
        self.total_len -= remaining;

        while (remaining > 0) {
            const blk = self.head orelse unreachable;
            const blk_left = blk.len - self.offset;

            if (remaining < blk_left) {
                self.offset += remaining;
                remaining = 0;
                break;
            }

            remaining -= blk_left;
            self.offset = 0;
            self.head = blk.next;
            if (self.head == null) self.tail = null;
            self.recycleBlock(blk);
        }

        if (self.total_len == 0) {
            self.head = null;
            self.tail = null;
            self.offset = 0;
        }
    }

    fn acquireBlock(self: *MessageQueue) !*MsgBlock {
        if (self.pool) |pool| return pool.acquire();
        return allocateMsgBlock(self.allocator);
    }

    fn recycleBlock(self: *MessageQueue, blk: *MsgBlock) void {
        if (self.pool) |pool| {
            pool.recycle(blk);
        } else {
            destroyMsgBlock(self.allocator, blk);
        }
    }
};

pub const QueueMemoryBudget = struct {
    per_connection_bytes: u64,
    shared_pool_bytes: u64,
};

/// Conservative physical-memory budget for page-allocator-backed relay queues.
///
/// Each connection owns two queues. The extra active block per queue covers a
/// consumed prefix retained in the head block while unread bytes refill the
/// queue to its byte cap. The event-loop pool is shared across all connections.
pub fn queueMemoryBudget(runtime_page_size: usize) QueueMemoryBudget {
    std.debug.assert(std.math.isPowerOfTwo(runtime_page_size));
    std.debug.assert(runtime_page_size >= std.heap.page_size_min);

    const full_queue_blocks =
        (MessageQueue.max_pending_bytes + msg_block_payload_size - 1) /
        msg_block_payload_size;
    const active_blocks_per_queue = full_queue_blocks + 1;
    const per_connection_wide =
        @as(u128, active_blocks_per_queue) * 2 * @as(u128, runtime_page_size);
    const shared_pool_wide =
        @as(u128, MessageBlockPool.max_free_blocks) * @as(u128, runtime_page_size);
    std.debug.assert(per_connection_wide <= std.math.maxInt(u64));
    std.debug.assert(shared_pool_wide <= std.math.maxInt(u64));

    return .{
        .per_connection_bytes = @intCast(per_connection_wide),
        .shared_pool_bytes = @intCast(shared_pool_wide),
    };
}

const UpstreamKind = enum {
    none,
    dc,
    mask,
};

const ClientTransport = enum {
    fake_tls,
    direct_obfuscated,
};

const MaskCause = enum {
    none,
    non_tls,
    invalid_tls_length,
    missing_sni,
    malformed_client_hello,
    sni_mismatch,
    web_carrier,
    web_only,
    invalid_session_id,
    secret_mismatch,
    timestamp_skew,
    replay,
    validation_error,
};

const ConnectionPhase = enum {
    idle,
    reading_web_prefix,
    reading_tls_header,
    reading_direct_obfuscated_handshake,
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

const WedgePhase = enum {
    inactive,
    request_pending_delivery,
    waiting_for_reply,
    reply_pending_delivery,
    waiting_for_client,
};

const WedgeCloseKind = enum {
    fresh,
    proven,
};

const WedgeResponseKind = enum {
    observing,
    fresh,
    proven,
};

fn wedgeClientIdentityKey(addr: net.Address, user: []const u8) u64 {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    const mix = struct {
        fn byte(value: *u64, input: u8) void {
            value.* = (value.* ^ input) *% 0x0000_0100_0000_01b3;
        }

        fn bytes(value: *u64, input: []const u8) void {
            for (input) |b| byte(value, b);
        }
    };

    if (addr.any.family == posix.AF.INET) {
        mix.byte(&hash, 4);
        mix.bytes(&hash, std.mem.asBytes(&addr.in.sa.addr));
    } else if (addr.any.family == posix.AF.INET6) {
        const ip6 = &addr.in6.sa.addr;
        const is_ipv4_mapped = std.mem.eql(u8, ip6[0..10], &[_]u8{0} ** 10) and
            ip6[10] == 0xff and ip6[11] == 0xff;
        if (is_ipv4_mapped) {
            mix.byte(&hash, 4);
            mix.bytes(&hash, ip6[12..16]);
        } else {
            mix.byte(&hash, 6);
            mix.bytes(&hash, ip6);
        }
    } else {
        return 0;
    }

    mix.byte(&hash, @intCast(@min(user.len, std.math.maxInt(u8))));
    mix.bytes(&hash, user);
    return if (hash == 0) 1 else hash;
}

const WedgeGateTicket = struct {
    armed_ms: i64,
    timeout_ms: i64,
    penalty: u8,
};

const WedgeRecoveryGate = struct {
    const bucket_count = 1024;
    const max_probes = 12;
    const max_penalty = 3;
    const max_wave_closes = 4;

    const Entry = struct {
        client_key: u64 = 0,
        last_seen_ms: i64 = 0,
        last_close_ms: i64 = 0,
        dc_abs: u16 = 0,
        penalty: u8 = 0,
        wave_closes: u8 = 0,
        suppression_reported: bool = false,
    };

    hash_seed: u64 = 0,
    entries: [bucket_count]Entry = [_]Entry{.{}} ** bucket_count,
    untracked_suppression_reported: bool = false,

    fn indexFor(self: *const WedgeRecoveryGate, client_key: u64, dc_abs: u16) usize {
        var x = self.hash_seed ^ client_key ^
            (@as(u64, dc_abs) *% 0x9E37_79B9_7F4A_7C15);
        x ^= x >> 30;
        x *%= 0xBF58_476D_1CE4_E5B9;
        x ^= x >> 27;
        x *%= 0x94D0_49BB_1331_11EB;
        x ^= x >> 31;
        return @as(usize, @intCast(x & (bucket_count - 1)));
    }

    fn resetPenaltyAfterCooldown(entry: *Entry, now_ms: i64) void {
        if (entry.penalty == 0 or entry.last_close_ms <= 0 or now_ms < entry.last_close_ms or
            now_ms - entry.last_close_ms < wedge_gate_cooldown_ms)
        {
            return;
        }
        entry.last_close_ms = 0;
        entry.penalty = 0;
        entry.wave_closes = 0;
        entry.suppression_reported = false;
    }

    fn markSuppression(entry: *Entry) bool {
        const report = !entry.suppression_reported;
        entry.suppression_reported = true;
        return report;
    }

    fn getEntry(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        now_ms: i64,
        create: bool,
    ) ?*Entry {
        if (client_key == 0 or dc_abs == 0) return null;

        const start = self.indexFor(client_key, dc_abs);
        var reusable_idx: ?usize = null;
        var probe: usize = 0;
        while (probe < max_probes) : (probe += 1) {
            const idx = (start + probe) & (bucket_count - 1);
            const entry = &self.entries[idx];
            const occupied = entry.client_key != 0;
            const stale = occupied and now_ms >= entry.last_seen_ms and
                now_ms - entry.last_seen_ms >= wedge_gate_entry_stale_ms;

            if (occupied and entry.client_key == client_key and entry.dc_abs == dc_abs) {
                if (stale) {
                    if (!create) return null;
                    entry.* = .{
                        .client_key = client_key,
                        .last_seen_ms = now_ms,
                        .dc_abs = dc_abs,
                    };
                } else {
                    entry.last_seen_ms = now_ms;
                }
                return entry;
            }

            if ((!occupied or stale) and reusable_idx == null) reusable_idx = idx;
        }

        if (!create) return null;
        const idx = reusable_idx orelse return null;
        self.entries[idx] = .{
            .client_key = client_key,
            .last_seen_ms = now_ms,
            .dc_abs = dc_abs,
        };
        return &self.entries[idx];
    }

    fn prepare(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        now_ms: i64,
        base_timeout_ms: i64,
        idle_deadline_ms: i64,
    ) ?WedgeGateTicket {
        if (base_timeout_ms <= 0) return null;
        const entry = self.getEntry(client_key, dc_abs, now_ms, true) orelse return null;
        resetPenaltyAfterCooldown(entry, now_ms);
        if (entry.penalty >= max_penalty) return null;

        var timeout_ms = base_timeout_ms;
        var stage: u8 = 0;
        while (stage < entry.penalty) : (stage += 1) {
            if (timeout_ms > std.math.maxInt(i64) / 2) return null;
            timeout_ms *= 2;
        }
        if (now_ms > std.math.maxInt(i64) - timeout_ms) return null;
        if (now_ms + timeout_ms >= idle_deadline_ms) return null;
        entry.suppression_reported = false;

        return .{
            .armed_ms = now_ms,
            .timeout_ms = timeout_ms,
            .penalty = entry.penalty,
        };
    }

    // After one matching exchange has reported the exhausted budget, skip
    // tracking further exchanges until the close-anchored cooldown expires.
    fn suppressesNewCandidates(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        now_ms: i64,
    ) bool {
        const entry = self.getEntry(client_key, dc_abs, now_ms, false) orelse return false;
        resetPenaltyAfterCooldown(entry, now_ms);
        return entry.penalty >= max_penalty and entry.suppression_reported;
    }

    fn reportSuppression(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        now_ms: i64,
    ) bool {
        const entry = self.getEntry(client_key, dc_abs, now_ms, false) orelse {
            const report = !self.untracked_suppression_reported;
            self.untracked_suppression_reported = true;
            return report;
        };
        resetPenaltyAfterCooldown(entry, now_ms);
        return markSuppression(entry);
    }

    fn allowClose(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        ticket: WedgeGateTicket,
        now_ms: i64,
    ) bool {
        const entry = self.getEntry(client_key, dc_abs, now_ms, false) orelse return false;
        if (entry.penalty == ticket.penalty) {
            entry.penalty +|= 1;
            entry.last_close_ms = now_ms;
            entry.wave_closes = 1;
            return true;
        }

        // A client can legitimately keep a small set of parallel generic
        // relays. Let candidates armed before the first close in the same wave
        // drain together, but cap the fan-out independently of max_connections.
        if (entry.penalty == ticket.penalty + 1 and
            entry.last_close_ms >= ticket.armed_ms and
            entry.wave_closes < max_wave_closes)
        {
            entry.wave_closes += 1;
            entry.last_close_ms = now_ms;
            return true;
        }
        return false;
    }
};

const WedgeTracker = struct {
    phase: WedgePhase = .inactive,
    request_ms: i64 = 0,
    response_latency_ms: i64 = 0,
    deadline_ms: i64 = 0,
    response_kind: ?WedgeResponseKind = null,
    gate_ticket: ?WedgeGateTicket = null,
    arm_reported: bool = false,
    // Proven candidates remain active on every matching exchange, but report
    // each recovery-gate stage only once during this connection's lifetime.
    reported_proven_stages: u8 = 0,
    fresh_available: bool = true,
    // Set only after a mature relay's client continues after a fully delivered
    // reply. The proof survives later exchanges but never crosses a slot reset.
    proven: bool = false,

    fn reset(self: *WedgeTracker) void {
        self.* = .{};
    }

    fn resetExchange(self: *WedgeTracker) void {
        const fresh_available = self.fresh_available;
        const proven = self.proven;
        const reported_proven_stages = self.reported_proven_stages;
        self.* = .{
            .fresh_available = fresh_available,
            .proven = proven,
            .reported_proven_stages = reported_proven_stages,
        };
    }

    fn relayCanBeProven(now_ms: i64, relay_started_at_ms: i64) bool {
        return relay_started_at_ms > 0 and
            now_ms - relay_started_at_ms >= wedge_proof_maturity_ms;
    }

    fn noteClientPayload(self: *WedgeTracker, now_ms: i64, relay_started_at_ms: i64) bool {
        const was_waiting_for_client = self.phase == .reply_pending_delivery or
            self.phase == .waiting_for_client;
        const cancelled = was_waiting_for_client and
            self.response_kind != null and self.response_kind.? != .observing;
        const proven = self.proven or
            (self.phase == .waiting_for_client and relayCanBeProven(now_ms, relay_started_at_ms));
        const fresh_available = self.fresh_available and !was_waiting_for_client;
        const reported_proven_stages = self.reported_proven_stages;
        self.* = .{
            .phase = .request_pending_delivery,
            .fresh_available = fresh_available,
            .proven = proven,
            .reported_proven_stages = reported_proven_stages,
        };
        return cancelled;
    }

    fn cancelForClientProgress(self: *WedgeTracker, now_ms: i64, relay_started_at_ms: i64) bool {
        if (self.phase != .reply_pending_delivery and self.phase != .waiting_for_client) return false;
        const cancelled = self.response_kind != null and self.response_kind.? != .observing;
        if (self.phase == .waiting_for_client and relayCanBeProven(now_ms, relay_started_at_ms)) {
            self.proven = true;
        }
        self.fresh_available = false;
        self.resetExchange();
        return cancelled;
    }

    fn noteRequestDelivered(self: *WedgeTracker, now_ms: i64) void {
        if (self.phase != .request_pending_delivery) return;
        self.phase = .waiting_for_reply;
        self.request_ms = now_ms;
    }

    fn noteServerPayload(self: *WedgeTracker, now_ms: i64) bool {
        switch (self.phase) {
            .waiting_for_reply => {
                const response_latency_ms = @max(now_ms - self.request_ms, 0);
                if (response_latency_ms > client_response_window_ms) {
                    self.fresh_available = false;
                    self.resetExchange();
                    return false;
                }
                const kind: WedgeResponseKind = if (self.proven)
                    .proven
                else if (self.fresh_available)
                    .fresh
                else
                    .observing;
                if (kind == .fresh) self.fresh_available = false;
                self.phase = .reply_pending_delivery;
                self.response_latency_ms = response_latency_ms;
                self.deadline_ms = 0;
                self.response_kind = kind;
                self.gate_ticket = null;
                return kind != .observing;
            },
            .reply_pending_delivery, .waiting_for_client => {
                self.phase = .reply_pending_delivery;
                self.deadline_ms = 0;
                self.gate_ticket = null;
                return false;
            },
            .inactive, .request_pending_delivery => return false,
        }
    }

    fn noteReplyDelivered(
        self: *WedgeTracker,
        now_ms: i64,
        timeout_ms: i64,
        gate_ticket: ?WedgeGateTicket,
    ) bool {
        if (self.phase != .reply_pending_delivery or self.response_kind == null) return false;
        if (self.response_kind.? == .observing) {
            self.phase = .waiting_for_client;
            self.deadline_ms = 0;
            self.gate_ticket = null;
            return false;
        }
        if (timeout_ms <= 0 or gate_ticket == null) return false;
        self.phase = .waiting_for_client;
        self.deadline_ms = now_ms + timeout_ms;
        self.gate_ticket = gate_ticket;
        const first_candidate_arm = !self.arm_reported;
        self.arm_reported = true;
        if (!first_candidate_arm or self.response_kind.? != .proven) return first_candidate_arm;

        if (gate_ticket.?.penalty >= WedgeRecoveryGate.max_penalty) return false;
        const stage_shift: u3 = @intCast(gate_ticket.?.penalty);
        const stage_bit = @as(u8, 1) << stage_shift;
        const report_stage = self.reported_proven_stages & stage_bit == 0;
        self.reported_proven_stages |= stage_bit;
        return report_stage;
    }

    fn deferForClientBackpressure(self: *WedgeTracker) void {
        if (self.phase != .waiting_for_client) return;
        self.phase = .reply_pending_delivery;
        self.deadline_ms = 0;
        self.gate_ticket = null;
    }

    fn abandonCandidate(self: *WedgeTracker) void {
        self.resetExchange();
    }

    fn nextDeadlineMs(self: *const WedgeTracker) ?i64 {
        if (self.phase != .waiting_for_client or self.deadline_ms <= 0) return null;
        return self.deadline_ms;
    }

    fn closeKind(self: *const WedgeTracker, now_ms: i64) ?WedgeCloseKind {
        if (self.phase != .waiting_for_client or self.deadline_ms <= 0 or now_ms < self.deadline_ms) return null;
        const kind = self.response_kind orelse return null;
        return switch (kind) {
            .fresh => .fresh,
            .proven => .proven,
            .observing => null,
        };
    }
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

test "wedge tracker measures response from delivered client request" {
    var tracker = WedgeTracker{};
    try std.testing.expect(!tracker.noteClientPayload(1_000, 900));
    try std.testing.expectEqual(WedgePhase.request_pending_delivery, tracker.phase);
    try std.testing.expect(!tracker.noteServerPayload(1_050));

    tracker.noteRequestDelivered(1_100);
    try std.testing.expect(tracker.noteServerPayload(1_200));
    try std.testing.expectEqual(WedgeResponseKind.fresh, tracker.response_kind.?);

    const ticket = WedgeGateTicket{ .armed_ms = 1_300, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_300, ticket.timeout_ms, ticket));
    try std.testing.expectEqual(@as(?i64, 16_300), tracker.nextDeadlineMs());
    try std.testing.expectEqual(@as(?WedgeCloseKind, null), tracker.closeKind(16_299));
    try std.testing.expectEqual(WedgeCloseKind.fresh, tracker.closeKind(16_300).?);
}

test "wedge tracker observes healthy progress before arming a proven recovery" {
    var tracker = WedgeTracker{};
    _ = tracker.noteClientPayload(1_000, 500);
    tracker.noteRequestDelivered(1_050);
    try std.testing.expect(tracker.noteServerPayload(1_100));
    const fresh_ticket = WedgeGateTicket{ .armed_ms = 1_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_200, fresh_ticket.timeout_ms, fresh_ticket));

    try std.testing.expect(tracker.noteClientPayload(1_300, 500));
    try std.testing.expect(!tracker.proven);
    tracker.noteRequestDelivered(1_350);
    try std.testing.expect(!tracker.noteServerPayload(1_400));
    try std.testing.expectEqual(WedgeResponseKind.observing, tracker.response_kind.?);
    try std.testing.expect(!tracker.noteReplyDelivered(1_500, 0, null));

    try std.testing.expect(!tracker.noteClientPayload(31_000, 500));
    try std.testing.expect(tracker.proven);
    tracker.noteRequestDelivered(31_050);
    try std.testing.expect(tracker.noteServerPayload(31_100));
    try std.testing.expectEqual(WedgeResponseKind.proven, tracker.response_kind.?);
    const proven_ticket = WedgeGateTicket{ .armed_ms = 31_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(31_200, proven_ticket.timeout_ms, proven_ticket));
    try std.testing.expectEqual(WedgeCloseKind.proven, tracker.closeKind(46_200).?);
}

test "wedge tracker cancels a candidate on any client progress" {
    var tracker = WedgeTracker{};
    _ = tracker.noteClientPayload(1_000, 900);
    tracker.noteRequestDelivered(1_050);
    try std.testing.expect(tracker.noteServerPayload(1_100));
    const ticket = WedgeGateTicket{ .armed_ms = 1_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_200, ticket.timeout_ms, ticket));

    try std.testing.expect(tracker.cancelForClientProgress(1_300, 900));
    try std.testing.expectEqual(WedgePhase.inactive, tracker.phase);
    try std.testing.expectEqual(@as(?i64, null), tracker.nextDeadlineMs());
}

test "wedge tracker defers timeout for client backpressure" {
    var tracker = WedgeTracker{};
    _ = tracker.noteClientPayload(1_000, 900);
    tracker.noteRequestDelivered(1_050);
    try std.testing.expect(tracker.noteServerPayload(1_100));
    const ticket = WedgeGateTicket{ .armed_ms = 1_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_200, ticket.timeout_ms, ticket));

    tracker.deferForClientBackpressure();
    try std.testing.expectEqual(WedgePhase.reply_pending_delivery, tracker.phase);
    try std.testing.expectEqual(@as(?i64, null), tracker.nextDeadlineMs());

    const rearmed = WedgeGateTicket{ .armed_ms = 1_500, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(!tracker.noteReplyDelivered(1_500, rearmed.timeout_ms, rearmed));
    try std.testing.expectEqual(@as(?i64, 16_500), tracker.nextDeadlineMs());
}

test "wedge tracker reports one arm across fragmented server delivery" {
    var tracker = WedgeTracker{};
    _ = tracker.noteClientPayload(1_000, 900);
    tracker.noteRequestDelivered(1_050);
    try std.testing.expect(tracker.noteServerPayload(1_100));

    const first = WedgeGateTicket{ .armed_ms = 1_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_200, first.timeout_ms, first));
    try std.testing.expect(!tracker.noteServerPayload(1_300));

    const rearmed = WedgeGateTicket{ .armed_ms = 1_400, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(!tracker.noteReplyDelivered(1_400, rearmed.timeout_ms, rearmed));
    try std.testing.expectEqual(@as(?i64, 16_400), tracker.nextDeadlineMs());
}

test "wedge tracker reports each proven backoff stage once per connection" {
    var tracker = WedgeTracker{
        .fresh_available = false,
        .proven = true,
    };

    try std.testing.expect(!tracker.noteClientPayload(1_000, 500));
    tracker.noteRequestDelivered(1_050);
    try std.testing.expect(tracker.noteServerPayload(1_100));
    const stage_one = WedgeGateTicket{ .armed_ms = 1_200, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(tracker.noteReplyDelivered(1_200, stage_one.timeout_ms, stage_one));

    try std.testing.expect(tracker.noteClientPayload(1_300, 500));
    tracker.noteRequestDelivered(1_350);
    try std.testing.expect(tracker.noteServerPayload(1_400));
    const stage_one_again = WedgeGateTicket{ .armed_ms = 1_500, .timeout_ms = 15_000, .penalty = 0 };
    try std.testing.expect(!tracker.noteReplyDelivered(1_500, stage_one_again.timeout_ms, stage_one_again));
    try std.testing.expectEqual(@as(?i64, 16_500), tracker.nextDeadlineMs());

    try std.testing.expect(tracker.noteClientPayload(1_600, 500));
    tracker.noteRequestDelivered(1_650);
    try std.testing.expect(tracker.noteServerPayload(1_700));
    const stage_two = WedgeGateTicket{ .armed_ms = 1_800, .timeout_ms = 30_000, .penalty = 1 };
    try std.testing.expect(tracker.noteReplyDelivered(1_800, stage_two.timeout_ms, stage_two));
    try std.testing.expectEqual(@as(?i64, 31_800), tracker.nextDeadlineMs());
}

test "wedge tracker ignores replies outside the client watchdog window" {
    var tracker = WedgeTracker{};
    _ = tracker.noteClientPayload(1_000, 900);
    tracker.noteRequestDelivered(2_000);

    try std.testing.expect(!tracker.noteServerPayload(2_000 + client_response_window_ms + 1));
    try std.testing.expectEqual(WedgePhase.inactive, tracker.phase);
    try std.testing.expect(!tracker.fresh_available);
}

test "wedge recovery gate backs off three waves then yields to idle timeout" {
    var gate = WedgeRecoveryGate{ .hash_seed = 0x1234 };
    const key: u64 = 0x5678;
    const base_ms: i64 = 15_000;

    const first = gate.prepare(key, 2, 1_000, base_ms, 300_000).?;
    try std.testing.expectEqual(@as(i64, 15_000), first.timeout_ms);
    try std.testing.expect(gate.allowClose(key, 2, first, 16_000));

    const second = gate.prepare(key, 2, 17_000, base_ms, 300_000).?;
    try std.testing.expectEqual(@as(i64, 30_000), second.timeout_ms);
    try std.testing.expect(gate.allowClose(key, 2, second, 47_000));

    const third = gate.prepare(key, 2, 48_000, base_ms, 300_000).?;
    try std.testing.expectEqual(@as(i64, 60_000), third.timeout_ms);
    try std.testing.expect(gate.allowClose(key, 2, third, 108_000));
    try std.testing.expect(!gate.suppressesNewCandidates(key, 2, 109_000));
    try std.testing.expect(gate.prepare(key, 2, 109_001, base_ms, 300_000) == null);
    try std.testing.expect(gate.reportSuppression(key, 2, 109_002));
    try std.testing.expect(gate.suppressesNewCandidates(key, 2, 109_003));
    try std.testing.expect(!gate.reportSuppression(key, 2, 120_000));

    // A different DC has an independent bounded budget.
    try std.testing.expect(gate.prepare(key, 1, 120_001, base_ms, 300_000) != null);

    // Normal matching traffic does not extend the cooldown. Recovery resumes
    // exactly 30 minutes after the most recent actual breaker close.
    const reset_at = 108_000 + wedge_gate_cooldown_ms;
    try std.testing.expect(gate.prepare(key, 2, reset_at - 1, base_ms, reset_at + 300_000) == null);
    try std.testing.expect(!gate.reportSuppression(key, 2, reset_at - 1));
    try std.testing.expect(!gate.suppressesNewCandidates(key, 2, reset_at));
    const reset = gate.prepare(key, 2, reset_at, base_ms, reset_at + 300_000).?;
    try std.testing.expectEqual(@as(u8, 0), reset.penalty);
    try std.testing.expect(gate.prepare(0x9999, 2, 1_000, base_ms, 16_000) == null);
}

test "wedge recovery gate bounds parallel candidates in one wave" {
    var gate = WedgeRecoveryGate{ .hash_seed = 0x1234 };
    const key: u64 = 0x5678;
    var tickets: [5]WedgeGateTicket = undefined;
    for (&tickets, 0..) |*ticket, idx| {
        ticket.* = gate.prepare(key, 2, 1_000 + @as(i64, @intCast(idx)), 15_000, 300_000).?;
    }

    try std.testing.expect(gate.allowClose(key, 2, tickets[0], 16_000));
    try std.testing.expect(gate.allowClose(key, 2, tickets[1], 16_001));
    try std.testing.expect(gate.allowClose(key, 2, tickets[2], 16_002));
    try std.testing.expect(gate.allowClose(key, 2, tickets[3], 16_003));
    try std.testing.expect(!gate.allowClose(key, 2, tickets[4], 16_004));
    try std.testing.expectEqual(@as(i64, 16_003), gate.entries[gate.indexFor(key, 2)].last_close_ms);
}

test "wedge client identity ignores port and normalizes mapped IPv4" {
    const native_a = net.Address.initIp4(.{ 203, 0, 113, 7 }, 1000);
    const native_b = net.Address.initIp4(.{ 203, 0, 113, 7 }, 2000);
    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.Address.initIp6(mapped_bytes, 3000, 0, 0);

    const key = wedgeClientIdentityKey(native_a, "alice");
    try std.testing.expectEqual(key, wedgeClientIdentityKey(native_b, "alice"));
    try std.testing.expectEqual(key, wedgeClientIdentityKey(mapped, "alice"));
    try std.testing.expect(key != wedgeClientIdentityKey(native_a, "bob"));
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
    // A validated FakeTLS timestamp can remain acceptable for at most the
    // distance between the lower and upper skew bounds. Retaining entries
    // longer only increases cache pressure after the handshake is already
    // guaranteed to fail timestamp validation.
    const stale_after_s: i64 = constants.time_skew_max - constants.time_skew_min;

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
        var oldest_idx: usize = start;
        var oldest_seen_s: i64 = std.math.maxInt(i64);
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
            if (e.last_seen_s < oldest_seen_s) {
                oldest_seen_s = e.last_seen_s;
                oldest_idx = idx;
            }
        }

        // Cache pressure is not proof of replay. Reuse the oldest entry in the
        // bounded probe window rather than rejecting a fresh authenticated
        // handshake as a replay.
        const victim_idx = first_stale_idx orelse oldest_idx;
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
    event_generation: u32 = 0,
    client_event_generation: u32 = 0,
    upstream_event_generation: u32 = 0,
    timer_heap_index: u32 = no_timer_heap_index,
    conn_id: u64 = 0,

    client_fd: posix.fd_t = invalid_fd,
    upstream_fd: posix.fd_t = invalid_fd,
    upstream_kind: UpstreamKind = .none,
    peer_addr: net.Address = undefined,
    /// Fixed from the kernel-reported address at accept time. A PROXY header may
    /// replace `peer_addr`, but can never grant relay trust.
    trusted_peer: bool = false,
    client_transport: ClientTransport = .fake_tls,

    phase: ConnectionPhase = .idle,
    active_reserved: bool = false,
    /// Set after the first client byte reserves a handshake-budget slot.
    /// Silent pre-warmed TCP sessions deliberately do not consume this budget.
    hs_counted: bool = false,
    subnet_key: u64 = 0,
    subnet_hs_counted: bool = false,

    created_at_ms: i64 = 0,
    /// Set when the upstream handshake completes and bidirectional relay starts.
    relay_started_at_ms: i64 = 0,
    first_byte_at_ms: i64 = 0,
    /// Timestamp for the current upstream connect attempt. Reset per candidate.
    upstream_connect_started_ms: i64 = 0,
    /// Fixed deadline for the current upstream connect attempt.
    upstream_connect_deadline_ms: i64 = 0,
    last_activity_ms: i64 = 0,
    idle_timeout_ms: i64 = 0,
    /// Non-secret hash of full real client IP plus access user. Source ports
    /// are deliberately excluded so reconnects share one recovery budget.
    wedge_client_key: u64 = 0,
    /// Advances only when client payload actually produces upstream bytes;
    /// MiddleProxy input fragments that remain buffered do not start a timer.
    wedge_forwarded_c2s_seq: u64 = 0,
    wedge: WedgeTracker = .{},
    desync_deadline_ns: i128 = 0,

    // Initial TLS handshake reassembly
    tls_hdr_buf: [tls_header_len]u8 = undefined,
    tls_hdr_pos: u8 = 0,
    tls_body_len: u16 = 0,
    tls_body_pos: u16 = 0,
    tls_record_type: u8 = 0,

    // Optional binary PROXY-v2 prefix from the trusted WEB relay.
    web_prefix_buf: [256]u8 = undefined,
    web_prefix_pos: u16 = 0,

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

    // Non-blocking write queues (intrusive page-backed chains)
    client_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },
    upstream_queue: MessageQueue = .{ .allocator = std.heap.page_allocator },

    // Masking: bytes already read from client before deciding to mask
    mask_prebuffer: ?[]u8 = null,
    mask_c2s_bytes: u64 = 0,
    mask_s2c_bytes: u64 = 0,
    mask_cause: MaskCause = .none,
    /// Server time minus authenticated client time for timestamp-skew masking.
    mask_timestamp_skew_s: ?i64 = null,
    mask_send_proxy_header: bool = false,
    /// Long-lived HTTPS/WebSocket carrier for the configured WEB domain. Unlike
    /// probe-cover relays it must not be cut off by mask_relay_max_secs.
    web_carrier: bool = false,

    // Non-blocking MiddleProxy handshake state
    mp_step: MiddleProxyHandshakeStep = .none,
    mp_write_seq_no: i32 = -2,
    mp_read_seq_no: i32 = -2,
    mp_nonce: [16]u8 = [_]u8{0} ** 16,
    mp_timestamp: u32 = 0,
    mp_rpc_nonce_ans: [16]u8 = [_]u8{0} ** 16,
    mp_enc: ?crypto.AesCbcEncryptor = null,
    mp_dec: ?crypto.AesCbcDecryptor = null,
    mp_frame_buf: ?[]u8 = null,
    mp_frame_have: usize = 0,
    mp_frame_need: usize = 0,
    mp_frame_total_len: usize = 0,
    mp_frame_padded_len: usize = 0,
    mp_frame_encrypted: bool = false,
    mp_frame_first_decrypted: bool = false,
    mp_step_deadline_ms: i64 = 0,
    mp_secret_version: u64 = 0,
    mp_nat_ip4: ?[4]u8 = null,

    // Current epoll interests
    client_interest_in: bool = false,
    client_interest_out: bool = false,
    client_interest_rdhup: bool = false,
    upstream_interest_in: bool = false,
    upstream_interest_out: bool = false,
    upstream_interest_rdhup: bool = false,
    client_registered: bool = false,
    upstream_registered: bool = false,
    event_io_budget: ?*EventIoBudget = null,
    client_read_closed: bool = false,
    upstream_read_closed: bool = false,
    client_write_shutdown: bool = false,
    upstream_write_shutdown: bool = false,

    fn hasClientPending(self: *const ConnectionSlot) bool {
        return !self.client_queue.isEmpty();
    }

    fn hasUpstreamPending(self: *const ConnectionSlot) bool {
        return !self.upstream_queue.isEmpty();
    }

    fn handshakeInProgress(self: *const ConnectionSlot) bool {
        return switch (self.phase) {
            .reading_web_prefix,
            .reading_tls_header,
            .reading_direct_obfuscated_handshake,
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
        const client_block_pool = self.client_queue.pool;
        const upstream_block_pool = self.upstream_queue.pool;
        self.client_queue.deinit();
        self.upstream_queue.deinit();
        self.client_queue = .{ .allocator = allocator, .pool = client_block_pool };
        self.upstream_queue = .{ .allocator = allocator, .pool = upstream_block_pool };

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
        self.validation_session_id_len = 0;
        self.validation_user_len = 0;
        self.validation_force_direct = false;
        self.handshake_pos = 0;
        self.mp_timestamp = 0;
        self.mp_secret_version = 0;
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

    fn releaseHandshakeOnly(self: *ConnectionSlot, allocator: std.mem.Allocator) void {
        self.releaseClientHello(allocator);
        if (self.server_hello) |buf| secureFree(allocator, buf);
        self.server_hello = null;

        if (self.upstream_candidates) |buf| allocator.free(buf);
        self.upstream_candidates = null;
        self.upstream_candidate_next = 0;

        if (self.mp_frame_buf) |buf| secureFree(allocator, buf);
        self.mp_frame_buf = null;
        self.mp_frame_have = 0;
        self.mp_frame_need = 0;
        self.mp_frame_total_len = 0;
        self.mp_frame_padded_len = 0;

        if (self.obf_params) |*params| params.wipe();
        self.obf_params = null;
        if (self.mp_enc) |*enc| enc.wipe();
        if (self.mp_dec) |*dec| dec.wipe();
        self.mp_enc = null;
        self.mp_dec = null;

        std.crypto.secureZero(u8, &self.validation_secret);
        std.crypto.secureZero(u8, &self.validation_digest);
        std.crypto.secureZero(u8, &self.validation_session_id);
        std.crypto.secureZero(u8, &self.validation_user);
        std.crypto.secureZero(u8, &self.handshake_buf);
        std.crypto.secureZero(u8, &self.mp_nonce);
        std.crypto.secureZero(u8, &self.mp_rpc_nonce_ans);
        self.validation_session_id_len = 0;
        self.validation_user_len = 0;
        self.validation_force_direct = false;
        self.handshake_pos = 0;
        self.mp_secret_version = 0;
        self.mp_nat_ip4 = null;
    }
};

const DeadlineEntry = struct {
    deadline_ns: i128,
    slot_index: u32,
};

const EventIoBudget = struct {
    bytes_remaining: usize = event_io_byte_budget,
    operations_remaining: usize = event_io_operation_budget,

    fn exhausted(self: *const EventIoBudget) bool {
        return self.bytes_remaining == 0 or self.operations_remaining == 0;
    }

    fn allowedBytes(self: *const EventIoBudget, requested: usize) usize {
        if (self.operations_remaining == 0) return 0;
        return @min(requested, self.bytes_remaining);
    }

    fn beginOperation(self: *EventIoBudget) bool {
        if (self.exhausted()) return false;
        self.operations_remaining -= 1;
        return true;
    }

    fn recordBytes(self: *EventIoBudget, count: usize) void {
        self.bytes_remaining -= @min(count, self.bytes_remaining);
    }
};

const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    slots: []?*ConnectionSlot,
    free_stack: []u32,
    free_count: u32,

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

        return ConnectionPool{
            .allocator = allocator,
            .slots = slots,
            .free_stack = free_stack,
            .free_count = capacity,
        };
    }

    fn deinit(self: *ConnectionPool) void {
        for (self.slots) |slot_opt| {
            if (slot_opt) |slot_ptr| {
                slot_ptr.resetOwnedBuffers(self.allocator);
                self.allocator.destroy(slot_ptr);
            }
        }
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
        const event_generation = slot.event_generation;
        slot.* = .{};
        slot.index = idx;
        slot.event_generation = event_generation;
        slot.client_queue.allocator = self.allocator;
        slot.upstream_queue.allocator = self.allocator;
        return slot;
    }

    fn release(self: *ConnectionPool, slot: *ConnectionSlot) void {
        self.free_stack[self.free_count] = slot.index;
        self.free_count += 1;
        slot.phase = .idle;
    }

    fn getByToken(self: *ConnectionPool, token: SlotEventToken) ?*ConnectionSlot {
        if (@as(usize, token.index) >= self.slots.len) return null;
        const slot = self.slots[token.index] orelse return null;
        if (slot.phase == .idle) return null;
        const current_generation = switch (token.role) {
            .client => slot.client_event_generation,
            .upstream => slot.upstream_event_generation,
        };
        if (current_generation != token.generation) return null;
        return slot;
    }
};

fn readSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, buffer: []u8) !usize {
    const limited = if (slot.event_io_budget) |budget|
        buffer[0..budget.allowedBytes(buffer.len)]
    else
        buffer;
    if (limited.len == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try posix.read(fd, limited);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

fn writeSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, data: []const u8) !usize {
    const limited = if (slot.event_io_budget) |budget|
        data[0..budget.allowedBytes(data.len)]
    else
        data;
    if (limited.len == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try writeFd(fd, limited);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

fn writevSlotFd(slot: *ConnectionSlot, fd: posix.fd_t, iovecs: []const posix.iovec_const) !usize {
    var limited_iovecs: [max_scatter_parts]posix.iovec_const = undefined;
    var limited_count: usize = 0;
    var remaining = if (slot.event_io_budget) |budget| budget.allowedBytes(std.math.maxInt(usize)) else std.math.maxInt(usize);
    if (remaining == 0) return error.WouldBlock;

    for (iovecs) |iov| {
        if (remaining == 0 or limited_count == limited_iovecs.len) break;
        const take = @min(iov.len, remaining);
        if (take == 0) continue;
        limited_iovecs[limited_count] = .{ .base = iov.base, .len = take };
        limited_count += 1;
        remaining -= take;
    }
    if (limited_count == 0) return error.WouldBlock;

    if (slot.event_io_budget) |budget| {
        if (!budget.beginOperation()) return error.WouldBlock;
    }
    const count = try writevFd(fd, limited_iovecs[0..limited_count]);
    if (slot.event_io_budget) |budget| budget.recordBytes(count);
    return count;
}

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
    managed_buffer_limit_bytes: u64,
    user_secrets: []obfuscation.UserSecret,
    connection_count: u64,
    active_connections: u32,
    handshakes_inflight: u32,
    mask_target: ?[]const u8,
    mask_addrs: []net.Address,
    trusted_web_peers: web_support.TrustedPeers,
    web_only: bool = false,
    web_mask_dns: ?*web_support.DnsCache = null,
    replay_cache: ReplayCache,
    tls_server_hello_template: []u8,

    // Degradation counters (monotonic totals, delta'd in stats log)
    stats_dropped_cap: u64,
    stats_dropped_saturation: u64,
    stats_dropped_rate_limit: u64,
    stats_dropped_hs_budget: u64,
    stats_hs_timeout: u64,
    stats_mp_fallback: u64,
    stats_web_only_masked: u64 = 0,

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
    middle_proxy_secret_version: u64,
    middle_proxy_previous_secret: [256]u8,
    middle_proxy_previous_secret_len: usize,
    middle_proxy_previous_secret_version: u64,
    middle_proxy_nat_ip4: ?[4]u8,
    middle_proxy_updater_stop: std.atomic.Value(bool),
    middle_proxy_refresh_requested: std.atomic.Value(bool),
    middle_proxy_updater_thread: ?std.Thread,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) !ProxyState {
        return initWithManagedBufferLimit(
            allocator,
            cfg,
            default_managed_buffer_limit_bytes,
        );
    }

    pub fn initWithManagedBufferLimit(
        allocator: std.mem.Allocator,
        cfg: Config,
        managed_buffer_limit_bytes: u64,
    ) !ProxyState {
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

        const relay_sources = try web_support.parseSources(allocator, cfg.web.relay_sources);
        errdefer if (relay_sources.len > 0) allocator.free(relay_sources);
        const trusted_web_peers = web_support.TrustedPeers{
            .enabled = cfg.web.enabled,
            .extra = relay_sources,
        };
        var web_mask_dns: ?*web_support.DnsCache = null;
        errdefer if (web_mask_dns) |cache| cache.destroy();
        if (cfg.web.enabled) {
            if (cfg.web.mask_backend) |spec| {
                web_mask_dns = try web_support.createMaskDns(allocator, spec);
                const snapshot = web_mask_dns.?.snapshot(0);
                if (snapshot.len == 0) {
                    log.warn("[web].mask_backend could not be resolved; background DNS refresh will retry", .{});
                }
                for (snapshot.slice()) |address| {
                    if (web_support.isLoopback(web_support.fromIo(address)) and address.getPort() == cfg.port) {
                        return error.WebMaskBackendLoopsToProxy;
                    }
                }
            }
            log.info("WEB relay trust enabled for loopback and {d} configured source(s)", .{relay_sources.len});
        }
        if (cfg.web.onlyActive()) {
            log.info("WEB-only mode active: direct MTProto is masked for every peer except the trusted relay", .{});
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
                    log.info("server.middle_proxy_nat_ip='{s}' is not an IPv4 literal; falling back to active-tunnel/public-egress detection", .{configured_nat_ip});
                }
            }
        }

        return .{
            .allocator = allocator,
            .config = cfg,
            .managed_buffer_limit_bytes = managed_buffer_limit_bytes,
            .user_secrets = user_secrets,
            .connection_count = 0,
            .active_connections = 0,
            .handshakes_inflight = 0,
            .mask_target = mask_target,
            .mask_addrs = resolved_addrs,
            .trusted_web_peers = trusted_web_peers,
            .web_only = cfg.web.onlyActive(),
            .web_mask_dns = web_mask_dns,
            .replay_cache = ReplayCache.init(),
            .tls_server_hello_template = tls_template,
            .stats_dropped_cap = 0,
            .stats_dropped_saturation = 0,
            .stats_dropped_rate_limit = 0,
            .stats_dropped_hs_budget = 0,
            .stats_hs_timeout = 0,
            .stats_mp_fallback = 0,
            .stats_web_only_masked = 0,
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addrs_media_primary = constants.tg_media_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.tg_cdn_middle_proxy_v4,
            .middle_proxy_candidates = defaultMiddleProxyCandidateLists(constants.tg_middle_proxies_v4),
            .middle_proxy_candidate_lens = [_]usize{1} ** 5,
            .middle_proxy_media_candidates = defaultMiddleProxyCandidateLists(constants.tg_media_middle_proxies_v4),
            .middle_proxy_media_candidate_lens = [_]usize{1} ** 5,
            .middle_proxy_candidates_203 = [_]net.Address{constants.tg_cdn_middle_proxy_v4} ** 16,
            .middle_proxy_candidates_203_len = 1,
            .middle_proxy_cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots,
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
            .middle_proxy_secret_version = 1,
            .middle_proxy_previous_secret = [_]u8{0} ** 256,
            .middle_proxy_previous_secret_len = 0,
            .middle_proxy_previous_secret_version = 0,
            .middle_proxy_nat_ip4 = detected_nat_ip4,
            .middle_proxy_updater_stop = std.atomic.Value(bool).init(false),
            .middle_proxy_refresh_requested = std.atomic.Value(bool).init(false),
            .middle_proxy_updater_thread = null,
        };
    }

    pub fn deinit(self: *ProxyState) void {
        if (self.web_mask_dns) |cache| cache.destroy();
        self.stopMiddleProxyUpdater();
        self.middle_proxy_lock.lock();
        std.crypto.secureZero(u8, &self.middle_proxy_secret);
        self.middle_proxy_secret_len = 0;
        self.middle_proxy_secret_version = 0;
        std.crypto.secureZero(u8, &self.middle_proxy_previous_secret);
        self.middle_proxy_previous_secret_len = 0;
        self.middle_proxy_previous_secret_version = 0;
        self.middle_proxy_lock.unlock();
        self.allocator.free(self.tls_server_hello_template);
        if (self.mask_addrs.len > 0) self.allocator.free(self.mask_addrs);
        if (self.trusted_web_peers.extra.len > 0) self.allocator.free(self.trusted_web_peers.extra);
        freeUserSecrets(self.allocator, self.user_secrets);
    }

    pub fn run(self: *ProxyState, shutdown_fd: posix.fd_t) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (self.web_mask_dns) |cache| try cache.start();

        var middle_proxy_updater_started = false;
        defer {
            if (middle_proxy_updater_started) self.stopMiddleProxyUpdater();
        }

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

        if (self.config.requiresMiddleProxyRuntime()) {
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

        const loop = try EventLoop.init(self, server.stream.handle, shutdown_fd);
        defer {
            loop.deinit();
            self.allocator.destroy(loop);
        }
        try loop.run();
    }

    const MiddleProxySnapshot = struct {
        candidates: [16]net.Address,
        candidate_len: usize,
        secret_version: u64,
        nat_ip4: ?[4]u8 = null,

        fn selectedCandidates(self: *const MiddleProxySnapshot) []const net.Address {
            return self.candidates[0..self.candidate_len];
        }
    };

    fn getMiddleProxySnapshot(self: *ProxyState, dc_abs: usize, media: bool) MiddleProxySnapshot {
        self.middle_proxy_lock.lockShared();
        defer self.middle_proxy_lock.unlockShared();

        var snapshot = MiddleProxySnapshot{
            .candidates = undefined,
            .candidate_len = 0,
            .secret_version = self.middle_proxy_secret_version,
            .nat_ip4 = self.middle_proxy_nat_ip4,
        };

        if (dc_abs == 203) {
            snapshot.candidate_len = self.middle_proxy_candidates_203_len;
            @memcpy(snapshot.candidates[0..snapshot.candidate_len], self.middle_proxy_candidates_203[0..snapshot.candidate_len]);
        } else if (dc_abs >= 1 and dc_abs <= self.middle_proxy_candidates.len) {
            const index = dc_abs - 1;
            const selected_len = if (media and self.middle_proxy_media_candidate_lens[index] > 0)
                self.middle_proxy_media_candidate_lens[index]
            else
                self.middle_proxy_candidate_lens[index];
            const selected = if (media and self.middle_proxy_media_candidate_lens[index] > 0)
                self.middle_proxy_media_candidates[index][0..selected_len]
            else
                self.middle_proxy_candidates[index][0..selected_len];
            snapshot.candidate_len = selected_len;
            @memcpy(snapshot.candidates[0..selected_len], selected);
        }

        const now_ms = compat.monotonicMilliTimestamp();
        prioritizeMiddleProxyCandidates(&snapshot.candidates, snapshot.candidate_len, &self.middle_proxy_cooldowns, now_ms);
        return snapshot;
    }

    /// Caller must hold middle_proxy_lock for shared or exclusive access.
    fn middleProxySecretForVersionLocked(self: *const ProxyState, version: u64) ?[]const u8 {
        if (version != 0 and version == self.middle_proxy_secret_version and self.middle_proxy_secret_len >= 4) {
            return self.middle_proxy_secret[0..self.middle_proxy_secret_len];
        }
        if (version != 0 and version == self.middle_proxy_previous_secret_version and self.middle_proxy_previous_secret_len >= 4) {
            return self.middle_proxy_previous_secret[0..self.middle_proxy_previous_secret_len];
        }
        return null;
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
                log.info("Middle-proxy reactive refresh: failed connection(s) suggest stale metadata", .{});
                return true;
            }
            const chunk = @min(middle_proxy_update_stop_poll_ns, middle_proxy_update_period_ns - slept_ns);
            compat.sleep(chunk);
            slept_ns += chunk;
        }
        return !self.middle_proxy_updater_stop.load(.acquire);
    }

    fn middleProxyUpdaterMain(self: *ProxyState) void {
        if (self.config.requiresMiddleProxyRuntime()) {
            self.ensureMiddleProxyNatIp() catch |err| {
                if (err == error.UpdateCancelled or self.middle_proxy_updater_stop.load(.acquire)) return;
                log.warn("Initial middle-proxy NAT IP discovery failed: {any}", .{err});
            };
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
            if (self.config.requiresMiddleProxyRuntime()) {
                self.ensureMiddleProxyNatIp() catch |err| {
                    if (err == error.UpdateCancelled or self.middle_proxy_updater_stop.load(.acquire)) return;
                    log.warn("Middle-proxy NAT IP discovery failed: {any}", .{err});
                };
                self.refreshMiddleProxyInfo() catch |err| {
                    if (err == error.UpdateCancelled or self.middle_proxy_updater_stop.load(.acquire)) return;
                    log.warn("Middle-proxy refresh failed: {any}", .{err});
                };
            }
            self.refreshMaskAddresses();
        }
    }

    fn ensureMiddleProxyNatIp(self: *ProxyState) !void {
        self.middle_proxy_lock.lock();
        const already_known = self.middle_proxy_nat_ip4 != null;
        self.middle_proxy_lock.unlock();
        if (already_known or self.middle_proxy_updater_stop.load(.acquire)) return;

        // An AWG config file only describes a possible tunnel. Its Endpoint is the
        // MiddleProxy egress address only while this process actually runs inside the
        // tunnel network namespace. Trusting a stale host config in direct mode would
        // put the VPN server's address into the KDF while Telegram observes the host's
        // public egress address, causing every MiddleProxy handshake to fail.
        const tunnel_active = isRunningInNonInitNetns();
        var awg_ip: ?[4]u8 = null;
        if (tunnel_active) {
            awg_ip = try detectAwgEndpointIpv4(
                self.allocator,
                &self.middle_proxy_updater_stop,
            );
        }

        var public_ip: ?[4]u8 = null;
        if (awg_ip == null and !self.middle_proxy_updater_stop.load(.acquire)) {
            public_ip = try detectPublicIpv4(
                self.allocator,
                &self.middle_proxy_updater_stop,
            );
        }

        const ip = selectDetectedMiddleProxyNatIpv4(tunnel_active, awg_ip, public_ip) orelse return;
        if (self.middle_proxy_updater_stop.load(.acquire)) return error.UpdateCancelled;

        self.middle_proxy_lock.lock();
        if (self.middle_proxy_updater_stop.load(.acquire)) {
            self.middle_proxy_lock.unlock();
            return error.UpdateCancelled;
        }
        if (self.middle_proxy_nat_ip4 == null) self.middle_proxy_nat_ip4 = ip;
        self.middle_proxy_lock.unlock();

        var ip_buf: [16]u8 = undefined;
        if (tunnel_active and awg_ip != null) {
            log.info("Using active AWG endpoint IPv4 for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(ip, &ip_buf)});
        } else {
            log.info("Detected public-egress IPv4 for middle-proxy NAT translation: {s}", .{formatIpv4Bytes(ip, &ip_buf)});
        }
    }

    fn refreshMaskAddresses(self: *ProxyState) void {
        const target = self.mask_target orelse return;
        if (self.middle_proxy_updater_stop.load(.acquire)) return;

        const list = net.getAddressListCancelable(
            self.allocator,
            target,
            self.config.mask_port,
            &self.middle_proxy_updater_stop,
        ) catch |err| {
            if (!self.middle_proxy_updater_stop.load(.acquire)) {
                log.warn("Failed to resolve mask target '{s}:{d}': {any}", .{ target, self.config.mask_port, err });
            }
            return;
        };
        if (self.middle_proxy_updater_stop.load(.acquire)) {
            list.deinit();
            return;
        }
        if (list.addrs.len == 0) {
            list.deinit();
            return;
        }
        prioritizeIpv4Addresses(list.addrs);

        self.middle_proxy_lock.lock();
        if (self.middle_proxy_updater_stop.load(.acquire)) {
            self.middle_proxy_lock.unlock();
            list.deinit();
            return;
        }
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
                .{
                    .max_response_bytes = 1 * 1024 * 1024,
                    .stop = &self.middle_proxy_updater_stop,
                },
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
                std.crypto.secureZero(u8, &self.middle_proxy_previous_secret);
                @memcpy(
                    self.middle_proxy_previous_secret[0..self.middle_proxy_secret_len],
                    self.middle_proxy_secret[0..self.middle_proxy_secret_len],
                );
                self.middle_proxy_previous_secret_len = self.middle_proxy_secret_len;
                self.middle_proxy_previous_secret_version = self.middle_proxy_secret_version;

                std.crypto.secureZero(u8, &self.middle_proxy_secret);
                @memcpy(self.middle_proxy_secret[0..next_secret.len], next_secret);
                self.middle_proxy_secret_len = next_secret.len;
                const next_version = self.middle_proxy_secret_version +% 1;
                self.middle_proxy_secret_version = if (next_version == 0) 1 else next_version;
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
    timer_fd: posix.fd_t,
    listen_fd: posix.fd_t,
    shutdown_fd: posix.fd_t,
    pool: ConnectionPool,
    managed_buffers: ManagedBufferAllocator,
    message_block_pool: MessageBlockPool,
    accept_paused: bool,
    accept_resume_ns: i128,
    saturation_paused: bool,
    shutting_down: bool,
    shutdown_deadline_ns: i128,
    deadline_heap: std.ArrayList(DeadlineEntry),
    armed_deadline_ns: i128,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,
    wedge_candidates_since_log: u64 = 0,
    wedge_cancelled_since_log: u64 = 0,
    wedge_fresh_closes_since_log: u64 = 0,
    wedge_proven_closes_since_log: u64 = 0,
    wedge_suppressed_since_log: u64 = 0,
    wedge_recovery_gate: WedgeRecoveryGate = .{},
    subnet_limiter: SubnetRateLimit,
    subnet_handshakes: SubnetHandshakeLimit,
    // Snapshot of degradation counters for delta logging
    prev_dropped_cap: u64,
    prev_dropped_saturation: u64,
    prev_dropped_rate_limit: u64,
    prev_dropped_hs_budget: u64,
    prev_hs_timeout: u64,
    prev_mp_fallback: u64,
    prev_buffer_denials: u64,
    prev_web_only_masked: u64 = 0,
    mp_c2s_scratch: ?[]u8,
    mp_s2c_scratch: ?[]u8,
    pending_close_fds: std.ArrayList(posix.fd_t),
    tracked_fds: u32,

    fn init(state: *ProxyState, listen_fd: posix.fd_t, shutdown_fd: posix.fd_t) !*EventLoop {
        const epoll_fd = try epollCreate();
        errdefer closeFd(epoll_fd);
        const timer_fd = try createTimerFd();
        errdefer closeFd(timer_fd);

        const loop = try state.allocator.create(EventLoop);
        errdefer state.allocator.destroy(loop);

        loop.state = state;
        loop.epoll_fd = epoll_fd;
        loop.timer_fd = timer_fd;
        loop.listen_fd = listen_fd;
        loop.shutdown_fd = shutdown_fd;
        loop.pool = try ConnectionPool.init(state.allocator, state.config.max_connections);
        errdefer loop.pool.deinit();
        const managed_buffer_limit: usize = @intCast(@min(
            state.managed_buffer_limit_bytes,
            @as(u64, std.math.maxInt(usize)),
        ));
        loop.managed_buffers = ManagedBufferAllocator.init(
            state.allocator,
            managed_buffer_limit,
        );
        loop.message_block_pool = .{ .allocator = loop.managed_buffers.allocator() };
        loop.accept_paused = false;
        loop.accept_resume_ns = 0;
        loop.saturation_paused = false;
        loop.shutting_down = false;
        loop.shutdown_deadline_ns = 0;
        loop.deadline_heap = .empty;
        try loop.deadline_heap.ensureTotalCapacity(state.allocator, state.config.max_connections);
        errdefer loop.deadline_heap.deinit(state.allocator);
        loop.armed_deadline_ns = 0;
        loop.stats_next_log_ns = compat.monotonicNanoTimestamp() + stats_log_interval_ns;
        loop.accepted_since_log = 0;
        loop.closed_since_log = 0;
        loop.wedge_candidates_since_log = 0;
        loop.wedge_cancelled_since_log = 0;
        loop.wedge_fresh_closes_since_log = 0;
        loop.wedge_proven_closes_since_log = 0;
        loop.wedge_suppressed_since_log = 0;
        loop.wedge_recovery_gate.hash_seed = crypto.randomInt(u64);
        for (&loop.wedge_recovery_gate.entries) |*entry| entry.* = .{};
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
        loop.prev_buffer_denials = 0;
        loop.prev_web_only_masked = 0;
        loop.mp_c2s_scratch = null;
        loop.mp_s2c_scratch = null;
        loop.pending_close_fds = .empty;
        loop.tracked_fds = 0;

        try loop.addControlFd(listen_fd, epoll_listener_token, true, false, false);
        try loop.addControlFd(timer_fd, epoll_timer_token, true, false, false);
        try loop.addControlFd(shutdown_fd, epoll_shutdown_token, true, false, false);
        try loop.rearmTimer();
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

        const managed_allocator = self.managed_buffers.allocator();
        if (self.mp_c2s_scratch) |buf| secureFree(managed_allocator, buf);
        if (self.mp_s2c_scratch) |buf| secureFree(managed_allocator, buf);

        self.drainPendingCloses();
        self.pending_close_fds.deinit(self.state.allocator);

        self.pool.deinit();
        self.message_block_pool.deinit();
        std.debug.assert(self.managed_buffers.used_bytes == 0);
        self.deadline_heap.deinit(self.state.allocator);
        closeFd(self.timer_fd);
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

        while (true) {
            self.drainPendingCloses();

            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), -1);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => |err| return posix.unexpectedErrno(err),
            }

            const n: usize = @intCast(rc);
            var shutdown_signal_count: u64 = 0;
            for (events[0..n]) |ev| {
                if (ev.data.u64 != epoll_shutdown_token) continue;
                shutdown_signal_count +|= try self.consumeShutdownSignal();
            }
            if (shutdown_signal_count > 0) {
                if (!self.shutting_down) {
                    self.beginGracefulShutdown();
                    if (shutdown_signal_count > 1) self.forceImmediateShutdown();
                } else {
                    self.forceImmediateShutdown();
                }
                if (self.maybeCompleteShutdown(compat.monotonicNanoTimestamp())) return;
            }

            for (events[0..n]) |ev| {
                const token = ev.data.u64;
                const ev_flags = ev.events;
                if (token == epoll_shutdown_token) continue;
                if (token == epoll_listener_token) {
                    if (!self.shutting_down) {
                        self.acceptNewConnections() catch |err| {
                            log.err("accept loop error: {any}", .{err});
                        };
                    }
                    continue;
                }
                if (token == epoll_timer_token) {
                    drainTimerFd(self.timer_fd);
                    self.armed_deadline_ns = 0;
                    continue;
                }

                const slot_token = decodeSlotEventToken(token) orelse continue;
                const slot = self.pool.getByToken(slot_token) orelse continue;
                const fd = switch (slot_token.role) {
                    .client => slot.client_fd,
                    .upstream => slot.upstream_fd,
                };
                if (isInvalidFd(fd)) continue;
                self.processSlotEvent(slot, fd, ev_flags);
            }

            const now_ns = compat.monotonicNanoTimestamp();
            if (!self.shutting_down and self.accept_paused and now_ns >= self.accept_resume_ns) {
                self.resumeAccepting();
            }
            // Saturation hysteresis: resume accepting when active drops below 80%
            if (!self.shutting_down and self.saturation_paused) {
                const active = self.state.active_connections;
                const resume_threshold = (self.state.config.max_connections * 8) / 10;
                if (active <= resume_threshold) {
                    self.resumeSaturation();
                }
            }
            self.runTimers(now_ns);
            if (now_ns >= self.stats_next_log_ns) {
                self.logPeriodicStats(now_ns);
            }
            if (self.shutting_down and self.maybeCompleteShutdown(now_ns)) return;
            try self.rearmTimer();
        }
    }

    fn consumeShutdownSignal(self: *EventLoop) !u64 {
        var count: u64 = 0;
        const bytes = std.mem.asBytes(&count);
        const n = posix.read(self.shutdown_fd, bytes) catch |err| switch (err) {
            error.WouldBlock => return 0,
            else => |e| return e,
        };
        if (n == 0) return error.ShutdownEventFdClosed;
        if (n != bytes.len) return error.ShortShutdownEventRead;
        return count;
    }

    fn processSlotEvent(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t, events: u32) void {
        if (slot.phase == .idle) return;
        if (fd != slot.client_fd and fd != slot.upstream_fd) return;
        var io_budget = EventIoBudget{};
        slot.event_io_budget = &io_budget;
        defer {
            slot.event_io_budget = null;
            self.refreshSlotDeadline(slot);
        }

        const graceful_rdhup = hasGracefulEpollRdhup(events);

        if (fd == slot.client_fd) {
            if ((events & linux.EPOLL.OUT) != 0) {
                self.onClientWritable(slot);
            }
            if (slot.phase == .idle) return;
            if (fd != slot.client_fd and fd != slot.upstream_fd) return;

            const relay_phase = slot.phase == .relaying or slot.phase == .mask_relaying;
            if (relay_phase and graceful_rdhup and !slot.client_read_closed and !io_budget.exhausted()) {
                self.drainRelayRdhup(slot, fd);
            } else if ((events & linux.EPOLL.IN) != 0 and
                !io_budget.exhausted() and
                (!relay_phase or !slot.client_read_closed))
            {
                self.onClientReadable(slot);
            }
        } else if (fd == slot.upstream_fd) {
            if ((events & linux.EPOLL.OUT) != 0 or
                (slot.phase == .connecting_upstream and hasFatalEpollHangup(events)))
            {
                self.onUpstreamWritable(slot);
            }
            if (slot.phase == .idle) return;
            if (fd != slot.client_fd and fd != slot.upstream_fd) return;

            const relay_phase = slot.phase == .relaying or slot.phase == .mask_relaying;
            if (relay_phase and graceful_rdhup and !slot.upstream_read_closed and !io_budget.exhausted()) {
                self.drainRelayRdhup(slot, fd);
            } else if ((events & linux.EPOLL.IN) != 0 and
                !io_budget.exhausted() and
                (!relay_phase or !slot.upstream_read_closed))
            {
                self.onUpstreamReadable(slot);
            }
        }

        if (slot.phase == .idle) return;
        if (fd != slot.client_fd and fd != slot.upstream_fd) return;

        const fatal_hangup = hasFatalEpollHangup(events) or
            ((events & linux.EPOLL.RDHUP) != 0 and
                slot.phase != .relaying and slot.phase != .mask_relaying);
        if (fatal_hangup and shouldCloseOnFatalHangup(slot.phase, fd, slot.upstream_fd)) {
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
        if (self.shutting_down) return;

        // Saturation hysteresis: if active > 90% of max, stop accepting entirely.
        // Resume only when active drops below 80% (checked in run() loop).
        const active_now = self.state.active_connections;
        const max = self.state.config.max_connections;
        if (active_now >= (max * 9) / 10) {
            if (!self.saturation_paused) {
                self.pauseSaturation();
            }
            self.state.stats_dropped_saturation +|= 1;
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

            const trusted_web_peer = self.state.trusted_web_peers.contains(client_addr);

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!trusted_web_peer and !self.subnet_limiter.check(client_addr, self.state.config.rate_limit_per_subnet)) {
                self.state.stats_dropped_rate_limit +|= 1;
                closeFd(cfd);
                continue;
            }

            const active_before = self.state.active_connections;
            self.state.active_connections +|= 1;
            if (active_before >= self.state.config.max_connections) {
                self.state.active_connections -= 1;
                self.state.stats_dropped_cap +|= 1;
                closeFd(cfd);
                continue;
            }

            const slot = self.pool.acquire() orelse {
                self.state.active_connections -= 1;
                closeFd(cfd);
                continue;
            };
            slot.client_queue.pool = &self.message_block_pool;
            slot.upstream_queue.pool = &self.message_block_pool;

            const subnet_key = if (trusted_web_peer) 0 else SubnetRateLimit.subnetKey(client_addr);
            if (!trusted_web_peer) {
                if (!self.subnet_handshakes.reserve(subnet_key, subnetHandshakeLimit(max))) {
                    self.state.active_connections -= 1;
                    self.state.stats_dropped_hs_budget +|= 1;
                    self.pool.release(slot);
                    closeFd(cfd);
                    continue;
                }
            }

            slot.active_reserved = true;
            slot.hs_counted = false;
            slot.subnet_key = subnet_key;
            slot.subnet_hs_counted = !trusted_web_peer;
            slot.conn_id = self.state.connection_count;
            self.state.connection_count +|= 1;
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.trusted_peer = trusted_web_peer;
            slot.client_transport = .fake_tls;
            slot.phase = if (trusted_web_peer) .reading_web_prefix else .reading_tls_header;
            slot.created_at_ms = compat.monotonicMilliTimestamp();
            slot.last_activity_ms = slot.created_at_ms;
            slot.idle_timeout_ms = jitteredIdleTimeoutMs(
                self.state.config.idle_timeout_sec,
                self.state.config.idle_timeout_jitter_pct,
                idleTimeoutSeed(slot),
            );
            slot.drs = DynamicRecordSizer.init(self.state.config.drs);

            if (self.addSlotFd(slot, cfd, .client, true, false, true)) |_| {
                slot.client_interest_in = true;
                slot.client_interest_out = false;
                slot.client_interest_rdhup = true;
                self.accepted_since_log += 1;
                self.refreshSlotDeadline(slot);
            } else |_| {
                self.closeSlot(slot, "epoll add client failed");
                continue;
            }
        }
    }

    fn logPeriodicStats(self: *EventLoop, now_ns: i128) void {
        const active = self.state.active_connections;
        const hs = self.state.handshakes_inflight;
        const accepted_total = self.state.connection_count;

        // Snapshot degradation counters and compute deltas
        const cur_cap = self.state.stats_dropped_cap;
        const cur_sat = self.state.stats_dropped_saturation;
        const cur_rate = self.state.stats_dropped_rate_limit;
        const cur_hs = self.state.stats_dropped_hs_budget;
        const cur_hst = self.state.stats_hs_timeout;
        const cur_mpf = self.state.stats_mp_fallback;
        const cur_buffer_denials = self.managed_buffers.denied_allocations;
        const cur_web_only_masked = self.state.stats_web_only_masked;

        const d_cap = cur_cap - self.prev_dropped_cap;
        const d_sat = cur_sat - self.prev_dropped_saturation;
        const d_rate = cur_rate - self.prev_dropped_rate_limit;
        const d_hs = cur_hs - self.prev_dropped_hs_budget;
        const d_hst = cur_hst - self.prev_hs_timeout;
        const d_mpf = cur_mpf - self.prev_mp_fallback;
        const d_buffer_denials = cur_buffer_denials - self.prev_buffer_denials;
        const d_web_only_masked = cur_web_only_masked - self.prev_web_only_masked;

        self.prev_dropped_cap = cur_cap;
        self.prev_dropped_saturation = cur_sat;
        self.prev_dropped_rate_limit = cur_rate;
        self.prev_dropped_hs_budget = cur_hs;
        self.prev_hs_timeout = cur_hst;
        self.prev_mp_fallback = cur_mpf;
        self.prev_buffer_denials = cur_buffer_denials;
        self.prev_web_only_masked = cur_web_only_masked;

        const has_drops =
            d_cap + d_sat + d_rate + d_hs + d_hst + d_mpf + d_buffer_denials > 0;

        log.info("conn stats: active={d}/{d} hs_inflight={d} accepted+={d} closed+={d} tracked_fds={d} total={d} paused={}/{} managed_buf={d}/{d}KiB peak={d}KiB", .{
            active,
            self.state.config.max_connections,
            hs,
            self.accepted_since_log,
            self.closed_since_log,
            self.tracked_fds,
            accepted_total,
            self.accept_paused,
            self.saturation_paused,
            self.managed_buffers.used_bytes / 1024,
            self.managed_buffers.limit_bytes / 1024,
            self.managed_buffers.peak_bytes / 1024,
        });

        if (has_drops) {
            log.info("drops: cap+={d} sat+={d} rate+={d} hs_budget+={d} hs_timeout+={d} mp_fallback+={d} memory_pressure+={d}", .{
                d_cap, d_sat, d_rate, d_hs, d_hst, d_mpf, d_buffer_denials,
            });
        }

        if (d_web_only_masked > 0) {
            log.info("web_only: direct clients masked+={d}", .{d_web_only_masked});
        }

        if (self.wedge_candidates_since_log + self.wedge_cancelled_since_log +
            self.wedge_fresh_closes_since_log + self.wedge_proven_closes_since_log +
            self.wedge_suppressed_since_log > 0)
        {
            log.info("ios_wedge: candidates+={d} cancelled+={d} fresh_close+={d} proven_close+={d} suppressed+={d}", .{
                self.wedge_candidates_since_log,
                self.wedge_cancelled_since_log,
                self.wedge_fresh_closes_since_log,
                self.wedge_proven_closes_since_log,
                self.wedge_suppressed_since_log,
            });
        }

        self.accepted_since_log = 0;
        self.closed_since_log = 0;
        self.wedge_candidates_since_log = 0;
        self.wedge_cancelled_since_log = 0;
        self.wedge_fresh_closes_since_log = 0;
        self.wedge_proven_closes_since_log = 0;
        self.wedge_suppressed_since_log = 0;

        while (self.stats_next_log_ns <= now_ns) {
            self.stats_next_log_ns += stats_log_interval_ns;
        }
    }

    fn wantsAcceptInterest(self: *const EventLoop) bool {
        return shouldAcceptListen(self.accept_paused, self.saturation_paused, self.shutting_down);
    }

    fn syncAcceptInterest(self: *EventLoop) !void {
        try self.modControlFd(self.listen_fd, epoll_listener_token, self.wantsAcceptInterest(), false, false);
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

        const active = self.state.active_connections;
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

        const active = self.state.active_connections;
        if (self.wantsAcceptInterest()) {
            log.info("saturation eased: active={d}/{d}; resuming accepts", .{ active, self.state.config.max_connections });
        } else {
            log.info("saturation eased: active={d}/{d}; accepts remain paused for fd quota", .{ active, self.state.config.max_connections });
        }
    }

    fn beginGracefulShutdown(self: *EventLoop) void {
        const now_ns = compat.monotonicNanoTimestamp();
        self.shutting_down = true;
        self.shutdown_deadline_ns = now_ns +
            (@as(i128, @intCast(self.state.config.graceful_shutdown_timeout_sec)) * std.time.ns_per_s);

        self.syncAcceptInterest() catch |err| {
            log.warn("failed to disable listen socket during graceful shutdown: {any}", .{err});
        };

        log.warn(
            "SIGINT/SIGTERM received: graceful shutdown started, active={d}, timeout={d}s",
            .{ self.state.active_connections, self.state.config.graceful_shutdown_timeout_sec },
        );
    }

    fn forceImmediateShutdown(self: *EventLoop) void {
        self.shutdown_deadline_ns = compat.monotonicNanoTimestamp();
        log.warn("SIGINT/SIGTERM received during graceful drain; forcing immediate shutdown", .{});
    }

    fn maybeCompleteShutdown(self: *EventLoop, now_ns: i128) bool {
        const active = self.state.active_connections;
        if (active == 0) {
            log.info("graceful shutdown complete: all connections drained", .{});
            return true;
        }
        if (now_ns < self.shutdown_deadline_ns) return false;

        log.warn("graceful shutdown timeout reached; forcing close of {d} active connections", .{active});
        self.forceCloseActiveSlots("shutdown timeout");
        return true;
    }

    fn forceCloseActiveSlots(self: *EventLoop, reason: []const u8) void {
        for (self.pool.slots) |slot_opt| {
            if (slot_opt) |slot| {
                if (slot.phase != .idle) self.closeSlot(slot, reason);
            }
        }
    }

    fn onClientReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.last_activity_ms = compat.monotonicMilliTimestamp();

        switch (slot.phase) {
            .reading_web_prefix => self.readWebPrefix(slot),
            .reading_tls_header => self.readTlsHeader(slot),
            .reading_direct_obfuscated_handshake => self.readDirectObfuscatedHandshake(slot),
            .reading_client_hello_body => self.readClientHelloBody(slot),
            .reading_mtproto_tls_header, .reading_mtproto_tls_body => self.readMtprotoHandshake(slot),
            .relaying => self.relayClientToUpstream(slot),
            .mask_relaying => self.relayRawClientToUpstream(slot),
            else => {},
        }
    }

    fn onClientWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.phase == .relaying and !slot.is_media_path and slot.hasClientPending()) {
            slot.wedge.deferForClientBackpressure();
        }
        var flushed_at_ms: i64 = 0;
        if (flushClientPending(slot)) |written| {
            if (written > 0) {
                flushed_at_ms = compat.monotonicMilliTimestamp();
                slot.last_activity_ms = flushed_at_ms;
            }
        } else |err| {
            log.debug("[{d}] client flush error: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "client flush error");
            return;
        }
        if (flushed_at_ms > 0 and !slot.hasClientPending()) {
            self.noteServerReplyDelivered(slot, flushed_at_ms);
        }
        if (slot.phase == .relaying or slot.phase == .mask_relaying) {
            self.maybeAdvanceRelayHalfClose(slot);
        }
        if (slot.phase == .idle) {
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
                var flushed_at_ms: i64 = 0;
                if (flushUpstreamPending(slot)) |written| {
                    if (written > 0) {
                        flushed_at_ms = compat.monotonicMilliTimestamp();
                        slot.last_activity_ms = flushed_at_ms;
                    }
                } else |err| {
                    log.debug("[{d}] upstream flush error: {any}", .{ slot.conn_id, err });
                    if (slot.phase == .middle_proxy_handshake and self.fallbackFromMiddleProxyToDirect(slot)) return;
                    self.closeSlot(slot, "upstream flush error");
                    return;
                }
                if (slot.phase == .relaying and flushed_at_ms > 0 and !slot.hasUpstreamPending()) {
                    self.noteClientRequestDelivered(slot, flushed_at_ms);
                }
                if (slot.phase == .relaying or slot.phase == .mask_relaying) {
                    self.maybeAdvanceRelayHalfClose(slot);
                }
                if (slot.phase == .idle) {
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

        const hs_inflight = self.state.handshakes_inflight;
        self.state.handshakes_inflight +|= 1;
        const hs_max = (self.state.config.max_connections * 3) / 10;
        if (hs_max > 0 and hs_inflight >= hs_max) {
            self.state.handshakes_inflight -= 1;
            self.state.stats_dropped_hs_budget +|= 1;
            return false;
        }

        slot.hs_counted = true;
        return true;
    }

    /// Release a reserved handshake-budget slot exactly once. Relay and mask
    /// completion can release it early; all error paths funnel through closeSlot.
    fn releaseHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.hs_counted) return;
        self.state.handshakes_inflight -= 1;
        slot.hs_counted = false;
    }

    fn releaseSubnetHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.subnet_hs_counted) return;
        self.subnet_handshakes.release(slot.subnet_key);
        slot.subnet_hs_counted = false;
        slot.subnet_key = 0;
    }

    fn readWebPrefix(self: *EventLoop, slot: *ConnectionSlot) void {
        while (true) {
            if (slot.web_prefix_pos > 0) {
                const prefix = slot.web_prefix_buf[0..slot.web_prefix_pos];
                switch (web_support.parseProxyV2(prefix)) {
                    .invalid => {
                        // A PROXY header is optional for a trusted local peer. A normal
                        // TLS connection is decided after the five-byte record header;
                        // a dd nonce that happens to begin with 0x0d must retain every
                        // byte already consumed while we ruled out the v2 signature.
                        if (prefix[0] != 0x0d) {
                            slot.tls_hdr_buf[0] = prefix[0];
                            slot.tls_hdr_pos = 1;
                            slot.web_prefix_pos = 0;
                            slot.phase = .reading_tls_header;
                            self.readTlsHeader(slot);
                            return;
                        }
                        if (prefix.len > slot.handshake_buf.len) {
                            self.closeSlot(slot, "invalid WEB relay PROXY header");
                            return;
                        }
                        slot.client_transport = .direct_obfuscated;
                        @memcpy(slot.handshake_buf[0..prefix.len], prefix);
                        slot.handshake_pos = @intCast(prefix.len);
                        slot.web_prefix_pos = 0;
                        slot.phase = .reading_direct_obfuscated_handshake;
                        self.readDirectObfuscatedHandshake(slot);
                        return;
                    },
                    .ok => |result| {
                        if (result.src) |real_client| {
                            slot.peer_addr = real_client;
                            if (!self.subnet_limiter.check(real_client, self.state.config.rate_limit_per_subnet)) {
                                self.state.stats_dropped_rate_limit +|= 1;
                                self.closeSlot(slot, "WEB client subnet rate limit");
                                return;
                            }
                            const subnet_key = SubnetRateLimit.subnetKey(real_client);
                            if (!self.subnet_handshakes.reserve(subnet_key, subnetHandshakeLimit(self.state.config.max_connections))) {
                                self.state.stats_dropped_hs_budget +|= 1;
                                self.closeSlot(slot, "WEB client subnet handshake limit");
                                return;
                            }
                            slot.subnet_key = subnet_key;
                            slot.subnet_hs_counted = true;
                        }
                        slot.web_prefix_pos = 0;
                        slot.phase = .reading_tls_header;
                        self.readTlsHeader(slot);
                        return;
                    },
                    .incomplete => {},
                }
            }

            const have: usize = slot.web_prefix_pos;
            const target: usize = if (have < 16)
                have + 1
            else
                16 + @as(usize, std.mem.readInt(u16, slot.web_prefix_buf[14..16], .big));

            if (target > slot.web_prefix_buf.len) {
                self.closeSlot(slot, "WEB relay PROXY header too long");
                return;
            }
            if (have < target) {
                const n = readSlotFd(slot, slot.client_fd, slot.web_prefix_buf[have..target]) catch |err| {
                    if (err == error.WouldBlock) return;
                    self.closeSlot(slot, "WEB relay prefix read error");
                    return;
                };
                if (n == 0) {
                    self.closeSlot(slot, "WEB relay prefix eof");
                    return;
                }
                slot.web_prefix_pos += @intCast(n);
                if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = compat.monotonicMilliTimestamp();
                if (!slot.hs_counted and !self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
                slot.last_activity_ms = compat.monotonicMilliTimestamp();
                continue;
            }
        }
    }

    fn readTlsHeader(self: *EventLoop, slot: *ConnectionSlot) void {
        while (slot.tls_hdr_pos < tls_header_len) {
            const n = readSlotFd(slot, slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "tls header read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "client eof before tls header");
                return;
            }
            if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = compat.monotonicMilliTimestamp();
            if (!slot.hs_counted) {
                if (!self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
        }

        if (!tls.isTlsHandshake(slot.tls_hdr_buf[0..])) {
            if (slot.trusted_peer) {
                slot.client_transport = .direct_obfuscated;
                @memcpy(slot.handshake_buf[0..tls_header_len], slot.tls_hdr_buf[0..]);
                slot.handshake_pos = tls_header_len;
                slot.phase = .reading_direct_obfuscated_handshake;
                self.readDirectObfuscatedHandshake(slot);
                return;
            }
            self.startMasking(slot, slot.tls_hdr_buf[0..], .non_tls) catch {
                self.closeSlot(slot, "non-tls masked failed");
            };
            return;
        }

        const record_len = std.mem.readInt(u16, slot.tls_hdr_buf[3..5], .big);
        if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
            self.startMasking(slot, slot.tls_hdr_buf[0..], .invalid_tls_length) catch {
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

    fn readDirectObfuscatedHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        while (slot.handshake_pos < constants.handshake_len) {
            const n = readSlotFd(slot, slot.client_fd, slot.handshake_buf[slot.handshake_pos..]) catch |err| {
                if (err == error.WouldBlock) return;
                self.closeSlot(slot, "direct obfuscated handshake read error");
                return;
            };
            if (n == 0) {
                self.closeSlot(slot, "direct obfuscated handshake eof");
                return;
            }
            slot.handshake_pos += @intCast(n);
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
        }

        var result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, self.state.user_secrets) orelse {
            self.closeSlot(slot, "invalid direct obfuscated handshake");
            return;
        };
        defer result.params.wipe();

        const user_len = @min(result.user.len, slot.validation_user.len);
        slot.validation_user_len = @intCast(user_len);
        @memcpy(slot.validation_user[0..user_len], result.user[0..user_len]);
        slot.validation_force_direct = self.state.config.userBypassesMiddleProxy(result.user);
        std.crypto.secureZero(u8, &slot.handshake_buf);
        slot.handshake_pos = 0;
        self.finishParsedClientHandshake(slot, result);
    }

    fn readClientHelloBody(self: *EventLoop, slot: *ConnectionSlot) void {
        const hello_buf = slot.clientHelloBuf();

        while (slot.tls_body_pos < slot.tls_body_len) {
            const off = tls_header_len + slot.tls_body_pos;
            const end = tls_header_len + slot.tls_body_len;
            const n = readSlotFd(slot, slot.client_fd, hello_buf[off..end]) catch |err| {
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

        const sni = switch (tls.inspectSni(client_hello)) {
            .found => |value| value,
            .missing => {
                self.startMasking(slot, client_hello, .missing_sni) catch {
                    self.closeSlot(slot, "tls missing sni");
                };
                return;
            },
            .malformed => {
                self.startMasking(slot, client_hello, .malformed_client_hello) catch {
                    self.closeSlot(slot, "malformed client hello");
                };
                return;
            },
        };
        if (!std.ascii.eqlIgnoreCase(sni, self.state.config.tls_domain)) {
            var mask_cause: MaskCause = .sni_mismatch;
            if (self.state.web_mask_dns != null) {
                if (self.state.config.web.domain) |web_domain| {
                    if (std.ascii.eqlIgnoreCase(sni, web_domain)) {
                        slot.mask_send_proxy_header = true;
                        slot.web_carrier = true;
                        mask_cause = .web_carrier;
                    }
                }
            }
            self.startMasking(slot, client_hello, mask_cause) catch {
                self.closeSlot(slot, "tls sni mismatch");
            };
            return;
        }

        // The WEB carrier's own SNI mismatch has already taken the Caddy path
        // above. At this point the SNI is the ordinary FakeTLS domain: in WEB-only
        // mode an external client gets the exact same masking behavior as a bad
        // secret, while the relay remains allowed through.
        if (webOnlyMasksPeer(self.state.web_only, slot.trusted_peer)) {
            self.state.stats_web_only_masked +|= 1;
            self.startMasking(slot, client_hello, .web_only) catch {
                self.closeSlot(slot, "web-only masking failed");
            };
            return;
        }

        var validation_diagnostic: tls.TlsValidationDiagnostic = .{};
        var validation = tls.validateTlsHandshakeDetailed(
            self.state.allocator,
            client_hello,
            self.state.user_secrets,
            false,
            &validation_diagnostic,
        ) catch {
            self.startMasking(slot, client_hello, .validation_error) catch {
                self.closeSlot(slot, "tls validation error masking failed");
            };
            return;
        };
        defer if (validation) |*value| value.wipe();

        const v = if (validation) |*value| value else {
            const mask_cause: MaskCause = switch (validation_diagnostic.failure) {
                .malformed_client_hello => .malformed_client_hello,
                .invalid_session_id => .invalid_session_id,
                .secret_mismatch => .secret_mismatch,
                .timestamp_skew => .timestamp_skew,
            };
            slot.mask_timestamp_skew_s = validation_diagnostic.timestamp_skew_s;
            self.startMasking(slot, client_hello, mask_cause) catch {
                self.closeSlot(slot, "tls validation failed");
            };
            return;
        };
        if (self.state.replay_cache.checkAndInsert(&v.canonical_hmac)) {
            self.startMasking(slot, client_hello, .replay) catch {
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
        var client_ip_buf: [64]u8 = undefined;
        const client_ip = formatClientIp(slot.peer_addr, &client_ip_buf);
        log.debug("[{d}] valid FakeTLS ClientHello: key_share={s} cipher={s} client={s}", .{
            slot.conn_id,
            if (offers_pq) "X25519MLKEM768(0x11ec)" else "x25519(0x001d)",
            cipher_label,
            client_ip,
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
                    const n = readSlotFd(slot, slot.client_fd, slot.tls_hdr_buf[slot.tls_hdr_pos..]) catch |err| {
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
            const n = readSlotFd(slot, slot.client_fd, read_buf[0..want]) catch |err| {
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
        var known_secret = [_]obfuscation.UserSecret{.{
            .name = slot.validation_user[0..slot.validation_user_len],
            .secret = slot.validation_secret,
        }};
        defer std.crypto.secureZero(u8, &known_secret[0].secret);
        var result = obfuscation.ObfuscationParams.fromHandshake(&slot.handshake_buf, &known_secret) orelse {
            self.closeSlot(slot, "bad mtproto obfuscation handshake");
            return;
        };
        defer result.params.wipe();
        std.crypto.secureZero(u8, &slot.validation_secret);
        std.crypto.secureZero(u8, &slot.handshake_buf);
        slot.handshake_pos = 0;

        self.finishParsedClientHandshake(slot, result);
    }

    fn finishParsedClientHandshake(self: *EventLoop, slot: *ConnectionSlot, result: anytype) void {
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
            self.state.getMiddleProxySnapshot(dc_abs, slot.dc_idx < 0 or dc_abs == 203)
        else
            null;

        const plan = buildDcConnectPlan(&self.state.config, dc_abs, slot.dc_idx, if (snapshot) |*s| s else null, slot.validation_force_direct);
        if (plan.count == 0) {
            if (dc_abs == 203 and self.state.config.datacenter_override == null) {
                // DC 203 cannot fall back to a raw direct stream. Ask the
                // debounced updater for fresh metadata and fail explicitly.
                self.state.requestMiddleProxyRefresh();
                self.closeSlot(slot, "no CDN DC 203 middle-proxy candidates");
            } else {
                self.closeSlot(slot, "no upstream candidates");
            }
            return;
        }

        slot.dc_abs = @intCast(dc_abs);
        slot.use_middle_proxy = plan.use_middle_proxy;
        slot.is_media_path = plan.is_media_path;
        slot.wedge_client_key = if (plan.is_media_path)
            0
        else
            wedgeClientIdentityKey(slot.peer_addr, slot.validation_user[0..slot.validation_user_len]);
        slot.use_fast_mode = self.state.config.fast_mode and !slot.use_middle_proxy and (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len);
        slot.direct_fallback_addr = plan.direct_fallback;
        slot.direct_fallback_used = false;
        if (plan.use_middle_proxy) {
            const snap = if (snapshot) |*s| s else {
                self.closeSlot(slot, "missing middle-proxy snapshot");
                return;
            };
            if (snap.secret_version == 0) {
                self.closeSlot(slot, "invalid middle-proxy secret snapshot");
                return;
            }
            slot.mp_secret_version = snap.secret_version;
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

    fn startMasking(
        self: *EventLoop,
        slot: *ConnectionSlot,
        buffered: []const u8,
        cause: MaskCause,
    ) !void {
        if (!self.state.config.mask) return error.MaskingDisabled;
        slot.mask_cause = cause;
        const candidates = if (slot.web_carrier) blk: {
            const cache = self.state.web_mask_dns orelse return error.NoMaskAddress;
            const snapshot = cache.snapshot(0);
            const copy = try self.state.allocator.alloc(net.Address, snapshot.len);
            errdefer self.state.allocator.free(copy);
            for (snapshot.slice(), copy) |address, *destination| {
                destination.* = web_support.fromIo(address);
                if (web_support.isLoopback(destination.*) and address.getPort() == self.state.config.port) {
                    return error.WebMaskBackendLoopsToProxy;
                }
            }
            break :blk copy;
        } else blk: {
            self.state.middle_proxy_lock.lock();
            const copy = self.state.allocator.dupe(net.Address, self.state.mask_addrs) catch |err| {
                self.state.middle_proxy_lock.unlock();
                return err;
            };
            self.state.middle_proxy_lock.unlock();
            break :blk copy;
        };
        if (candidates.len == 0) {
            self.state.allocator.free(candidates);
            return error.NoMaskAddress;
        }

        var proxy_header_buf: [64]u8 = undefined;
        const proxy_header: []const u8 = if (slot.mask_send_proxy_header)
            web_support.buildProxyV2(&proxy_header_buf, slot.peer_addr, candidates[0])
        else
            "";
        slot.mask_send_proxy_header = false;

        const pre = self.state.allocator.alloc(u8, proxy_header.len + buffered.len) catch |err| {
            self.state.allocator.free(candidates);
            return err;
        };
        @memcpy(pre[0..proxy_header.len], proxy_header);
        @memcpy(pre[proxy_header.len..], buffered);
        slot.mask_prebuffer = pre;
        slot.mask_c2s_bytes += buffered.len;

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

        var candidate_count = if (slot.upstream_candidates) |candidates| blk: {
            const next_index = @min(@as(usize, @intCast(slot.upstream_candidate_next)), candidates.len);
            break :blk candidates.len - next_index + 1;
        } else 1;
        if (slot.use_middle_proxy and !slot.direct_fallback_used and slot.direct_fallback_addr != null) {
            candidate_count += 1;
        }
        const attempt_timeout_ms = budgetedConnectTimeoutMs(
            configured_timeout_ms,
            slot.first_byte_at_ms,
            secondsToMs(self.state.config.handshake_timeout_sec),
            started_at_ms,
            candidate_count,
        );
        if (attempt_timeout_ms <= 0) return 0;
        return started_at_ms + attempt_timeout_ms;
    }

    fn startConnectUpstream(self: *EventLoop, slot: *ConnectionSlot, addr: net.Address, kind: UpstreamKind) !void {
        const fd = try socketTcpNonblocking(addr.any.family);
        errdefer closeFd(fd);

        slot.upstream_fd = fd;
        slot.upstream_interest_in = false;
        slot.upstream_interest_out = true;
        slot.upstream_interest_rdhup = true;
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

        try self.addSlotFd(slot, fd, .upstream, false, true, true);
        errdefer _ = self.delSlotFd(slot, .upstream) catch {};

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
            slot.releaseHandshakeOnly(self.state.allocator);
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
            _ = self.delSlotFd(slot, .upstream) catch {};
            self.deferClose(fd);
            slot.upstream_fd = invalid_fd;
        }
        slot.upstream_kind = .none;
        slot.current_upstream_addr = null;
        slot.upstream_connect_started_ms = 0;
        slot.upstream_connect_deadline_ms = 0;
        slot.upstream_interest_in = false;
        slot.upstream_interest_out = false;
        slot.upstream_interest_rdhup = false;
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

        if (slot.use_middle_proxy) {
            // Candidate exhaustion may mean Telegram rotated the route. The
            // updater coalesces repeated requests, so this remains bounded
            // under a burst of simultaneous failures.
            self.state.requestMiddleProxyRefresh();
        }

        if (!slot.direct_fallback_used and slot.direct_fallback_addr != null and slot.use_middle_proxy) {
            slot.direct_fallback_used = true;
            self.state.stats_mp_fallback +|= 1;
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
        const params = if (slot.obf_params) |*value| value else {
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
        var tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&tg_enc_iv));

        var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &tg_dec_key_iv);
        for (0..tg_enc_key_iv.len) |i| {
            tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
        }
        var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
        defer std.crypto.secureZero(u8, &tg_dec_key);
        var tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&tg_dec_iv));

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
        if (self.state.config.tag) |*tag| {
            const dc_abs: usize = slot.dc_abs;
            if (dc_abs >= 1 and dc_abs <= constants.tg_datacenters_v4.len and dc_abs != 203) {
                var promote_buf: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &promote_buf);
                var packet_len: usize = 0;

                const rpc_id: u32 = 0xaeaf0c42;
                var rpc_payload: [20]u8 = undefined;
                defer std.crypto.secureZero(u8, &rpc_payload);
                std.mem.writeInt(u32, rpc_payload[0..4], rpc_id, .little);
                @memcpy(rpc_payload[4..20], tag);

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

    fn wedgeEligibleSlot(self: *const EventLoop, slot: *const ConnectionSlot) bool {
        return self.state.config.client_silence_close_sec > 0 and
            !self.shutting_down and
            slot.phase == .relaying and
            !slot.is_media_path and
            slot.wedge_client_key != 0 and
            !slot.client_read_closed and
            !slot.upstream_read_closed and
            !slot.client_write_shutdown and
            !slot.upstream_write_shutdown;
    }

    fn noteClientRelayPayload(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64) void {
        if (!self.wedgeEligibleSlot(slot)) {
            slot.wedge.reset();
        } else {
            if (slot.wedge.noteClientPayload(now_ms, slot.relay_started_at_ms)) {
                self.wedge_cancelled_since_log +|= 1;
            }
            if (self.wedge_recovery_gate.suppressesNewCandidates(
                slot.wedge_client_key,
                slot.dc_abs,
                now_ms,
            )) {
                slot.wedge.abandonCandidate();
                return;
            }
            if (!slot.hasUpstreamPending()) slot.wedge.noteRequestDelivered(now_ms);
        }
    }

    fn noteClientRelayProgress(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64) void {
        if (!self.wedgeEligibleSlot(slot)) {
            slot.wedge.reset();
        } else if (slot.wedge.cancelForClientProgress(now_ms, slot.relay_started_at_ms)) {
            self.wedge_cancelled_since_log +|= 1;
        }
    }

    fn noteClientRequestDelivered(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64) void {
        if (!self.wedgeEligibleSlot(slot) or slot.hasUpstreamPending()) return;
        slot.wedge.noteRequestDelivered(now_ms);
    }

    fn noteServerRelayPayload(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64) void {
        if (!self.wedgeEligibleSlot(slot)) {
            slot.wedge.reset();
            return;
        }

        if (slot.wedge.noteServerPayload(now_ms)) {
            self.wedge_candidates_since_log +|= 1;
        }
        if (!slot.hasClientPending()) self.noteServerReplyDelivered(slot, now_ms);
    }

    fn noteServerReplyDelivered(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64) void {
        if (!self.wedgeEligibleSlot(slot) or slot.hasClientPending() or
            slot.wedge.phase != .reply_pending_delivery or slot.wedge.response_kind == null)
        {
            return;
        }

        const base_timeout_ms = secondsToMs(self.state.config.client_silence_close_sec);
        const kind = slot.wedge.response_kind.?;
        if (kind == .observing) {
            _ = slot.wedge.noteReplyDelivered(now_ms, 0, null);
            return;
        }
        const ticket = self.wedge_recovery_gate.prepare(
            slot.wedge_client_key,
            slot.dc_abs,
            now_ms,
            base_timeout_ms,
            slot.last_activity_ms + slot.idle_timeout_ms,
        ) orelse {
            if (self.wedge_recovery_gate.reportSuppression(
                slot.wedge_client_key,
                slot.dc_abs,
                now_ms,
            )) {
                self.wedge_suppressed_since_log +|= 1;
            }
            slot.wedge.abandonCandidate();
            return;
        };
        const report_arm = slot.wedge.noteReplyDelivered(now_ms, ticket.timeout_ms, ticket);
        if (!report_arm) return;

        switch (kind) {
            .observing => unreachable,
            .fresh => {
                log.debug("[{d}] armed fresh iOS wedge breaker: dc_idx={d} timeout={d}ms stage={d} response={d}ms", .{
                    slot.conn_id,
                    slot.dc_idx,
                    ticket.timeout_ms,
                    ticket.penalty + 1,
                    slot.wedge.response_latency_ms,
                });
            },
            .proven => {
                log.debug("[{d}] armed proven iOS wedge breaker: dc_idx={d} timeout={d}ms stage={d} response={d}ms", .{
                    slot.conn_id,
                    slot.dc_idx,
                    ticket.timeout_ms,
                    ticket.penalty + 1,
                    slot.wedge.response_latency_ms,
                });
            },
        }
    }

    fn startRelay(self: *EventLoop, slot: *ConnectionSlot) void {
        // Handshake complete — release from handshake budget.
        self.releaseHandshakeBudget(slot);
        self.releaseSubnetHandshake(slot);
        slot.relay_started_at_ms = compat.monotonicMilliTimestamp();
        slot.phase = .relaying;

        if (slot.pipelined_data) |buf| {
            const data = buf[0..slot.pipelined_len];
            var forwarded_payload = false;
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
                    forwarded_payload = true;
                }
            } else if (slot.tg_encryptor) |*enc| {
                enc.apply(data);
                _ = queueUpstream(slot, data) catch {
                    self.closeSlot(slot, "queue pipelined direct payload failed");
                    return;
                };
                forwarded_payload = true;
            }

            slot.c2s_bytes += data.len;
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
            if (forwarded_payload) {
                slot.wedge_forwarded_c2s_seq +|= 1;
                self.noteClientRelayPayload(slot, slot.last_activity_ms);
            }
            secureFree(self.state.allocator, buf);
            slot.pipelined_data = null;
            slot.pipelined_len = 0;
        }

        slot.releaseHandshakeOnly(self.state.allocator);
    }

    fn relayClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;
        if (slot.client_transport == .direct_obfuscated) {
            self.relayObfuscatedClientToUpstream(slot);
            return;
        }

        const forwarded_before = slot.wedge_forwarded_c2s_seq;
        const progress = relayClientToUpstreamStep(self, slot) catch |err| {
            if (err == error.EndOfStream) {
                self.noteRelayReadEof(slot, .client);
                return;
            }
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
            if (slot.wedge_forwarded_c2s_seq > forwarded_before) {
                self.noteClientRelayPayload(slot, slot.last_activity_ms);
            } else {
                self.noteClientRelayProgress(slot, slot.last_activity_ms);
            }
        }
    }

    fn relayUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;
        if (slot.client_transport == .direct_obfuscated) {
            self.relayObfuscatedUpstreamToClient(slot);
            return;
        }

        const s2c_before = slot.s2c_bytes;
        const progress = relayUpstreamToClientStep(self, slot) catch |err| {
            if (err == error.EndOfStream) {
                self.noteRelayReadEof(slot, .upstream);
                return;
            }
            if (slot.is_media_path) {
                if (slot.middle_ctx) |*mp| {
                    if (mp.diagnostic_proxy_ans_flags) |flags| {
                        log.debug("[{d}] relay s2c error: dc_idx={d} err={any} mp_flags=0x{x} proto={s} ad_tag={} c2s={d} s2c={d}", .{
                            slot.conn_id,
                            slot.dc_idx,
                            err,
                            flags,
                            @tagName(mp.proto_tag),
                            mp.ad_tag != null,
                            slot.c2s_bytes,
                            slot.s2c_bytes,
                        });
                    } else {
                        log.debug("[{d}] relay s2c error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                            slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                        });
                    }
                } else {
                    log.debug("[{d}] relay s2c error: dc_idx={d} err={any} c2s={d} s2c={d}", .{
                        slot.conn_id, slot.dc_idx, err, slot.c2s_bytes, slot.s2c_bytes,
                    });
                }
            }
            self.closeSlot(slot, "relay s2c failed");
            return;
        };
        if (progress == .forwarded or progress == .partial) {
            slot.last_activity_ms = compat.monotonicMilliTimestamp();
            if (slot.s2c_bytes > s2c_before) {
                self.noteServerRelayPayload(slot, slot.last_activity_ms);
            }
        }
    }

    fn relayObfuscatedClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "direct obfuscated c2s buffer allocation failed");
            return;
        };
        const n = readSlotFd(slot, slot.client_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "direct obfuscated c2s read error");
            return;
        };
        if (n == 0) {
            self.noteRelayReadEof(slot, .client);
            return;
        }

        const payload = read_buf[0..n];
        var forwarded_payload = false;
        if (slot.client_decryptor) |*decryptor| decryptor.apply(payload);

        if (slot.middle_ctx) |*mp| {
            const required = mp.requiredC2sScratchCapacity(payload) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy scratch sizing failed");
                return;
            };
            const scratch = self.ensureMpC2sScratch(required) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy scratch allocation failed");
                return;
            };
            const framed = mp.encapsulateC2S(payload, scratch) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy c2s failed");
                return;
            };
            if (framed.len > 0) {
                _ = queueUpstream(slot, framed) catch {
                    self.closeSlot(slot, "direct obfuscated c2s queue failed");
                    return;
                };
                forwarded_payload = true;
            }
        } else if (slot.tg_encryptor) |*encryptor| {
            encryptor.apply(payload);
            _ = queueUpstream(slot, payload) catch {
                self.closeSlot(slot, "direct obfuscated c2s queue failed");
                return;
            };
            forwarded_payload = true;
        } else {
            self.closeSlot(slot, "direct obfuscated c2s crypto state missing");
            return;
        }

        slot.c2s_bytes += payload.len;
        slot.last_activity_ms = compat.monotonicMilliTimestamp();
        if (forwarded_payload) {
            slot.wedge_forwarded_c2s_seq +|= 1;
            self.noteClientRelayPayload(slot, slot.last_activity_ms);
        } else {
            self.noteClientRelayProgress(slot, slot.last_activity_ms);
        }
    }

    fn relayObfuscatedUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "direct obfuscated s2c buffer allocation failed");
            return;
        };
        const n = readSlotFd(slot, slot.upstream_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "direct obfuscated s2c read error");
            return;
        };
        if (n == 0) {
            self.noteRelayReadEof(slot, .upstream);
            return;
        }

        const raw = read_buf[0..n];
        if (slot.middle_ctx) |*mp| {
            const required = mp.requiredS2cScratchCapacity(raw) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy scratch sizing failed");
                return;
            };
            const scratch = self.ensureMpS2cScratch(required) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy scratch allocation failed");
                return;
            };
            const payload = mp.decapsulateS2C(raw, scratch) catch {
                self.closeSlot(slot, "direct obfuscated middleproxy s2c failed");
                return;
            };
            if (payload.len == 0) {
                slot.last_activity_ms = compat.monotonicMilliTimestamp();
                return;
            }
            if (slot.client_encryptor) |*encryptor| encryptor.apply(payload);
            _ = queueClient(slot, payload) catch {
                self.closeSlot(slot, "direct obfuscated s2c queue failed");
                return;
            };
            slot.s2c_bytes += payload.len;
        } else {
            if (!slot.use_fast_mode) {
                if (slot.tg_decryptor) |*decryptor| decryptor.apply(raw);
                if (slot.client_encryptor) |*encryptor| encryptor.apply(raw);
            }
            _ = queueClient(slot, raw) catch {
                self.closeSlot(slot, "direct obfuscated s2c queue failed");
                return;
            };
            slot.s2c_bytes += raw.len;
        }

        slot.last_activity_ms = compat.monotonicMilliTimestamp();
        self.noteServerRelayPayload(slot, slot.last_activity_ms);
    }

    fn relayRawClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "mask read buffer alloc failed");
            return;
        };

        const n = readSlotFd(slot, slot.client_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "mask client read failed");
            return;
        };
        if (n == 0) {
            self.noteRelayReadEof(slot, .client);
            return;
        }

        _ = queueUpstream(slot, read_buf[0..n]) catch {
            self.closeSlot(slot, "mask queue upstream failed");
            return;
        };
        slot.mask_c2s_bytes += n;
    }

    fn relayRawUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;

        const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
            self.closeSlot(slot, "mask upstream read buffer alloc failed");
            return;
        };

        const n = readSlotFd(slot, slot.upstream_fd, read_buf) catch |err| {
            if (err == error.WouldBlock) return;
            self.closeSlot(slot, "mask upstream read failed");
            return;
        };
        if (n == 0) {
            self.noteRelayReadEof(slot, .upstream);
            return;
        }

        _ = queueClient(slot, read_buf[0..n]) catch {
            self.closeSlot(slot, "mask queue client failed");
            return;
        };
        slot.mask_s2c_bytes += n;
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
        defer std.crypto.secureZero(u8, &crypto_ts);
        std.mem.writeInt(u32, &crypto_ts, ts, .little);

        var msg: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &msg);
        @memcpy(msg[0..4], &middleproxy.rpc_nonce_req);
        @memset(msg[4..8], 0);
        self.state.middle_proxy_lock.lockShared();
        const secret = self.state.middleProxySecretForVersionLocked(slot.mp_secret_version) orelse {
            self.state.middle_proxy_lock.unlockShared();
            if (!self.fallbackFromMiddleProxyToDirect(slot)) self.closeSlot(slot, "missing middle-proxy secret snapshot");
            return;
        };
        @memcpy(msg[4..8], secret[0..4]);
        self.state.middle_proxy_lock.unlockShared();
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
                    self.state.middle_proxy_lock.lockShared();
                    defer self.state.middle_proxy_lock.unlockShared();
                    const secret_slice = self.state.middleProxySecretForVersionLocked(slot.mp_secret_version) orelse
                        break :handshake "mp secret version expired";
                    if (!std.mem.eql(u8, payload[4..8], secret_slice[0..4])) {
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

                slot.mp_enc = crypto.AesCbcEncryptor.init(&enc_keys[0], &enc_keys[1]);
                slot.mp_dec = crypto.AesCbcDecryptor.init(&dec_keys[0], &dec_keys[1]);

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
                    self.managed_buffers.allocator(),
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
            // A protocol-stage failure can also indicate stale endpoint or
            // secret metadata. Refresh reactively even when this route cannot
            // use a direct fallback (notably CDN DC 203).
            self.state.requestMiddleProxyRefresh();
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

        if (slot.obf_params == null) return false;
        slot.direct_fallback_used = true;
        self.state.stats_mp_fallback +|= 1;
        slot.use_middle_proxy = false;
        slot.mp_secret_version = 0;
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
            else => blk: {
                const now_ms = compat.monotonicMilliTimestamp();
                const configured_stage_ms = @min(
                    secondsToMs(self.state.config.handshake_timeout_sec),
                    middle_proxy_stage_timeout_ms,
                );
                const reserve_direct_fallback = slot.use_middle_proxy and
                    !slot.direct_fallback_used and
                    slot.direct_fallback_addr != null;
                const stage_timeout_ms = budgetedMiddleProxyStageTimeoutMs(
                    configured_stage_ms,
                    slot.first_byte_at_ms,
                    secondsToMs(self.state.config.handshake_timeout_sec),
                    now_ms,
                    reserve_direct_fallback,
                );
                break :blk now_ms + stage_timeout_ms;
            },
        };
    }

    fn mpWriteFrame(self: *EventLoop, slot: *ConnectionSlot, payload: []const u8, encrypted: bool) !void {
        _ = self;
        var plain: [mp_handshake_frame_buf_size]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
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
                const n = readSlotFd(slot, slot.upstream_fd, frame_buf[slot.mp_frame_have..slot.mp_frame_need]) catch |err| {
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

    fn earlierDeadline(current: ?i128, candidate: i128) i128 {
        return if (current) |deadline| @min(deadline, candidate) else candidate;
    }

    fn deadlineMsToNs(deadline_ms: i64) i128 {
        return @as(i128, deadline_ms) * std.time.ns_per_ms;
    }

    fn nextSlotDeadlineNs(self: *const EventLoop, slot: *const ConnectionSlot) ?i128 {
        if (slot.phase == .idle) return null;
        if (slot.phase == .closing) return 1;

        var deadline: ?i128 = null;
        if (slot.phase == .desync_wait) {
            deadline = earlierDeadline(deadline, slot.desync_deadline_ns);
        }
        if (slot.phase == .connecting_upstream and slot.upstream_connect_deadline_ms > 0) {
            deadline = earlierDeadline(deadline, deadlineMsToNs(slot.upstream_connect_deadline_ms));
        }
        if (slot.phase == .middle_proxy_handshake and slot.mp_step_deadline_ms > 0) {
            deadline = earlierDeadline(deadline, deadlineMsToNs(slot.mp_step_deadline_ms));
        }

        if (slot.handshakeInProgress()) {
            const handshake_deadline_ms = if (slot.first_byte_at_ms == 0)
                slot.created_at_ms + @min(slot.idle_timeout_ms, pre_first_byte_timeout_ms)
            else
                slot.first_byte_at_ms + secondsToMs(self.state.config.handshake_timeout_sec);
            deadline = earlierDeadline(deadline, deadlineMsToNs(handshake_deadline_ms));
        } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
            deadline = earlierDeadline(deadline, deadlineMsToNs(slot.last_activity_ms + slot.idle_timeout_ms));
            if (slot.phase == .mask_relaying and !slot.web_carrier and self.state.config.mask_relay_max_secs > 0) {
                deadline = earlierDeadline(
                    deadline,
                    deadlineMsToNs(slot.created_at_ms + secondsToMs(self.state.config.mask_relay_max_secs)),
                );
            }
            if (self.wedgeEligibleSlot(slot) and !slot.hasClientPending()) {
                if (slot.wedge.nextDeadlineMs()) |wedge_deadline_ms| {
                    deadline = earlierDeadline(deadline, deadlineMsToNs(wedge_deadline_ms));
                }
            }
        }
        return deadline;
    }

    fn deadlineLess(self: *const EventLoop, lhs: usize, rhs: usize) bool {
        return self.deadline_heap.items[lhs].deadline_ns < self.deadline_heap.items[rhs].deadline_ns;
    }

    fn swapDeadlines(self: *EventLoop, lhs: usize, rhs: usize) void {
        if (lhs == rhs) return;
        std.mem.swap(DeadlineEntry, &self.deadline_heap.items[lhs], &self.deadline_heap.items[rhs]);
        self.pool.slots[@as(usize, self.deadline_heap.items[lhs].slot_index)].?.timer_heap_index = @intCast(lhs);
        self.pool.slots[@as(usize, self.deadline_heap.items[rhs].slot_index)].?.timer_heap_index = @intCast(rhs);
    }

    fn siftDeadlineUp(self: *EventLoop, start: usize) void {
        var index = start;
        while (index > 0) {
            const parent = (index - 1) / 2;
            if (!self.deadlineLess(index, parent)) break;
            self.swapDeadlines(index, parent);
            index = parent;
        }
    }

    fn siftDeadlineDown(self: *EventLoop, start: usize) void {
        var index = start;
        while (true) {
            const left = index * 2 + 1;
            if (left >= self.deadline_heap.items.len) break;
            const right = left + 1;
            const child = if (right < self.deadline_heap.items.len and self.deadlineLess(right, left)) right else left;
            if (!self.deadlineLess(child, index)) break;
            self.swapDeadlines(index, child);
            index = child;
        }
    }

    fn removeDeadlineAt(self: *EventLoop, index: usize) void {
        const removed = self.deadline_heap.items[index];
        self.pool.slots[@as(usize, removed.slot_index)].?.timer_heap_index = no_timer_heap_index;
        const last = self.deadline_heap.pop().?;
        if (index == self.deadline_heap.items.len) return;

        self.deadline_heap.items[index] = last;
        self.pool.slots[@as(usize, last.slot_index)].?.timer_heap_index = @intCast(index);
        if (index > 0 and self.deadlineLess(index, (index - 1) / 2)) {
            self.siftDeadlineUp(index);
        } else {
            self.siftDeadlineDown(index);
        }
    }

    fn removeSlotDeadline(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.timer_heap_index == no_timer_heap_index) return;
        self.removeDeadlineAt(@as(usize, slot.timer_heap_index));
    }

    fn refreshSlotDeadline(self: *EventLoop, slot: *ConnectionSlot) void {
        const next = self.nextSlotDeadlineNs(slot) orelse {
            self.removeSlotDeadline(slot);
            self.rearmTimer() catch |err| log.err("failed to rearm deadline timer: {any}", .{err});
            return;
        };

        if (slot.timer_heap_index == no_timer_heap_index) {
            std.debug.assert(self.deadline_heap.items.len < self.deadline_heap.capacity);
            slot.timer_heap_index = @intCast(self.deadline_heap.items.len);
            self.deadline_heap.appendAssumeCapacity(.{ .deadline_ns = next, .slot_index = slot.index });
            self.siftDeadlineUp(@as(usize, slot.timer_heap_index));
        } else {
            const index = @as(usize, slot.timer_heap_index);
            const previous = self.deadline_heap.items[index].deadline_ns;
            self.deadline_heap.items[index].deadline_ns = next;
            if (next < previous) self.siftDeadlineUp(index) else self.siftDeadlineDown(index);
        }
        self.rearmTimer() catch |err| log.err("failed to rearm deadline timer: {any}", .{err});
    }

    fn rearmTimer(self: *EventLoop) !void {
        var next: ?i128 = self.stats_next_log_ns;
        if (self.shutting_down and self.shutdown_deadline_ns > 0) {
            next = earlierDeadline(next, self.shutdown_deadline_ns);
        }
        if (self.accept_paused and self.accept_resume_ns > 0) {
            next = earlierDeadline(next, self.accept_resume_ns);
        }
        if (self.deadline_heap.items.len > 0) {
            next = earlierDeadline(next, self.deadline_heap.items[0].deadline_ns);
        }

        const deadline = next orelse 0;
        if (deadline == self.armed_deadline_ns) return;
        try armTimerFd(self.timer_fd, next);
        self.armed_deadline_ns = deadline;
    }

    fn runTimers(self: *EventLoop, now_ns: i128) void {
        const now_ms: i64 = @intCast(@divTrunc(now_ns, std.time.ns_per_ms));
        while (self.deadline_heap.items.len > 0 and self.deadline_heap.items[0].deadline_ns <= now_ns) {
            const slot_index = self.deadline_heap.items[0].slot_index;
            self.removeDeadlineAt(0);
            const slot = self.pool.slots[@as(usize, slot_index)] orelse continue;
            if (slot.phase == .idle) continue;
            self.runSlotTimer(slot, now_ms, now_ns);
            if (slot.phase != .idle) self.refreshSlotDeadline(slot);
        }
    }

    fn runSlotTimer(self: *EventLoop, slot: *ConnectionSlot, now_ms: i64, now_ns: i128) void {
        if (slot.phase == .desync_wait and now_ns >= slot.desync_deadline_ns) {
            slot.phase = .writing_server_hello_rest;
            if (slot.server_hello) |sh| {
                if (slot.server_hello_off < sh.len) {
                    if (queueClient(slot, sh[slot.server_hello_off..])) |_| {} else |_| {
                        self.closeSlot(slot, "desync rest write failed");
                        return;
                    }
                    slot.server_hello_off = sh.len;
                }
            }
        }

        if (slot.phase == .closing) {
            self.closeSlot(slot, "closing phase");
            return;
        }

        if (slot.phase == .connecting_upstream and slot.upstream_connect_deadline_ms > 0 and
            now_ms >= slot.upstream_connect_deadline_ms)
        {
            const failed_kind = slot.upstream_kind;
            const failed_addr = slot.current_upstream_addr;
            self.cleanupFailedUpstreamConnect(slot);
            if (failed_kind == .dc and self.tryNextDcEndpoint(slot, error.ConnectionTimedOut, failed_addr)) return;
            if (failed_kind == .mask and self.tryNextMaskEndpoint(slot, error.ConnectionTimedOut, failed_addr)) return;
            self.closeSlot(slot, "dc connect timeout");
            return;
        }

        if (slot.phase == .middle_proxy_handshake and slot.mp_step_deadline_ms > 0 and
            now_ms >= slot.mp_step_deadline_ms)
        {
            self.state.requestMiddleProxyRefresh();
            if (self.fallbackFromMiddleProxyToDirect(slot)) return;
            self.closeSlot(slot, "middle-proxy stage timeout");
            return;
        }

        if (slot.handshakeInProgress()) {
            if (slot.first_byte_at_ms == 0) {
                if (now_ms - slot.created_at_ms >= @min(slot.idle_timeout_ms, pre_first_byte_timeout_ms)) {
                    self.closeSlot(slot, "idle pre-first-byte timeout");
                    return;
                }
            } else if (now_ms - slot.first_byte_at_ms >= secondsToMs(self.state.config.handshake_timeout_sec)) {
                self.state.stats_hs_timeout +|= 1;
                if (slot.phase == .middle_proxy_handshake and slot.mp_step.awaitingMiddleProxy()) {
                    self.state.requestMiddleProxyRefresh();
                }
                self.closeSlot(slot, "handshake timeout");
                return;
            }
        } else if (slot.phase == .relaying or slot.phase == .mask_relaying) {
            if (slot.phase == .mask_relaying and !slot.web_carrier and self.state.config.mask_relay_max_secs > 0 and
                now_ms - slot.created_at_ms >= secondsToMs(self.state.config.mask_relay_max_secs))
            {
                self.closeSlot(slot, "mask relay max lifetime");
                return;
            }
            if (self.wedgeEligibleSlot(slot) and !slot.hasClientPending()) {
                if (slot.wedge.closeKind(now_ms)) |kind| {
                    const ticket = slot.wedge.gate_ticket orelse {
                        if (self.wedge_recovery_gate.reportSuppression(
                            slot.wedge_client_key,
                            slot.dc_abs,
                            now_ms,
                        )) {
                            self.wedge_suppressed_since_log +|= 1;
                        }
                        slot.wedge.abandonCandidate();
                        return;
                    };
                    if (!self.wedge_recovery_gate.allowClose(
                        slot.wedge_client_key,
                        slot.dc_abs,
                        ticket,
                        now_ms,
                    )) {
                        if (self.wedge_recovery_gate.reportSuppression(
                            slot.wedge_client_key,
                            slot.dc_abs,
                            now_ms,
                        )) {
                            self.wedge_suppressed_since_log +|= 1;
                        }
                        slot.wedge.abandonCandidate();
                    } else {
                        switch (kind) {
                            .fresh => {
                                self.wedge_fresh_closes_since_log +|= 1;
                                log.info("[{d}] closing fresh relay: client silent {d}ms after delivered server reply (bounded iOS wedge breaker, dc_idx={d}, stage={d}, response={d}ms)", .{
                                    slot.conn_id,
                                    ticket.timeout_ms,
                                    slot.dc_idx,
                                    ticket.penalty + 1,
                                    slot.wedge.response_latency_ms,
                                });
                                self.closeSlot(slot, "client silence fresh wedge breaker");
                            },
                            .proven => {
                                self.wedge_proven_closes_since_log +|= 1;
                                log.info("[{d}] closing proven relay: client silent {d}ms after delivered server reply (bounded iOS wedge breaker, dc_idx={d}, stage={d}, relay_age={d}ms, response={d}ms)", .{
                                    slot.conn_id,
                                    ticket.timeout_ms,
                                    slot.dc_idx,
                                    ticket.penalty + 1,
                                    @max(now_ms - slot.relay_started_at_ms, 0),
                                    slot.wedge.response_latency_ms,
                                });
                                self.closeSlot(slot, "client silence proven wedge breaker");
                            },
                        }
                    }
                    if (slot.phase == .idle) return;
                }
            }
            if (now_ms - slot.last_activity_ms >= slot.idle_timeout_ms) {
                self.closeSlot(slot, "relay idle timeout");
                return;
            }
        }

        self.syncInterests(slot) catch |err| {
            log.debug("[{d}] syncInterests error at deadline: {any}", .{ slot.conn_id, err });
            self.closeSlot(slot, "sync interest error");
        };
    }

    fn syncInterests(self: *EventLoop, slot: *ConnectionSlot) !void {
        var want_client_in = false;
        var want_client_out = slot.hasClientPending();
        var want_client_rdhup = !isInvalidFd(slot.client_fd);
        var want_upstream_in = false;
        var want_upstream_out = slot.hasUpstreamPending();
        var want_upstream_rdhup = !isInvalidFd(slot.upstream_fd);

        switch (slot.phase) {
            .reading_web_prefix,
            .reading_tls_header,
            .reading_direct_obfuscated_handshake,
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
                want_client_in = !slot.client_read_closed and !slot.hasUpstreamPending();
                want_upstream_in = !slot.upstream_read_closed and !slot.hasClientPending();
                want_client_out = !slot.client_write_shutdown and slot.hasClientPending();
                want_upstream_out = !slot.upstream_write_shutdown and slot.hasUpstreamPending();
                want_client_rdhup = want_client_in;
                want_upstream_rdhup = want_upstream_in;
            },

            else => {},
        }

        if (!isInvalidFd(slot.client_fd)) {
            if (slot.client_interest_in != want_client_in or
                slot.client_interest_out != want_client_out or
                slot.client_interest_rdhup != want_client_rdhup)
            {
                try self.modSlotFd(
                    slot,
                    slot.client_fd,
                    .client,
                    want_client_in,
                    want_client_out,
                    want_client_rdhup,
                );
                slot.client_interest_in = want_client_in;
                slot.client_interest_out = want_client_out;
                slot.client_interest_rdhup = want_client_rdhup;
            }
        }

        if (!isInvalidFd(slot.upstream_fd)) {
            if (slot.upstream_interest_in != want_upstream_in or
                slot.upstream_interest_out != want_upstream_out or
                slot.upstream_interest_rdhup != want_upstream_rdhup)
            {
                try self.modSlotFd(
                    slot,
                    slot.upstream_fd,
                    .upstream,
                    want_upstream_in,
                    want_upstream_out,
                    want_upstream_rdhup,
                );
                slot.upstream_interest_in = want_upstream_in;
                slot.upstream_interest_out = want_upstream_out;
                slot.upstream_interest_rdhup = want_upstream_rdhup;
            }
        }
    }

    fn ensureMpC2sScratch(self: *EventLoop, min_capacity: usize) ![]u8 {
        const target_capacity = @max(self.state.config.middleProxyC2sScratchBytes(), min_capacity);
        if (self.mp_c2s_scratch) |buf| {
            if (buf.len >= target_capacity) return buf;
        }

        const allocator = self.managed_buffers.allocator();
        const next = try allocator.alloc(u8, target_capacity);
        if (self.mp_c2s_scratch) |prev| secureFree(allocator, prev);
        self.mp_c2s_scratch = next;
        return next;
    }

    fn ensureMpS2cScratch(self: *EventLoop, min_capacity: usize) ![]u8 {
        const target_capacity = @max(self.state.config.middleProxyBufferBytes(), min_capacity);
        if (self.mp_s2c_scratch) |buf| {
            if (buf.len >= target_capacity) return buf;
        }

        const allocator = self.managed_buffers.allocator();
        const next = try allocator.alloc(u8, target_capacity);
        if (self.mp_s2c_scratch) |prev| secureFree(allocator, prev);
        self.mp_s2c_scratch = next;
        return next;
    }

    fn noteRelayReadEof(self: *EventLoop, slot: *ConnectionSlot, role: SlotFdRole) void {
        if (slot.phase != .relaying and slot.phase != .mask_relaying) {
            self.closeSlot(slot, "unexpected relay eof");
            return;
        }

        const already_closed = switch (role) {
            .client => slot.client_read_closed,
            .upstream => slot.upstream_read_closed,
        };
        if (already_closed) return;

        const at_frame_boundary = switch (role) {
            .client => clientRelayAtFrameBoundary(slot),
            .upstream => upstreamRelayAtFrameBoundary(slot),
        };
        if (!at_frame_boundary) {
            self.closeSlot(
                slot,
                if (role == .client)
                    "truncated client relay frame"
                else
                    "truncated upstream relay frame",
            );
            return;
        }

        slot.wedge.reset();
        switch (role) {
            .client => {
                slot.client_read_closed = true;
            },
            .upstream => slot.upstream_read_closed = true,
        }
        slot.last_activity_ms = compat.monotonicMilliTimestamp();
        self.maybeAdvanceRelayHalfClose(slot);
    }

    fn maybeAdvanceRelayHalfClose(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.phase != .relaying and slot.phase != .mask_relaying) return;

        if (slot.client_read_closed and
            !slot.upstream_write_shutdown and
            !slot.hasUpstreamPending())
        {
            shutdownWriteFd(slot.upstream_fd) catch |err| {
                log.debug("[{d}] upstream SHUT_WR failed after client EOF: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "upstream write shutdown failed");
                return;
            };
            slot.upstream_write_shutdown = true;
        }

        if (slot.upstream_read_closed and
            !slot.client_write_shutdown and
            !slot.hasClientPending())
        {
            shutdownWriteFd(slot.client_fd) catch |err| {
                log.debug("[{d}] client SHUT_WR failed after upstream EOF: {any}", .{ slot.conn_id, err });
                self.closeSlot(slot, "client write shutdown failed");
                return;
            };
            slot.client_write_shutdown = true;
        }

        if (relayHalfCloseComplete(slot)) {
            self.closeSlot(slot, "graceful relay shutdown complete");
        }
    }

    fn drainRelayRdhup(self: *EventLoop, slot: *ConnectionSlot, hung_fd: posix.fd_t) void {
        const from_client = hung_fd == slot.client_fd;
        const from_upstream = hung_fd == slot.upstream_fd;
        if (!from_client and !from_upstream) return;
        if ((from_client and slot.client_read_closed) or
            (from_upstream and slot.upstream_read_closed))
        {
            return;
        }
        if ((from_client and slot.hasUpstreamPending()) or
            (from_upstream and slot.hasClientPending()))
        {
            return;
        }

        // The ordinary relay-step helpers below parse FakeTLS records. WEB backend
        // streams carry the client's direct-obfuscated transport instead, so their
        // final RDHUP read must stay on the same crypto/framing path as a normal IN
        // event. Level-triggered RDHUP will notify us again after any queued output
        // drains and read interest is restored, until read() returns zero and the
        // regular half-close machinery records EOF.
        if (slot.phase == .relaying and slot.client_transport == .direct_obfuscated) {
            if (from_client) {
                self.relayObfuscatedClientToUpstream(slot);
            } else {
                self.relayObfuscatedUpstreamToClient(slot);
            }
            return;
        }

        if (slot.phase == .relaying) {
            var operations: usize = 0;
            var processed_bytes: usize = 0;
            while (slot.phase == .relaying and operations < event_io_operation_budget and processed_bytes < event_io_byte_budget) {
                const forwarded_before = slot.wedge_forwarded_c2s_seq;
                const s2c_before = slot.s2c_bytes;
                const progress = if (from_client)
                    relayClientToUpstreamStep(self, slot)
                else
                    relayUpstreamToClientStep(self, slot);

                const step = progress catch |err| {
                    if (err == error.EndOfStream) {
                        self.noteRelayReadEof(
                            slot,
                            if (from_client) .client else .upstream,
                        );
                        return;
                    }
                    self.closeSlot(slot, if (from_client) "relay client rdhup drain failed" else "relay upstream rdhup drain failed");
                    return;
                };

                if (step == .none) break;
                operations += 1;
                processed_bytes += read_buf_size;
                const now_ms = compat.monotonicMilliTimestamp();
                slot.last_activity_ms = now_ms;
                if (from_client) {
                    if (slot.wedge_forwarded_c2s_seq > forwarded_before) {
                        self.noteClientRelayPayload(slot, now_ms);
                    } else {
                        self.noteClientRelayProgress(slot, now_ms);
                    }
                } else if (slot.s2c_bytes > s2c_before) {
                    self.noteServerRelayPayload(slot, now_ms);
                }
                if ((from_client and slot.hasUpstreamPending()) or
                    (from_upstream and slot.hasClientPending()))
                {
                    break;
                }
            }
        } else {
            const read_buf = ensureReadBuf(slot, self.state.allocator) catch {
                self.closeSlot(slot, "mask rdhup read buffer alloc failed");
                return;
            };
            var operations: usize = 0;
            var processed_bytes: usize = 0;
            while (slot.phase == .mask_relaying and operations < event_io_operation_budget and processed_bytes < event_io_byte_budget) {
                const n = readSlotFd(slot, hung_fd, read_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    self.closeSlot(slot, "mask rdhup drain failed");
                    return;
                };
                if (n == 0) {
                    self.noteRelayReadEof(
                        slot,
                        if (from_client) .client else .upstream,
                    );
                    return;
                }
                operations += 1;
                processed_bytes += n;
                if (from_client) {
                    _ = queueUpstream(slot, read_buf[0..n]) catch {
                        self.closeSlot(slot, "mask rdhup queue upstream failed");
                        return;
                    };
                    slot.mask_c2s_bytes += n;
                } else {
                    _ = queueClient(slot, read_buf[0..n]) catch {
                        self.closeSlot(slot, "mask rdhup queue client failed");
                        return;
                    };
                    slot.mask_s2c_bytes += n;
                }
                slot.last_activity_ms = compat.monotonicMilliTimestamp();
                if ((from_client and slot.hasUpstreamPending()) or
                    (from_upstream and slot.hasClientPending()))
                {
                    break;
                }
            }
        }
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        if (slot.phase == .mask_relaying) {
            var client_ip_buf: [64]u8 = undefined;
            const client_ip = formatClientIp(slot.peer_addr, &client_ip_buf);
            if (slot.mask_timestamp_skew_s) |skew_s| {
                log.debug("[{d}] closing: dc_idx={d} media={} phase={s} mask_cause={s} skew_s={d} reason={s} raw_c2s={d} raw_s2c={d} client={s}", .{
                    slot.conn_id,
                    slot.dc_idx,
                    slot.is_media_path,
                    @tagName(slot.phase),
                    @tagName(slot.mask_cause),
                    skew_s,
                    reason,
                    slot.mask_c2s_bytes,
                    slot.mask_s2c_bytes,
                    client_ip,
                });
            } else {
                log.debug("[{d}] closing: dc_idx={d} media={} phase={s} mask_cause={s} reason={s} raw_c2s={d} raw_s2c={d} client={s}", .{
                    slot.conn_id,
                    slot.dc_idx,
                    slot.is_media_path,
                    @tagName(slot.phase),
                    @tagName(slot.mask_cause),
                    reason,
                    slot.mask_c2s_bytes,
                    slot.mask_s2c_bytes,
                    client_ip,
                });
            }
        } else {
            log.debug("[{d}] closing: dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d}", .{
                slot.conn_id,
                slot.dc_idx,
                slot.is_media_path,
                @tagName(slot.phase),
                reason,
                slot.c2s_bytes,
                slot.s2c_bytes,
            });
        }
        self.removeSlotDeadline(slot);

        if (!isInvalidFd(slot.client_fd)) {
            _ = self.delSlotFd(slot, .client) catch {};
            self.deferClose(slot.client_fd);
            slot.client_fd = invalid_fd;
        }

        if (!isInvalidFd(slot.upstream_fd)) {
            _ = self.delSlotFd(slot, .upstream) catch {};
            self.deferClose(slot.upstream_fd);
            slot.upstream_fd = invalid_fd;
        }

        self.releaseHandshakeBudget(slot);
        self.releaseSubnetHandshake(slot);
        slot.resetOwnedBuffers(self.state.allocator);

        if (slot.active_reserved) {
            self.state.active_connections -= 1;
            slot.active_reserved = false;
            self.closed_since_log += 1;
        }

        slot.phase = .idle;
        self.pool.release(slot);
        self.rearmTimer() catch |err| log.err("failed to rearm deadline timer after close: {any}", .{err});
    }

    fn addControlFd(
        self: *EventLoop,
        fd: posix.fd_t,
        token: u64,
        want_in: bool,
        want_out: bool,
        want_rdhup: bool,
    ) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;
        if (want_rdhup) events |= linux.EPOLL.RDHUP;

        var ev = linux.epoll_event{ .events = events, .data = .{ .u64 = token } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn addSlotFd(
        self: *EventLoop,
        slot: *ConnectionSlot,
        fd: posix.fd_t,
        role: SlotFdRole,
        want_in: bool,
        want_out: bool,
        want_rdhup: bool,
    ) !void {
        slot.event_generation = nextSlotGeneration(slot.event_generation);
        switch (role) {
            .client => slot.client_event_generation = slot.event_generation,
            .upstream => slot.upstream_event_generation = slot.event_generation,
        }
        try self.addControlFd(
            fd,
            encodeSlotEventToken(slot, role),
            want_in,
            want_out,
            want_rdhup,
        );
        switch (role) {
            .client => slot.client_registered = true,
            .upstream => slot.upstream_registered = true,
        }
        self.tracked_fds += 1;
    }

    fn modControlFd(
        self: *EventLoop,
        fd: posix.fd_t,
        token: u64,
        want_in: bool,
        want_out: bool,
        want_rdhup: bool,
    ) !void {
        var events: u32 = linux.EPOLL.ERR | linux.EPOLL.HUP;
        if (want_in) events |= linux.EPOLL.IN;
        if (want_out) events |= linux.EPOLL.OUT;
        if (want_rdhup) events |= linux.EPOLL.RDHUP;

        var ev = linux.epoll_event{ .events = events, .data = .{ .u64 = token } };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, fd, &ev);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    fn modSlotFd(
        self: *EventLoop,
        slot: *ConnectionSlot,
        fd: posix.fd_t,
        role: SlotFdRole,
        want_in: bool,
        want_out: bool,
        want_rdhup: bool,
    ) !void {
        return self.modControlFd(
            fd,
            encodeSlotEventToken(slot, role),
            want_in,
            want_out,
            want_rdhup,
        );
    }

    fn delSlotFd(self: *EventLoop, slot: *ConnectionSlot, role: SlotFdRole) !void {
        const registered = switch (role) {
            .client => slot.client_registered,
            .upstream => slot.upstream_registered,
        };
        if (!registered) return;

        const fd = switch (role) {
            .client => slot.client_fd,
            .upstream => slot.upstream_fd,
        };
        try self.delFd(fd);
        switch (role) {
            .client => slot.client_registered = false,
            .upstream => slot.upstream_registered = false,
        }
        std.debug.assert(self.tracked_fds > 0);
        self.tracked_fds -= 1;
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
            const n = readSlotFd(slot, slot.client_fd, slot.relay_tls_hdr[slot.relay_tls_hdr_pos..]) catch |err| {
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
        const n = readSlotFd(slot, slot.client_fd, read_buf[0..want]) catch |err| {
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
                slot.wedge_forwarded_c2s_seq +|= 1;
            }
        } else if (slot.tg_encryptor) |*enc| {
            enc.apply(payload);
            _ = try queueUpstream(slot, payload);
            slot.wedge_forwarded_c2s_seq +|= 1;
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
    const n = readSlotFd(slot, slot.upstream_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;

    const raw = read_buf[0..n];

    if (slot.middle_ctx) |*mp| {
        const required = try mp.requiredS2cScratchCapacity(raw);
        const scratch = try self.ensureMpS2cScratch(required);
        const payload = try mp.decapsulateS2C(raw, scratch);
        if (mp.diagnostic_unexpected_proxy_ans_flags) |flags| {
            log.debug("[{d}] accepting advisory middle-proxy response flags: dc_idx={d} mp_flags=0x{x} proto={s} ad_tag={}", .{
                slot.conn_id,
                slot.dc_idx,
                flags,
                @tagName(mp.proto_tag),
                mp.ad_tag != null,
            });
            mp.diagnostic_unexpected_proxy_ans_flags = null;
        }
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

fn shouldAcceptListen(accept_paused: bool, saturation_paused: bool, shutting_down: bool) bool {
    return !accept_paused and !saturation_paused and !shutting_down;
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
    if (first_byte_at_ms <= 0) return configured_timeout_ms;

    const handshake_deadline_ms = first_byte_at_ms + handshake_timeout_ms;
    const remaining_handshake_ms = @max(@as(i64, 1), handshake_deadline_ms - started_at_ms);
    const attempts = @max(@as(usize, 1), candidate_count);
    const fair_share_ms = @max(
        @as(i64, 1),
        @divTrunc(remaining_handshake_ms, @as(i64, @intCast(attempts))),
    );
    if (configured_timeout_ms <= 0) return fair_share_ms;
    return @min(configured_timeout_ms, fair_share_ms);
}

fn budgetedMiddleProxyStageTimeoutMs(
    configured_stage_timeout_ms: i64,
    first_byte_at_ms: i64,
    handshake_timeout_ms: i64,
    started_at_ms: i64,
    reserve_direct_fallback: bool,
) i64 {
    if (!reserve_direct_fallback or first_byte_at_ms <= 0) return configured_stage_timeout_ms;

    const handshake_deadline_ms = first_byte_at_ms + handshake_timeout_ms;
    const remaining_handshake_ms = @max(@as(i64, 1), handshake_deadline_ms - started_at_ms);
    const stage_share_ms = @max(@as(i64, 1), @divTrunc(remaining_handshake_ms, 2));
    return @min(configured_stage_timeout_ms, stage_share_ms);
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

/// Format an authenticated client's real IP without its ephemeral source port.
/// Unlike `formatAddress`, this deliberately exposes the address: callers must
/// keep it out of production-level logs.
fn formatClientIp(addr: net.Address, buf: *[64]u8) []const u8 {
    if (addr.any.family == posix.AF.INET) {
        const bytes = std.mem.asBytes(&addr.in.sa.addr);
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            bytes[0], bytes[1], bytes[2], bytes[3],
        }) catch "?";
    }

    if (addr.any.family == posix.AF.INET6) {
        const bytes: *const [16]u8 = @ptrCast(&addr.in6.sa.addr);
        const is_ipv4_mapped = std.mem.eql(u8, bytes[0..10], &[_]u8{0} ** 10) and
            std.mem.eql(u8, bytes[10..12], &[_]u8{ 0xff, 0xff });
        if (is_ipv4_mapped) {
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                bytes[12], bytes[13], bytes[14], bytes[15],
            }) catch "?";
        }

        var writer: std.Io.Writer = .fixed(buf);
        addr.format(&writer) catch return "?";
        const endpoint = writer.buffered();
        if (endpoint.len < 2 or endpoint[0] != '[') return "?";
        const closing = std.mem.indexOfScalar(u8, endpoint, ']') orelse return "?";
        return endpoint[1..closing];
    }

    return "?";
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

fn resolveHostnameIpv4(
    allocator: std.mem.Allocator,
    host: []const u8,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    if (stop) |stop_flag| {
        if (stop_flag.load(.acquire)) return error.UpdateCancelled;
    }

    var list = if (stop) |stop_flag|
        net.getAddressListCancelable(allocator, host, 443, stop_flag) catch |err| {
            if (err == error.UpdateCancelled) return err;
            return null;
        }
    else
        net.getAddressList(allocator, host, 443) catch return null;
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

fn parseAwgEndpointIpv4FromConfig(
    allocator: std.mem.Allocator,
    content: []const u8,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    var in_peer = false;
    var lines = std.mem.splitScalar(u8, content, '\n');

    while (lines.next()) |raw_line| {
        if (stop) |stop_flag| {
            if (stop_flag.load(.acquire)) return error.UpdateCancelled;
        }

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
        if (try resolveHostnameIpv4(allocator, host, stop)) |resolved_ip| return resolved_ip;
    }

    return null;
}

fn detectAwgEndpointIpv4(
    allocator: std.mem.Allocator,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    if (builtin.os.tag != .linux) return null;

    const paths = [_][]const u8{
        "/etc/amnezia/amneziawg/awg0.conf",
        "/etc/amnezia/amneziawg/wg0.conf",
        "/etc/wireguard/wg0.conf",
    };

    for (paths) |path| {
        if (stop) |stop_flag| {
            if (stop_flag.load(.acquire)) return error.UpdateCancelled;
        }

        const content = compat.readFileAbsoluteAlloc(allocator, path, 64 * 1024) catch continue;
        defer allocator.free(content);

        if (try parseAwgEndpointIpv4FromConfig(allocator, content, stop)) |ip| return ip;
    }

    return null;
}

fn selectDetectedMiddleProxyNatIpv4(
    tunnel_active: bool,
    awg_ip: ?[4]u8,
    public_ip: ?[4]u8,
) ?[4]u8 {
    if (tunnel_active) {
        if (awg_ip) |ip| return ip;
    }
    return public_ip;
}

fn detectPublicIpv4(
    allocator: std.mem.Allocator,
    stop: ?*const std.atomic.Value(bool),
) !?[4]u8 {
    const services = [_][]const u8{
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://ipv4.icanhazip.com",
    };

    for (services) |url| {
        const stdout = http_fetch.fetchUrlBytes(
            allocator,
            url,
            .{
                .max_response_bytes = 64 * 1024,
                .stop = stop,
            },
        ) catch |err| {
            if (err == error.UpdateCancelled) return err;
            continue;
        };
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\r', '\n' });
        const parsed = parseIpv4Literal(trimmed);
        allocator.free(stdout);
        if (parsed) |ip| return ip;
    }

    return null;
}

test "middle-proxy NAT selection ignores a stale AWG endpoint in direct mode" {
    const awg_ip = [4]u8{ 203, 0, 113, 9 };
    const public_ip = [4]u8{ 198, 51, 100, 20 };

    try std.testing.expectEqual(
        @as(?[4]u8, public_ip),
        selectDetectedMiddleProxyNatIpv4(false, awg_ip, public_ip),
    );
}

test "middle-proxy NAT selection uses AWG endpoint only in tunnel mode" {
    const awg_ip = [4]u8{ 203, 0, 113, 9 };
    const public_ip = [4]u8{ 198, 51, 100, 20 };

    try std.testing.expectEqual(
        @as(?[4]u8, awg_ip),
        selectDetectedMiddleProxyNatIpv4(true, awg_ip, public_ip),
    );
    try std.testing.expectEqual(
        @as(?[4]u8, public_ip),
        selectDetectedMiddleProxyNatIpv4(true, null, public_ip),
    );
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
    // CDN DC 203 has no raw direct endpoint. Its MiddleProxy route is a
    // protocol requirement, not an optional routing preference.
    if (dc_abs == 203) return true;
    if (cfg.use_middle_proxy) return true;

    return cfg.force_media_middle_proxy and dc_idx < 0;
}

fn directDcAddressV4(dc_abs: usize) ?net.Address {
    return constants.getDirectDcAddressV4(dc_abs);
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

    const direct_addr = directDcAddressV4(dc_abs);

    var middle_candidates: []const net.Address = &.{};
    if (snapshot) |snap| {
        middle_candidates = snap.selectedCandidates();
    }
    const middle_addr = if (middle_candidates.len > 0) middle_candidates[0] else null;

    // DC 203 has no direct datacenter endpoint. Its bundled address is a
    // `proxy_for 203` MiddleProxy that speaks RPC transport, so sending a raw
    // obfuscated client stream there succeeds at TCP connect but produces no
    // reply. Handle this invariant before direct-user and preference switches.
    const cdn_dc = dc_abs == 203;
    if (cdn_dc) {
        plan.use_middle_proxy = true;
        for (middle_candidates) |addr| {
            appendUniqueAddress(&plan.candidates, &plan.count, addr);
        }
        // Missing metadata fails closed: there is no valid direct fallback.
        plan.direct_fallback = null;
        return plan;
    }

    // Every remaining known DC is one of DC1..5 and has a real direct route.
    const direct = direct_addr orelse return plan;

    if (bypass_middle_proxy) {
        plan.candidates[0] = direct;
        plan.count = 1;
        plan.use_middle_proxy = false;
        plan.direct_fallback = null;
        return plan;
    }

    const force_media_middle_proxy = cfg.force_media_middle_proxy and dc_idx < 0 and middle_addr != null;
    plan.use_middle_proxy = if (force_media_middle_proxy)
        true
    else
        cfg.use_middle_proxy and middle_addr != null;

    if (!plan.use_middle_proxy) {
        plan.candidates[0] = direct;
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
        // DC1..5 have real direct endpoints, so an empty optional MiddleProxy
        // snapshot can safely fall back without changing application protocol.
        plan.use_middle_proxy = false;
        plan.candidates[0] = direct;
        plan.count = 1;
        plan.direct_fallback = null;
        return plan;
    }

    // Optional MiddleProxy routing for DC1..5 may retry their real direct endpoint.
    plan.direct_fallback = direct;
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
    const max_parallel_probes = 4;
    var start: usize = 0;
    while (start < candidates.len) : (start += max_parallel_probes) {
        const end = @min(candidates.len, start + max_parallel_probes);
        if (trySelectReachableMiddleProxyBatch(candidates[start..end], timeout_ms, stop)) |addr| return addr;
    }
    return null;
}

fn trySelectReachableMiddleProxyBatch(
    candidates: []const net.Address,
    timeout_ms: i32,
    stop: ?*const std.atomic.Value(bool),
) ?net.Address {
    if (builtin.os.tag != .linux) return null;

    var fds: [4]linux.pollfd = undefined;
    var addrs: [4]net.Address = undefined;
    var count: usize = 0;
    defer for (fds[0..count]) |poll_fd| {
        if (poll_fd.fd >= 0) _ = linux.close(poll_fd.fd);
    };

    for (candidates) |addr| {
        if (stop) |flag| if (flag.load(.acquire)) return null;

        const socket_rc = linux.socket(
            @intCast(addr.any.family),
            linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            linux.IPPROTO.TCP,
        );
        const fd: linux.fd_t = switch (posix.errno(socket_rc)) {
            .SUCCESS => @intCast(socket_rc),
            else => continue,
        };

        const connect_rc = linux.connect(fd, &addr.any, @intCast(addr.getOsSockLen()));
        switch (posix.errno(connect_rc)) {
            .SUCCESS => {
                _ = linux.close(fd);
                return addr;
            },
            .AGAIN, .INPROGRESS => {
                fds[count] = .{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 };
                addrs[count] = addr;
                count += 1;
            },
            else => _ = linux.close(fd),
        }
    }
    if (count == 0) return null;

    var remaining_ms = @max(timeout_ms, 0);
    while (true) {
        if (stop) |flag| if (flag.load(.acquire)) return null;
        const chunk_ms = @min(remaining_ms, 100);
        for (fds[0..count]) |*poll_fd| poll_fd.revents = 0;
        const poll_rc = linux.poll(&fds, count, chunk_ms);
        const ready = switch (posix.errno(poll_rc)) {
            .SUCCESS => poll_rc,
            .INTR => continue,
            else => return null,
        };

        if (ready > 0) {
            for (fds[0..count], addrs[0..count]) |*poll_fd, addr| {
                if (poll_fd.fd < 0 or poll_fd.revents == 0) continue;
                if (socketConnectSucceeded(poll_fd.fd)) return addr;
                _ = linux.close(poll_fd.fd);
                poll_fd.fd = -1;
            }
        }
        if (remaining_ms <= chunk_ms) return null;
        remaining_ms -= chunk_ms;
    }
}

fn socketConnectSucceeded(fd: linux.fd_t) bool {
    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const opt_rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    return posix.errno(opt_rc) == .SUCCESS and err_code == 0;
}

fn addressesEqual(a: []const net.Address, b: []const net.Address) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!lhs.eql(rhs)) return false;
    }
    return true;
}

fn parseMiddleProxyAddressForDc(config_text: []const u8, target_dc: i16) ?net.Address {
    var one: [1]net.Address = undefined;
    const sign: DcSignFilter = if (target_dc < 0) .negative_only else .positive_only;
    const n = parseMiddleProxyAddressesForDc(config_text, target_dc, sign, &one);
    if (n == 0) return null;
    return one[0];
}

fn queueOrWriteMsg(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue, data: []const u8) !bool {
    if (data.len == 0) return true;

    if (queue.isEmpty()) {
        const n = writeSlotFd(slot, fd, data) catch |err| {
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

fn queueOrWriteMsgPair(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue, first: []const u8, second: []const u8) !bool {
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
        const n = writevSlotFd(slot, fd, iovecs[0..n_iov]) catch |err| {
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

fn flushQueue(slot: *ConnectionSlot, fd: posix.fd_t, queue: *MessageQueue) !usize {
    if (queue.isEmpty()) return 0;

    var iovecs: [max_scatter_parts]posix.iovec_const = undefined;
    var total_written: usize = 0;
    var operations: usize = 0;

    while (!queue.isEmpty() and operations < queue_flush_operation_budget and total_written < event_io_byte_budget) {
        const local_remaining = event_io_byte_budget - total_written;
        const max_bytes = if (slot.event_io_budget) |budget| budget.allowedBytes(local_remaining) else local_remaining;
        const n_iov = queue.prepareIovecs(iovecs[0..], max_bytes);
        if (n_iov == 0) return total_written;

        const n = writevSlotFd(slot, fd, iovecs[0..n_iov]) catch |err| {
            if (err == error.WouldBlock) return total_written;
            return err;
        };

        if (n == 0) return error.ConnectionReset;
        try queue.consume(n);
        total_written += n;
        operations += 1;

        if (n < iovecs[0].len) return total_written;
    }

    return total_written;
}

fn queueClient(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot, slot.client_fd, &slot.client_queue, data);
}

fn queueClientPair(slot: *ConnectionSlot, first: []const u8, second: []const u8) !bool {
    return queueOrWriteMsgPair(slot, slot.client_fd, &slot.client_queue, first, second);
}

fn queueUpstream(slot: *ConnectionSlot, data: []const u8) !bool {
    return queueOrWriteMsg(slot, slot.upstream_fd, &slot.upstream_queue, data);
}

fn flushClientPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot, slot.client_fd, &slot.client_queue);
}

fn flushUpstreamPending(slot: *ConnectionSlot) !usize {
    return flushQueue(slot, slot.upstream_fd, &slot.upstream_queue);
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
    const timer_fd = try createTimerFd();
    defer closeFd(timer_fd);
    var deadlines: std.ArrayList(DeadlineEntry) = .empty;
    try deadlines.ensureTotalCapacity(std.testing.allocator, 4);

    var loop = EventLoop{
        .state = &state,
        .epoll_fd = epoll_fd,
        .timer_fd = timer_fd,
        .listen_fd = invalid_fd,
        .shutdown_fd = invalid_fd,
        .pool = try ConnectionPool.init(std.testing.allocator, 4),
        .managed_buffers = ManagedBufferAllocator.init(
            std.testing.allocator,
            @intCast(default_managed_buffer_limit_bytes),
        ),
        .message_block_pool = .{ .allocator = std.testing.allocator },
        .accept_paused = false,
        .accept_resume_ns = 0,
        .saturation_paused = false,
        .shutting_down = false,
        .shutdown_deadline_ns = 0,
        .deadline_heap = deadlines,
        .armed_deadline_ns = 0,
        .stats_next_log_ns = compat.monotonicNanoTimestamp() + stats_log_interval_ns,
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
        .prev_buffer_denials = 0,
        .mp_c2s_scratch = null,
        .mp_s2c_scratch = null,
        .pending_close_fds = .empty,
        .tracked_fds = 0,
    };
    defer {
        loop.drainPendingCloses();
        loop.pending_close_fds.deinit(std.testing.allocator);
        loop.pool.deinit();
        loop.message_block_pool.deinit();
        loop.deadline_heap.deinit(std.testing.allocator);
    }

    const slot = loop.pool.acquire() orelse return error.TestExpectedEqual;
    slot.client_queue.pool = &loop.message_block_pool;
    slot.upstream_queue.pool = &loop.message_block_pool;
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
    try std.testing.expectEqual(@as(u64, 1), state.stats_mp_fallback);
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

test "DC 203 always requests MiddleProxy metadata" {
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
    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 203, 203));
    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 203, -203));

    cfg.use_middle_proxy = true;
    try std.testing.expect(shouldUseMiddleProxySnapshot(&cfg, 4, 4));

    cfg.datacenter_override = net.Address.initIp4(.{ 127, 0, 0, 1 }, 443);
    try std.testing.expect(!shouldUseMiddleProxySnapshot(&cfg, 4, -4));
    try std.testing.expect(!shouldUseMiddleProxySnapshot(&cfg, 203, -203));
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

test "direct users bypass middle-proxy routing except CDN DC 203" {
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
    const regular_snapshot = ProxyState.MiddleProxySnapshot{
        .candidates = [_]net.Address{mp_dc4} ** 16,
        .candidate_len = 1,
        .secret_version = 1,
    };
    const media_203_snapshot = ProxyState.MiddleProxySnapshot{
        .candidates = [_]net.Address{mp_dc203} ** 16,
        .candidate_len = 1,
        .secret_version = 1,
    };
    const media_dc5_snapshot = ProxyState.MiddleProxySnapshot{
        .candidates = [_]net.Address{ constants.tg_media_middle_proxies_v4[4], mp_media_dc5_secondary } ++
            ([_]net.Address{constants.tg_media_middle_proxies_v4[4]} ** 14),
        .candidate_len = 2,
        .secret_version = 1,
    };

    const regular_plan = buildDcConnectPlan(&cfg, 4, 4, &regular_snapshot, false);
    try std.testing.expect(regular_plan.use_middle_proxy);
    try std.testing.expect(regular_plan.direct_fallback != null);
    try std.testing.expect(regular_plan.candidates[0].eql(mp_dc4));

    const admin_plan = buildDcConnectPlan(&cfg, 4, 4, &regular_snapshot, true);
    try std.testing.expect(!admin_plan.use_middle_proxy);
    try std.testing.expect(admin_plan.direct_fallback == null);
    try std.testing.expect(admin_plan.candidates[0].eql(constants.getDirectDcAddressV4(4).?));

    const regular_media = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, false);
    try std.testing.expect(regular_media.use_middle_proxy);
    try std.testing.expect(regular_media.candidates[0].eql(mp_dc203));
    try std.testing.expect(regular_media.direct_fallback == null);

    const regular_media_dc5 = buildDcConnectPlan(&cfg, 5, -5, &media_dc5_snapshot, false);
    try std.testing.expectEqual(@as(usize, 2), regular_media_dc5.count);
    try std.testing.expect(regular_media_dc5.candidates[1].eql(mp_media_dc5_secondary));

    const admin_media = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, true);
    try std.testing.expect(admin_media.use_middle_proxy);
    try std.testing.expect(admin_media.candidates[0].eql(mp_dc203));
    try std.testing.expect(admin_media.direct_fallback == null);

    // A missing DC 203 route fails closed instead of sending raw MTProto to a
    // MiddleProxy endpoint. The caller requests a debounced metadata refresh.
    const admin_media_no_mp = buildDcConnectPlan(&cfg, 203, -203, null, true);
    try std.testing.expect(admin_media_no_mp.use_middle_proxy);
    try std.testing.expectEqual(@as(usize, 0), admin_media_no_mp.count);
    try std.testing.expect(admin_media_no_mp.direct_fallback == null);

    // Disabling both optional MiddleProxy preferences keeps real media DCs
    // direct, but cannot override the protocol requirement for CDN DC 203.
    cfg.use_middle_proxy = false;
    cfg.force_media_middle_proxy = false;

    const direct_media_dc5 = buildDcConnectPlan(&cfg, 5, -5, &media_dc5_snapshot, false);
    try std.testing.expect(!direct_media_dc5.use_middle_proxy);
    try std.testing.expectEqual(@as(usize, 1), direct_media_dc5.count);
    try std.testing.expect(direct_media_dc5.candidates[0].eql(constants.getDirectDcAddressV4(5).?));

    const mandatory_cdn = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, false);
    try std.testing.expect(mandatory_cdn.use_middle_proxy);
    try std.testing.expectEqual(@as(usize, 1), mandatory_cdn.count);
    try std.testing.expect(mandatory_cdn.candidates[0].eql(mp_dc203));
    try std.testing.expect(mandatory_cdn.direct_fallback == null);

    const mandatory_cdn_direct_user = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, true);
    try std.testing.expect(mandatory_cdn_direct_user.use_middle_proxy);
    try std.testing.expect(mandatory_cdn_direct_user.candidates[0].eql(mp_dc203));
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
    const n = q.prepareIovecs(iov[0..], std.math.maxInt(usize));
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u8, 'c'), iov[0].base[0]);

    try q.consume(5);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.offset);
    try std.testing.expect(q.head == null);
    try std.testing.expect(q.tail == null);
}

test "message queue uses page-sized blocks and fills the tail first" {
    try std.testing.expectEqual(std.heap.page_size_min, @sizeOf(MsgBlock));
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    try q.appendCopy("abc");
    const first = q.head.?;
    try q.appendCopy("defg");
    try std.testing.expect(q.head.? == first);
    try std.testing.expect(q.tail.? == first);
    try std.testing.expect(first.next == null);
    try std.testing.expectEqual(@as(usize, 7), first.len);
    try std.testing.expectEqualStrings("abcdefg", blockStorageConst(first)[0..first.len]);

    q.clear();

    var payload: [msg_block_payload_size + 1]u8 = [_]u8{0xA5} ** (msg_block_payload_size + 1);
    try q.appendCopy(&payload);
    const page_first = q.head.?;
    const page_second = page_first.next.?;
    try std.testing.expectEqual(msg_block_payload_size, page_first.len);
    try std.testing.expectEqual(@as(usize, 1), page_second.len);
    try std.testing.expect(q.tail.? == page_second);
    try std.testing.expect(page_second.next == null);
}

test "message queue consumed prefix permits one conservative extra block" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    var payload: [msg_block_payload_size]u8 = [_]u8{0x5A} ** msg_block_payload_size;
    try q.appendCopy(&payload);
    const first = q.head.?;
    try q.consume(1);
    try q.appendCopy(&[_]u8{0xA5});

    try std.testing.expectEqual(msg_block_payload_size, q.total_len);
    try std.testing.expect(q.head.? == first);
    try std.testing.expect(first.next != null);
    try std.testing.expect(q.tail.? == first.next.?);
}

test "message queue rejects pending byte overflow" {
    var q = MessageQueue{ .allocator = std.testing.allocator };
    defer q.deinit();

    q.total_len = MessageQueue.max_pending_bytes;
    try std.testing.expectError(error.PendingQueueOverflow, q.ensureCanAppend(1));
    q.total_len = 0;
}

test "shared message block pool trims and wipes recycled page blocks" {
    var pool = MessageBlockPool{ .allocator = std.testing.allocator };
    defer pool.deinit();

    var blocks: [MessageBlockPool.max_free_blocks + 8]*MsgBlock = undefined;
    for (&blocks) |*entry| {
        entry.* = try pool.acquire();
        @memset(blockStorage(entry.*), 0xA5);
        entry.*.len = msg_block_payload_size;
    }
    for (blocks) |blk| pool.recycle(blk);

    try std.testing.expectEqual(MessageBlockPool.max_free_blocks, pool.free_count);
    const recycled = pool.free_head.?;
    try std.testing.expectEqual(@as(usize, 0), recycled.len);
    for (blockStorageConst(recycled)) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "managed buffer allocator enforces limit and accounts transient growth" {
    var budget = ManagedBufferAllocator.init(std.testing.allocator, 128);
    const allocator = budget.allocator();

    const first = try allocator.alloc(u8, 64);
    try std.testing.expectEqual(@as(usize, 64), budget.used_bytes);
    try std.testing.expectEqual(@as(usize, 64), budget.peak_bytes);

    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 65));
    try std.testing.expectEqual(@as(u64, 1), budget.denied_allocations);

    // The wrapper refuses remap, so realloc must reserve the replacement while
    // the old allocation is still resident. A failed growth leaves accounting
    // and ownership of the original allocation unchanged.
    try std.testing.expectError(error.OutOfMemory, allocator.realloc(first, 96));
    try std.testing.expectEqual(@as(usize, 64), budget.used_bytes);
    try std.testing.expectEqual(@as(u64, 2), budget.denied_allocations);

    allocator.free(first);
    try std.testing.expectEqual(@as(usize, 0), budget.used_bytes);
}

test "managed buffer budget includes retained message pages" {
    const page_bytes = @sizeOf(MsgBlock);
    var budget = ManagedBufferAllocator.init(std.testing.allocator, page_bytes);
    var pool = MessageBlockPool{ .allocator = budget.allocator() };

    const first = try pool.acquire();
    try std.testing.expectEqual(page_bytes, budget.used_bytes);
    try std.testing.expectError(error.OutOfMemory, pool.acquire());

    pool.recycle(first);
    try std.testing.expectEqual(page_bytes, budget.used_bytes);
    const reused = try pool.acquire();
    try std.testing.expect(reused == first);
    pool.recycle(reused);

    pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), budget.used_bytes);
}

test "queue memory budget covers two queues and the shared pool" {
    const runtime_page_size = std.heap.page_size_min;
    const full_queue_blocks =
        (MessageQueue.max_pending_bytes + msg_block_payload_size - 1) /
        msg_block_payload_size;
    const active_blocks_per_queue = full_queue_blocks + 1;
    const budget = queueMemoryBudget(runtime_page_size);

    try std.testing.expectEqual(
        @as(u64, @intCast(active_blocks_per_queue * 2 * runtime_page_size)),
        budget.per_connection_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(MessageBlockPool.max_free_blocks * runtime_page_size)),
        budget.shared_pool_bytes,
    );
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

test "relay EOF requires complete transport frames" {
    var slot = ConnectionSlot{};
    slot.phase = .relaying;
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
    try std.testing.expect(upstreamRelayAtFrameBoundary(&slot));

    slot.relay_tls_hdr_pos = 1;
    try std.testing.expect(!clientRelayAtFrameBoundary(&slot));
    slot.relay_tls_hdr_pos = 0;
    slot.relay_tls_body_len = 16;
    slot.relay_tls_body_pos = 8;
    try std.testing.expect(!clientRelayAtFrameBoundary(&slot));

    slot.phase = .mask_relaying;
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
    try std.testing.expect(upstreamRelayAtFrameBoundary(&slot));
}

test "relay half-close completes only after both FIN paths drain" {
    var slot = ConnectionSlot{};
    slot.phase = .relaying;
    slot.client_read_closed = true;
    slot.upstream_read_closed = true;
    slot.client_write_shutdown = true;
    try std.testing.expect(!relayHalfCloseComplete(&slot));

    slot.upstream_write_shutdown = true;
    try std.testing.expect(relayHalfCloseComplete(&slot));

    slot.client_queue.total_len = 1;
    try std.testing.expect(!relayHalfCloseComplete(&slot));
    slot.client_queue.total_len = 0;
    slot.upstream_queue.total_len = 1;
    try std.testing.expect(!relayHalfCloseComplete(&slot));
}

test "epoll slot tokens preserve registration generation and fd role" {
    var slot = ConnectionSlot{
        .index = 123,
        .client_event_generation = 77,
        .upstream_event_generation = 91,
    };

    const client = decodeSlotEventToken(encodeSlotEventToken(&slot, .client)).?;
    try std.testing.expectEqual(@as(u32, 123), client.index);
    try std.testing.expectEqual(@as(u32, 77), client.generation);
    try std.testing.expectEqual(SlotFdRole.client, client.role);

    const upstream = decodeSlotEventToken(encodeSlotEventToken(&slot, .upstream)).?;
    try std.testing.expectEqual(@as(u32, 91), upstream.generation);
    try std.testing.expectEqual(SlotFdRole.upstream, upstream.role);
    try std.testing.expectEqual(@as(u32, 1), nextSlotGeneration(max_slot_generation));
    try std.testing.expect(decodeSlotEventToken(epoll_listener_token) == null);
    try std.testing.expect(decodeSlotEventToken(epoll_timer_token) == null);
    try std.testing.expect(decodeSlotEventToken(epoll_shutdown_token) == null);
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
        @as(i64, 7000),
        budgetedConnectTimeoutMs(0, 1_000, 15_000, 2_000, 2),
    );
    try std.testing.expectEqual(
        @as(i64, 5000),
        budgetedConnectTimeoutMs(10_000, 1_000, 15_000, 11_000, 1),
    );
}

test "middle proxy stage reserves remaining handshake budget for direct fallback" {
    try std.testing.expectEqual(
        @as(i64, 1000),
        budgetedMiddleProxyStageTimeoutMs(5_000, 1_000, 5_000, 4_000, true),
    );
    try std.testing.expectEqual(
        @as(i64, 5_000),
        budgetedMiddleProxyStageTimeoutMs(5_000, 1_000, 5_000, 4_000, false),
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
    try std.testing.expect(shouldAcceptListen(false, false, false));
    try std.testing.expect(!shouldAcceptListen(true, false, false));
    try std.testing.expect(!shouldAcceptListen(false, true, false));
    try std.testing.expect(!shouldAcceptListen(true, true, false));
    try std.testing.expect(!shouldAcceptListen(false, false, true));
}

test "WEB-only masks direct peers and always serves its trusted relay" {
    try std.testing.expect(!webOnlyMasksPeer(false, false));
    try std.testing.expect(!webOnlyMasksPeer(false, true));
    try std.testing.expect(webOnlyMasksPeer(true, false));
    try std.testing.expect(!webOnlyMasksPeer(true, true));
}

test "parse ipv4 literal" {
    const parsed = parseIpv4Literal("179.43.141.146") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual([4]u8{ 179, 43, 141, 146 }, parsed);
    try std.testing.expect(parseIpv4Literal("179.43.141") == null);
    try std.testing.expect(parseIpv4Literal("179.43.141.999") == null);
}

test "client IP formatting omits port and normalizes mapped IPv4" {
    var buf: [64]u8 = undefined;
    const native = net.Address.initIp4(.{ 203, 0, 113, 7 }, 54321);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(native, &buf));

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.Address.initIp6(mapped_bytes, 54321, 0, 0);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(mapped, &buf));
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

    const parsed = (try parseAwgEndpointIpv4FromConfig(
        std.testing.allocator,
        content,
        null,
    )) orelse return error.TestExpectedEqual;
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

test "replay cache replaces oldest live entry without reporting false replay" {
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
            .last_seen_s = now_s - @as(i64, @intCast(probe)),
        };
    }

    try std.testing.expect(!cache.checkAndInsert(&digest));
    probe = 0;
    while (probe + 1 < ReplayCache.MAX_PROBES) : (probe += 1) {
        const idx = (start + probe) & (ReplayCache.BUCKETS - 1);
        try std.testing.expectEqual(@as(u64, @intCast(probe + 1)), cache.entries[idx].key);
    }
    const replaced_idx = (start + ReplayCache.MAX_PROBES - 1) & (ReplayCache.BUCKETS - 1);
    try std.testing.expectEqual(ReplayCache.digestKey(&digest), cache.entries[replaced_idx].key);
    try std.testing.expect(cache.checkAndInsert(&digest));
}

test "handshakeInProgress - phases" {
    var slot: ConnectionSlot = undefined;

    const hs_phases = [_]ConnectionPhase{
        .reading_web_prefix,
        .reading_tls_header,
        .reading_direct_obfuscated_handshake,
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
        .timer_fd = invalid_fd,
        .listen_fd = invalid_fd,
        .shutdown_fd = invalid_fd,
        .pool = try ConnectionPool.init(std.testing.allocator, 1),
        .managed_buffers = ManagedBufferAllocator.init(
            std.testing.allocator,
            @intCast(default_managed_buffer_limit_bytes),
        ),
        .message_block_pool = .{ .allocator = std.testing.allocator },
        .accept_paused = false,
        .accept_resume_ns = 0,
        .saturation_paused = false,
        .shutting_down = false,
        .shutdown_deadline_ns = 0,
        .deadline_heap = .empty,
        .armed_deadline_ns = 0,
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
        .prev_buffer_denials = 0,
        .mp_c2s_scratch = null,
        .mp_s2c_scratch = null,
        .pending_close_fds = .empty,
        .tracked_fds = 0,
    };
    defer {
        loop.pending_close_fds.deinit(std.testing.allocator);
        loop.pool.deinit();
        loop.message_block_pool.deinit();
        loop.deadline_heap.deinit(std.testing.allocator);
    }

    const slot = loop.pool.acquire() orelse return error.TestExpectedEqual;
    defer loop.pool.release(slot);

    try std.testing.expectEqual(@as(u32, 0), state.handshakes_inflight);
    try std.testing.expect(loop.reserveHandshakeBudget(slot));
    try std.testing.expect(slot.hs_counted);
    try std.testing.expectEqual(@as(u32, 1), state.handshakes_inflight);

    try std.testing.expect(loop.reserveHandshakeBudget(slot));
    try std.testing.expectEqual(@as(u32, 1), state.handshakes_inflight);

    loop.releaseHandshakeBudget(slot);
    loop.releaseHandshakeBudget(slot);
    try std.testing.expect(!slot.hs_counted);
    try std.testing.expectEqual(@as(u32, 0), state.handshakes_inflight);
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
