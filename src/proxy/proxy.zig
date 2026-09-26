//! Proxy core — worker-owned Linux epoll event loops.
//!
//! This replaces the thread-per-connection model with a pre-allocated
//! connection pool and non-blocking state machine.

const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net_helpers.zig");
const posix = std.posix;
const linux = std.os.linux;
// Direct linux.* calls return negated errno even when libc is linked (e.g. TSan).
// Match them with linux.errno; reserve posix.errno for posix.system.* calls.

const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const runtime_time = @import("../runtime/time.zig");
const runtime_sync = @import("../runtime/sync.zig");
const linux_fs = @import("../runtime/linux_fs.zig");
const http_fetch = @import("../http_fetch.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;
const web_support = @import("web_support.zig");
const ManagedBufferAllocator = @import("managed_buffer_allocator.zig").ManagedBufferAllocator;
const message_queue = @import("message_queue.zig");
const MessageBlockPool = message_queue.MessageBlockPool;
const MessageQueue = message_queue.MessageQueue;
pub const QueueMemoryBudget = message_queue.QueueMemoryBudget;
pub const queueMemoryBudget = message_queue.queueMemoryBudget;
const wedge_recovery = @import("wedge_recovery.zig");
const WedgeGateTicket = wedge_recovery.WedgeGateTicket;
const WedgeRecoveryGate = wedge_recovery.WedgeRecoveryGate;
const wedgeClientIdentityKey = wedge_recovery.wedgeClientIdentityKey;
const security_state = @import("security_state.zig");
const SubnetRateLimit = security_state.SubnetRateLimit;
const SecurityState = security_state.SecurityState;
const subnetHandshakeLimit = security_state.subnetHandshakeLimit;
const reserveGlobalCount = security_state.reserveGlobalCount;
const releaseGlobalCount = security_state.releaseGlobalCount;
const countStat = security_state.countStat;
const connection = @import("connection.zig");
const tls_header_len = connection.tls_header_len;
const event_io_byte_budget = connection.event_io_byte_budget;
const event_io_operation_budget = connection.event_io_operation_budget;
const invalid_fd = connection.invalid_fd;
const UpstreamKind = connection.UpstreamKind;
const MaskCause = connection.MaskCause;
const ConnectionPhase = connection.ConnectionPhase;
const MiddleProxyHandshakeStep = connection.MiddleProxyHandshakeStep;
const DynamicRecordSizer = connection.DynamicRecordSizer;
const EventIoBudget = connection.EventIoBudget;
const ConnectionSlot = connection.ConnectionSlot;
pub const BenchCandidatePath = connection.BenchCandidatePath;
const secureFree = connection.secureFree;
const connection_pool = @import("connection_pool.zig");
const epoll_listener_token = connection_pool.epoll_listener_token;
const epoll_timer_token = connection_pool.epoll_timer_token;
const epoll_shutdown_token = connection_pool.epoll_shutdown_token;
const SlotFdRole = connection_pool.SlotFdRole;
const nextSlotGeneration = connection_pool.nextSlotGeneration;
const encodeSlotEventToken = connection_pool.encodeSlotEventToken;
const decodeSlotEventToken = connection_pool.decodeSlotEventToken;
const ConnectionPool = connection_pool.ConnectionPool;
const DeadlineQueue = @import("deadline_queue.zig").DeadlineQueue;

const log = std.log.scoped(.proxy);

const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
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
const mp_handshake_frame_buf_size: usize = 2048;
const relay_read_scratch_size: usize = 32 * 1024;
const pipelined_initial_capacity: usize = 4096;
pub const default_managed_buffer_limit_bytes: u64 = 64 * 1024 * 1024;
const min_worker_managed_bytes: u64 = 8 * 1024 * 1024;
const min_worker_slots: u32 = 32;
const worker_health_timeout_ms: i64 = 45 * std.time.ms_per_s;
const worker_health_poll_ms: i32 = 10 * std.time.ms_per_s;
const pre_first_byte_timeout_ms: i64 = 10 * std.time.ms_per_s;
const middle_proxy_stage_timeout_ms: i64 = 5 * std.time.ms_per_s;
const tls_control_record_budget: usize = 8;
const tls_control_byte_budget: usize = 64 * 1024;

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
    switch (linux.errno(rc)) {
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
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn drainTimerFd(fd: posix.fd_t) void {
    var expirations: u64 = 0;
    while (true) {
        const bytes = std.mem.asBytes(&expirations);
        const rc = linux.read(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return,
            else => return,
        }
    }
}

fn getsockoptErrorFd(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    var err_code: i32 = 0;
    var err_len: linux.socklen_t = @sizeOf(i32);
    const err_bytes = std.mem.asBytes(&err_code);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, err_bytes.ptr, &err_len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    if (err_code == 0) return;

    const err: @TypeOf(linux.errno(rc)) = @enumFromInt(err_code);
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
        switch (linux.errno(rc)) {
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
        switch (linux.errno(rc)) {
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
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return,
    }
}

fn seekFdToStart(fd: posix.fd_t) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const rc = linux.lseek(fd, 0, linux.SEEK.SET);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .SPIPE => return error.Unseekable,
        else => return error.Unexpected,
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

fn shouldCloseOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    if (phase == .idle) return false;

    // During connecting_upstream, EPOLLERR on upstream fd is expected and
    // handled via onUpstreamWritable -> onUpstreamConnectComplete.
    return !(phase == .connecting_upstream and event_fd == upstream_fd);
}

fn shouldFallbackMiddleProxyOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    return phase == .middle_proxy_handshake and event_fd == upstream_fd;
}

const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

const DcConnectPlan = struct {
    candidates: [16]net.Address = undefined,
    count: usize = 0,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,
    direct_fallback: ?net.Address = null,
};

const MiddleProxyLock = struct {
    mutex: runtime_sync.BlockingMutex = .{},

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

const middle_proxy_connect_cooldown_ms: i64 = 60 * std.time.ms_per_s;
const middle_proxy_cooldown_slots = 32;

const MiddleProxyCooldown = struct {
    active: bool = false,
    addr: net.Address = undefined,
    until_ms: i64 = 0,
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

fn freeUserSecrets(allocator: std.mem.Allocator, secrets: []obfuscation.UserSecret) void {
    for (secrets) |*secret| {
        std.crypto.secureZero(u8, &secret.secret);
        allocator.free(secret.name);
    }
    allocator.free(secrets);
}

/// Slots and managed queue/block bytes are partitioned rather than cloned.
/// MiddleProxy scratch is lazy but can consume most of an 8 MiB partition
/// with a large configured MP stream cap. Keep queue/stream headroom when
/// selecting workers automatically or admitting an explicit count.
fn minWorkerManagedBytes(cfg: *const Config) u64 {
    if (!cfg.requiresMiddleProxyRuntime()) return min_worker_managed_bytes;
    const scratch: u64 = @intCast(cfg.middleProxySharedScratchBytes());
    return @max(min_worker_managed_bytes, scratch + 4 * 1024 * 1024);
}

fn workerResourceLimit(max_connections: u32, managed_bytes: u64, min_managed_bytes: u64) u8 {
    const by_slots = @as(u64, max_connections / min_worker_slots);
    const by_memory = managed_bytes / min_managed_bytes;
    return @intCast(@max(1, @min(@as(u64, Config.max_workers), @min(by_slots, by_memory))));
}

fn selectWorkerCount(requested: u8, max_connections: u32, managed_bytes: u64, min_managed_bytes: u64, cpu_count: usize) !u8 {
    if (requested > Config.max_workers) return error.InvalidWorkers;
    const resource_limit = workerResourceLimit(max_connections, managed_bytes, min_managed_bytes);
    if (requested == 0) return @intCast(@max(1, @min(@as(usize, resource_limit), cpu_count)));
    if (requested > 1 and requested > resource_limit) return error.InsufficientWorkerResources;
    return requested;
}

fn workerSlotCapacity(total: u32, workers: u8, index: u8) u32 {
    const count: u32 = workers;
    return total / count + @intFromBool(@as(u32, index) < total % count);
}

fn workerManagedBudget(total: u64, workers: u8, index: u8) u64 {
    const count: u64 = workers;
    return total / count + @intFromBool(@as(u64, index) < total % count);
}

fn workerHeartbeatStale(now_ms: i64, last_ms: i64) bool {
    return now_ms >= last_ms and now_ms - last_ms > worker_health_timeout_ms;
}

pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    managed_buffer_limit_bytes: u64,
    user_secrets: []obfuscation.UserSecret,
    connection_count: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    handshakes_inflight: std.atomic.Value(u32),
    mask_target: ?[]const u8,
    mask_addrs: []net.Address,
    trusted_web_peers: web_support.TrustedPeers,
    web_only: bool = false,
    web_mask_dns: ?*web_support.DnsCache = null,
    security: *SecurityState,
    tls_server_hello_template: []u8,

    // Degradation counters (monotonic totals, delta'd in stats log)
    stats_dropped_cap: std.atomic.Value(u64),
    stats_dropped_saturation: std.atomic.Value(u64),
    stats_dropped_rate_limit: std.atomic.Value(u64),
    stats_dropped_hs_budget: std.atomic.Value(u64),
    stats_hs_timeout: std.atomic.Value(u64),
    stats_mp_fallback: std.atomic.Value(u64),
    stats_web_only_masked: std.atomic.Value(u64) = .init(0),

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

        const security = try SecurityState.create(allocator);
        errdefer allocator.destroy(security);

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
                    if (web_support.isLoopback(address) and address.getPort() == cfg.port) {
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
            .connection_count = .init(0),
            .active_connections = .init(0),
            .handshakes_inflight = .init(0),
            .mask_target = mask_target,
            .mask_addrs = resolved_addrs,
            .trusted_web_peers = trusted_web_peers,
            .web_only = cfg.web.onlyActive(),
            .web_mask_dns = web_mask_dns,
            .security = security,
            .tls_server_hello_template = tls_template,
            .stats_dropped_cap = .init(0),
            .stats_dropped_saturation = .init(0),
            .stats_dropped_rate_limit = .init(0),
            .stats_dropped_hs_budget = .init(0),
            .stats_hs_timeout = .init(0),
            .stats_mp_fallback = .init(0),
            .stats_web_only_masked = .init(0),
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
        self.stopMiddleProxyUpdater();
        if (self.web_mask_dns) |cache| cache.destroy();
        self.allocator.destroy(self.security);
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

    fn allowSubnet(self: *ProxyState, addr: net.Address) bool {
        if (self.config.rate_limit_per_subnet == 0) return true;
        self.security.lock.lock();
        defer self.security.lock.unlock();
        return self.security.subnet_limiter.check(addr, self.config.rate_limit_per_subnet);
    }

    fn reserveSubnetHandshake(self: *ProxyState, key: u64) bool {
        self.security.lock.lock();
        defer self.security.lock.unlock();
        return self.security.subnet_handshakes.reserve(key, subnetHandshakeLimit(self.config.max_connections));
    }

    fn releaseSubnetHandshake(self: *ProxyState, key: u64) void {
        self.security.lock.lock();
        defer self.security.lock.unlock();
        self.security.subnet_handshakes.release(key);
    }

    fn isReplay(self: *ProxyState, digest: *const [32]u8) bool {
        self.security.lock.lock();
        defer self.security.lock.unlock();
        return self.security.replay_cache.checkAndInsert(digest);
    }

    fn wedgeSuppressesNewCandidates(self: *ProxyState, key: u64, dc: u16, now_ms: i64) bool {
        self.security.wedge_lock.lock();
        defer self.security.wedge_lock.unlock();
        return self.security.wedge_recovery_gate.suppressesNewCandidates(key, dc, now_ms);
    }

    fn prepareWedge(self: *ProxyState, key: u64, dc: u16, now_ms: i64, timeout_ms: i64, idle_deadline_ms: i64) ?WedgeGateTicket {
        self.security.wedge_lock.lock();
        defer self.security.wedge_lock.unlock();
        return self.security.wedge_recovery_gate.prepare(key, dc, now_ms, timeout_ms, idle_deadline_ms);
    }

    fn reportWedgeSuppression(self: *ProxyState, key: u64, dc: u16, now_ms: i64) bool {
        self.security.wedge_lock.lock();
        defer self.security.wedge_lock.unlock();
        return self.security.wedge_recovery_gate.reportSuppression(key, dc, now_ms);
    }

    fn allowWedgeClose(self: *ProxyState, key: u64, dc: u16, ticket: WedgeGateTicket, now_ms: i64) bool {
        self.security.wedge_lock.lock();
        defer self.security.wedge_lock.unlock();
        return self.security.wedge_recovery_gate.allowClose(key, dc, ticket, now_ms);
    }

    pub fn run(self: *ProxyState, shutdown_fd: posix.fd_t) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (self.web_mask_dns) |cache| try cache.start();

        var middle_proxy_updater_started = false;
        defer {
            if (middle_proxy_updater_started) self.stopMiddleProxyUpdater();
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

        const cpu_count = std.Thread.getCpuCount() catch 1;
        const min_managed_bytes = minWorkerManagedBytes(&self.config);
        const workers = selectWorkerCount(
            self.config.workers,
            self.config.max_connections,
            self.managed_buffer_limit_bytes,
            min_managed_bytes,
            cpu_count,
        ) catch |err| {
            log.err("server.workers={d} cannot fit max_connections={d} and managed_budget={d}MiB (need at least {d} slots and {d}KiB per worker): {any}", .{
                self.config.workers,
                self.config.max_connections,
                self.managed_buffer_limit_bytes / (1024 * 1024),
                min_worker_slots,
                min_managed_bytes / 1024,
                err,
            });
            return err;
        };
        const mode: []const u8 = if (self.config.workers == 0) "auto" else if (workers == 1) "single" else "explicit";
        log.info("MTProto workers: requested={d} effective={d} mode={s} CPUs={d} max_connections={d} managed_budget={d}MiB min_worker_budget={d}KiB", .{
            self.config.workers,
            workers,
            mode,
            cpu_count,
            self.config.max_connections,
            self.managed_buffer_limit_bytes / (1024 * 1024),
            min_managed_bytes / 1024,
        });

        if (workers > 1) return self.runMultiWorkers(workers, shutdown_fd);

        var listener = try self.openFirstListener(false);
        defer listener.server.deinit();
        log.info("Listening on {s}:{d} (epoll, single-thread)", .{
            if (listener.ipv6) "[::]" else "0.0.0.0",
            self.config.port,
        });
        const loop = try EventLoop.init(
            self,
            listener.server.handle,
            shutdown_fd,
            0,
            self.config.max_connections,
            self.managed_buffer_limit_bytes,
            null,
        );
        defer {
            loop.deinit();
            self.allocator.destroy(loop);
        }
        try loop.run();
    }

    const ClientListener = struct {
        server: net.Listener,
        ipv6: bool,
    };

    fn listenClient(self: *ProxyState, ipv6: bool, reuse_port: bool) !net.Listener {
        const address = if (ipv6)
            net.ip6([_]u8{0} ** 16, self.config.port, 0, 0)
        else
            net.ip4(.{ 0, 0, 0, 0 }, self.config.port);
        return net.listen(address, .{
            .reuse_address = true,
            .reuse_port = reuse_port,
            .kernel_backlog = @intCast(self.config.backlog),
        });
    }

    fn openFirstListener(self: *ProxyState, reuse_port: bool) !ClientListener {
        const server = self.listenClient(true, reuse_port) catch |err| {
            if (err != error.AddressFamilyNotSupported) return err;
            log.warn("IPv6 not available, falling back to IPv4 (0.0.0.0)", .{});
            return .{ .server = try self.listenClient(false, reuse_port), .ipv6 = false };
        };
        return .{ .server = server, .ipv6 = true };
    }

    fn runMultiWorkers(self: *ProxyState, count: u8, signal_fd: posix.fd_t) !void {
        const completion_fd = try createWorkerEventFd();
        defer closeFd(completion_fd);

        // Stable stack addresses are shared with the threads. A worker owns
        // its listener and loop after spawn; the control thread owns each
        // worker's eventfd until every thread has been joined.
        var workers: [Config.max_workers]Worker = undefined;
        var started: usize = 0;
        defer {
            signalWorkers(workers[0..started], 2) catch |err| {
                // Joining a worker that cannot be woken could hang forever
                // while its listener remains in the reuseport group.
                log.err("cannot wake MTProto workers during cleanup: {any}; exiting", .{err});
                std.process.exit(1);
            };
            for (workers[0..started]) |*worker| worker.thread.join();
            std.debug.assert(self.active_connections.load(.monotonic) == 0);
            std.debug.assert(self.handshakes_inflight.load(.monotonic) == 0);
            for (workers[0..started]) |*worker| closeFd(worker.control_fd);
        }

        var ipv6 = true;
        for (0..count) |i| {
            var listener = if (i == 0)
                try self.openFirstListener(true)
            else
                ClientListener{ .server = try self.listenClient(ipv6, true), .ipv6 = ipv6 };
            ipv6 = listener.ipv6;
            const control_fd = createWorkerEventFd() catch |err| {
                listener.server.deinit();
                return err;
            };
            const id: u8 = @intCast(i);
            workers[i] = .{
                .id = id,
                .loop = undefined,
                .listen_fd = listener.server.handle,
                .control_fd = control_fd,
                .completion_fd = completion_fd,
                .heartbeat_ms = .init(runtime_time.monotonicMilli()),
                .finished = .init(false),
                .failed = .init(false),
                .thread = undefined,
            };
            const loop = EventLoop.init(
                self,
                listener.server.handle,
                control_fd,
                id,
                workerSlotCapacity(self.config.max_connections, count, id),
                workerManagedBudget(self.managed_buffer_limit_bytes, count, id),
                &workers[i].heartbeat_ms,
            ) catch |err| {
                closeFd(control_fd);
                listener.server.deinit();
                return err;
            };
            workers[i].loop = loop;
            workers[i].thread = std.Thread.spawn(.{}, Worker.run, .{&workers[i]}) catch |err| {
                abandonUnstartedWorker(self, loop, control_fd, &listener.server);
                return err;
            };
            started += 1;
            log.info("MTProto worker {d}/{d} online: {s}:{d} slots={d} managed_budget={d}MiB", .{
                i + 1,
                count,
                if (ipv6) "[::]" else "0.0.0.0",
                self.config.port,
                workerSlotCapacity(self.config.max_connections, count, id),
                workerManagedBudget(self.managed_buffer_limit_bytes, count, id) / (1024 * 1024),
            });
        }

        var shutdown_started = false;
        var failure_shutdown_sent = false;
        while (true) {
            var completed: usize = 0;
            var failed = false;
            const now_ms = runtime_time.monotonicMilli();
            for (workers[0..started]) |*worker| {
                if (worker.finished.load(.acquire)) {
                    completed += 1;
                    failed = failed or worker.failed.load(.monotonic);
                } else if (workerHeartbeatStale(now_ms, worker.heartbeat_ms.load(.monotonic))) {
                    // A permanently wedged worker still owns sockets. Joining
                    // it would hang; terminate the process so the supervisor
                    // can restart a complete reuseport group.
                    log.err("MTProto worker {d} unresponsive for >{d}ms; exiting", .{ worker.id, worker_health_timeout_ms });
                    std.process.exit(1);
                }
            }
            if (failed and !failure_shutdown_sent) {
                log.err("MTProto worker failed; shutting down all workers", .{});
                signalWorkers(workers[0..started], 2) catch |err| {
                    log.err("cannot wake MTProto workers after failure: {any}; exiting", .{err});
                    std.process.exit(1);
                };
                shutdown_started = true;
                failure_shutdown_sent = true;
            }
            if (completed == started) {
                if (failed) return error.WorkerFailed;
                if (!shutdown_started) return error.WorkerExitedUnexpectedly;
                return;
            }

            var fds = [_]posix.pollfd{
                .{ .fd = signal_fd, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = completion_fd, .events = posix.POLL.IN, .revents = 0 },
            };
            _ = try posix.poll(&fds, worker_health_poll_ms);
            if ((fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0 or
                (fds[1].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0)
            {
                return error.WorkerControlFdFailed;
            }
            if ((fds[0].revents & posix.POLL.IN) != 0) {
                const signal_count = try readWorkerEventFd(signal_fd);
                if (signal_count > 0) {
                    // Each worker needs its own eventfd: a read on a shared
                    // eventfd would wake only one epoll waiter.
                    signalWorkers(workers[0..started], if (shutdown_started) 2 else signal_count) catch |err| {
                        log.err("cannot broadcast MTProto shutdown: {any}; exiting", .{err});
                        std.process.exit(1);
                    };
                    shutdown_started = true;
                }
            }
            if ((fds[1].revents & posix.POLL.IN) != 0) {
                _ = try readWorkerEventFd(completion_fd);
            }
        }
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

        const now_ms = runtime_time.monotonicMilli();
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

        const now_ms = runtime_time.monotonicMilli();
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
            runtime_time.sleep(chunk);
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
                        runtime_time.sleep(100 * std.time.ns_per_ms);
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
                    if (!net.exactAddressEql(self.middle_proxy_addrs_primary[i], addr)) {
                        self.middle_proxy_addrs_primary[i] = addr;
                        changed = true;
                    }
                }
                if (next_media_primary[i]) |addr| {
                    if (!net.exactAddressEql(self.middle_proxy_addrs_media_primary[i], addr)) {
                        self.middle_proxy_addrs_media_primary[i] = addr;
                        changed = true;
                    }
                }
            }

            if (next_addr_203) |addr| {
                if (!net.exactAddressEql(self.middle_proxy_addr_203, addr)) {
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

const Worker = struct {
    id: u8,
    loop: *EventLoop,
    listen_fd: posix.fd_t,
    control_fd: posix.fd_t,
    completion_fd: posix.fd_t,
    heartbeat_ms: std.atomic.Value(i64),
    finished: std.atomic.Value(bool),
    failed: std.atomic.Value(bool),
    thread: std.Thread,

    fn run(self: *Worker) void {
        self.loop.run() catch |err| {
            log.err("MTProto worker {d} stopped on event-loop error: {any}", .{ self.id, err });
            self.failed.store(true, .monotonic);
        };
        // Close before teardown: a failed loop must not leave a dead member
        // in the kernel's SO_REUSEPORT listener group.
        closeFd(self.listen_fd);
        const allocator = self.loop.state.allocator;
        self.loop.deinit();
        allocator.destroy(self.loop);
        self.finished.store(true, .release);
        writeWorkerEventFd(self.completion_fd, 1) catch |err| {
            log.err("MTProto worker {d} completion wake failed: {any}", .{ self.id, err });
        };
    }
};

fn signalWorkers(workers: []Worker, count: u64) !void {
    for (workers) |*worker| try writeWorkerEventFd(worker.control_fd, count);
}

fn abandonUnstartedWorker(state: *ProxyState, loop: *EventLoop, control_fd: posix.fd_t, listener: *net.Listener) void {
    loop.deinit();
    state.allocator.destroy(loop);
    closeFd(control_fd);
    listener.deinit();
}

const EventLoop = struct {
    state: *ProxyState,
    worker_id: u8 = 0,
    heartbeat_ms: ?*std.atomic.Value(i64) = null,
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
    deadline_heap: DeadlineQueue,
    armed_deadline_ns: i128,
    stats_next_log_ns: i128,
    accepted_since_log: u64,
    closed_since_log: u64,
    local_pool_drops_since_log: u64 = 0,
    wedge_candidates_since_log: u64 = 0,
    wedge_cancelled_since_log: u64 = 0,
    wedge_fresh_closes_since_log: u64 = 0,
    wedge_proven_closes_since_log: u64 = 0,
    wedge_suppressed_since_log: u64 = 0,
    // Snapshot of degradation counters for delta logging
    prev_dropped_cap: u64,
    prev_dropped_saturation: u64,
    prev_dropped_rate_limit: u64,
    prev_dropped_hs_budget: u64,
    prev_hs_timeout: u64,
    prev_mp_fallback: u64,
    prev_buffer_denials: u64,
    prev_web_only_masked: u64 = 0,
    relay_read_scratch: [relay_read_scratch_size]u8,
    mp_c2s_scratch: ?[]u8,
    mp_s2c_scratch: ?[]u8,
    pending_close_fds: std.ArrayList(posix.fd_t),
    tracked_fds: u32,

    fn init(
        state: *ProxyState,
        listen_fd: posix.fd_t,
        shutdown_fd: posix.fd_t,
        worker_id: u8,
        slot_capacity: u32,
        managed_limit_bytes: u64,
        heartbeat_ms: ?*std.atomic.Value(i64),
    ) !*EventLoop {
        const epoll_fd = try epollCreate();
        errdefer closeFd(epoll_fd);
        const timer_fd = try createTimerFd();
        errdefer closeFd(timer_fd);

        const loop = try state.allocator.create(EventLoop);
        errdefer state.allocator.destroy(loop);

        loop.state = state;
        loop.worker_id = worker_id;
        loop.heartbeat_ms = heartbeat_ms;
        loop.epoll_fd = epoll_fd;
        loop.timer_fd = timer_fd;
        loop.listen_fd = listen_fd;
        loop.shutdown_fd = shutdown_fd;
        loop.pool = try ConnectionPool.init(state.allocator, slot_capacity);
        errdefer loop.pool.deinit();
        const managed_buffer_limit: usize = @intCast(@min(
            managed_limit_bytes,
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
        try loop.deadline_heap.ensureTotalCapacity(state.allocator, slot_capacity);
        errdefer loop.deadline_heap.deinit(state.allocator);
        loop.armed_deadline_ns = 0;
        loop.stats_next_log_ns = runtime_time.monotonicNano() + stats_log_interval_ns;
        loop.accepted_since_log = 0;
        loop.closed_since_log = 0;
        loop.local_pool_drops_since_log = 0;
        loop.wedge_candidates_since_log = 0;
        loop.wedge_cancelled_since_log = 0;
        loop.wedge_fresh_closes_since_log = 0;
        loop.wedge_proven_closes_since_log = 0;
        loop.wedge_suppressed_since_log = 0;
        loop.prev_dropped_cap = 0;
        loop.prev_dropped_saturation = 0;
        loop.prev_dropped_rate_limit = 0;
        loop.prev_dropped_hs_budget = 0;
        loop.prev_hs_timeout = 0;
        loop.prev_mp_fallback = 0;
        loop.prev_buffer_denials = 0;
        loop.prev_web_only_masked = 0;
        loop.relay_read_scratch = undefined;
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
        std.crypto.secureZero(u8, &self.relay_read_scratch);

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
            if (self.heartbeat_ms) |heartbeat| {
                heartbeat.store(runtime_time.monotonicMilli(), .monotonic);
            }
            self.drainPendingCloses();

            const rc = linux.epoll_wait(self.epoll_fd, events[0..].ptr, @intCast(events.len), -1);
            switch (linux.errno(rc)) {
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
                if (self.maybeCompleteShutdown(runtime_time.monotonicNano())) return;
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

            const now_ns = runtime_time.monotonicNano();
            if (!self.shutting_down and self.accept_paused and now_ns >= self.accept_resume_ns) {
                self.resumeAccepting();
            }
            // Saturation hysteresis: resume accepting when active drops below 80%
            if (!self.shutting_down and self.saturation_paused) {
                const active = self.state.active_connections.load(.monotonic);
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
        return readWorkerEventFd(self.shutdown_fd);
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
        const active_now = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        if (active_now >= (max * 9) / 10) {
            if (!self.saturation_paused) {
                self.pauseSaturation();
            }
            countStat(&self.state.stats_dropped_saturation);
            return;
        }

        var accepted_this_round: usize = 0;
        while (accepted_this_round < accept_batch_limit) {
            const accepted = net.acceptFd(self.listen_fd) catch |err| {
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
            const cfd = accepted.fd;
            const client_addr = accepted.peer;
            accepted_this_round += 1;

            const trusted_web_peer = self.state.trusted_web_peers.contains(client_addr);

            // Per-/24 subnet rate limit (before we allocate any slot)
            if (!trusted_web_peer and !self.state.allowSubnet(client_addr)) {
                countStat(&self.state.stats_dropped_rate_limit);
                closeFd(cfd);
                continue;
            }

            if (!reserveGlobalCount(&self.state.active_connections, self.state.config.max_connections)) {
                countStat(&self.state.stats_dropped_cap);
                closeFd(cfd);
                continue;
            }

            const slot = self.pool.acquire() orelse {
                releaseGlobalCount(&self.state.active_connections);
                self.local_pool_drops_since_log +|= 1;
                closeFd(cfd);
                continue;
            };
            slot.client_queue.pool = &self.message_block_pool;
            slot.upstream_queue.pool = &self.message_block_pool;

            const subnet_key = if (trusted_web_peer) 0 else SubnetRateLimit.subnetKey(client_addr);
            if (!trusted_web_peer) {
                if (!self.state.reserveSubnetHandshake(subnet_key)) {
                    releaseGlobalCount(&self.state.active_connections);
                    countStat(&self.state.stats_dropped_hs_budget);
                    self.pool.release(slot);
                    closeFd(cfd);
                    continue;
                }
            }

            // Apply this before any FakeTLS response so Nagle cannot delay or
            // coalesce the deliberate one-byte desync write.
            setTcpNoDelay(cfd);

            slot.active_reserved = true;
            slot.hs_counted = false;
            slot.subnet_key = subnet_key;
            slot.subnet_hs_counted = !trusted_web_peer;
            slot.conn_id = self.state.connection_count.fetchAdd(1, .monotonic);
            slot.client_fd = cfd;
            slot.peer_addr = client_addr;
            slot.trusted_peer = trusted_web_peer;
            slot.client_transport = .fake_tls;
            slot.phase = if (trusted_web_peer) .reading_web_prefix else .reading_tls_header;
            slot.created_at_ms = runtime_time.monotonicMilli();
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
        const active = self.state.active_connections.load(.monotonic);
        const hs = self.state.handshakes_inflight.load(.monotonic);
        const accepted_total = self.state.connection_count.load(.monotonic);
        const primary = self.worker_id == 0;

        // Only worker 0 delta-logs process counters. Every worker reports
        // its own pool, fd, wedge, and managed-buffer utilization.
        const cur_cap = if (primary) self.state.stats_dropped_cap.load(.monotonic) else self.prev_dropped_cap;
        const cur_sat = if (primary) self.state.stats_dropped_saturation.load(.monotonic) else self.prev_dropped_saturation;
        const cur_rate = if (primary) self.state.stats_dropped_rate_limit.load(.monotonic) else self.prev_dropped_rate_limit;
        const cur_hs = if (primary) self.state.stats_dropped_hs_budget.load(.monotonic) else self.prev_dropped_hs_budget;
        const cur_hst = if (primary) self.state.stats_hs_timeout.load(.monotonic) else self.prev_hs_timeout;
        const cur_mpf = if (primary) self.state.stats_mp_fallback.load(.monotonic) else self.prev_mp_fallback;
        const cur_buffer_denials = self.managed_buffers.denied_allocations;
        const cur_web_only_masked = if (primary) self.state.stats_web_only_masked.load(.monotonic) else self.prev_web_only_masked;

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

        const has_global_drops = d_cap + d_sat + d_rate + d_hs + d_hst + d_mpf > 0;

        log.info("conn stats: worker={d} local_active={d}/{d} global_active={d}/{d} global_hs={d} accepted+={d} closed+={d} local_pool_drops+={d} tracked_fds={d} global_total={d} paused={}/{} worker_managed_buf={d}/{d}KiB peak={d}KiB", .{
            self.worker_id,
            self.pool.slots.len - @as(usize, self.pool.free_count),
            self.pool.slots.len,
            active,
            self.state.config.max_connections,
            hs,
            self.accepted_since_log,
            self.closed_since_log,
            self.local_pool_drops_since_log,
            self.tracked_fds,
            accepted_total,
            self.accept_paused,
            self.saturation_paused,
            self.managed_buffers.used_bytes / 1024,
            self.managed_buffers.limit_bytes / 1024,
            self.managed_buffers.peak_bytes / 1024,
        });

        if (has_global_drops) {
            log.info("global drops: cap+={d} sat+={d} rate+={d} hs_budget+={d} hs_timeout+={d} mp_fallback+={d}", .{
                d_cap, d_sat, d_rate, d_hs, d_hst, d_mpf,
            });
        }
        if (d_buffer_denials > 0) {
            log.info("worker {d} memory_pressure+={d}", .{ self.worker_id, d_buffer_denials });
        }

        if (d_web_only_masked > 0) {
            log.info("web_only: direct clients masked+={d}", .{d_web_only_masked});
        }

        if (self.wedge_candidates_since_log + self.wedge_cancelled_since_log +
            self.wedge_fresh_closes_since_log + self.wedge_proven_closes_since_log +
            self.wedge_suppressed_since_log > 0)
        {
            log.info("ios_wedge: worker={d} candidates+={d} cancelled+={d} fresh_close+={d} proven_close+={d} suppressed+={d}", .{
                self.worker_id,
                self.wedge_candidates_since_log,
                self.wedge_cancelled_since_log,
                self.wedge_fresh_closes_since_log,
                self.wedge_proven_closes_since_log,
                self.wedge_suppressed_since_log,
            });
        }

        self.accepted_since_log = 0;
        self.closed_since_log = 0;
        self.local_pool_drops_since_log = 0;
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
        self.accept_resume_ns = runtime_time.monotonicNano() + accept_backoff_ns;
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
                self.accept_resume_ns = runtime_time.monotonicNano() + accept_backoff_ns;
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

    fn beginGracefulShutdown(self: *EventLoop) void {
        const now_ns = runtime_time.monotonicNano();
        self.shutting_down = true;
        self.shutdown_deadline_ns = now_ns +
            (@as(i128, @intCast(self.state.config.graceful_shutdown_timeout_sec)) * std.time.ns_per_s);

        self.syncAcceptInterest() catch |err| {
            log.warn("failed to disable listen socket during graceful shutdown: {any}", .{err});
        };

        log.warn(
            "SIGINT/SIGTERM received: graceful shutdown started, active={d}, timeout={d}s",
            .{ self.state.active_connections.load(.monotonic), self.state.config.graceful_shutdown_timeout_sec },
        );
    }

    fn forceImmediateShutdown(self: *EventLoop) void {
        self.shutdown_deadline_ns = runtime_time.monotonicNano();
        log.warn("SIGINT/SIGTERM received during graceful drain; forcing immediate shutdown", .{});
    }

    fn maybeCompleteShutdown(self: *EventLoop, now_ns: i128) bool {
        const active: u32 = @intCast(self.pool.slots.len - @as(usize, self.pool.free_count));
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
        slot.last_activity_ms = runtime_time.monotonicMilli();

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
                flushed_at_ms = runtime_time.monotonicMilli();
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
        slot.last_activity_ms = runtime_time.monotonicMilli();

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
                        flushed_at_ms = runtime_time.monotonicMilli();
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

        const hs_max = (self.state.config.max_connections * 3) / 10;
        if (!reserveGlobalCount(&self.state.handshakes_inflight, hs_max)) {
            countStat(&self.state.stats_dropped_hs_budget);
            return false;
        }

        slot.hs_counted = true;
        return true;
    }

    /// Release a reserved handshake-budget slot exactly once. Relay and mask
    /// completion can release it early; all error paths funnel through closeSlot.
    fn releaseHandshakeBudget(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.hs_counted) return;
        releaseGlobalCount(&self.state.handshakes_inflight);
        slot.hs_counted = false;
    }

    fn releaseSubnetHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        if (!slot.subnet_hs_counted) return;
        self.state.releaseSubnetHandshake(slot.subnet_key);
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
                            if (!self.state.allowSubnet(real_client)) {
                                countStat(&self.state.stats_dropped_rate_limit);
                                self.closeSlot(slot, "WEB client subnet rate limit");
                                return;
                            }
                            const subnet_key = SubnetRateLimit.subnetKey(real_client);
                            if (!self.state.reserveSubnetHandshake(subnet_key)) {
                                countStat(&self.state.stats_dropped_hs_budget);
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
                if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = runtime_time.monotonicMilli();
                if (!slot.hs_counted and !self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
                slot.last_activity_ms = runtime_time.monotonicMilli();
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
            if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = runtime_time.monotonicMilli();
            if (!slot.hs_counted) {
                if (!self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
            slot.last_activity_ms = runtime_time.monotonicMilli();
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
            slot.last_activity_ms = runtime_time.monotonicMilli();
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
            slot.last_activity_ms = runtime_time.monotonicMilli();
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
            countStat(&self.state.stats_web_only_masked);
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
        if (self.state.isReplay(&v.canonical_hmac)) {
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

            const read_buf = self.relay_read_scratch[0..];
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

        slot.setUpstreamCandidates(self.state.allocator, plan.candidates[0..plan.count]) catch {
            self.closeSlot(slot, "alloc upstream candidate list failed");
            return;
        };
        const candidates = slot.upstreamCandidates();
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
        errdefer slot.clearUpstreamCandidates(self.state.allocator);

        if (slot.web_carrier) {
            const cache = self.state.web_mask_dns orelse return error.NoMaskAddress;
            const snapshot = cache.snapshot(0);
            const snapshot_addresses = snapshot.slice();
            for (snapshot_addresses) |address| {
                if (web_support.isLoopback(address) and address.getPort() == self.state.config.port) {
                    return error.WebMaskBackendLoopsToProxy;
                }
            }
            try slot.setUpstreamCandidates(self.state.allocator, snapshot_addresses);
        } else {
            const set_result = blk: {
                self.state.middle_proxy_lock.lock();
                defer self.state.middle_proxy_lock.unlock();
                break :blk slot.setUpstreamCandidates(self.state.allocator, self.state.mask_addrs);
            };
            try set_result;
        }

        const candidates = slot.upstreamCandidates();
        if (candidates.len == 0) {
            return error.NoMaskAddress;
        }

        var proxy_header_buf: [64]u8 = undefined;
        const proxy_header: []const u8 = if (slot.mask_send_proxy_header)
            web_support.buildProxyV2(&proxy_header_buf, slot.peer_addr, candidates[0])
        else
            "";
        slot.mask_send_proxy_header = false;

        const pre = try self.state.allocator.alloc(u8, proxy_header.len + buffered.len);
        @memcpy(pre[0..proxy_header.len], proxy_header);
        @memcpy(pre[proxy_header.len..], buffered);
        slot.mask_prebuffer = pre;
        slot.mask_c2s_bytes += buffered.len;

        slot.upstream_candidate_next = 1;
        const first = candidates[0];
        self.startConnectUpstream(slot, first, .mask) catch |err| {
            if (self.tryNextMaskEndpoint(slot, err, first)) return;
            return err;
        };
    }

    fn upstreamConnectDeadlineMs(self: *EventLoop, slot: *const ConnectionSlot, started_at_ms: i64) i64 {
        const configured_timeout_ms = secondsToMs(self.state.config.dc_connect_timeout_sec);

        const candidates = slot.upstreamCandidates();
        var candidate_count = if (candidates.len > 0) blk: {
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
        const fd = try net.socketTcpNonblocking(addr);
        errdefer closeFd(fd);

        slot.upstream_fd = fd;
        slot.upstream_interest_in = false;
        slot.upstream_interest_out = true;
        slot.upstream_interest_rdhup = true;
        slot.upstream_kind = kind;
        slot.current_upstream_addr = addr;
        slot.phase = .connecting_upstream;
        slot.upstream_connect_started_ms = runtime_time.monotonicMilli();
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

        net.connectFd(fd, addr) catch |err| switch (err) {
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
        return runtime_time.monotonicNano() + (@as(i128, @intCast(delay_ms)) * std.time.ns_per_ms);
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
        const candidates = slot.upstreamCandidates();
        if (candidates.len == 0) return false;
        const candidate_count = candidates.len;

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
            countStat(&self.state.stats_mp_fallback);
            slot.use_middle_proxy = false;
            const fallback = slot.direct_fallback_addr.?;
            const one = [_]net.Address{fallback};
            slot.setUpstreamCandidates(self.state.allocator, &one) catch {
                return false;
            };
            slot.upstream_candidate_next = 1;

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
        const candidates = slot.upstreamCandidates();
        if (candidates.len == 0) return false;
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
            if (self.state.wedgeSuppressesNewCandidates(
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
        const ticket = self.state.prepareWedge(
            slot.wedge_client_key,
            slot.dc_abs,
            now_ms,
            base_timeout_ms,
            slot.last_activity_ms + slot.idle_timeout_ms,
        ) orelse {
            if (self.state.reportWedgeSuppression(
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
        slot.relay_started_at_ms = runtime_time.monotonicMilli();
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
            slot.last_activity_ms = runtime_time.monotonicMilli();
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
            slot.last_activity_ms = runtime_time.monotonicMilli();
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
            slot.last_activity_ms = runtime_time.monotonicMilli();
            if (slot.s2c_bytes > s2c_before) {
                self.noteServerRelayPayload(slot, slot.last_activity_ms);
            }
        }
    }

    fn relayObfuscatedClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        const read_buf = self.relay_read_scratch[0..];
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
        slot.last_activity_ms = runtime_time.monotonicMilli();
        if (forwarded_payload) {
            slot.wedge_forwarded_c2s_seq +|= 1;
            self.noteClientRelayPayload(slot, slot.last_activity_ms);
        } else {
            self.noteClientRelayProgress(slot, slot.last_activity_ms);
        }
    }

    fn relayObfuscatedUpstreamToClient(self: *EventLoop, slot: *ConnectionSlot) void {
        const read_buf = self.relay_read_scratch[0..];
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
                slot.last_activity_ms = runtime_time.monotonicMilli();
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

        slot.last_activity_ms = runtime_time.monotonicMilli();
        self.noteServerRelayPayload(slot, slot.last_activity_ms);
    }

    fn relayRawClientToUpstream(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;

        const read_buf = self.relay_read_scratch[0..];

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

        const read_buf = self.relay_read_scratch[0..];

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
        const ts: u32 = @intCast(@mod(runtime_time.realtimeSeconds(), 4294967296));
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

                    const peer_addr = net.peerAddress(slot.upstream_fd) catch {
                        break :handshake "mp getpeername failed";
                    };

                    const local_addr = net.localAddress(slot.upstream_fd) catch {
                        break :handshake "mp getsockname failed";
                    };
                    middle_local_addr = local_addr;

                    var tg_port: [2]u8 = undefined;
                    var my_port: [2]u8 = undefined;
                    var tg_ip_v4_opt: ?[4]u8 = null;
                    var my_ip_v4_opt: ?[4]u8 = null;
                    var tg_ip_v6_opt: ?[16]u8 = null;
                    var my_ip_v6_opt: ?[16]u8 = null;

                    if (peer_addr == .ip4 and local_addr == .ip4) {
                        tg_ip_v4_opt = ipv4AddressBytesForMiddleProxyKdf(peer_addr);
                        var my_ip_v4 = ipv4AddressBytesForMiddleProxyKdf(local_addr);

                        if (slot.mp_nat_ip4) |nat_ip| {
                            my_ip_v4 = ipv4BytesForMiddleProxyKdf(nat_ip);
                            middle_local_addr = net.ip4(nat_ip, local_addr.ip4.port);
                        }

                        my_ip_v4_opt = my_ip_v4;

                        std.mem.writeInt(u16, &tg_port, peer_addr.ip4.port, .little);
                        std.mem.writeInt(u16, &my_port, local_addr.ip4.port, .little);
                    } else if (peer_addr == .ip6 and local_addr == .ip6) {
                        tg_ip_v6_opt = peer_addr.ip6.bytes;
                        my_ip_v6_opt = local_addr.ip6.bytes;

                        std.mem.writeInt(u16, &tg_port, peer_addr.ip6.port, .little);
                        std.mem.writeInt(u16, &my_port, local_addr.ip6.port, .little);
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

                const local_addr = net.localAddress(slot.upstream_fd) catch {
                    if (!self.fallbackFromMiddleProxyToDirect(slot)) {
                        self.closeSlot(slot, "mp getsockname failed");
                    }
                    return;
                };

                var middle_local_addr = local_addr;
                if (slot.mp_nat_ip4) |nat_ip| {
                    if (local_addr == .ip4) {
                        middle_local_addr = net.ip4(nat_ip, local_addr.ip4.port);
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
        countStat(&self.state.stats_mp_fallback);
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
        const one = [_]net.Address{fallback};
        slot.setUpstreamCandidates(self.state.allocator, &one) catch {
            return false;
        };
        slot.upstream_candidate_next = 1;

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
                const now_ms = runtime_time.monotonicMilli();
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

    fn refreshSlotDeadline(self: *EventLoop, slot: *ConnectionSlot) void {
        const next = self.nextSlotDeadlineNs(slot) orelse {
            self.deadline_heap.remove(self.pool.slots, slot);
            self.rearmTimer() catch |err| log.err("failed to rearm deadline timer: {any}", .{err});
            return;
        };

        self.deadline_heap.update(self.pool.slots, slot, next);
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
        if (self.deadline_heap.peek()) |entry| {
            next = earlierDeadline(next, entry.deadline_ns);
        }

        const deadline = next orelse 0;
        if (deadline == self.armed_deadline_ns) return;
        try armTimerFd(self.timer_fd, next);
        self.armed_deadline_ns = deadline;
    }

    fn runTimers(self: *EventLoop, now_ns: i128) void {
        const now_ms: i64 = @intCast(@divTrunc(now_ns, std.time.ns_per_ms));
        while (self.deadline_heap.popExpired(self.pool.slots, now_ns)) |slot_index| {
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
                countStat(&self.state.stats_hs_timeout);
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
                        if (self.state.reportWedgeSuppression(
                            slot.wedge_client_key,
                            slot.dc_abs,
                            now_ms,
                        )) {
                            self.wedge_suppressed_since_log +|= 1;
                        }
                        slot.wedge.abandonCandidate();
                        return;
                    };
                    if (!self.state.allowWedgeClose(
                        slot.wedge_client_key,
                        slot.dc_abs,
                        ticket,
                        now_ms,
                    )) {
                        if (self.state.reportWedgeSuppression(
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
        slot.last_activity_ms = runtime_time.monotonicMilli();
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
                processed_bytes += relay_read_scratch_size;
                const now_ms = runtime_time.monotonicMilli();
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
            const read_buf = self.relay_read_scratch[0..];
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
                slot.last_activity_ms = runtime_time.monotonicMilli();
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
            var client_ip_buf: [64]u8 = undefined;
            const client_ip = formatClientIp(slot.peer_addr, &client_ip_buf);
            log.debug("[{d}] closing: dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d} client={s}", .{
                slot.conn_id,
                slot.dc_idx,
                slot.is_media_path,
                @tagName(slot.phase),
                reason,
                slot.c2s_bytes,
                slot.s2c_bytes,
                client_ip,
            });
        }
        self.deadline_heap.remove(self.pool.slots, slot);

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
            releaseGlobalCount(&self.state.active_connections);
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
        switch (linux.errno(rc)) {
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
        switch (linux.errno(rc)) {
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
        switch (linux.errno(rc)) {
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
        @min(@as(usize, pipelined_initial_capacity), constants.max_tls_ciphertext_size)
    else
        current_capacity;

    while (next < required_len) {
        next = @min(next * 2, constants.max_tls_ciphertext_size);
    }

    return next;
}

fn relayClientToUpstreamStep(self: *EventLoop, slot: *ConnectionSlot) !RelayProgress {
    const read_buf = self.relay_read_scratch[0..];
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
    const read_buf = self.relay_read_scratch[0..];
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
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn createWorkerEventFd() !posix.fd_t {
    const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn writeWorkerEventFd(fd: posix.fd_t, count: u64) !void {
    var value = count;
    const bytes = std.mem.asBytes(&value);
    while (true) {
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc != bytes.len) return error.ShortWorkerEventWrite;
                return;
            },
            .INTR => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn readWorkerEventFd(fd: posix.fd_t) !u64 {
    var value: u64 = 0;
    const bytes = std.mem.asBytes(&value);
    while (true) {
        const rc = linux.read(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.WorkerEventFdClosed;
                if (rc != bytes.len) return error.ShortWorkerEventRead;
                return value;
            },
            .INTR => continue,
            .AGAIN => return 0,
            else => |err| return posix.unexpectedErrno(err),
        }
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
    switch (linux.errno(rc)) {
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
    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    return switch (normalized) {
        .ip4 => std.fmt.bufPrint(buf, "[ipv4]:{d}", .{addr.getPort()}) catch "?",
        .ip6 => std.fmt.bufPrint(buf, "[ipv6]:{d}", .{addr.getPort()}) catch "?",
    };
}

/// Format an authenticated client's real IP without its ephemeral source port.
/// Unlike `formatAddress`, this deliberately exposes the address: callers must
/// keep it out of production-level logs.
fn formatClientIp(addr: net.Address, buf: *[64]u8) []const u8 {
    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    switch (normalized) {
        .ip4 => |v4| {
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                v4.bytes[0], v4.bytes[1], v4.bytes[2], v4.bytes[3],
            }) catch "?";
        },
        .ip6 => {
            var writer: std.Io.Writer = .fixed(buf);
            normalized.format(&writer) catch return "?";
            const endpoint = writer.buffered();
            if (endpoint.len < 2 or endpoint[0] != '[') return "?";
            const closing = std.mem.indexOfScalar(u8, endpoint, ']') orelse return "?";
            return endpoint[1..closing];
        },
    }
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

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
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
        if (addr == .ip4) return addr.ip4.bytes;
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

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    const io = threaded_io.io();

    const paths = [_][]const u8{
        "/etc/amnezia/amneziawg/awg0.conf",
        "/etc/amnezia/amneziawg/wg0.conf",
        "/etc/wireguard/wg0.conf",
    };

    for (paths) |path| {
        if (stop) |stop_flag| {
            if (stop_flag.load(.acquire)) return error.UpdateCancelled;
        }

        const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024 + 1)) catch continue;
        defer allocator.free(content);
        if (content.len > 64 * 1024) continue;

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
    return ipv4BytesForMiddleProxyKdf(addr.ip4.bytes);
}

fn isSameIpEndpoint(a: net.Address, b: net.Address) bool {
    // Native IpAddress.eql intentionally ignores IPv6 flow/scope, matching
    // the identity used for MiddleProxy endpoint promotion and cooldown.
    return net.Address.eql(&a, &b);
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
        if (addrs[read] != .ip4) continue;
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

        const parsed = std.Io.net.IpAddress.parseLiteral(host_port) catch continue;

        var dup = false;
        for (out[0..count]) |existing| {
            if (net.exactAddressEql(existing, parsed)) {
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

        const fd = net.socketTcpNonblocking(addr) catch continue;
        net.connectFd(fd, addr) catch |err| {
            switch (err) {
                error.WouldBlock, error.ConnectionPending => {
                    fds[count] = .{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 };
                    addrs[count] = addr;
                    count += 1;
                },
                else => _ = linux.close(fd),
            }
            continue;
        };
        _ = linux.close(fd);
        return addr;
    }
    if (count == 0) return null;

    var remaining_ms = @max(timeout_ms, 0);
    while (true) {
        if (stop) |flag| if (flag.load(.acquire)) return null;
        const chunk_ms = @min(remaining_ms, 100);
        for (fds[0..count]) |*poll_fd| poll_fd.revents = 0;
        const poll_rc = linux.poll(&fds, count, chunk_ms);
        const ready = switch (linux.errno(poll_rc)) {
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
    return linux.errno(opt_rc) == .SUCCESS and err_code == 0;
}

fn addressesEqual(a: []const net.Address, b: []const net.Address) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (!net.exactAddressEql(lhs, rhs)) return false;
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
    try std.testing.expect(addr == .ip4);
    try std.testing.expectEqual(@as(u16, 443), addr.getPort());
}

test "middle proxy nonce response failures fall back to direct path" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tmp_io_state = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer tmp_io_state.deinit();
    const tmp_io = tmp_io_state.io();

    var upstream_file = try tmp.dir.createFile(tmp_io, "middle-proxy-upstream", .{ .read = true });
    var upstream_file_owned = true;
    defer if (upstream_file_owned) upstream_file.close(tmp_io);

    const epoll_fd = try epollCreate();
    defer closeFd(epoll_fd);
    const timer_fd = try createTimerFd();
    defer closeFd(timer_fd);
    var deadlines: DeadlineQueue = .empty;
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
        .stats_next_log_ns = runtime_time.monotonicNano() + stats_log_interval_ns,
        .accepted_since_log = 0,
        .closed_since_log = 0,
        .prev_dropped_cap = 0,
        .prev_dropped_saturation = 0,
        .prev_dropped_rate_limit = 0,
        .prev_dropped_hs_budget = 0,
        .prev_hs_timeout = 0,
        .prev_mp_fallback = 0,
        .prev_buffer_denials = 0,
        .relay_read_scratch = undefined,
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

    var fallback_server = try net.listen(net.ip4(.{ 127, 0, 0, 1 }, 0), .{
        .reuse_address = true,
        .kernel_backlog = 1,
    });
    defer fallback_server.deinit();

    const fallback_addr = try net.localAddress(fallback_server.handle);

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
    try std.testing.expectEqual(@as(usize, 1), slot.upstreamCandidates().len);
    try std.testing.expect(net.exactAddressEql(slot.current_upstream_addr.?, fallback_addr));
    try std.testing.expect(slot.phase == .connecting_upstream or slot.phase == .writing_dc_nonce);
    try std.testing.expectEqual(@as(u64, 1), state.stats_mp_fallback.load(.monotonic));
}

test "pipelined handshake capacity stays independent of relay scratch size" {
    try std.testing.expectEqual(
        @as(usize, pipelined_initial_capacity),
        pipelinedCapacity(0, 1),
    );
    try std.testing.expectEqual(
        @as(usize, pipelined_initial_capacity * 2),
        pipelinedCapacity(0, pipelined_initial_capacity + 1),
    );
    try std.testing.expectEqual(
        @as(usize, constants.max_tls_ciphertext_size),
        pipelinedCapacity(0, constants.max_tls_ciphertext_size),
    );
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

    cfg.datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443);
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
    cfg.datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443);

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

    const mp_dc4 = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const mp_dc203 = net.ip4(.{ 12, 12, 12, 12 }, 443);
    const mp_media_dc5_secondary = net.ip4(.{ 13, 13, 13, 13 }, 443);
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
    try std.testing.expect(net.exactAddressEql(regular_plan.candidates[0], mp_dc4));

    const admin_plan = buildDcConnectPlan(&cfg, 4, 4, &regular_snapshot, true);
    try std.testing.expect(!admin_plan.use_middle_proxy);
    try std.testing.expect(admin_plan.direct_fallback == null);
    try std.testing.expect(net.exactAddressEql(admin_plan.candidates[0], constants.getDirectDcAddressV4(4).?));

    const regular_media = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, false);
    try std.testing.expect(regular_media.use_middle_proxy);
    try std.testing.expect(net.exactAddressEql(regular_media.candidates[0], mp_dc203));
    try std.testing.expect(regular_media.direct_fallback == null);

    const regular_media_dc5 = buildDcConnectPlan(&cfg, 5, -5, &media_dc5_snapshot, false);
    try std.testing.expectEqual(@as(usize, 2), regular_media_dc5.count);
    try std.testing.expect(net.exactAddressEql(regular_media_dc5.candidates[1], mp_media_dc5_secondary));

    const admin_media = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, true);
    try std.testing.expect(admin_media.use_middle_proxy);
    try std.testing.expect(net.exactAddressEql(admin_media.candidates[0], mp_dc203));
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
    try std.testing.expect(net.exactAddressEql(direct_media_dc5.candidates[0], constants.getDirectDcAddressV4(5).?));

    const mandatory_cdn = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, false);
    try std.testing.expect(mandatory_cdn.use_middle_proxy);
    try std.testing.expectEqual(@as(usize, 1), mandatory_cdn.count);
    try std.testing.expect(net.exactAddressEql(mandatory_cdn.candidates[0], mp_dc203));
    try std.testing.expect(mandatory_cdn.direct_fallback == null);

    const mandatory_cdn_direct_user = buildDcConnectPlan(&cfg, 203, -203, &media_203_snapshot, true);
    try std.testing.expect(mandatory_cdn_direct_user.use_middle_proxy);
    try std.testing.expect(net.exactAddressEql(mandatory_cdn_direct_user.candidates[0], mp_dc203));
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
    const first = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const second = net.ip4(.{ 12, 12, 12, 12 }, 443);
    const third = net.ip4(.{ 13, 13, 13, 13 }, 443);
    var candidates = [_]net.Address{ first, second, third } ++ ([_]net.Address{first} ** 13);

    try std.testing.expect(promoteMiddleProxyCandidateInList(&candidates, 3, second));
    try std.testing.expect(net.exactAddressEql(candidates[0], second));
    try std.testing.expect(net.exactAddressEql(candidates[1], first));
    try std.testing.expect(net.exactAddressEql(candidates[2], third));
    try std.testing.expect(!promoteMiddleProxyCandidateInList(&candidates, 3, second));
}

test "middle-proxy cooldown prioritizes healthy candidates" {
    const first = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const second = net.ip4(.{ 12, 12, 12, 12 }, 443);
    var candidates = [_]net.Address{ first, second } ++ ([_]net.Address{first} ** 14);
    var cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots;
    cooldowns[0] = .{ .active = true, .addr = first, .until_ms = 200 };

    prioritizeMiddleProxyCandidates(&candidates, 2, &cooldowns, 100);
    try std.testing.expect(net.exactAddressEql(candidates[0], second));
    try std.testing.expect(net.exactAddressEql(candidates[1], first));
}

test "middle-proxy cooldown tries earliest recovery first when all cooled" {
    const first = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const second = net.ip4(.{ 12, 12, 12, 12 }, 443);
    const third = net.ip4(.{ 13, 13, 13, 13 }, 443);
    var candidates = [_]net.Address{ first, second, third } ++ ([_]net.Address{first} ** 13);
    var cooldowns = [_]MiddleProxyCooldown{.{}} ** middle_proxy_cooldown_slots;
    cooldowns[0] = .{ .active = true, .addr = first, .until_ms = 300 };
    cooldowns[1] = .{ .active = true, .addr = second, .until_ms = 200 };
    cooldowns[2] = .{ .active = true, .addr = third, .until_ms = 250 };

    prioritizeMiddleProxyCandidates(&candidates, 3, &cooldowns, 100);
    try std.testing.expect(net.exactAddressEql(candidates[0], second));
    try std.testing.expect(net.exactAddressEql(candidates[1], third));
    try std.testing.expect(net.exactAddressEql(candidates[2], first));
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
    const native = net.ip4(.{ 203, 0, 113, 7 }, 54321);
    try std.testing.expectEqualStrings("203.0.113.7", formatClientIp(native, &buf));

    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.ip6(mapped_bytes, 54321, 0, 0);
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

test "handshake budget is charged once after the first client byte" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 10,
        .mask = false,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
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
        .prev_dropped_cap = 0,
        .prev_dropped_saturation = 0,
        .prev_dropped_rate_limit = 0,
        .prev_dropped_hs_budget = 0,
        .prev_hs_timeout = 0,
        .prev_mp_fallback = 0,
        .prev_buffer_denials = 0,
        .relay_read_scratch = undefined,
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

test "worker selection and partitioning preserve process budgets" {
    const budget = 64 * 1024 * 1024;
    try std.testing.expectEqual(@as(u8, 1), try selectWorkerCount(1, 512, budget, min_worker_managed_bytes, 64));
    try std.testing.expectEqual(@as(u8, 2), try selectWorkerCount(2, 512, budget, min_worker_managed_bytes, 1));
    try std.testing.expectEqual(@as(u8, 8), try selectWorkerCount(0, 512, budget, min_worker_managed_bytes, 64));
    try std.testing.expectEqual(@as(u8, 2), try selectWorkerCount(0, 64, budget, min_worker_managed_bytes, 64));
    try std.testing.expectEqual(@as(u8, 1), try selectWorkerCount(0, 512, budget, min_worker_managed_bytes, 1));
    try std.testing.expectError(error.InsufficientWorkerResources, selectWorkerCount(9, 512, budget, min_worker_managed_bytes, 64));
    try std.testing.expectError(error.InsufficientWorkerResources, selectWorkerCount(3, 64, budget, min_worker_managed_bytes, 64));
    try std.testing.expectError(error.InvalidWorkers, selectWorkerCount(17, 512, budget, min_worker_managed_bytes, 64));

    var mp_cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer mp_cfg.deinit(std.testing.allocator);
    const mp_floor = minWorkerManagedBytes(&mp_cfg);
    try std.testing.expect(mp_floor > min_worker_managed_bytes);
    try std.testing.expectEqual(@as(u8, 7), try selectWorkerCount(0, 512, budget, mp_floor, 64));

    var slots: u32 = 0;
    var bytes: u64 = 0;
    for (0..8) |i| {
        const id: u8 = @intCast(i);
        const local_slots = workerSlotCapacity(513, 8, id);
        const local_bytes = workerManagedBudget(budget + 3, 8, id);
        try std.testing.expect(local_slots >= min_worker_slots);
        try std.testing.expect(local_bytes >= min_worker_managed_bytes);
        slots += local_slots;
        bytes += local_bytes;
    }
    try std.testing.expectEqual(@as(u32, 513), slots);
    try std.testing.expectEqual(@as(u64, budget + 3), bytes);
    try std.testing.expect(!workerHeartbeatStale(1000, 1000));
    try std.testing.expect(!workerHeartbeatStale(worker_health_timeout_ms, 0));
    try std.testing.expect(workerHeartbeatStale(worker_health_timeout_ms + 1, 0));
}

const MultiWorkerRace = struct {
    state: *ProxyState,
    counter: *std.atomic.Value(u32),
    admitted: *std.atomic.Value(u32),
    handshake_winners: *std.atomic.Value(u32),
    replay_winners: *std.atomic.Value(u32),
    wedge_winners: *std.atomic.Value(u32),
    rate_winners: *std.atomic.Value(u32),
    ready: *std.atomic.Value(u32),
    go: *std.atomic.Value(bool),
    digest: [32]u8,
    wedge_ticket: WedgeGateTicket,

    fn run(self: *MultiWorkerRace) void {
        _ = self.ready.fetchAdd(1, .monotonic);
        while (!self.go.load(.acquire)) std.atomic.spinLoopHint();
        if (reserveGlobalCount(self.counter, 4)) {
            _ = self.admitted.fetchAdd(1, .monotonic);
        } else {
            countStat(&self.state.stats_dropped_cap);
        }
        if (reserveGlobalCount(&self.state.handshakes_inflight, 3))
            _ = self.handshake_winners.fetchAdd(1, .monotonic);
        if (!self.state.isReplay(&self.digest)) _ = self.replay_winners.fetchAdd(1, .monotonic);
        if (self.state.allowWedgeClose(0x1234, 1, self.wedge_ticket, 1000))
            _ = self.wedge_winners.fetchAdd(1, .monotonic);
        if (self.state.allowSubnet(net.ip4(.{ 198, 51, 100, 1 }, 443)))
            _ = self.rate_winners.fetchAdd(1, .monotonic);
    }
};

test "concurrent workers share connection, handshake, replay, rate and wedge limits" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .rate_limit_per_subnet = 1,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    var cap = std.atomic.Value(u32).init(0);
    var admitted = std.atomic.Value(u32).init(0);
    var handshake_winners = std.atomic.Value(u32).init(0);
    var replay_winners = std.atomic.Value(u32).init(0);
    var wedge_winners = std.atomic.Value(u32).init(0);
    var rate_winners = std.atomic.Value(u32).init(0);
    var ready = std.atomic.Value(u32).init(0);
    var go = std.atomic.Value(bool).init(false);
    const wedge_ticket = state.prepareWedge(0x1234, 1, 1000, 15_000, 100_000) orelse return error.TestExpectedEqual;
    const rate_addr = net.ip4(.{ 198, 51, 100, 1 }, 443);
    const rate_key = SubnetRateLimit.subnetKey(rate_addr);
    const rate_index = state.security.subnet_limiter.indexFor(rate_key);
    state.security.subnet_limiter.entries[rate_index] = .{
        .subnet_key = rate_key,
        .last_refill_s = @divTrunc(runtime_time.monotonicMilli(), 1000) + 60,
        .used = true,
        .tokens = 1,
    };
    var race = MultiWorkerRace{
        .state = &state,
        .counter = &cap,
        .admitted = &admitted,
        .handshake_winners = &handshake_winners,
        .replay_winners = &replay_winners,
        .wedge_winners = &wedge_winners,
        .rate_winners = &rate_winners,
        .ready = &ready,
        .go = &go,
        .digest = [_]u8{0x42} ** 32,
        .wedge_ticket = wedge_ticket,
    };
    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        go.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, MultiWorkerRace.run, .{&race});
        spawned += 1;
    }
    while (ready.load(.monotonic) < threads.len) std.atomic.spinLoopHint();
    go.store(true, .release);
    for (threads) |thread| thread.join();
    spawned = 0;
    try std.testing.expectEqual(@as(u32, 4), admitted.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 4), cap.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 4), state.stats_dropped_cap.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 3), handshake_winners.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 3), state.handshakes_inflight.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1), replay_winners.load(.monotonic));
    try std.testing.expectEqual(@as(u32, WedgeRecoveryGate.max_wave_closes), wedge_winners.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1), rate_winners.load(.monotonic));
    for (0..4) |_| releaseGlobalCount(&cap);
    for (0..3) |_| releaseGlobalCount(&state.handshakes_inflight);
    try std.testing.expectEqual(@as(u32, 0), cap.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 0), state.handshakes_inflight.load(.monotonic));
}

test "shared subnet admission and unauthenticated caps are not multiplied" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 64,
        .rate_limit_per_subnet = 1,
        .mask = false,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    const address = net.ip4(.{ 198, 51, 100, 1 }, 443);
    try std.testing.expect(state.allowSubnet(address));
    // Freeze this entry's refill clock to avoid a test flake at a second edge.
    const key = SubnetRateLimit.subnetKey(address);
    state.security.lock.lock();
    state.security.subnet_limiter.findEntry(key).?.last_refill_s += 5;
    state.security.lock.unlock();
    try std.testing.expect(!state.allowSubnet(net.ip4(.{ 198, 51, 100, 2 }, 443)));

    const hs_limit = subnetHandshakeLimit(state.config.max_connections);
    for (0..hs_limit) |_| try std.testing.expect(state.reserveSubnetHandshake(key));
    try std.testing.expect(!state.reserveSubnetHandshake(key));
    for (0..hs_limit) |_| state.releaseSubnetHandshake(key);
    try std.testing.expect(state.reserveSubnetHandshake(key));
    state.releaseSubnetHandshake(key);
}

const MiddleProxyMetadataRace = struct {
    state: *ProxyState,

    fn run(self: *MiddleProxyMetadataRace) void {
        const candidate = constants.tg_middle_proxies_v4[0];
        for (0..500) |_| {
            const snapshot = self.state.getMiddleProxySnapshot(1, false);
            std.debug.assert(snapshot.candidate_len > 0);
            _ = self.state.cooldownMiddleProxyCandidate(candidate);
            _ = self.state.promoteMiddleProxyCandidate(1, false, candidate);
        }
    }
};

test "MiddleProxy route snapshots remain synchronized across workers" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();
    var race = MiddleProxyMetadataRace{ .state = &state };
    var threads: [4]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, MiddleProxyMetadataRace.run, .{&race});
        spawned += 1;
    }
    for (threads) |thread| thread.join();
    spawned = 0;
}

test "nonblocking accept reports EAGAIN when libc is linked" {
    if (builtin.os.tag != .linux) return;

    const address = net.ip4(.{ 127, 0, 0, 1 }, 0);
    var listener = try net.listen(address, .{});
    defer listener.deinit();

    try std.testing.expectError(error.WouldBlock, net.acceptFd(listener.handle));
}

test "control broadcast wakes every worker eventfd" {
    if (builtin.os.tag != .linux) return;
    const first = try createWorkerEventFd();
    defer closeFd(first);
    const second = try createWorkerEventFd();
    defer closeFd(second);
    try std.testing.expectEqual(@as(u64, 0), try readWorkerEventFd(first));
    try std.testing.expectEqual(@as(u64, 0), try readWorkerEventFd(second));
    var workers = [_]Worker{
        .{ .id = 0, .loop = undefined, .listen_fd = invalid_fd, .control_fd = first, .completion_fd = invalid_fd, .heartbeat_ms = .init(0), .finished = .init(false), .failed = .init(false), .thread = undefined },
        .{ .id = 1, .loop = undefined, .listen_fd = invalid_fd, .control_fd = second, .completion_fd = invalid_fd, .heartbeat_ms = .init(0), .finished = .init(false), .failed = .init(false), .thread = undefined },
    };
    try signalWorkers(&workers, 1);
    try std.testing.expectEqual(@as(u64, 1), try readWorkerEventFd(first));
    try std.testing.expectEqual(@as(u64, 1), try readWorkerEventFd(second));
    try std.testing.expectEqual(@as(u64, 0), try readWorkerEventFd(first));
    try std.testing.expectEqual(@as(u64, 0), try readWorkerEventFd(second));
}

test "abandoned worker startup releases its reuseport listener" {
    if (builtin.os.tag != .linux) return;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, cfg);
    defer state.deinit();

    const address = net.ip4(.{ 127, 0, 0, 1 }, 0);
    var listener = try net.listen(address, .{ .reuse_address = true, .reuse_port = true });
    var listener_owned = true;
    defer if (listener_owned) listener.deinit();
    const bound = try net.localAddress(listener.handle);
    const port = bound.getPort();

    const control_fd = try createWorkerEventFd();
    var control_owned = true;
    defer if (control_owned) closeFd(control_fd);
    const loop = try EventLoop.init(&state, listener.handle, control_fd, 0, 32, default_managed_buffer_limit_bytes, null);
    var loop_owned = true;
    defer if (loop_owned) {
        loop.deinit();
        state.allocator.destroy(loop);
    };

    // Exercise the same cleanup used when Thread.spawn fails after a valid
    // epoll/timer/listener has already been prepared.
    abandonUnstartedWorker(&state, loop, control_fd, &listener);
    loop_owned = false;
    control_owned = false;
    listener_owned = false;
    var replacement = try net.listen(net.ip4(.{ 127, 0, 0, 1 }, port), .{ .reuse_address = true });
    defer replacement.deinit();
}
