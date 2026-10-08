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
const runtime_io = @import("../runtime/io.zig");
const linux_events = @import("../runtime/linux_events.zig");
const createTimerFd = linux_events.createTimerFd;
const armTimerFd = linux_events.armTimerFd;
const drainTimerFd = linux_events.drainTimerFd;
const epollCreate = linux_events.epollCreate;
const createWorkerEventFd = linux_events.createWorkerEventFd;
const writeWorkerEventFd = linux_events.writeWorkerEventFd;
const readWorkerEventFd = linux_events.readWorkerEventFd;
const socket_ops = @import("socket_ops.zig");
const getsockoptErrorFd = socket_ops.getsockoptErrorFd;
const writeFd = socket_ops.writeFd;
const seekFdToStart = socket_ops.seekFdToStart;
const setTcpNoDelay = socket_ops.setTcpNoDelay;
const configureRelaySocket = socket_ops.configureRelaySocket;
const formatAddress = socket_ops.formatAddress;
const formatClientIp = socket_ops.formatClientIp;
const relay_io = @import("relay_io.zig");
const clientRelayAtFrameBoundary = relay_io.clientRelayAtFrameBoundary;
const upstreamRelayAtFrameBoundary = relay_io.upstreamRelayAtFrameBoundary;
const relayHalfCloseComplete = relay_io.relayHalfCloseComplete;
const shutdownWriteFd = relay_io.shutdownWriteFd;
const readSlotFd = relay_io.readSlotFd;
const queueTlsAppRecords = relay_io.queueTlsAppRecords;
const queueClient = relay_io.queueClient;
const queueUpstream = relay_io.queueUpstream;
const flushClientPending = relay_io.flushClientPending;
const flushUpstreamPending = relay_io.flushUpstreamPending;
const middle_proxy_nat = @import("middle_proxy_nat.zig");
const parseIpv4Literal = middle_proxy_nat.parseIpv4Literal;
const isRunningInNonInitNetns = middle_proxy_nat.isRunningInNonInitNetns;
const detectAwgEndpointIpv4 = middle_proxy_nat.detectAwgEndpointIpv4;
const selectDetectedMiddleProxyNatIpv4 = middle_proxy_nat.selectDetectedMiddleProxyNatIpv4;
const detectPublicIpv4 = middle_proxy_nat.detectPublicIpv4;
const formatIpv4Bytes = middle_proxy_nat.formatIpv4Bytes;
const middle_proxy_handshake = @import("middle_proxy_handshake.zig");
const middle_proxy_routing = @import("middle_proxy_routing.zig");
const MiddleProxyLock = middle_proxy_routing.MiddleProxyLock;
const MiddleProxyCooldown = middle_proxy_routing.MiddleProxyCooldown;
const MiddleProxyHealthStore = middle_proxy_routing.MiddleProxyHealthStore;
const MiddleProxySnapshot = middle_proxy_routing.MiddleProxySnapshot;
const middle_proxy_connect_cooldown_ms = middle_proxy_routing.middle_proxy_connect_cooldown_ms;
const middle_proxy_cooldown_slots = middle_proxy_routing.middle_proxy_cooldown_slots;
const isSameIpEndpoint = middle_proxy_routing.isSameIpEndpoint;
const defaultMiddleProxyCandidateLists = middle_proxy_routing.defaultMiddleProxyCandidateLists;
const copyMiddleProxyCandidates = middle_proxy_routing.copyMiddleProxyCandidates;
const promoteMiddleProxyCandidateInList = middle_proxy_routing.promoteMiddleProxyCandidateInList;
const prioritizeIpv4Addresses = middle_proxy_routing.prioritizeIpv4Addresses;
const shouldUseMiddleProxySnapshot = middle_proxy_routing.shouldUseMiddleProxySnapshot;
const buildDcConnectPlan = middle_proxy_routing.buildDcConnectPlan;
const parseMiddleProxyAddressesForDc = middle_proxy_routing.parseMiddleProxyAddressesForDc;
const trySelectReachableMiddleProxy = middle_proxy_routing.trySelectReachableMiddleProxy;
const addressesEqual = middle_proxy_routing.addressesEqual;
const linux_fs = @import("../runtime/linux_fs.zig");
const http_fetch = @import("../http_fetch.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const middleproxy = @import("../protocol/middleproxy.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;
const limits = @import("limits.zig");
const web_support = @import("web_support.zig");
const ManagedBufferAllocator = @import("managed_buffer_allocator.zig").ManagedBufferAllocator;
const message_queue = @import("message_queue.zig");
const MessageBlockPool = message_queue.MessageBlockPool;
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
const RelayEofSide = connection.RelayEofSide;
const connectionLifetimeMs = connection.connectionLifetimeMs;
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
const timeout_policy = @import("timeout_policy.zig");
const secondsToMs = timeout_policy.secondsToMs;
const earlierDeadline = timeout_policy.earlierDeadline;
const idleTimeoutSeed = timeout_policy.idleTimeoutSeed;
const jitteredIdleTimeoutMs = timeout_policy.jitteredIdleTimeoutMs;

const log = std.log.scoped(.proxy);

const accept_backoff_ms: i64 = 500;
const accept_backoff_ns: i128 = @as(i128, accept_backoff_ms) * std.time.ns_per_ms;
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
const mp_handshake_frame_buf_size = middle_proxy_handshake.frame_buf_size;
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
    return switch (builtin.target.os.tag) {
        .windows => @ptrFromInt(value),
        else => @intCast(value),
    };
}

fn closeFd(fd: posix.fd_t) void {
    if (builtin.target.os.tag == .linux) {
        _ = linux.close(fd);
    } else if (builtin.target.os.tag == .windows) {
        std.os.windows.CloseHandle(fd);
    }
}

fn hasFatalEpollHangup(events: u32) bool {
    return (events & (linux.EPOLL.ERR | linux.EPOLL.HUP)) != 0;
}

fn hasGracefulEpollReadHangup(events: u32) bool {
    return (events & (linux.EPOLL.RDHUP | linux.EPOLL.HUP)) != 0 and
        (events & linux.EPOLL.ERR) == 0;
}

fn shouldCloseOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    if (phase == .idle) return false;

    // During connecting_upstream, EPOLLERR on upstream fd is expected and
    // handled via onUpstreamWritable -> onUpstreamConnectComplete.
    return !(phase == .connecting_upstream and event_fd == upstream_fd);
}

fn shouldRecoverMiddleProxyOnFatalHangup(phase: ConnectionPhase, event_fd: posix.fd_t, upstream_fd: posix.fd_t) bool {
    return phase == .middle_proxy_handshake and event_fd == upstream_fd;
}

const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

fn freeUserSecrets(allocator: std.mem.Allocator, secrets: []obfuscation.UserSecret) void {
    for (secrets) |*secret| {
        std.crypto.secureZero(u8, &secret.secret);
        allocator.free(secret.name);
    }
    allocator.free(secrets);
}

fn prepareUserHmacs(allocator: std.mem.Allocator, secrets: []const obfuscation.UserSecret) ![]tls.PreparedHmacState {
    const contexts = try allocator.alloc(tls.PreparedHmacState, secrets.len);
    for (secrets, contexts) |*secret, *context| {
        var prepared = tls.PreparedHmacState.init(&secret.secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&prepared));
        context.* = prepared;
    }
    return contexts;
}

fn wipeUserHmacs(contexts: []tls.PreparedHmacState) void {
    // HmacSha256 and its Sha256 state contain no pointers or enums in Zig 0.17.
    std.crypto.secureZero(u8, std.mem.sliceAsBytes(contexts));
}

fn freeUserHmacs(allocator: std.mem.Allocator, contexts: []tls.PreparedHmacState) void {
    wipeUserHmacs(contexts);
    allocator.free(contexts);
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
    /// Borrowed from main for startup discovery and the joined updater only.
    /// EventLoop and its Linux data plane do not use this Io backend.
    io: std.Io,
    config: Config,
    managed_buffer_limit_bytes: u64,
    user_secrets: []obfuscation.UserSecret,
    user_tls_hmacs: []tls.PreparedHmacState,
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
    stats_relay_client_eof_first: std.atomic.Value(u64) = .init(0),
    stats_relay_upstream_eof_first: std.atomic.Value(u64) = .init(0),

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
    middle_proxy_health: MiddleProxyHealthStore,
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

    pub fn init(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !ProxyState {
        return initWithManagedBufferLimit(
            allocator,
            io,
            cfg,
            default_managed_buffer_limit_bytes,
        );
    }

    pub fn initWithManagedBufferLimit(
        allocator: std.mem.Allocator,
        io: std.Io,
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
        const user_tls_hmacs = try prepareUserHmacs(allocator, user_secrets);
        errdefer freeUserHmacs(allocator, user_tls_hmacs);

        const security = try SecurityState.create(allocator);
        errdefer allocator.destroy(security);

        // Freeze one certificate size for the process; both classical and PQ
        // responses derive it from this shared template instead of rerolling.
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

                if (isRunningInNonInitNetns(io)) {
                    log.info(
                        "mask_port={d} with non-init netns detected, using host veth IP {s} for local masking",
                        .{ cfg.mask_port, tunnel_mask_gateway_ip },
                    );
                    break :blk tunnel_mask_gateway_ip;
                }

                break :blk "127.0.0.1";
            };
            if (std.Io.net.IpAddress.parse(mask_target.?, cfg.mask_port)) |_| {
                const list = try net.getAddressList(allocator, io, mask_target.?, cfg.mask_port);
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
                web_mask_dns = try web_support.createMaskDns(allocator, io, spec);
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

        var default_middle_proxy_secret: [256]u8 = @splat(0);
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
            .io = io,
            .config = cfg,
            .managed_buffer_limit_bytes = managed_buffer_limit_bytes,
            .user_secrets = user_secrets,
            .user_tls_hmacs = user_tls_hmacs,
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
            .stats_relay_client_eof_first = .init(0),
            .stats_relay_upstream_eof_first = .init(0),
            .middle_proxy_addrs_primary = constants.tg_middle_proxies_v4,
            .middle_proxy_addrs_media_primary = constants.tg_media_middle_proxies_v4,
            .middle_proxy_addr_203 = constants.tg_cdn_middle_proxy_v4,
            .middle_proxy_candidates = defaultMiddleProxyCandidateLists(constants.tg_middle_proxies_v4),
            .middle_proxy_candidate_lens = @as([5]usize, @splat(1)),
            .middle_proxy_media_candidates = defaultMiddleProxyCandidateLists(constants.tg_media_middle_proxies_v4),
            .middle_proxy_media_candidate_lens = @as([5]usize, @splat(1)),
            .middle_proxy_candidates_203 = @as([16]net.Address, @splat(constants.tg_cdn_middle_proxy_v4)),
            .middle_proxy_candidates_203_len = 1,
            .middle_proxy_cooldowns = @as([middle_proxy_cooldown_slots]MiddleProxyCooldown, @splat(.{})),
            .middle_proxy_health = .{},
            .middle_proxy_secret = default_middle_proxy_secret,
            .middle_proxy_secret_len = middleproxy.proxy_secret.len,
            .middle_proxy_secret_version = 1,
            .middle_proxy_previous_secret = @as([256]u8, @splat(0)),
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
        freeUserHmacs(self.allocator, self.user_tls_hmacs);
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
        if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (self.web_mask_dns) |cache| try cache.start();

        var middle_proxy_updater_started = false;
        defer {
            if (middle_proxy_updater_started) self.stopMiddleProxyUpdater();
        }

        if (self.config.requiresMiddleProxyRuntime()) {
            self.startMiddleProxyUpdater();
            middle_proxy_updater_started = self.middle_proxy_updater_thread != null;
        }

        // Startup normally applies this before its banner and buffer sizing.
        // Keep the guard for callers that construct and run ProxyState directly.
        try enforceNofileCapacity(&self.config);

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
            net.ip6(@as([16]u8, @splat(0)), self.config.port, 0, 0)
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

    fn getMiddleProxySnapshot(self: *ProxyState, dc_abs: usize, media: bool) MiddleProxySnapshot {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();

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
        self.middle_proxy_health.rank(&snapshot.candidates, snapshot.candidate_len, &self.middle_proxy_cooldowns, now_ms);
        return snapshot;
    }

    fn noteMiddleProxyConnectSuccess(self: *ProxyState, addr: net.Address, secret_version: u64, duration_ms: i64, now_ms: i64) void {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();
        if (secret_version != self.middle_proxy_secret_version) return;
        self.middle_proxy_health.noteConnect(addr, duration_ms, now_ms);
    }

    fn noteMiddleProxyAuthSuccess(self: *ProxyState, addr: net.Address, secret_version: u64, duration_ms: i64, now_ms: i64) void {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();
        if (secret_version != self.middle_proxy_secret_version) return;
        self.middle_proxy_health.noteAuth(addr, duration_ms, now_ms);
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

    fn promoteMiddleProxyCandidate(self: *ProxyState, dc_abs: usize, media: bool, addr: net.Address, secret_version: u64) bool {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();
        if (secret_version != self.middle_proxy_secret_version) return false;

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

    fn cooldownMiddleProxyCandidate(self: *ProxyState, addr: net.Address, secret_version: u64) bool {
        self.middle_proxy_lock.lock();
        defer self.middle_proxy_lock.unlock();
        if (secret_version != self.middle_proxy_secret_version) return false;

        const now_ms = runtime_time.monotonicMilli();
        self.middle_proxy_health.noteFailure(addr, now_ms);
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
        const tunnel_active = isRunningInNonInitNetns(self.io);
        var awg_ip: ?[4]u8 = null;
        if (tunnel_active) {
            awg_ip = try detectAwgEndpointIpv4(
                self.allocator,
                self.io,
                &self.middle_proxy_updater_stop,
            );
        }

        var public_ip: ?[4]u8 = null;
        if (awg_ip == null and !self.middle_proxy_updater_stop.load(.acquire)) {
            public_ip = try detectPublicIpv4(
                self.allocator,
                self.io,
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
            self.io,
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
                self.io,
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

        var next_primary: [5]?net.Address = @splat(null);
        var next_media_primary: [5]?net.Address = @splat(null);
        var next_candidates: [5][16]net.Address = undefined;
        var next_candidate_lens: [5]usize = @splat(0);
        var next_media_candidates: [5][16]net.Address = undefined;
        var next_media_candidate_lens: [5]usize = @splat(0);
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
                // Scores from the previous authentication epoch cannot rank
                // endpoints whose new shared secret has not succeeded yet.
                self.middle_proxy_health.clear();
                for (&self.middle_proxy_cooldowns) |*entry| entry.* = .{};
                changed = true;
            }

            if (changed) {
                var active_candidates: [11 * 16]net.Address = undefined;
                var active_len: usize = 0;
                for (0..self.middle_proxy_candidates.len) |i| {
                    for (self.middle_proxy_candidates[i][0..self.middle_proxy_candidate_lens[i]]) |addr| {
                        active_candidates[active_len] = addr;
                        active_len += 1;
                    }
                    for (self.middle_proxy_media_candidates[i][0..self.middle_proxy_media_candidate_lens[i]]) |addr| {
                        active_candidates[active_len] = addr;
                        active_len += 1;
                    }
                }
                for (self.middle_proxy_candidates_203[0..self.middle_proxy_candidates_203_len]) |addr| {
                    active_candidates[active_len] = addr;
                    active_len += 1;
                }
                self.middle_proxy_health.retain(active_candidates[0..active_len]);
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
    prev_relay_client_eof_first: u64 = 0,
    prev_relay_upstream_eof_first: u64 = 0,
    relay_read_scratch: [relay_read_scratch_size]u8,
    server_hello_scratch: [tls.max_server_hello_len]u8 = undefined,
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
        loop.managed_buffers.pressure_handler = .{
            .context = &loop.message_block_pool,
            .reclaim = MessageBlockPool.reclaimForPressure,
        };
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
        loop.prev_relay_client_eof_first = 0;
        loop.prev_relay_upstream_eof_first = 0;
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
            // Saturation hysteresis: resume at or below the rounded 80% point.
            if (!self.shutting_down and self.saturation_paused) {
                const active = self.state.active_connections.load(.monotonic);
                const resume_threshold = limits.admissionResumeThreshold(self.state.config.max_connections);
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

        const graceful_read_hangup = hasGracefulEpollReadHangup(events);

        if (fd == slot.client_fd) {
            if ((events & linux.EPOLL.OUT) != 0) {
                self.onClientWritable(slot);
            }
            if (slot.phase == .idle) return;
            if (fd != slot.client_fd and fd != slot.upstream_fd) return;

            const relay_phase = slot.phase == .relaying or slot.phase == .mask_relaying;
            if (relay_phase and graceful_read_hangup and !slot.client_read_closed and !io_budget.exhausted()) {
                self.drainRelayReads(slot, fd);
            } else if ((events & linux.EPOLL.IN) != 0 and
                !io_budget.exhausted() and
                (!relay_phase or !slot.client_read_closed))
            {
                if (relay_phase) {
                    self.drainRelayReads(slot, fd);
                } else {
                    self.onClientReadable(slot);
                }
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
            if (relay_phase and graceful_read_hangup and !slot.upstream_read_closed and !io_budget.exhausted()) {
                self.drainRelayReads(slot, fd);
            } else if ((events & linux.EPOLL.IN) != 0 and
                !io_budget.exhausted() and
                (!relay_phase or !slot.upstream_read_closed))
            {
                if (relay_phase) {
                    self.drainRelayReads(slot, fd);
                } else {
                    self.onUpstreamReadable(slot);
                }
            }
        }

        if (slot.phase == .idle) return;
        if (fd != slot.client_fd and fd != slot.upstream_fd) return;

        const relay_phase = slot.phase == .relaying or slot.phase == .mask_relaying;
        const fatal_hangup = (events & linux.EPOLL.ERR) != 0 or
            ((events & (linux.EPOLL.HUP | linux.EPOLL.RDHUP)) != 0 and !relay_phase);
        if (fatal_hangup and shouldCloseOnFatalHangup(slot.phase, fd, slot.upstream_fd)) {
            if (shouldRecoverMiddleProxyOnFatalHangup(slot.phase, fd, slot.upstream_fd) and
                self.recoverMiddleProxyFailure(slot, .endpoint, error.ConnectionReset))
            {
                return;
            }
            self.closeSlot(slot, "epoll hup/err");
            return;
        }

        if (relay_phase and (events & linux.EPOLL.HUP) != 0) {
            if (fd == slot.client_fd) slot.client_hup = true else slot.upstream_hup = true;
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

        // Check the rounded 90% pause point before each accept batch; the hard
        // cap is reserved per slot. Resume at or below 80% in run().
        const active_now = self.state.active_connections.load(.monotonic);
        const max = self.state.config.max_connections;
        if (active_now >= limits.admissionPauseThreshold(max)) {
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
        const cur_client_eof_first = if (primary) self.state.stats_relay_client_eof_first.load(.monotonic) else self.prev_relay_client_eof_first;
        const cur_upstream_eof_first = if (primary) self.state.stats_relay_upstream_eof_first.load(.monotonic) else self.prev_relay_upstream_eof_first;

        const d_cap = cur_cap - self.prev_dropped_cap;
        const d_sat = cur_sat - self.prev_dropped_saturation;
        const d_rate = cur_rate - self.prev_dropped_rate_limit;
        const d_hs = cur_hs - self.prev_dropped_hs_budget;
        const d_hst = cur_hst - self.prev_hs_timeout;
        const d_mpf = cur_mpf - self.prev_mp_fallback;
        const d_buffer_denials = cur_buffer_denials - self.prev_buffer_denials;
        const d_web_only_masked = cur_web_only_masked - self.prev_web_only_masked;
        const d_client_eof_first = cur_client_eof_first - self.prev_relay_client_eof_first;
        const d_upstream_eof_first = cur_upstream_eof_first - self.prev_relay_upstream_eof_first;

        self.prev_dropped_cap = cur_cap;
        self.prev_dropped_saturation = cur_sat;
        self.prev_dropped_rate_limit = cur_rate;
        self.prev_dropped_hs_budget = cur_hs;
        self.prev_hs_timeout = cur_hst;
        self.prev_mp_fallback = cur_mpf;
        self.prev_buffer_denials = cur_buffer_denials;
        self.prev_web_only_masked = cur_web_only_masked;
        self.prev_relay_client_eof_first = cur_client_eof_first;
        self.prev_relay_upstream_eof_first = cur_upstream_eof_first;

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
        if (d_client_eof_first != 0 or d_upstream_eof_first != 0) {
            log.info("relay first EOF: client+={d} upstream+={d}", .{ d_client_eof_first, d_upstream_eof_first });
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

        self.advanceServerHelloWrite(slot);
    }

    /// Complete a ServerHello phase as soon as its last byte reaches the kernel.
    /// The split timer remains the only way to start the second desync write.
    fn advanceServerHelloWrite(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasClientPending()) return;
        switch (slot.phase) {
            .writing_server_hello_first => {
                slot.phase = .desync_wait;
                slot.desync_deadline_ns = self.desyncSplitDeadlineNs();
            },
            .writing_server_hello_rest => {
                if (slot.server_hello) |buf| {
                    secureFree(self.state.allocator, buf);
                    slot.server_hello = null;
                }
                slot.phase = .reading_mtproto_tls_header;
                slot.tls_hdr_pos = 0;
                slot.tls_body_len = 0;
                slot.tls_body_pos = 0;
            },
            else => {},
        }
    }

    fn onUpstreamReadable(self: *EventLoop, slot: *ConnectionSlot) void {
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
                    if (slot.phase == .middle_proxy_handshake and
                        self.recoverMiddleProxyFailure(slot, if (err == error.OutOfMemory) .local else .endpoint, err)) return;
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
        if (!slot.hasUpstreamPending()) {
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
                const read_at_ms = runtime_time.monotonicMilli();
                slot.last_activity_ms = read_at_ms;
                if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = read_at_ms;
                if (!slot.hs_counted and !self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
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
            const read_at_ms = runtime_time.monotonicMilli();
            slot.last_activity_ms = read_at_ms;
            if (slot.first_byte_at_ms == 0) slot.first_byte_at_ms = read_at_ms;
            if (!slot.hs_counted) {
                if (!self.reserveHandshakeBudget(slot)) {
                    self.closeSlot(slot, "handshake budget exhausted");
                    return;
                }
            }
            slot.tls_hdr_pos += @intCast(n);
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

        const hello_len = tls_header_len + @as(usize, record_len);
        if (hello_len > slot.client_hello_inline.len) {
            slot.client_hello_heap = self.state.allocator.alloc(u8, hello_len) catch {
                self.closeSlot(slot, "client_hello alloc failed");
                return;
            };
        }
        // Cleanup may use this length only after its backing storage exists.
        slot.client_hello_len = hello_len;

        const hello_buf = slot.clientHelloBuf();
        @memcpy(hello_buf[0..tls_header_len], slot.tls_hdr_buf[0..]);
        slot.tls_body_len = @intCast(record_len);
        slot.tls_body_pos = 0;
        slot.phase = .reading_client_hello_body;
        // readSlotFd enforces the same per-event budget and returns WouldBlock
        // if either the budget or the socket has no more readable bytes.
        self.readClientHelloBody(slot);
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
        var validation = tls.validateTlsHandshakePrepared(
            self.state.allocator,
            client_hello,
            self.state.user_secrets,
            self.state.user_tls_hmacs,
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
                .oversized_client_hello => .oversized_client_hello,
                .malformed_client_hello => .malformed_client_hello,
                .invalid_session_id => .invalid_session_id,
                .unsupported_key_share => .unsupported_key_share,
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

        const offers_pq = v.key_share == .x25519_mlkem768;
        const echoed_cipher = v.first_tls13_cipher;
        if (runtime_io.logEnabled(.debug, .proxy)) {
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
        }

        const server_hello = self.prepareServerHello(slot, offers_pq, echoed_cipher) catch {
            self.closeSlot(slot, "build server hello failed");
            return;
        };
        defer if (!self.state.config.desync) std.crypto.secureZero(u8, server_hello);
        slot.server_hello_off = 0;
        slot.releaseClientHello(self.state.allocator);

        if (self.state.config.desync and server_hello.len > 1) {
            slot.phase = .writing_server_hello_first;
            if (queueClient(slot, server_hello[0..1])) |_| {} else |_| {
                self.closeSlot(slot, "queue first desync byte failed");
                return;
            }
            slot.server_hello_off = 1;
            self.advanceServerHelloWrite(slot);
        } else {
            slot.phase = .writing_server_hello_rest;
            if (queueClient(slot, server_hello)) |_| {} else |_| {
                self.closeSlot(slot, "queue server hello failed");
                return;
            }
            slot.server_hello_off = server_hello.len;
            self.advanceServerHelloWrite(slot);
        }
    }

    fn prepareServerHello(self: *EventLoop, slot: *ConnectionSlot, offers_pq: bool, cipher: ?u16) ![]u8 {
        const cert_size = self.state.tls_server_hello_template.len - tls.server_hello_prefix_len;
        const session_id = slot.validation_session_id[0..slot.validation_session_id_len];
        if (!self.state.config.desync) {
            errdefer std.crypto.secureZero(u8, &self.server_hello_scratch);
            return if (offers_pq)
                tls.buildServerHelloPqInto(&self.server_hello_scratch, &slot.validation_secret, &slot.validation_digest, session_id, cipher, cert_size)
            else
                tls.buildServerHelloWithTemplateInto(&self.server_hello_scratch, self.state.tls_server_hello_template, &slot.validation_secret, &slot.validation_digest, session_id, cipher);
        }
        // Split-TLS spans timer callbacks, so its response must remain owned.
        const response = try (if (offers_pq)
            tls.buildServerHelloPq(
                self.state.allocator,
                &slot.validation_secret,
                &slot.validation_digest,
                session_id,
                cipher,
                cert_size,
            )
        else
            tls.buildServerHelloWithTemplateCipher(
                self.state.allocator,
                self.state.tls_server_hello_template,
                &slot.validation_secret,
                &slot.validation_digest,
                session_id,
                cipher,
            ));
        slot.server_hello = response;
        return response;
    }

    fn readMtprotoHandshake(self: *EventLoop, slot: *ConnectionSlot) void {
        var read_progress = false;
        defer if (read_progress and slot.phase != .idle) {
            slot.last_activity_ms = runtime_time.monotonicMilli();
        };
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
                    read_progress = true;
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
            read_progress = true;
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
        if (plan.is_media_path and runtime_io.logEnabled(.debug, .proxy)) {
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
        return timeout_policy.upstreamConnectDeadlineMs(
            slot,
            secondsToMs(self.state.config.dc_connect_timeout_sec),
            secondsToMs(self.state.config.handshake_timeout_sec),
            started_at_ms,
        );
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
        if (slot.use_middle_proxy and slot.upstream_kind == .dc) {
            const now_ms = runtime_time.monotonicMilli();
            if (slot.current_upstream_addr) |addr| {
                if (slot.upstream_connect_started_ms > 0) {
                    self.state.noteMiddleProxyConnectSuccess(addr, slot.mp_secret_version, now_ms - slot.upstream_connect_started_ms, now_ms);
                }
            }
            slot.mp_auth_started_at_ms = now_ms;
        }
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
        const candidate_count = candidates.len;

        // No alternate remote address can repair exhausted local socket or
        // epoll resources, and this is not evidence against an MP endpoint.
        if (err == error.OutOfMemory or err == error.SystemResources or
            err == error.ProcessFdQuotaExceeded or err == error.SystemFdQuotaExceeded)
            return false;

        if (slot.use_middle_proxy) {
            if (attempt_addr) |addr| {
                if (self.state.cooldownMiddleProxyCandidate(addr, slot.mp_secret_version)) {
                    log.info("[{d}] cooling failed middle-proxy endpoint for {d}s: dc_idx={d}", .{
                        slot.conn_id,
                        60,
                        slot.dc_idx,
                    });
                }
            }
        }

        const now_ms = runtime_time.monotonicMilli();
        const has_time = slot.first_byte_at_ms == 0 or
            now_ms - slot.first_byte_at_ms < secondsToMs(self.state.config.handshake_timeout_sec);
        if (!has_time) return false;

        if (slot.takeNextUpstreamCandidate()) |next_addr| {
            const next_idx = slot.upstream_candidate_next - 1;
            self.startConnectUpstream(slot, next_addr, .dc) catch |next_err| {
                log.warn("[{d}] dc connect candidate {d}/{d} failed immediately: {any}", .{
                    slot.conn_id,
                    next_idx + 1,
                    candidate_count,
                    next_err,
                });
                return self.tryNextDcEndpoint(slot, next_err, next_addr);
            };

            if (attempt_addr != null and runtime_io.logEnabled(.warn, .proxy)) {
                const addr = attempt_addr.?;
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

            if (runtime_io.logEnabled(.warn, .proxy)) {
                var fb_buf: [64]u8 = undefined;
                const fb_str = formatAddress(fallback, &fb_buf);
                log.warn("[{d}] middle-proxy dc={d} exhausted after {d} candidate(s) ({any}), fallback to direct {s}", .{
                    slot.conn_id,
                    slot.dc_idx,
                    candidate_count,
                    err,
                    fb_str,
                });
            }
            return true;
        }

        if (slot.is_media_path) {
            log.warn("[{d}] media path connect failed after all candidates: {any}", .{ slot.conn_id, err });
        }
        return false;
    }

    fn tryNextMaskEndpoint(self: *EventLoop, slot: *ConnectionSlot, err: anyerror, attempt_addr: ?net.Address) bool {
        const candidates = slot.upstreamCandidates();
        var previous_err = err;
        var previous_addr = attempt_addr;
        // DNS snapshots can exceed 255 entries. Immediate failures must not
        // turn a large candidate list into recursive stack growth.
        while (true) {
            if (previous_err == error.OutOfMemory or previous_err == error.SystemResources or
                previous_err == error.ProcessFdQuotaExceeded or previous_err == error.SystemFdQuotaExceeded)
                return false;
            if (slot.first_byte_at_ms != 0 and
                runtime_time.monotonicMilli() - slot.first_byte_at_ms >= secondsToMs(self.state.config.handshake_timeout_sec))
                return false;
            const next_addr = slot.takeNextUpstreamCandidate() orelse return false;
            const next_index = slot.upstream_candidate_next;
            self.startConnectUpstream(slot, next_addr, .mask) catch |next_err| {
                previous_err = next_err;
                previous_addr = next_addr;
                continue;
            };

            if (previous_addr != null and runtime_io.logEnabled(.debug, .proxy)) {
                const addr = previous_addr.?;
                var prev_buf: [64]u8 = undefined;
                log.debug("[{d}] mask connect failed ({any}), retry candidate {d}/{d} after {s}", .{
                    slot.conn_id,
                    previous_err,
                    next_index,
                    candidates.len,
                    formatAddress(addr, &prev_buf),
                });
            }
            return true;
        }
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

        // Promotion metadata belongs to MiddleProxy RPC_PROXY_REQ. A direct
        // stream contains only the nonce followed by the client's MTProto data,
        // including when a configured tag coexists with a direct-user bypass.

        slot.tg_encryptor = tg_encryptor;
        slot.tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
        slot.phase = .writing_dc_nonce;
        if (!slot.hasUpstreamPending()) self.onDcNonceWritable(slot);
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
        slot.last_activity_ms = runtime_time.monotonicMilli();
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
        slot.last_activity_ms = runtime_time.monotonicMilli();
    }

    fn middleProxyBegin(self: *EventLoop, slot: *ConnectionSlot) void {
        slot.phase = .middle_proxy_handshake;

        var nonce: [16]u8 = undefined;
        crypto.randomBytes(&nonce);
        defer std.crypto.secureZero(u8, &nonce);
        const timestamp: u32 = @intCast(@mod(runtime_time.realtimeSeconds(), 4294967296));
        var selector: [4]u8 = undefined;
        defer std.crypto.secureZero(u8, &selector);

        self.state.middle_proxy_lock.lockShared();
        const secret = self.state.middleProxySecretForVersionLocked(slot.mp_secret_version) orelse {
            self.state.middle_proxy_lock.unlockShared();
            if (!self.recoverMiddleProxyFailure(slot, .shared_metadata, error.MissingMiddleProxySecret))
                self.closeSlot(slot, "missing middle-proxy secret snapshot");
            return;
        };
        @memcpy(&selector, secret[0..4]);
        self.state.middle_proxy_lock.unlockShared();

        var frame_buf: [mp_handshake_frame_buf_size]u8 = undefined;
        defer std.crypto.secureZero(u8, &frame_buf);
        const frame = slot.mp_transport.begin(&frame_buf, &selector, &nonce, timestamp) catch |err| {
            if (!self.recoverMiddleProxyFailure(slot, .local, err))
                self.closeSlot(slot, "mp prepare nonce failed");
            return;
        };
        self.setMiddleProxyStep(slot, .sending_rpc_nonce);
        _ = queueUpstream(slot, frame) catch |err| {
            if (!self.recoverMiddleProxyFailure(slot, if (err == error.OutOfMemory) .local else .endpoint, err))
                self.closeSlot(slot, "mp send nonce failed");
            return;
        };
        if (!slot.hasUpstreamPending()) self.middleProxyOnWritable(slot);
    }

    fn middleProxyOnWritable(self: *EventLoop, slot: *ConnectionSlot) void {
        if (slot.hasUpstreamPending()) return;
        const previous_step = slot.mp_transport.step;
        slot.mp_transport.writeDrained();
        if (slot.mp_transport.step != previous_step)
            self.setMiddleProxyStep(slot, slot.mp_transport.step);
    }

    fn middleProxyOnReadable(self: *EventLoop, slot: *ConnectionSlot) void {
        const step = slot.mp_transport.step;
        if (step != .waiting_rpc_nonce_response and step != .waiting_rpc_handshake_response) return;
        const encrypted = step == .waiting_rpc_handshake_response;
        const ReadContext = struct {
            slot: *ConnectionSlot,
            progressed: bool = false,

            fn read(context: *@This(), dest: []u8) !usize {
                const n = try readSlotFd(context.slot, context.slot.upstream_fd, dest);
                if (n > 0) context.progressed = true;
                return n;
            }
        };
        var read_context = ReadContext{ .slot = slot };
        defer if (read_context.progressed and slot.phase != .idle) {
            slot.last_activity_ms = runtime_time.monotonicMilli();
        };
        const payload = slot.mp_transport.tryReadFrame(
            self.state.allocator,
            &read_context,
            ReadContext.read,
            encrypted,
        ) catch |err| {
            log.debug("[{d}] mp frame read failed: step={s} err={any}", .{ slot.conn_id, @tagName(step), err });
            if (!self.recoverMiddleProxyFailure(slot, if (err == error.OutOfMemory) .local else .endpoint, err))
                self.closeSlot(slot, "mp frame read failed");
            return;
        } orelse return;

        switch (step) {
            .waiting_rpc_nonce_response => {
                if (payload.len != 32 or !std.mem.eql(u8, payload[0..4], &middleproxy.rpc_nonce_req)) {
                    if (!self.recoverMiddleProxyFailure(slot, .endpoint, error.BadMiddleProxyNonceResponse))
                        self.closeSlot(slot, "mp bad nonce answer");
                    return;
                }
                self.state.middle_proxy_lock.lockShared();
                const secret = self.state.middleProxySecretForVersionLocked(slot.mp_secret_version) orelse {
                    self.state.middle_proxy_lock.unlockShared();
                    if (!self.recoverMiddleProxyFailure(slot, .shared_metadata, error.MissingMiddleProxySecret))
                        self.closeSlot(slot, "mp secret version expired");
                    return;
                };
                slot.mp_transport.validateNonceResponse(payload, secret) catch |err| {
                    self.state.middle_proxy_lock.unlockShared();
                    if (!self.recoverMiddleProxyFailure(slot, .endpoint, err))
                        self.closeSlot(slot, "mp nonce answer invalid");
                    return;
                };
                const peer_addr = net.peerAddress(slot.upstream_fd) catch |err| {
                    self.state.middle_proxy_lock.unlockShared();
                    if (!self.recoverMiddleProxyFailure(slot, .local, err))
                        self.closeSlot(slot, "mp getpeername failed");
                    return;
                };
                const local_addr = net.localAddress(slot.upstream_fd) catch |err| {
                    self.state.middle_proxy_lock.unlockShared();
                    if (!self.recoverMiddleProxyFailure(slot, .local, err))
                        self.closeSlot(slot, "mp getsockname failed");
                    return;
                };

                var frame_buf: [mp_handshake_frame_buf_size]u8 = undefined;
                defer std.crypto.secureZero(u8, &frame_buf);
                const frame = slot.mp_transport.acceptNonceResponse(
                    &frame_buf,
                    payload,
                    peer_addr,
                    local_addr,
                    slot.mp_nat_ip4,
                    secret,
                ) catch |err| {
                    self.state.middle_proxy_lock.unlockShared();
                    const class: MiddleProxyFailureClass = if (err == error.BadMiddleProxyNonceResponse)
                        .endpoint
                    else
                        .local;
                    if (!self.recoverMiddleProxyFailure(slot, class, err))
                        self.closeSlot(slot, "mp nonce answer invalid");
                    return;
                };
                self.state.middle_proxy_lock.unlockShared();

                _ = queueUpstream(slot, frame) catch |err| {
                    if (!self.recoverMiddleProxyFailure(slot, if (err == error.OutOfMemory) .local else .endpoint, err))
                        self.closeSlot(slot, "mp send handshake failed");
                    return;
                };
                if (!slot.hasUpstreamPending()) slot.mp_transport.writeDrained();
                self.setMiddleProxyStep(slot, slot.mp_transport.step);
            },
            .waiting_rpc_handshake_response => {
                slot.mp_transport.acceptHandshakeResponse(payload) catch |err| {
                    if (!self.recoverMiddleProxyFailure(slot, .endpoint, err))
                        self.closeSlot(slot, "mp handshake answer invalid");
                    return;
                };

                var auth = slot.mp_transport.takeAuthenticatedState() catch |err| {
                    if (!self.recoverMiddleProxyFailure(slot, .local, err))
                        self.closeSlot(slot, "mp authenticated state unavailable");
                    return;
                };
                defer auth.wipe();
                var conn_id: [8]u8 = undefined;
                crypto.randomBytes(&conn_id);
                defer std.crypto.secureZero(u8, &conn_id);

                slot.middle_ctx = middleproxy.MiddleProxyContext.initWithBuffer(
                    self.managed_buffers.allocator(),
                    auth.encryptor,
                    auth.decryptor,
                    conn_id,
                    auth.write_seq_no,
                    slot.peer_addr,
                    auth.effective_local_addr,
                    slot.proto_tag,
                    self.state.config.tag,
                    self.state.config.middleProxyBufferBytes(),
                ) catch |err| {
                    if (!self.recoverMiddleProxyFailure(slot, .local, err))
                        self.closeSlot(slot, "mp context init failed");
                    return;
                };

                self.setMiddleProxyStep(slot, .done);
                if (slot.current_upstream_addr) |addr| {
                    if (slot.mp_auth_started_at_ms > 0) {
                        const now_ms = runtime_time.monotonicMilli();
                        self.state.noteMiddleProxyAuthSuccess(
                            addr,
                            slot.mp_secret_version,
                            now_ms - slot.mp_auth_started_at_ms,
                            now_ms,
                        );
                    }
                }
                slot.mp_auth_started_at_ms = 0;
                self.promoteSuccessfulMiddleProxyCandidate(slot);
                self.startRelay(slot);
            },
            else => unreachable,
        }
    }

    fn promoteSuccessfulMiddleProxyCandidate(self: *EventLoop, slot: *const ConnectionSlot) void {
        if (!slot.use_middle_proxy or slot.upstream_candidate_next <= 1) return;
        const addr = slot.current_upstream_addr orelse return;

        if (self.state.promoteMiddleProxyCandidate(@intCast(slot.dc_abs), slot.is_media_path, addr, slot.mp_secret_version)) {
            log.info("[{d}] promoted successful middle-proxy fallback candidate: dc_idx={d}", .{
                slot.conn_id,
                slot.dc_idx,
            });
        }
    }

    const MiddleProxyFailureClass = enum { endpoint, shared_metadata, local };

    /// An endpoint-specific protocol failure can use another MP candidate.
    /// A missing shared secret cannot be repaired by trying the same metadata
    /// against every endpoint, and a local resource error is not remote health.
    fn recoverMiddleProxyFailure(
        self: *EventLoop,
        slot: *ConnectionSlot,
        class: MiddleProxyFailureClass,
        err: anyerror,
    ) bool {
        switch (class) {
            .local => return false,
            .shared_metadata => {
                self.state.requestMiddleProxyRefresh();
                return self.fallbackFromMiddleProxyToDirect(slot);
            },
            .endpoint => {
                const failed_addr = slot.current_upstream_addr;
                self.state.requestMiddleProxyRefresh();
                self.resetMiddleProxyAttempt(slot);
                return self.tryNextDcEndpoint(slot, err, failed_addr);
            },
        }
    }

    /// Keep the client handshake, route plan and handshake reservation intact.
    /// All fd, queue, CBC and RPC state below belongs to one MP attempt only.
    fn resetMiddleProxyAttempt(self: *EventLoop, slot: *ConnectionSlot) void {
        self.cleanupFailedUpstreamConnect(slot);
        self.setMiddleProxyStep(slot, .none);
        slot.mp_auth_started_at_ms = 0;
        if (slot.middle_ctx) |*mp| mp.deinit();
        slot.middle_ctx = null;
        slot.mp_transport.deinit(self.state.allocator);
    }

    fn fallbackFromMiddleProxyToDirect(self: *EventLoop, slot: *ConnectionSlot) bool {
        if (slot.direct_fallback_addr == null or slot.direct_fallback_used) return false;

        if (slot.obf_params == null) return false;
        slot.direct_fallback_used = true;
        countStat(&self.state.stats_mp_fallback);
        self.resetMiddleProxyAttempt(slot);
        slot.use_middle_proxy = false;
        slot.mp_secret_version = 0;
        slot.mp_nat_ip4 = null;

        slot.use_fast_mode = self.state.config.fast_mode and
            (slot.dc_abs >= 1 and slot.dc_abs <= constants.tg_datacenters_v4.len);

        // Reset nonce path state to cleanly re-send direct nonce.
        if (slot.tg_encryptor) |*enc| enc.wipe();
        if (slot.tg_decryptor) |*dec| dec.wipe();
        slot.tg_encryptor = null;
        slot.tg_decryptor = null;

        const fallback = slot.direct_fallback_addr.?;
        const one = [_]net.Address{fallback};
        slot.setUpstreamCandidates(self.state.allocator, &one) catch {
            return false;
        };
        slot.upstream_candidate_next = 1;

        self.startConnectUpstream(slot, fallback, .dc) catch |err| {
            log.warn("[{d}] direct fallback connect start failed: {any}", .{ slot.conn_id, err });
            return false;
        };

        if (runtime_io.logEnabled(.warn, .proxy)) {
            var fb_buf: [64]u8 = undefined;
            const fb_str = formatAddress(fallback, &fb_buf);
            log.warn("[{d}] middle-proxy handshake failed, reconnecting direct to {s}", .{ slot.conn_id, fb_str });
        }
        return true;
    }

    fn setMiddleProxyStep(self: *EventLoop, slot: *ConnectionSlot, step: MiddleProxyHandshakeStep) void {
        slot.mp_transport.step = step;
        slot.mp_step_deadline_ms = switch (step) {
            .none, .done => 0,
            else => timeout_policy.middleProxyStepDeadlineMs(
                slot,
                step,
                secondsToMs(self.state.config.handshake_timeout_sec),
                middle_proxy_stage_timeout_ms,
                runtime_time.monotonicMilli(),
            ),
        };
    }

    fn nextSlotDeadline(self: *const EventLoop, slot: *const ConnectionSlot) ?timeout_policy.SlotDeadline {
        return timeout_policy.nextSlotDeadline(slot, .{
            .handshake_timeout_sec = self.state.config.handshake_timeout_sec,
            .mask_relay_max_secs = self.state.config.mask_relay_max_secs,
            .pre_first_byte_timeout_ms = pre_first_byte_timeout_ms,
            .wedge_eligible = self.wedgeEligibleSlot(slot),
        });
    }

    fn refreshSlotDeadline(self: *EventLoop, slot: *ConnectionSlot) void {
        const next = self.nextSlotDeadline(slot) orelse {
            self.deadline_heap.remove(self.pool.slots, slot);
            self.rearmTimer() catch |err| log.err("failed to rearm deadline timer: {any}", .{err});
            return;
        };

        switch (next.kind) {
            .relay_idle => self.deadline_heap.updateRelayIdle(self.pool.slots, slot, next.deadline_ns),
            .absolute => self.deadline_heap.update(self.pool.slots, slot, next.deadline_ns),
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
            self.advanceServerHelloWrite(slot);
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
            if (self.recoverMiddleProxyFailure(slot, .endpoint, error.MiddleProxyStageTimedOut)) return;
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
                if (slot.phase == .middle_proxy_handshake and slot.mp_transport.step.awaitingMiddleProxy()) {
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
                    slot.mp_transport.step == .sending_rpc_nonce or
                    slot.mp_transport.step == .sending_rpc_handshake;
                want_upstream_in = slot.mp_transport.step == .waiting_rpc_nonce_response or
                    slot.mp_transport.step == .waiting_rpc_handshake_response;
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

        try self.syncSlotFdInterests(slot, .client, want_client_in, want_client_out, want_client_rdhup);
        try self.syncSlotFdInterests(slot, .upstream, want_upstream_in, want_upstream_out, want_upstream_rdhup);
    }

    fn syncSlotFdInterests(self: *EventLoop, slot: *ConnectionSlot, role: SlotFdRole, want_in: bool, want_out: bool, want_rdhup: bool) !void {
        const client = role == .client;
        const fd = if (client) slot.client_fd else slot.upstream_fd;
        if (isInvalidFd(fd)) return;
        const registered = if (client) slot.client_registered else slot.upstream_registered;
        const interest_in = if (client) &slot.client_interest_in else &slot.upstream_interest_in;
        const interest_out = if (client) &slot.client_interest_out else &slot.upstream_interest_out;
        const interest_rdhup = if (client) &slot.client_interest_rdhup else &slot.upstream_interest_rdhup;
        const hup = if (client) slot.client_hup else slot.upstream_hup;
        const fully_closed = if (client)
            slot.client_read_closed and slot.client_write_shutdown
        else
            slot.upstream_read_closed and slot.upstream_write_shutdown;
        const relay_phase = slot.phase == .relaying or slot.phase == .mask_relaying;
        if (relay_phase and (hup or fully_closed) and !want_in and !want_out) {
            // Modifying interests cannot mask HUP. Keep ownership of the fd,
            // but remove readiness until the opposite queue drains (or close).
            try self.delSlotFd(slot, role);
        } else if (!registered) {
            // A fresh generation prevents events from the parked registration
            // from being mistaken for the resumed fd's readiness.
            try self.addSlotFd(slot, fd, role, want_in, want_out, want_rdhup);
        } else if (interest_in.* != want_in or interest_out.* != want_out or interest_rdhup.* != want_rdhup) {
            try self.modSlotFd(slot, fd, role, want_in, want_out, want_rdhup);
        }
        interest_in.* = want_in;
        interest_out.* = want_out;
        interest_rdhup.* = want_rdhup;
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
        const side: RelayEofSide = switch (role) {
            .client => .client,
            .upstream => .upstream,
        };
        if (slot.recordRelayReadEof(side)) {
            switch (side) {
                .client => countStat(&self.state.stats_relay_client_eof_first),
                .upstream => countStat(&self.state.stats_relay_upstream_eof_first),
            }
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

    /// IN, RDHUP and error-free HUP share transport handlers and dispatch budget.
    /// Level-triggered epoll preserves readiness after yielding for fairness or
    /// backpressure; hangup becomes EOF only when the handler actually reads zero.
    fn drainRelayReads(self: *EventLoop, slot: *ConnectionSlot, fd: posix.fd_t) void {
        if (isInvalidFd(fd)) return;
        const from_client = fd == slot.client_fd;
        const from_upstream = fd == slot.upstream_fd;
        if (!from_client and !from_upstream) return;
        const phase = slot.phase;
        if (phase != .relaying and phase != .mask_relaying) return;
        const generation = slot.event_generation;
        const budget = slot.event_io_budget orelse return;

        // Pool release marks a slot idle but does not free its allocation. None
        // of these handlers accepts another connection; still recheck phase,
        // fd and registration generation before every subsequent read.
        while (slot.phase == phase and slot.event_generation == generation and
            fd == (if (from_client) slot.client_fd else slot.upstream_fd) and
            !(if (from_client) slot.client_read_closed else slot.upstream_read_closed) and
            !(if (from_client) slot.hasUpstreamPending() else slot.hasClientPending()) and
            !budget.exhausted())
        {
            const bytes_before = budget.bytes_remaining;
            if (from_client) {
                self.onClientReadable(slot);
            } else {
                self.onUpstreamReadable(slot);
            }
            // WouldBlock or a handler doing no I/O must yield even though a failed
            // read used an operation. Successful reads charge bytes, including partial
            // TLS/MP framing that has not produced an output payload yet.
            if (budget.bytes_remaining == bytes_before) break;
        }
    }

    fn logSlotClose(slot: *ConnectionSlot, reason: []const u8) void {
        const first_eof = if (slot.first_relay_eof) |side| @tagName(side) else "none";
        const lifetime_ms = connectionLifetimeMs(slot.created_at_ms, runtime_time.monotonicMilli());
        if (slot.phase == .mask_relaying) {
            var client_ip_buf: [64]u8 = undefined;
            const client_ip = formatClientIp(slot.peer_addr, &client_ip_buf);
            if (slot.mask_timestamp_skew_s) |skew_s| {
                log.debug("[{d}] closing: dc_idx={d} media={} phase={s} mask_cause={s} skew_s={d} reason={s} raw_c2s={d} raw_s2c={d} first_eof={s} lifetime_ms={d} client={s}", .{
                    slot.conn_id,
                    slot.dc_idx,
                    slot.is_media_path,
                    @tagName(slot.phase),
                    @tagName(slot.mask_cause),
                    skew_s,
                    reason,
                    slot.mask_c2s_bytes,
                    slot.mask_s2c_bytes,
                    first_eof,
                    lifetime_ms,
                    client_ip,
                });
            } else {
                log.debug("[{d}] closing: dc_idx={d} media={} phase={s} mask_cause={s} reason={s} raw_c2s={d} raw_s2c={d} first_eof={s} lifetime_ms={d} client={s}", .{
                    slot.conn_id,
                    slot.dc_idx,
                    slot.is_media_path,
                    @tagName(slot.phase),
                    @tagName(slot.mask_cause),
                    reason,
                    slot.mask_c2s_bytes,
                    slot.mask_s2c_bytes,
                    first_eof,
                    lifetime_ms,
                    client_ip,
                });
            }
        } else {
            var client_ip_buf: [64]u8 = undefined;
            const client_ip = formatClientIp(slot.peer_addr, &client_ip_buf);
            log.debug("[{d}] closing: dc_idx={d} media={} phase={s} reason={s} c2s={d} s2c={d} first_eof={s} lifetime_ms={d} client={s}", .{
                slot.conn_id,
                slot.dc_idx,
                slot.is_media_path,
                @tagName(slot.phase),
                reason,
                slot.c2s_bytes,
                slot.s2c_bytes,
                first_eof,
                lifetime_ms,
                client_ip,
            });
        }
    }

    fn closeSlot(self: *EventLoop, slot: *ConnectionSlot, reason: []const u8) void {
        if (slot.phase == .idle) return;
        if (runtime_io.logEnabled(.debug, .proxy)) logSlotClose(slot, reason);
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

fn queueDirectClientPayloadBatch(slot: *ConnectionSlot, parts: []const []const u8) !void {
    _ = try relay_io.queueUpstreamParts(slot, parts);
    // Account accepted payload pieces, regardless of physical write count.
    for (parts) |payload| {
        slot.wedge_forwarded_c2s_seq +|= 1;
        slot.c2s_bytes += payload.len;
    }
}

fn relayClientToUpstreamStep(self: *EventLoop, slot: *ConnectionSlot) !RelayProgress {
    const read_buf = self.relay_read_scratch[0..];
    const n = readSlotFd(slot, slot.client_fd, read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (n == 0) return error.EndOfStream;

    var remaining = read_buf[0..n];
    var forwarded = false;
    var parts: [relay_io.max_scatter_parts][]const u8 = undefined;
    var part_count: usize = 0;
    // Finish this bounded chunk even if output becomes queued: all slices borrow
    // read scratch and the queue helpers own unsent bytes before the next read.
    while (true) {
        const payload = (relay_io.nextClientTlsPayload(slot, &remaining) catch |err| {
            // The previous per-payload path already forwarded valid prefixes
            // before encountering a malformed record in the same read.
            if (part_count > 0) try queueDirectClientPayloadBatch(slot, parts[0..part_count]);
            return err;
        }) orelse break;
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
            parts[part_count] = payload;
            part_count += 1;
            if (part_count == parts.len) {
                try queueDirectClientPayloadBatch(slot, &parts);
                part_count = 0;
            }
            forwarded = true;
            continue;
        }

        slot.c2s_bytes += payload.len;
        forwarded = true;
    }
    if (part_count > 0) try queueDirectClientPayloadBatch(slot, parts[0..part_count]);
    return if (forwarded) .forwarded else .partial;
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

/// Apply the same FD policy before startup diagnostics and for direct runners.
pub fn enforceNofileCapacity(cfg: *Config) !void {
    const soft = getNofileSoftLimit() orelse return;
    try enforceNofileCapacityWithLimit(cfg, soft);
}

fn enforceNofileCapacityWithLimit(cfg: *Config, soft: usize) !void {
    const configured_max = cfg.max_connections;
    if (soft >= requiredFdsForConnections(configured_max)) return;

    const clamped = maxConnectionsForNofile(soft);
    if (clamped == 0) {
        log.err("RLIMIT_NOFILE soft={d} cannot support the minimum 32 connections (need at least {d})", .{
            soft,
            requiredFdsForConnections(32),
        });
        return error.InsufficientFileDescriptorLimit;
    }
    cfg.max_connections = clamped;
    log.warn("max_connections clamped from {d} to {d} due to RLIMIT_NOFILE soft={d}", .{
        configured_max,
        clamped,
        soft,
    });
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
    if (builtin.target.os.tag != .linux) return null;

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

fn writePlainMiddleProxyTestFrame(fd: posix.fd_t, seq_no: i32, payload: []const u8) !void {
    var frame: [mp_handshake_frame_buf_size]u8 = undefined;
    var frame_seq = seq_no;
    const encoded = try middle_proxy_handshake.encodeFrame(&frame, &frame_seq, payload, null);
    const written = try writeFd(fd, encoded);
    try std.testing.expectEqual(encoded.len, written);
}

test "middle proxy nonce response failure retries another candidate before direct fallback" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;

    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_io = std.testing.io;

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
    var next_mp_server = try net.listen(net.ip4(.{ 127, 0, 0, 1 }, 0), .{
        .reuse_address = true,
        .kernel_backlog = 8,
    });
    defer next_mp_server.deinit();
    const next_mp_addr = try net.localAddress(next_mp_server.handle);

    slot.conn_id = 42;
    slot.upstream_fd = upstream_file.handle;
    upstream_file_owned = false;
    slot.phase = .middle_proxy_handshake;
    slot.mp_transport.step = .waiting_rpc_nonce_response;
    slot.mp_transport.read_seq_no = -2;
    slot.use_middle_proxy = true;
    slot.direct_fallback_addr = fallback_addr;
    slot.current_upstream_addr = fallback_addr;
    slot.dc_abs = 4;
    slot.mp_secret_version = state.middle_proxy_secret_version;
    slot.first_byte_at_ms = runtime_time.monotonicMilli();
    const original_first_byte_ms = slot.first_byte_at_ms;
    slot.pipelined_data = try state.allocator.alloc(u8, 4);
    @memcpy(slot.pipelined_data.?, "test"[0..4]);
    slot.pipelined_len = 4;
    const mp_candidates = [_]net.Address{ fallback_addr, next_mp_addr };
    try slot.setUpstreamCandidates(state.allocator, &mp_candidates);
    slot.upstream_candidate_next = 1;
    slot.obf_params = .{
        .decrypt_key = @as([constants.key_len]u8, @splat(0)),
        .decrypt_iv = 0,
        .encrypt_key = @as([constants.key_len]u8, @splat(0)),
        .encrypt_iv = 0,
        .proto_tag = .intermediate,
        .dc_idx = 4,
    };
    slot.mp_transport.resetFrame(false);

    var bad_nonce_payload: [32]u8 = @splat(0);
    @memcpy(bad_nonce_payload[0..4], &middleproxy.rpc_proxy_ans);
    try writePlainMiddleProxyTestFrame(upstream_file.handle, -2, &bad_nonce_payload);
    try seekFdToStart(upstream_file.handle);

    loop.middleProxyOnReadable(slot);

    try std.testing.expect(!slot.direct_fallback_used);
    try std.testing.expect(slot.use_middle_proxy);
    try std.testing.expect(net.exactAddressEql(slot.current_upstream_addr.?, next_mp_addr));
    try std.testing.expectEqual(original_first_byte_ms, slot.first_byte_at_ms);
    try std.testing.expectEqualStrings("test", slot.pipelined_data.?[0..slot.pipelined_len]);
    if (slot.phase == .connecting_upstream) {
        try std.testing.expectEqual(@as(i32, -2), slot.mp_transport.write_seq_no);
        try std.testing.expectEqual(@as(i32, -2), slot.mp_transport.read_seq_no);
        try std.testing.expectEqual(@as(u32, 0), slot.mp_transport.timestamp);
        try std.testing.expect(slot.mp_transport.enc == null and slot.mp_transport.dec == null);
    } else {
        try std.testing.expectEqual(ConnectionPhase.middle_proxy_handshake, slot.phase);
    }
    try std.testing.expectEqual(@as(u64, 0), state.stats_mp_fallback.load(.monotonic));

    try std.testing.expect(loop.recoverMiddleProxyFailure(slot, .endpoint, error.BadMiddleProxyHandshakeResponse));
    try std.testing.expect(slot.direct_fallback_used);
    try std.testing.expect(!slot.use_middle_proxy);
    try std.testing.expectEqual(MiddleProxyHandshakeStep.none, slot.mp_transport.step);
    try std.testing.expectEqual(UpstreamKind.dc, slot.upstream_kind);
    try std.testing.expectEqual(@as(usize, 1), slot.upstreamCandidates().len);
    try std.testing.expect(net.exactAddressEql(slot.current_upstream_addr.?, fallback_addr));
    try std.testing.expect(slot.phase == .connecting_upstream or slot.phase == .writing_dc_nonce);
    try std.testing.expectEqual(@as(u64, 1), state.stats_mp_fallback.load(.monotonic));

    const cdn_slot = loop.pool.acquire() orelse return error.TestExpectedEqual;
    cdn_slot.client_queue.pool = &loop.message_block_pool;
    cdn_slot.upstream_queue.pool = &loop.message_block_pool;
    defer if (cdn_slot.phase != .idle) {
        if (!isInvalidFd(cdn_slot.upstream_fd)) closeFd(cdn_slot.upstream_fd);
        cdn_slot.upstream_fd = invalid_fd;
        cdn_slot.resetOwnedBuffers(state.allocator);
        loop.pool.release(cdn_slot);
    };
    var cdn_file = try tmp.dir.createFile(tmp_io, "cdn-middle-proxy-upstream", .{ .read = true });
    var cdn_file_owned = true;
    defer if (cdn_file_owned) cdn_file.close(tmp_io);
    cdn_slot.conn_id = 43;
    cdn_slot.upstream_fd = cdn_file.handle;
    cdn_file_owned = false;
    cdn_slot.phase = .middle_proxy_handshake;
    cdn_slot.mp_transport.step = .waiting_rpc_nonce_response;
    cdn_slot.mp_transport.read_seq_no = -2;
    cdn_slot.use_middle_proxy = true;
    cdn_slot.current_upstream_addr = fallback_addr;
    cdn_slot.dc_abs = 203;
    cdn_slot.dc_idx = 203;
    cdn_slot.mp_secret_version = state.middle_proxy_secret_version;
    try cdn_slot.setUpstreamCandidates(state.allocator, &mp_candidates);
    cdn_slot.upstream_candidate_next = 1;
    cdn_slot.mp_transport.resetFrame(false);
    try writePlainMiddleProxyTestFrame(cdn_file.handle, -2, &bad_nonce_payload);
    try seekFdToStart(cdn_file.handle);

    loop.middleProxyOnReadable(cdn_slot);
    try std.testing.expect(cdn_slot.use_middle_proxy);
    try std.testing.expect(!cdn_slot.direct_fallback_used);
    try std.testing.expect(net.exactAddressEql(cdn_slot.current_upstream_addr.?, next_mp_addr));
    try std.testing.expect(!loop.recoverMiddleProxyFailure(cdn_slot, .endpoint, error.BadMiddleProxyHandshakeResponse));
    try std.testing.expect(isInvalidFd(cdn_slot.upstream_fd));
    try std.testing.expect(!cdn_slot.direct_fallback_used);
}

test "ServerHello advances only after the queued bytes are fully written" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .desync = true,
        .desync_split_delay_ms = 3,
        .desync_split_jitter_ms = 0,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    var loop: EventLoop = undefined;
    loop.state = &state;

    var slot = ConnectionSlot{};
    defer slot.client_queue.deinit();
    slot.phase = .writing_server_hello_first;
    try slot.client_queue.appendCopy(&.{0x16});
    loop.advanceServerHelloWrite(&slot);
    try std.testing.expectEqual(ConnectionPhase.writing_server_hello_first, slot.phase);
    try std.testing.expectEqual(@as(i128, 0), slot.desync_deadline_ns);

    slot.client_queue.clear();
    const before = runtime_time.monotonicNano();
    loop.advanceServerHelloWrite(&slot);
    const after = runtime_time.monotonicNano();
    try std.testing.expectEqual(ConnectionPhase.desync_wait, slot.phase);
    try std.testing.expect(slot.desync_deadline_ns >= before + 3 * std.time.ns_per_ms);
    try std.testing.expect(slot.desync_deadline_ns <= after + 3 * std.time.ns_per_ms);

    slot.phase = .writing_server_hello_rest;
    slot.server_hello = try state.allocator.alloc(u8, 3);
    slot.tls_hdr_pos = 5;
    slot.tls_body_len = 17;
    slot.tls_body_pos = 2;
    loop.advanceServerHelloWrite(&slot);
    try std.testing.expectEqual(ConnectionPhase.reading_mtproto_tls_header, slot.phase);
    try std.testing.expect(slot.server_hello == null);
    try std.testing.expectEqual(@as(u8, 0), slot.tls_hdr_pos);
    try std.testing.expectEqual(@as(u16, 0), slot.tls_body_len);
    try std.testing.expectEqual(@as(u16, 0), slot.tls_body_pos);

    slot.phase = .idle;
    loop.advanceServerHelloWrite(&slot);
    try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
}

test "ServerHello preparation freezes process certificate size and preserves scratch ownership" {
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    for ([_]u32{ 0, 4096 }) |configured| {
        var cfg = Config{
            .users = std.StringHashMap([16]u8).init(std.testing.allocator),
            .direct_users = std.StringHashMap(void).init(std.testing.allocator),
            .mask = false,
            .fake_cert_size = configured,
            .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
        };
        defer cfg.deinit(std.testing.allocator);
        var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
        defer state.deinit();
        loop.state = &state;
        const cert_size = tls.firstAppDataRecordLen(state.tls_server_hello_template).?;
        if (configured == 0) {
            try std.testing.expect(cert_size >= tls.default_fake_cert_min_size);
            try std.testing.expect(cert_size <= tls.default_fake_cert_max_size);
        } else {
            try std.testing.expectEqual(@as(usize, configured), cert_size);
        }
        for ([_]bool{ false, true }) |desync| {
            state.config.desync = desync;
            for ([_]bool{ false, true }) |pq| {
                for (0..3) |_| {
                    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
                    state.allocator = if (desync) std.testing.allocator else failing.allocator();
                    defer state.allocator = std.testing.allocator;
                    var slot = ConnectionSlot{
                        .validation_secret = @as([16]u8, @splat(0x42)),
                        .validation_digest = @as([32]u8, @splat(0x71)),
                        .validation_session_id = @as([32]u8, @splat(0x39)),
                        .validation_session_id_len = 32,
                    };
                    defer if (slot.server_hello) |response| secureFree(state.allocator, response);
                    const response = try loop.prepareServerHello(&slot, pq, 0x1302);
                    const expected = try std.testing.allocator.dupe(u8, response);
                    defer std.testing.allocator.free(expected);
                    try std.testing.expectEqual(@as(?usize, cert_size), tls.firstAppDataRecordLen(response));
                    try std.testing.expectEqual(desync, slot.server_hello != null);
                    try std.testing.expectEqual(!desync, response.ptr == loop.server_hello_scratch[0..].ptr);
                    try std.testing.expect(!failing.has_induced_failure);
                    @memset(&loop.server_hello_scratch, 0xa5);
                    if (desync) try std.testing.expectEqualSlices(u8, expected, slot.server_hello.?);
                }
            }
        }
    }
}

test "unsplit ServerHello pending bytes survive worker scratch reuse" {
    const cert_size = tls.max_fake_cert_size;
    const template = try tls.buildServerHelloTemplateAlloc(std.testing.allocator, 42, cert_size);
    defer std.testing.allocator.free(template);
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    var state: ProxyState = undefined;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    state.allocator = failing.allocator();
    state.config.desync = false;
    state.tls_server_hello_template = template;
    loop.state = &state;
    for ([_]bool{ false, true }) |pq| {
        for ([_]struct { prefix: ?usize, blocked: bool }{
            .{ .prefix = null, .blocked = false },
            .{ .prefix = 17, .blocked = false },
            .{ .prefix = 0, .blocked = true },
        }) |fixture| {
            const client = try relayDrainTestSocketPair();
            defer closeFd(client[0]);
            defer closeFd(client[1]);
            const fill: [4096]u8 = @splat(0);
            var filled: usize = 0;
            if (fixture.blocked) {
                var blocked = false;
                for (0..1024) |_| {
                    filled += writeFd(client[0], &fill) catch |err| {
                        if (err != error.WouldBlock) return err;
                        blocked = true;
                        break;
                    };
                }
                try std.testing.expect(blocked);
            }
            var budget = EventIoBudget{
                .bytes_remaining = if (fixture.blocked) event_io_byte_budget else fixture.prefix orelse event_io_byte_budget,
                .operations_remaining = 1,
            };
            var slot = ConnectionSlot{
                .phase = .writing_server_hello_rest,
                .client_fd = client[0],
                .validation_secret = @as([16]u8, @splat(0x42)),
                .validation_digest = @as([32]u8, @splat(0x71)),
                .validation_session_id = @as([32]u8, @splat(0x39)),
                .validation_session_id_len = 32,
                .client_queue = .{ .allocator = if (fixture.prefix == null) failing.allocator() else std.testing.allocator },
                .event_io_budget = &budget,
            };
            defer slot.client_queue.deinit();
            const response = try loop.prepareServerHello(&slot, pq, 0x1303);
            const expected = try std.testing.allocator.dupe(u8, response);
            defer std.testing.allocator.free(expected);
            const prefix = fixture.prefix orelse response.len;
            try std.testing.expectEqual(prefix == response.len, try queueClient(&slot, response));
            loop.advanceServerHelloWrite(&slot);
            try std.testing.expectEqual(if (prefix == response.len) ConnectionPhase.reading_mtproto_tls_header else .writing_server_hello_rest, slot.phase);
            try std.testing.expect(slot.server_hello == null);
            try std.testing.expect(!failing.has_induced_failure);
            @memset(&loop.server_hello_scratch, 0xa5);
            try expectRelayTestQueue(&slot.client_queue, expected[prefix..]);
            var drain: [4096]u8 = undefined;
            while (filled > 0) {
                const count = try posix.read(client[1], drain[0..@min(filled, drain.len)]);
                try std.testing.expect(count > 0);
                filled -= count;
            }
            const actual = try std.testing.allocator.alloc(u8, expected.len);
            defer std.testing.allocator.free(actual);
            if (prefix > 0) try std.testing.expectEqual(prefix, try posix.read(client[1], actual[0..prefix]));
            var flush_budget: EventIoBudget = .{};
            slot.event_io_budget = &flush_budget;
            try std.testing.expectEqual(expected.len - prefix, try flushClientPending(&slot));
            if (prefix < expected.len) try std.testing.expectEqual(expected.len - prefix, try posix.read(client[1], actual[prefix..]));
            try std.testing.expectEqualSlices(u8, expected, actual);
            loop.advanceServerHelloWrite(&slot);
            try std.testing.expectEqual(ConnectionPhase.reading_mtproto_tls_header, slot.phase);
        }
    }
}

test "FakeTLS size and key-share refusals mask the complete original record" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    const hostname = "example.org";
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
        .mask = false,
        .tls_domain = hostname,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);
    const secret: [16]u8 = @splat(0x1a);
    const username = try std.testing.allocator.dupe(u8, "alice");
    cfg.users.put(username, secret) catch |err| {
        std.testing.allocator.free(username);
        return err;
    };
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    var backend = try net.listen(net.ip4(.{ 127, 0, 0, 1 }, 0), .{});
    defer backend.deinit();
    state.mask_addrs = try std.testing.allocator.alloc(net.Address, 1);
    state.mask_addrs[0] = try net.localAddress(backend.handle);
    state.config.mask = true;
    const client = try relayDrainTestSocketPair();
    defer closeFd(client[0]);
    defer closeFd(client[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, client[0], control, 0, 1, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }

    var storage: [tls.max_authenticated_hello_len + 1]u8 = undefined;
    for ([_]struct { len: usize, cause: MaskCause }{
        .{ .len = storage.len, .cause = .oversized_client_hello },
        .{ .len = 256, .cause = .unsupported_key_share },
    }) |fixture| {
        const original = storage[0..fixture.len];
        @memset(original, 0);
        @memcpy(original[0..11], &[_]u8{ 0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0, 0x03, 0x03 });
        std.mem.writeInt(u16, original[3..5], @intCast(original.len - 5), .big);
        std.mem.writeInt(u24, original[6..9], @intCast(original.len - 9), .big);
        original[43] = 32;
        @memset(original[44..76], 0xaa);
        @memcpy(original[76..82], &[_]u8{ 0, 2, 0x13, 0x01, 1, 0 });
        std.mem.writeInt(u16, original[82..84], @intCast(original.len - 84), .big);
        std.mem.writeInt(u16, original[86..88], @intCast(5 + hostname.len), .big);
        std.mem.writeInt(u16, original[88..90], @intCast(3 + hostname.len), .big);
        std.mem.writeInt(u16, original[91..93], @intCast(hostname.len), .big);
        @memcpy(original[93..][0..hostname.len], hostname);
        const padding_pos = 93 + hostname.len;
        std.mem.writeInt(u16, original[padding_pos..][0..2], 0x0015, .big);
        std.mem.writeInt(u16, original[padding_pos + 2 ..][0..2], @intCast(original.len - padding_pos - 4), .big);
        const digest = crypto.sha256Hmac(&secret, original);
        @memcpy(original[constants.tls_digest_pos..][0..32], &digest);
        var timestamp: [4]u8 = undefined;
        std.mem.writeInt(u32, &timestamp, @intCast(runtime_time.realtimeSeconds()), .little);
        for (timestamp, 0..) |byte, i| original[constants.tls_digest_pos + 28 + i] ^= byte;
        try std.testing.expectEqualStrings(hostname, tls.extractSni(original).?);

        const now_ms = runtime_time.monotonicMilli();
        var slot = ConnectionSlot{
            .phase = .reading_client_hello_body,
            .client_fd = client[0],
            .client_hello_heap = try std.testing.allocator.dupe(u8, original),
            .client_hello_len = original.len,
            .tls_body_len = @intCast(original.len - tls_header_len),
            .tls_body_pos = @intCast(original.len - tls_header_len),
            .created_at_ms = now_ms,
            .last_activity_ms = now_ms,
            .client_queue = .{ .allocator = std.testing.allocator },
            .upstream_queue = .{ .allocator = std.testing.allocator },
        };
        defer {
            if (!isInvalidFd(slot.upstream_fd)) closeFd(slot.upstream_fd);
            slot.resetOwnedBuffers(std.testing.allocator);
        }
        loop.readClientHelloBody(&slot);
        try std.testing.expectEqual(fixture.cause, slot.mask_cause);
        try std.testing.expect(slot.phase == .connecting_upstream or slot.phase == .mask_relaying);
        if (slot.mask_prebuffer) |pre| try std.testing.expectEqualSlices(u8, original, pre);
        slot.releaseClientHello(std.testing.allocator); // Masking owns its own copy.
        const accepted = try net.acceptFd(backend.handle);
        defer closeFd(accepted.fd);
        if (slot.phase == .connecting_upstream) loop.onUpstreamConnectComplete(&slot);
        try std.testing.expectEqual(ConnectionPhase.mask_relaying, slot.phase);
        try std.testing.expectEqual(original.len, slot.mask_c2s_bytes);
        try std.testing.expect(slot.mask_prebuffer == null);
        var received_storage: [storage.len]u8 = undefined;
        const received = received_storage[0..original.len];
        var received_len: usize = 0;
        while (received_len < received.len) {
            const n = try posix.read(accepted.fd, received[received_len..]);
            try std.testing.expect(n > 0);
            received_len += n;
        }
        try std.testing.expectEqualSlices(u8, original, received);
    }
}

test "relay idle deadlines wake early, recompute live activity and preserve timer ordering" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .client_silence_close_sec = 0,
        .handshake_timeout_sec = 15,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const listener = try relayDrainTestSocketPair();
    defer closeFd(listener[0]);
    defer closeFd(listener[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, listener[0], control, 0, 4, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }
    const ms: i128 = std.time.ns_per_ms;
    loop.stats_next_log_ns = 1_000_000 * ms;
    const first = loop.pool.acquire().?;
    first.phase = .relaying;
    first.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 1234);
    first.last_activity_ms = 1000;
    first.idle_timeout_ms = 10_000;
    first.event_generation = 7;
    first.client_event_generation = 7;
    const old_token = decodeSlotEventToken(encodeSlotEventToken(first, .client)).?;
    loop.refreshSlotDeadline(first);
    try std.testing.expectEqual(11_000 * ms, loop.armed_deadline_ns);
    first.last_activity_ms = 3000;
    loop.refreshSlotDeadline(first);
    try std.testing.expectEqual(11_000 * ms, loop.deadline_heap.peek().?.deadline_ns);
    try std.testing.expectEqual(11_000 * ms, loop.armed_deadline_ns);
    try std.testing.expectEqual(13_000 * ms, loop.nextSlotDeadline(first).?.deadline_ns);

    const second = loop.pool.acquire().?;
    second.phase = .relaying;
    second.peer_addr = first.peer_addr;
    second.last_activity_ms = 1500;
    second.idle_timeout_ms = 10_000;
    loop.refreshSlotDeadline(second);
    loop.runTimers(11_000 * ms);
    try std.testing.expectEqual(ConnectionPhase.relaying, first.phase);
    try std.testing.expectEqual(13_000 * ms, loop.deadline_heap.entries.items[first.timer_heap_index].deadline_ns);
    try std.testing.expectEqual(second.index, loop.deadline_heap.peek().?.slot_index);
    try std.testing.expectEqual(11_500 * ms, loop.armed_deadline_ns);

    first.idle_timeout_ms = 8250; // A nearer idle deadline must update immediately.
    loop.refreshSlotDeadline(first);
    try std.testing.expectEqual(first.index, loop.deadline_heap.peek().?.slot_index);
    try std.testing.expectEqual(11_250 * ms, loop.armed_deadline_ns);
    loop.runTimers(11_250 * ms);
    try std.testing.expectEqual(ConnectionPhase.idle, first.phase);
    try std.testing.expectEqual(connection.no_timer_heap_index, first.timer_heap_index);
    try std.testing.expectEqual(11_500 * ms, loop.armed_deadline_ns);

    const reused = loop.pool.acquire().?;
    try std.testing.expectEqual(first, reused);
    try std.testing.expectEqual(connection.no_timer_heap_index, reused.timer_heap_index);
    reused.phase = .relaying;
    reused.peer_addr = second.peer_addr;
    reused.last_activity_ms = 8000;
    reused.idle_timeout_ms = 10_000;
    reused.event_generation = nextSlotGeneration(reused.event_generation);
    reused.client_event_generation = reused.event_generation;
    try std.testing.expect(loop.pool.getByToken(old_token) == null);
    loop.refreshSlotDeadline(reused);
    try std.testing.expectEqual(18_000 * ms, loop.deadline_heap.entries.items[reused.timer_heap_index].deadline_ns);
    loop.runTimers(11_500 * ms);
    try std.testing.expectEqual(ConnectionPhase.idle, second.phase);
    try std.testing.expectEqual(ConnectionPhase.relaying, reused.phase);
    try std.testing.expectEqual(18_000 * ms, loop.armed_deadline_ns);
    loop.closeSlot(reused, "deadline test removal");
    try std.testing.expect(loop.deadline_heap.peek() == null);
    try std.testing.expectEqual(loop.stats_next_log_ns, loop.armed_deadline_ns);

    state.config.client_silence_close_sec = 10;
    const wedge_slot = loop.pool.acquire().?;
    wedge_slot.phase = .relaying;
    wedge_slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 1234);
    wedge_slot.wedge_client_key = 1;
    wedge_slot.dc_abs = 1;
    wedge_slot.last_activity_ms = 20_000;
    wedge_slot.idle_timeout_ms = 120_000;
    loop.refreshSlotDeadline(wedge_slot);
    wedge_slot.wedge.phase = .waiting_for_client;
    wedge_slot.wedge.response_kind = .fresh;
    wedge_slot.wedge.deadline_ms = 25_000;
    loop.refreshSlotDeadline(wedge_slot);
    try std.testing.expectEqual(25_000 * ms, loop.armed_deadline_ns);
    wedge_slot.wedge.deadline_ms = 26_000;
    loop.refreshSlotDeadline(wedge_slot);
    try std.testing.expectEqual(26_000 * ms, loop.armed_deadline_ns); // Absolute, never lazy.
    wedge_slot.wedge.reset();
    loop.refreshSlotDeadline(wedge_slot);
    try std.testing.expectEqual(26_000 * ms, loop.armed_deadline_ns); // Canceled wedge is an early wake.
    loop.runTimers(26_000 * ms);
    try std.testing.expectEqual(ConnectionPhase.relaying, wedge_slot.phase);
    try std.testing.expectEqual(140_000 * ms, loop.armed_deadline_ns);
    loop.closeSlot(wedge_slot, "deadline test wedge cleanup");
    state.config.client_silence_close_sec = 0;

    // Shutdown, accept backoff and stats remain independent absolute timers.
    loop.shutting_down = true;
    loop.shutdown_deadline_ns = 150_000 * ms;
    try loop.rearmTimer();
    try std.testing.expectEqual(150_000 * ms, loop.armed_deadline_ns);
    loop.accept_paused = true;
    loop.accept_resume_ns = 145_000 * ms;
    try loop.rearmTimer();
    try std.testing.expectEqual(145_000 * ms, loop.armed_deadline_ns);
    loop.stats_next_log_ns = 144_000 * ms;
    try loop.rearmTimer();
    try std.testing.expectEqual(144_000 * ms, loop.armed_deadline_ns);
}

test "active ordinary masking expires by default while opt-out, WEB and authenticated relays survive" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const listener = try relayDrainTestSocketPair();
    defer closeFd(listener[0]);
    defer closeFd(listener[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, listener[0], control, 0, 1, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }
    const ms: i128 = std.time.ns_per_ms;
    loop.stats_next_log_ns = 2_000_000 * ms;
    for ([_]struct {
        configured: ?u32 = null,
        phase: ConnectionPhase = .mask_relaying,
        web_carrier: bool = false,
        checkpoint_ms: i64 = 301_000,
        expires: bool,
    }{
        .{ .expires = true },
        .{ .configured = 0, .expires = false },
        .{ .configured = 60, .checkpoint_ms = 61_000, .expires = true },
        .{ .web_carrier = true, .expires = false },
        .{ .phase = .relaying, .expires = false },
    }) |fixture| {
        state.config.mask_relay_max_secs = fixture.configured orelse cfg.mask_relay_max_secs;
        const slot = loop.pool.acquire().?;
        slot.phase = fixture.phase;
        slot.web_carrier = fixture.web_carrier;
        slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 1234);
        slot.created_at_ms = 1000;
        slot.last_activity_ms = 1000;
        slot.idle_timeout_ms = 120_000;
        loop.refreshSlotDeadline(slot);

        // Simulate regular progress and real heap wakeups without sleeping.
        var heartbeat_ms: i64 = 31_000;
        while (heartbeat_ms < fixture.checkpoint_ms - 1) : (heartbeat_ms += 30_000) {
            slot.last_activity_ms = heartbeat_ms;
            loop.refreshSlotDeadline(slot);
            loop.runTimers(@as(i128, heartbeat_ms) * ms);
            try std.testing.expectEqual(fixture.phase, slot.phase);
        }
        slot.last_activity_ms = fixture.checkpoint_ms - 1;
        loop.refreshSlotDeadline(slot);
        loop.runTimers(@as(i128, fixture.checkpoint_ms - 1) * ms);
        try std.testing.expectEqual(fixture.phase, slot.phase);
        const selected = loop.nextSlotDeadline(slot).?;
        try std.testing.expectEqual(fixture.expires, selected.kind == .absolute);
        const expected_ms = if (fixture.expires) fixture.checkpoint_ms else slot.last_activity_ms + slot.idle_timeout_ms;
        try std.testing.expectEqual(@as(i128, expected_ms) * ms, selected.deadline_ns);

        loop.runTimers(@as(i128, fixture.checkpoint_ms) * ms);
        if (fixture.expires) {
            try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
            try std.testing.expectEqual(connection.no_timer_heap_index, slot.timer_heap_index);
        } else {
            try std.testing.expectEqual(fixture.phase, slot.phase);
            // Exempt/opted-out relays still expire if they become idle.
            loop.runTimers(@as(i128, expected_ms) * ms);
            try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
        }
        try std.testing.expect(loop.deadline_heap.peek() == null);
    }
}

test "absolute slot timers remain immediate across handshake, connect, MP, mask and desync" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .client_silence_close_sec = 0,
        .handshake_timeout_sec = 15,
        .mask_relay_max_secs = 12,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const listener = try relayDrainTestSocketPair();
    defer closeFd(listener[0]);
    defer closeFd(listener[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, listener[0], control, 0, 1, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }
    const ms: i128 = std.time.ns_per_ms;
    loop.stats_next_log_ns = 1_000_000 * ms;
    for ([_]struct { phase: ConnectionPhase, first_byte_ms: i64 = 2000, deadline_ms: i64 }{
        .{ .phase = .reading_tls_header, .deadline_ms = 17_000 },
        .{ .phase = .reading_tls_header, .first_byte_ms = 0, .deadline_ms = 11_000 },
        .{ .phase = .connecting_upstream, .deadline_ms = 6000 },
        .{ .phase = .middle_proxy_handshake, .deadline_ms = 6000 },
        .{ .phase = .mask_relaying, .deadline_ms = 13_000 },
    }) |fixture| {
        const slot = loop.pool.acquire().?;
        slot.phase = fixture.phase;
        slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 1234);
        slot.created_at_ms = 1000;
        slot.first_byte_at_ms = fixture.first_byte_ms;
        slot.last_activity_ms = 2000;
        slot.idle_timeout_ms = 120_000;
        slot.upstream_connect_deadline_ms = 6000;
        slot.mp_step_deadline_ms = 6000;
        loop.refreshSlotDeadline(slot);
        try std.testing.expectEqual(@as(i128, fixture.deadline_ms) * ms, loop.armed_deadline_ns);
        slot.last_activity_ms = 4000;
        loop.refreshSlotDeadline(slot);
        try std.testing.expectEqual(@as(i128, fixture.deadline_ms) * ms, loop.armed_deadline_ns);
        var expires_ms = fixture.deadline_ms;
        if (fixture.phase == .connecting_upstream or fixture.phase == .middle_proxy_handshake) {
            if (fixture.phase == .connecting_upstream) slot.upstream_connect_deadline_ms = 7000 else slot.mp_step_deadline_ms = 7000;
            loop.refreshSlotDeadline(slot);
            try std.testing.expectEqual(7000 * ms, loop.armed_deadline_ns); // Later absolute stage.
            if (fixture.phase == .connecting_upstream) slot.upstream_connect_deadline_ms = 6500 else slot.mp_step_deadline_ms = 6500;
            loop.refreshSlotDeadline(slot);
            try std.testing.expectEqual(6500 * ms, loop.armed_deadline_ns);
            expires_ms = 6500;
        }
        loop.runTimers(@as(i128, expires_ms) * ms);
        try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
        try std.testing.expectEqual(connection.no_timer_heap_index, slot.timer_heap_index);
        try std.testing.expect(loop.deadline_heap.peek() == null);
        try std.testing.expectEqual(loop.stats_next_log_ns, loop.armed_deadline_ns);
    }

    const slot = loop.pool.acquire().?;
    slot.phase = .desync_wait;
    slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 1234);
    slot.created_at_ms = 1000;
    slot.first_byte_at_ms = 2000;
    slot.desync_deadline_ns = 5000 * ms;
    slot.server_hello = try std.testing.allocator.dupe(u8, "hello");
    slot.server_hello_off = 1;
    var blocked = EventIoBudget{ .operations_remaining = 0 };
    slot.event_io_budget = &blocked;
    loop.refreshSlotDeadline(slot);
    try std.testing.expectEqual(5000 * ms, loop.armed_deadline_ns);
    loop.runTimers(5000 * ms);
    try std.testing.expectEqual(ConnectionPhase.writing_server_hello_rest, slot.phase);
    try expectRelayTestQueue(&slot.client_queue, "ello");
    try std.testing.expect(slot.server_hello != null);
    try std.testing.expectEqual(17_000 * ms, loop.armed_deadline_ns);
    loop.runTimers(17_000 * ms);
    try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
    try std.testing.expect(slot.server_hello == null);
    try std.testing.expect(loop.deadline_heap.peek() == null);
}

test "readable activity changes only with actual relay or handshake progress" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
        .client_silence_close_sec = 0,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    loop.state = &state;
    loop.shutting_down = false;
    for ([_]struct { phase: ConnectionPhase, role: SlotFdRole, direct: bool = false }{
        .{ .phase = .relaying, .role = .client },
        .{ .phase = .relaying, .role = .upstream },
        .{ .phase = .relaying, .role = .client, .direct = true },
        .{ .phase = .relaying, .role = .upstream, .direct = true },
        .{ .phase = .mask_relaying, .role = .client },
        .{ .phase = .mask_relaying, .role = .upstream },
        .{ .phase = .reading_web_prefix, .role = .client },
        .{ .phase = .reading_tls_header, .role = .client },
        .{ .phase = .reading_direct_obfuscated_handshake, .role = .client },
        .{ .phase = .reading_mtproto_tls_header, .role = .client },
        .{ .phase = .middle_proxy_handshake, .role = .upstream },
    }) |fixture| {
        const client = try relayDrainTestSocketPair();
        defer closeFd(client[0]);
        defer closeFd(client[1]);
        const upstream = try relayDrainTestSocketPair();
        defer closeFd(upstream[0]);
        defer closeFd(upstream[1]);
        var budget: EventIoBudget = .{};
        var slot = ConnectionSlot{
            .phase = fixture.phase,
            .client_fd = client[0],
            .upstream_fd = upstream[0],
            .client_transport = if (fixture.direct) .direct_obfuscated else .fake_tls,
            .use_fast_mode = true,
            .tg_encryptor = crypto.AesCtr.init(&(@as([32]u8, @splat(0x42))), 0),
            .last_activity_ms = 123,
            .client_queue = .{ .allocator = std.testing.allocator },
            .upstream_queue = .{ .allocator = std.testing.allocator },
            .event_io_budget = &budget,
        };
        if (fixture.phase == .middle_proxy_handshake) slot.mp_transport.step = .waiting_rpc_nonce_response;
        defer {
            loop.releaseHandshakeBudget(&slot);
            slot.resetOwnedBuffers(std.testing.allocator);
        }
        if (fixture.role == .client) loop.onClientReadable(&slot) else loop.onUpstreamReadable(&slot);
        try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms); // Real EAGAIN.
        try std.testing.expectEqual(@as(i64, 0), slot.first_byte_at_ms);

        budget = .{ .operations_remaining = 0 };
        if (fixture.role == .client) loop.onClientReadable(&slot) else loop.onUpstreamReadable(&slot);
        try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms); // Budget exhaustion.
        budget = .{};
        const byte = [_]u8{0x17}; // Partial TLS/MP framing also counts as progress.
        const source = if (fixture.role == .client) client[1] else upstream[1];
        try std.testing.expectEqual(byte.len, try writeFd(source, &byte));
        if (fixture.role == .client) loop.onClientReadable(&slot) else loop.onUpstreamReadable(&slot);
        try std.testing.expect(slot.last_activity_ms > 123);
        if (fixture.phase == .reading_tls_header) {
            try std.testing.expectEqual(slot.last_activity_ms, slot.first_byte_at_ms);
        }
        const first_byte_ms = slot.first_byte_at_ms;
        slot.last_activity_ms = 123;
        budget = .{};
        if (fixture.role == .client) loop.onClientReadable(&slot) else loop.onUpstreamReadable(&slot);
        try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms);
        try std.testing.expectEqual(first_byte_ms, slot.first_byte_at_ms);
    }
}

test "writable activity records sent bytes and ignores a blocked flush" {
    const client = try relayDrainTestSocketPair();
    defer closeFd(client[0]);
    defer closeFd(client[1]);
    const upstream = try relayDrainTestSocketPair();
    defer closeFd(upstream[0]);
    defer closeFd(upstream[1]);
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    var state: ProxyState = undefined;
    state.config.client_silence_close_sec = 0;
    loop.state = &state;
    loop.shutting_down = false;
    var budget = EventIoBudget{ .operations_remaining = 0 };
    var slot = ConnectionSlot{
        .phase = .mask_relaying,
        .client_fd = client[0],
        .upstream_fd = upstream[0],
        .client_queue = .{ .allocator = std.testing.allocator },
        .upstream_queue = .{ .allocator = std.testing.allocator },
        .event_io_budget = &budget,
    };
    defer slot.resetOwnedBuffers(std.testing.allocator);
    for ([_]SlotFdRole{ .client, .upstream }) |role| {
        budget = .{ .operations_remaining = 0 };
        if (role == .client) _ = try queueClient(&slot, "abc") else _ = try queueUpstream(&slot, "abc");
        slot.last_activity_ms = 123;
        if (role == .client) loop.onClientWritable(&slot) else loop.onUpstreamWritable(&slot);
        try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms);
        budget = .{};
        if (role == .client) loop.onClientWritable(&slot) else loop.onUpstreamWritable(&slot);
        try std.testing.expect(slot.last_activity_ms > 123);
        slot.last_activity_ms = 123;
        if (role == .client) loop.onClientWritable(&slot) else loop.onUpstreamWritable(&slot);
        try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms);
    }
}

test "ClientHello allocation failure preserves cleanup ownership at the inline boundary" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const listener = try relayDrainTestSocketPair();
    defer closeFd(listener[0]);
    defer closeFd(listener[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, listener[0], control, 0, 1, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }
    try loop.pending_close_fds.ensureTotalCapacity(std.testing.allocator, 1);

    const inline_len = (ConnectionSlot{}).client_hello_inline.len;
    for ([_]usize{ inline_len, inline_len + 1, tls_header_len + constants.max_tls_plaintext_size }) |hello_len| {
        const client = try relayDrainTestSocketPair();
        defer closeFd(client[1]);
        const slot = loop.pool.acquire() orelse return error.TestUnexpectedResult;
        slot.phase = .reading_tls_header;
        slot.client_fd = client[0];
        slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 12345);
        defer if (slot.phase != .idle) loop.closeSlot(slot, "ClientHello test cleanup");
        slot.tls_hdr_buf = .{ 0x16, 0x03, 0x01, 0, 0 };
        std.mem.writeInt(u16, slot.tls_hdr_buf[3..5], @intCast(hello_len - tls_header_len), .big);
        slot.tls_hdr_pos = tls_header_len;
        @memset(&slot.client_hello_inline, 0xaa);

        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        state.allocator = failing.allocator();
        defer state.allocator = std.testing.allocator;
        loop.readTlsHeader(slot);
        if (hello_len <= inline_len) {
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(ConnectionPhase.reading_client_hello_body, slot.phase);
            try std.testing.expectEqual(hello_len, slot.client_hello_len);
            loop.closeSlot(slot, "inline ClientHello test cleanup");
            for (slot.client_hello_inline) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
        } else {
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(ConnectionPhase.idle, slot.phase);
            // No inline bytes were acquired, so failed heap ownership must not wipe them.
            for (slot.client_hello_inline) |byte| try std.testing.expectEqual(@as(u8, 0xaa), byte);
        }
        try std.testing.expectEqual(@as(usize, 0), slot.client_hello_len);
        try std.testing.expect(slot.client_hello_heap == null);
        try std.testing.expectEqual(@as(u32, 1), loop.pool.free_count);
        loop.drainPendingCloses();
    }
}

test "handshake read yields when the event I/O budget is exhausted" {
    var slot = ConnectionSlot{};
    var budget = EventIoBudget{ .bytes_remaining = 0 };
    slot.event_io_budget = &budget;
    var byte: [1]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, readSlotFd(&slot, invalid_fd, &byte));
    try std.testing.expectEqual(@as(usize, 0), budget.bytes_remaining);
}

test "direct nonce ignores promotion and preserves pipelined cipher continuity" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    var loop: EventLoop = undefined;
    loop.state = &state;
    loop.shutting_down = false;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // The opaque client bytes also exercise a partial AES block. Decode the
    // emitted stream as a DC would, without relying on the slot's cipher state.
    const client_payload = "client payload immediately after nonce";
    for ([_]bool{ false, true }) |with_tag| {
        state.config.tag = if (with_tag) @as([16]u8, @splat(0x42)) else null;
        for ([_]constants.ProtoTag{ .abridged, .intermediate, .secure }) |proto_tag| {
            for ([_]bool{ false, true }) |fast_mode| {
                for ([_]i16{ 4, -4 }) |dc_idx| {
                    for ([_]bool{ false, true }) |with_payload| {
                        var upstream_file = try tmp.dir.createFile(std.testing.io, "direct-startup", .{ .read = true });
                        defer upstream_file.close(std.testing.io);
                        var slot = ConnectionSlot{
                            .upstream_fd = upstream_file.handle,
                            .dc_abs = 4,
                            .proto_tag = proto_tag,
                            .use_fast_mode = fast_mode,
                            .is_media_path = dc_idx < 0,
                            .obf_params = .{
                                .decrypt_key = @as([constants.key_len]u8, @splat(0)),
                                .decrypt_iv = 0,
                                .encrypt_key = @as([constants.key_len]u8, @splat(0x37)),
                                .encrypt_iv = 0x1234,
                                .proto_tag = proto_tag,
                                .dc_idx = dc_idx,
                            },
                        };
                        defer slot.resetOwnedBuffers(std.testing.allocator);
                        if (with_payload) {
                            slot.pipelined_data = try std.testing.allocator.dupe(u8, client_payload);
                            slot.pipelined_len = client_payload.len;
                        }

                        loop.sendDcNonce(&slot);
                        try std.testing.expectEqual(ConnectionPhase.relaying, slot.phase);
                        try std.testing.expect(!slot.hasUpstreamPending());
                        try std.testing.expect(slot.pipelined_data == null);
                        try seekFdToStart(upstream_file.handle);
                        var bytes: [constants.handshake_len + client_payload.len + 32]u8 = undefined;
                        const expected_len = constants.handshake_len + (if (with_payload) client_payload.len else @as(usize, 0));
                        try std.testing.expectEqual(expected_len, try posix.read(upstream_file.handle, &bytes));
                        var dc_decryptor = crypto.AesCtr.init(
                            bytes[constants.skip_len..][0..constants.key_len],
                            std.mem.readInt(u128, bytes[constants.skip_len + constants.key_len ..][0..constants.iv_len], .big),
                        );
                        defer dc_decryptor.wipe();
                        dc_decryptor.apply(bytes[0..expected_len]);
                        const proto_bytes = proto_tag.toBytes();
                        try std.testing.expectEqualSlices(u8, &proto_bytes, bytes[constants.proto_tag_pos..][0..4]);
                        try std.testing.expectEqual(dc_idx, std.mem.readInt(i16, bytes[constants.dc_idx_pos..][0..2], .little));
                        try std.testing.expectEqualSlices(u8, if (with_payload) client_payload else "", bytes[constants.handshake_len..expected_len]);
                    }
                }
            }
        }
    }
}

test "multiple client TLS records consume one read operation before queue backpressure" {
    if (builtin.target.os.tag != .linux) return;
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return posix.unexpectedErrno(linux.errno(rc));
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const wire = [_]u8{ 0x17, 3, 3, 0, 3, 'a', 'b', 'c', 0x14, 3, 3, 0, 1, 1, 0x17, 3, 3, 0, 2, 'd', 'e' };
    try std.testing.expectEqual(wire.len, try socket_ops.writeFd(fds[1], &wire));
    // The direct step only uses read scratch. Allocate the large EventLoop on
    // the heap, without starting listeners, updater threads, or a full daemon.
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    const key: [32]u8 = @splat(0x37);
    var budget = EventIoBudget{ .operations_remaining = 1 };
    var slot = ConnectionSlot{
        .phase = .relaying,
        .client_fd = fds[0],
        .client_decryptor = crypto.AesCtr.init(&key, 7),
        .tg_encryptor = crypto.AesCtr.init(&key, 7),
        .upstream_queue = .{ .allocator = std.testing.allocator },
        .event_io_budget = &budget,
    };
    defer slot.upstream_queue.deinit();
    try std.testing.expectEqual(RelayProgress.forwarded, try relayClientToUpstreamStep(loop, &slot));
    try std.testing.expectEqual(@as(usize, 0), budget.operations_remaining);
    try std.testing.expectEqual(event_io_byte_budget - wire.len, budget.bytes_remaining);
    try std.testing.expectEqual(@as(u64, 5), slot.c2s_bytes);
    try std.testing.expect(clientRelayAtFrameBoundary(&slot));
    var iovecs: [1]posix.iovec_const = undefined;
    try std.testing.expectEqual(@as(usize, 1), slot.upstream_queue.prepareIovecs(&iovecs, 5));
    try std.testing.expectEqualStrings("abcde", iovecs[0].base[0..iovecs[0].len]);
}

fn relayDrainTestSocketPair() ![2]posix.fd_t {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]posix.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0, &fds);
    if (linux.errno(rc) != .SUCCESS) return posix.unexpectedErrno(linux.errno(rc));
    return fds;
}

fn expectRelayTestQueue(queue: *const message_queue.MessageQueue, expected: []const u8) !void {
    try std.testing.expectEqual(expected.len, queue.total_len);
    var iovecs: [relay_io.max_scatter_parts]posix.iovec_const = undefined;
    const count = queue.prepareIovecs(&iovecs, expected.len);
    var off: usize = 0;
    for (iovecs[0..count]) |iov| {
        try std.testing.expectEqualSlices(u8, expected[off..][0..iov.len], iov.base[0..iov.len]);
        off += iov.len;
    }
    try std.testing.expectEqual(expected.len, off);
}

test "direct C2S batches records with CCS and owns backpressured suffixes" {
    const client_key: [32]u8 = @splat(0x37);
    const upstream_key: [32]u8 = @splat(0x92);
    var plaintext: [47]u8 = undefined;
    for (&plaintext, 0..) |*byte, i| byte.* = @truncate(i * 29 + 9);
    var ciphertext = plaintext;
    var client_cipher = crypto.AesCtr.init(&client_key, 7);
    client_cipher.apply(&ciphertext);
    var expected = plaintext;
    var upstream_cipher = crypto.AesCtr.init(&upstream_key, 19);
    upstream_cipher.apply(&expected);

    var wire: [plaintext.len + 3 * 5 + 6]u8 = undefined;
    var wire_off: usize = 0;
    var payload_off: usize = 0;
    for ([_]usize{ 7, 19, 21 }, 0..) |len, i| {
        if (i == 1) {
            @memcpy(wire[wire_off..][0..6], &[_]u8{ 0x14, 3, 3, 0, 1, 1 });
            wire_off += 6;
        }
        @memcpy(wire[wire_off..][0..3], &[_]u8{ 0x17, 3, 3 });
        std.mem.writeInt(u16, wire[wire_off + 3 ..][0..2], @intCast(len), .big);
        @memcpy(wire[wire_off + 5 ..][0..len], ciphertext[payload_off..][0..len]);
        wire_off += 5 + len;
        payload_off += len;
    }

    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    const fixtures = [_]struct { budget: EventIoBudget, sent: usize, blocked: bool = false }{
        .{ .budget = .{ .operations_remaining = 2 }, .sent = expected.len },
        // The byte limit clips writev five bytes into the second payload.
        .{ .budget = .{ .bytes_remaining = wire.len + 12, .operations_remaining = 2 }, .sent = 12 },
        .{ .budget = .{ .operations_remaining = 1 }, .sent = 0 },
        .{ .budget = .{ .bytes_remaining = wire.len, .operations_remaining = 2 }, .sent = 0 },
        .{ .budget = .{ .operations_remaining = 2 }, .sent = 0, .blocked = true },
    };
    for (fixtures) |fixture| {
        const client = try relayDrainTestSocketPair();
        defer closeFd(client[0]);
        defer closeFd(client[1]);
        const upstream = try relayDrainTestSocketPair();
        defer closeFd(upstream[0]);
        defer closeFd(upstream[1]);
        var blocked_bytes: usize = 0;
        const fill: [4096]u8 = @splat(0);
        if (fixture.blocked) {
            var blocked = false;
            for (0..1024) |_| {
                blocked_bytes += socket_ops.writeFd(upstream[0], &fill) catch |err| {
                    if (err != error.WouldBlock) return err;
                    blocked = true;
                    break;
                };
            }
            try std.testing.expect(blocked);
        }
        try std.testing.expectEqual(wire.len, try socket_ops.writeFd(client[1], &wire));
        var budget = fixture.budget;
        var slot = ConnectionSlot{
            .phase = .relaying,
            .client_fd = client[0],
            .upstream_fd = upstream[0],
            .client_decryptor = crypto.AesCtr.init(&client_key, 7),
            .tg_encryptor = crypto.AesCtr.init(&upstream_key, 19),
            .upstream_queue = .{ .allocator = std.testing.allocator },
            .event_io_budget = &budget,
        };
        defer slot.upstream_queue.deinit();
        try std.testing.expectEqual(RelayProgress.forwarded, try relayClientToUpstreamStep(loop, &slot));
        const writes: usize = @intFromBool(fixture.sent > 0 or fixture.blocked);
        try std.testing.expectEqual(fixture.budget.operations_remaining - 1 - writes, budget.operations_remaining);
        try std.testing.expectEqual(fixture.budget.bytes_remaining - wire.len - fixture.sent, budget.bytes_remaining);
        try std.testing.expectEqual(@as(u64, expected.len), slot.c2s_bytes);
        try std.testing.expectEqual(@as(u64, 3), slot.wedge_forwarded_c2s_seq);
        try std.testing.expect(clientRelayAtFrameBoundary(&slot));

        // Drain only the artificial socket fill, before checking relay bytes.
        var fill_read: [4096]u8 = undefined;
        while (blocked_bytes > 0) {
            const count = try posix.read(upstream[1], fill_read[0..@min(blocked_bytes, fill_read.len)]);
            try std.testing.expect(count > 0);
            try std.testing.expectEqualSlices(u8, fill[0..count], fill_read[0..count]);
            blocked_bytes -= count;
        }
        var actual: [expected.len]u8 = undefined;
        if (fixture.sent > 0) {
            try std.testing.expectEqual(fixture.sent, try posix.read(upstream[1], actual[0..fixture.sent]));
            try std.testing.expectEqualSlices(u8, expected[0..fixture.sent], actual[0..fixture.sent]);
        } else {
            try std.testing.expectError(error.WouldBlock, posix.read(upstream[1], &actual));
        }
        @memset(loop.relay_read_scratch[0..], 0xa5);
        try expectRelayTestQueue(&slot.upstream_queue, expected[fixture.sent..]);
        // A later dispatch flushes owned storage after the read scratch changed.
        var flush_budget = EventIoBudget{ .operations_remaining = 1 };
        slot.event_io_budget = &flush_budget;
        const pending = expected.len - fixture.sent;
        try std.testing.expectEqual(pending, try flushUpstreamPending(&slot));
        if (pending > 0) try std.testing.expectEqual(pending, try posix.read(upstream[1], actual[fixture.sent..]));
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        try std.testing.expect(slot.upstream_queue.isEmpty());
    }
}

test "direct C2S flushes each read without waiting for a complete TLS record" {
    const client = try relayDrainTestSocketPair();
    defer closeFd(client[0]);
    defer closeFd(client[1]);
    const upstream = try relayDrainTestSocketPair();
    defer closeFd(upstream[0]);
    defer closeFd(upstream[1]);
    const client_key: [32]u8 = @splat(0x73);
    const upstream_key: [32]u8 = @splat(0x29);
    const plaintext = "one record forwarded across two body reads";
    var ciphertext = plaintext.*;
    var client_cipher = crypto.AesCtr.init(&client_key, 3);
    client_cipher.apply(&ciphertext);
    var expected = plaintext.*;
    var upstream_cipher = crypto.AesCtr.init(&upstream_key, 11);
    upstream_cipher.apply(&expected);
    var wire: [5 + plaintext.len]u8 = undefined;
    @memcpy(wire[0..3], &[_]u8{ 0x17, 3, 3 });
    std.mem.writeInt(u16, wire[3..5], plaintext.len, .big);
    @memcpy(wire[5..], &ciphertext);
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    var slot = ConnectionSlot{
        .phase = .relaying,
        .client_fd = client[0],
        .upstream_fd = upstream[0],
        .client_decryptor = crypto.AesCtr.init(&client_key, 3),
        .tg_encryptor = crypto.AesCtr.init(&upstream_key, 11),
        .upstream_queue = .{ .allocator = std.testing.allocator },
    };
    defer slot.upstream_queue.deinit();
    var wire_off: usize = 0;
    var payload_off: usize = 0;
    var pieces: u64 = 0;
    for ([_]usize{ 2, 5 + 7, wire.len }) |end| {
        const chunk = wire[wire_off..end];
        try std.testing.expectEqual(chunk.len, try socket_ops.writeFd(client[1], chunk));
        var budget = EventIoBudget{ .operations_remaining = 2 };
        slot.event_io_budget = &budget;
        const payload_end = end - @min(end, 5);
        const forwarded = payload_end - payload_off;
        try std.testing.expectEqual(if (forwarded > 0) RelayProgress.forwarded else .partial, try relayClientToUpstreamStep(loop, &slot));
        var actual: [expected.len]u8 = undefined;
        if (forwarded > 0) {
            pieces += 1;
            try std.testing.expectEqual(forwarded, try posix.read(upstream[1], actual[0..forwarded]));
            try std.testing.expectEqualSlices(u8, expected[payload_off..payload_end], actual[0..forwarded]);
        } else {
            try std.testing.expectError(error.WouldBlock, posix.read(upstream[1], &actual));
        }
        try std.testing.expectEqual(@as(usize, if (forwarded > 0) 0 else 1), budget.operations_remaining);
        try std.testing.expectEqual(event_io_byte_budget - chunk.len - forwarded, budget.bytes_remaining);
        try std.testing.expectEqual(@as(u64, @intCast(payload_end)), slot.c2s_bytes);
        try std.testing.expectEqual(pieces, slot.wedge_forwarded_c2s_seq);
        try std.testing.expectEqual(end == wire.len, clientRelayAtFrameBoundary(&slot));
        try std.testing.expect(slot.upstream_queue.isEmpty());
        wire_off = end;
        payload_off = payload_end;
    }
}

test "direct C2S bounds scatter batches and queues the rest of a consumed chunk" {
    const client_key: [32]u8 = @splat(0x18);
    const upstream_key: [32]u8 = @splat(0xc9);
    var plaintext: [2 * relay_io.max_scatter_parts + 3]u8 = undefined;
    for (&plaintext, 0..) |*byte, i| byte.* = @truncate(i * 31 + 5);
    var ciphertext = plaintext;
    var client_cipher = crypto.AesCtr.init(&client_key, 13);
    client_cipher.apply(&ciphertext);
    var expected = plaintext;
    var upstream_cipher = crypto.AesCtr.init(&upstream_key, 27);
    upstream_cipher.apply(&expected);
    var wire: [plaintext.len * 6]u8 = undefined;
    for (ciphertext, 0..) |byte, i| {
        @memcpy(wire[i * 6 ..][0..5], &[_]u8{ 0x17, 3, 3, 0, 1 });
        wire[i * 6 + 5] = byte;
    }
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    const fixtures = [_]struct { budget: EventIoBudget, sent: usize, writes: usize }{
        .{ .budget = .{ .operations_remaining = 4 }, .sent = expected.len, .writes = 3 },
        .{ .budget = .{ .operations_remaining = 2 }, .sent = relay_io.max_scatter_parts, .writes = 1 },
        .{ .budget = .{ .bytes_remaining = wire.len + 17, .operations_remaining = 4 }, .sent = 17, .writes = 1 },
    };
    for (fixtures) |fixture| {
        const client = try relayDrainTestSocketPair();
        defer closeFd(client[0]);
        defer closeFd(client[1]);
        const upstream = try relayDrainTestSocketPair();
        defer closeFd(upstream[0]);
        defer closeFd(upstream[1]);
        try std.testing.expectEqual(wire.len, try socket_ops.writeFd(client[1], &wire));
        var budget = fixture.budget;
        var slot = ConnectionSlot{
            .phase = .relaying,
            .client_fd = client[0],
            .upstream_fd = upstream[0],
            .client_decryptor = crypto.AesCtr.init(&client_key, 13),
            .tg_encryptor = crypto.AesCtr.init(&upstream_key, 27),
            .upstream_queue = .{ .allocator = std.testing.allocator },
            .event_io_budget = &budget,
        };
        defer slot.upstream_queue.deinit();
        try std.testing.expectEqual(RelayProgress.forwarded, try relayClientToUpstreamStep(loop, &slot));
        try std.testing.expectEqual(fixture.budget.operations_remaining - 1 - fixture.writes, budget.operations_remaining);
        try std.testing.expectEqual(fixture.budget.bytes_remaining - wire.len - fixture.sent, budget.bytes_remaining);
        try std.testing.expectEqual(@as(u64, expected.len), slot.c2s_bytes);
        try std.testing.expectEqual(@as(u64, expected.len), slot.wedge_forwarded_c2s_seq);
        try std.testing.expect(clientRelayAtFrameBoundary(&slot));
        var actual: [expected.len]u8 = undefined;
        try std.testing.expectEqual(fixture.sent, try posix.read(upstream[1], actual[0..fixture.sent]));
        @memset(loop.relay_read_scratch[0..], 0x5a);
        try expectRelayTestQueue(&slot.upstream_queue, expected[fixture.sent..]);
        var flush_budget = EventIoBudget{ .operations_remaining = 1 };
        slot.event_io_budget = &flush_budget;
        const pending = expected.len - fixture.sent;
        try std.testing.expectEqual(pending, try flushUpstreamPending(&slot));
        if (pending > 0) try std.testing.expectEqual(pending, try posix.read(upstream[1], actual[fixture.sent..]));
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        try std.testing.expect(slot.upstream_queue.isEmpty());
    }
}

test "direct C2S forwards a valid batch before rejecting a later malformed record" {
    const client = try relayDrainTestSocketPair();
    defer closeFd(client[0]);
    defer closeFd(client[1]);
    const upstream = try relayDrainTestSocketPair();
    defer closeFd(upstream[0]);
    defer closeFd(upstream[1]);
    const client_key: [32]u8 = @splat(0x24);
    const upstream_key: [32]u8 = @splat(0x81);
    var ciphertext = "abcdefg".*;
    var client_cipher = crypto.AesCtr.init(&client_key, 17);
    client_cipher.apply(&ciphertext);
    var expected = "abcdefg".*;
    var upstream_cipher = crypto.AesCtr.init(&upstream_key, 31);
    upstream_cipher.apply(&expected);
    var wire = [_]u8{ 0x17, 3, 3, 0, 3, 0, 0, 0, 0x17, 3, 3, 0, 4, 0, 0, 0, 0, 0x16, 3, 3, 0, 1 };
    @memcpy(wire[5..8], ciphertext[0..3]);
    @memcpy(wire[13..17], ciphertext[3..]);
    try std.testing.expectEqual(wire.len, try socket_ops.writeFd(client[1], &wire));
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    var budget = EventIoBudget{ .operations_remaining = 2 };
    var slot = ConnectionSlot{
        .phase = .relaying,
        .client_fd = client[0],
        .upstream_fd = upstream[0],
        .client_decryptor = crypto.AesCtr.init(&client_key, 17),
        .tg_encryptor = crypto.AesCtr.init(&upstream_key, 31),
        .upstream_queue = .{ .allocator = std.testing.allocator },
        .event_io_budget = &budget,
    };
    defer slot.upstream_queue.deinit();
    try std.testing.expectError(error.ConnectionReset, relayClientToUpstreamStep(loop, &slot));
    var actual: [expected.len]u8 = undefined;
    try std.testing.expectEqual(actual.len, try posix.read(upstream[1], &actual));
    try std.testing.expectEqualSlices(u8, &expected, &actual);
    try std.testing.expect(slot.upstream_queue.isEmpty());
    try std.testing.expectEqual(@as(u64, expected.len), slot.c2s_bytes);
    try std.testing.expectEqual(@as(u64, 2), slot.wedge_forwarded_c2s_seq);
    try std.testing.expectEqual(@as(usize, 0), budget.operations_remaining);
    try std.testing.expectEqual(event_io_byte_budget - wire.len - expected.len, budget.bytes_remaining);
}

test "relay drain forwards multiple chunks and respects the shared byte and operation budgets" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    const payload = try std.testing.allocator.alloc(u8, 3 * relay_read_scratch_size);
    defer std.testing.allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i * 29 + 7);
    const received = try std.testing.allocator.alloc(u8, payload.len);
    defer std.testing.allocator.free(received);
    // Successful mask handlers only use the worker scratch, without needing
    // listeners, epoll registrations, timers, discovery or a full ProxyState.
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    const fixtures = [_]struct { budget: EventIoBudget, forwarded: usize, operations_left: usize }{
        .{ .budget = .{}, .forwarded = payload.len, .operations_left = event_io_operation_budget - 7 },
        .{ .budget = .{ .bytes_remaining = 4 * relay_read_scratch_size }, .forwarded = 2 * relay_read_scratch_size, .operations_left = event_io_operation_budget - 4 },
        .{ .budget = .{ .operations_remaining = 4 }, .forwarded = 2 * relay_read_scratch_size, .operations_left = 0 },
    };
    for ([_]SlotFdRole{ .client, .upstream }) |role| {
        for (fixtures) |fixture| {
            const source = try relayDrainTestSocketPair();
            defer closeFd(source[0]);
            defer closeFd(source[1]);
            const destination = try relayDrainTestSocketPair();
            defer closeFd(destination[0]);
            defer closeFd(destination[1]);
            try std.testing.expectEqual(payload.len, try socket_ops.writeFd(source[1], payload));
            var budget = fixture.budget;
            var slot = ConnectionSlot{
                .phase = .mask_relaying,
                .client_fd = if (role == .client) source[0] else destination[0],
                .upstream_fd = if (role == .upstream) source[0] else destination[0],
                .event_io_budget = &budget,
            };
            defer slot.client_queue.deinit();
            defer slot.upstream_queue.deinit();

            loop.drainRelayReads(&slot, source[0]);
            try std.testing.expectEqual(@as(u64, @intCast(fixture.forwarded)), if (role == .client) slot.mask_c2s_bytes else slot.mask_s2c_bytes);
            try std.testing.expectEqual(fixture.operations_left, budget.operations_remaining);
            // Both the source read and destination write consume the same byte budget.
            try std.testing.expectEqual(fixture.budget.bytes_remaining - 2 * fixture.forwarded, budget.bytes_remaining);
            try std.testing.expect(slot.client_queue.isEmpty() and slot.upstream_queue.isEmpty());
            try std.testing.expectEqual(fixture.forwarded, try posix.read(destination[1], received[0..fixture.forwarded]));
            try std.testing.expectEqualSlices(u8, payload[0..fixture.forwarded], received[0..fixture.forwarded]);
            if (fixture.forwarded < payload.len) {
                const left = payload.len - fixture.forwarded;
                try std.testing.expectEqual(left, try posix.read(source[0], received[0..left]));
                try std.testing.expectEqualSlices(u8, payload[fixture.forwarded..], received[0..left]);
            }
        }
    }
}

test "relay drain leaves unread bytes under queue backpressure even with a fresh budget" {
    const source = try relayDrainTestSocketPair();
    defer closeFd(source[0]);
    defer closeFd(source[1]);
    const payload = try std.testing.allocator.alloc(u8, relay_read_scratch_size + 17);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0x5a);
    try std.testing.expectEqual(payload.len, try socket_ops.writeFd(source[1], payload));
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    var budget = EventIoBudget{ .operations_remaining = 1 };
    var slot = ConnectionSlot{
        .phase = .mask_relaying,
        .client_fd = source[0],
        .event_io_budget = &budget,
        .upstream_queue = .{ .allocator = std.testing.allocator },
    };
    defer slot.upstream_queue.deinit();
    loop.drainRelayReads(&slot, source[0]);
    try std.testing.expectEqual(@as(usize, relay_read_scratch_size), slot.upstream_queue.total_len);
    try std.testing.expectEqual(@as(u64, relay_read_scratch_size), slot.mask_c2s_bytes);

    budget = .{};
    slot.last_activity_ms = 123;
    loop.drainRelayReads(&slot, source[0]);
    try std.testing.expectEqual(@as(i64, 123), slot.last_activity_ms);
    try std.testing.expectEqual(event_io_operation_budget, budget.operations_remaining);
    try std.testing.expectEqual(event_io_byte_budget, budget.bytes_remaining);
    var tail: [17]u8 = undefined;
    try std.testing.expectEqual(tail.len, try posix.read(source[0], &tail));
    try std.testing.expectEqualSlices(u8, payload[relay_read_scratch_size..], &tail);
}

test "relay drain records EOF once and keeps the reverse half open" {
    const client = try relayDrainTestSocketPair();
    defer closeFd(client[0]);
    defer closeFd(client[1]);
    const upstream = try relayDrainTestSocketPair();
    defer closeFd(upstream[0]);
    defer closeFd(upstream[1]);
    const loop = try std.testing.allocator.create(EventLoop);
    defer std.testing.allocator.destroy(loop);
    // Only the EOF counters are needed by this mask-relay path; no background
    // workers or production network discovery are started by the fixture.
    const state = try std.testing.allocator.create(ProxyState);
    defer std.testing.allocator.destroy(state);
    state.stats_relay_client_eof_first = .init(0);
    state.stats_relay_upstream_eof_first = .init(0);
    loop.state = state;
    var budget = EventIoBudget{};
    var slot = ConnectionSlot{
        .phase = .mask_relaying,
        .client_fd = client[0],
        .upstream_fd = upstream[0],
        .event_io_budget = &budget,
    };
    defer slot.client_queue.deinit();
    defer slot.upstream_queue.deinit();
    const request = "request";
    try std.testing.expectEqual(request.len, try socket_ops.writeFd(client[1], request));
    try shutdownWriteFd(client[1]);
    loop.drainRelayReads(&slot, client[0]);
    try std.testing.expect(slot.client_read_closed and slot.upstream_write_shutdown);
    try std.testing.expect(!slot.upstream_read_closed and !slot.client_write_shutdown);
    try std.testing.expectEqual(@as(?RelayEofSide, .client), slot.first_relay_eof);
    try std.testing.expectEqual(@as(u64, 1), state.stats_relay_client_eof_first.load(.monotonic));
    const remaining_operations = budget.operations_remaining;
    const eof_activity_ms = slot.last_activity_ms;
    loop.drainRelayReads(&slot, client[0]);
    try std.testing.expectEqual(eof_activity_ms, slot.last_activity_ms);
    try std.testing.expectEqual(remaining_operations, budget.operations_remaining);
    try std.testing.expectEqual(@as(u64, 1), state.stats_relay_client_eof_first.load(.monotonic));
    var got_request: [request.len]u8 = undefined;
    try std.testing.expectEqual(request.len, try posix.read(upstream[1], &got_request));
    try std.testing.expectEqualStrings(request, &got_request);
    var eof_byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try posix.read(upstream[1], &eof_byte));

    const response = "reverse half is still open";
    try std.testing.expectEqual(response.len, try socket_ops.writeFd(upstream[1], response));
    loop.drainRelayReads(&slot, upstream[0]);
    var got_response: [response.len]u8 = undefined;
    try std.testing.expectEqual(response.len, try posix.read(client[1], &got_response));
    try std.testing.expectEqualStrings(response, &got_response);
    try std.testing.expectEqual(ConnectionPhase.mask_relaying, slot.phase);
    try std.testing.expectEqual(@as(u64, 0), state.stats_relay_upstream_eof_first.load(.monotonic));
}

fn relayHangupTestTcpPair() ![2]posix.fd_t {
    var listener = try net.listen(net.ip4(.{ 127, 0, 0, 1 }, 0), .{});
    defer listener.deinit();
    const addr = try net.localAddress(listener.handle);
    const peer = try net.socketTcpNonblocking(addr);
    errdefer closeFd(peer);
    net.connectFd(peer, addr) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => return err,
    };
    var ready = [_]posix.pollfd{.{ .fd = listener.handle, .events = linux.POLL.IN, .revents = 0 }};
    if (try posix.poll(&ready, 5000) == 0) return error.TestUnexpectedResult;
    const accepted = try net.acceptFd(listener.handle);
    return .{ accepted.fd, peer };
}

test "TCP HUP drains oversized responses across budgets and client backpressure" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask_relay_max_secs = 0,
        .client_silence_close_sec = 0,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();
    const listener = try relayDrainTestSocketPair();
    defer closeFd(listener[0]);
    defer closeFd(listener[1]);
    const control = try createWorkerEventFd();
    defer closeFd(control);
    const loop = try EventLoop.init(&state, listener[0], control, 0, 1, default_managed_buffer_limit_bytes, null);
    defer {
        loop.deinit();
        std.testing.allocator.destroy(loop);
    }
    const response = try std.testing.allocator.alloc(u8, 6 * relay_read_scratch_size + 37);
    defer std.testing.allocator.free(response);
    for (response, 0..) |*byte, i| byte.* = @truncate(i * 29 + 7);
    const received = try std.testing.allocator.alloc(u8, response.len);
    defer std.testing.allocator.free(received);

    for ([_]ConnectionPhase{ .mask_relaying, .relaying }) |phase| {
        for ([_]bool{ false, true }) |backpressure| {
            const client = try relayDrainTestSocketPair();
            defer closeFd(client[1]);
            const upstream = try relayHangupTestTcpPair();
            defer closeFd(upstream[1]);
            const slot = loop.pool.acquire() orelse return error.TestUnexpectedResult;
            slot.phase = phase;
            slot.client_transport = .direct_obfuscated;
            slot.use_fast_mode = true;
            slot.client_fd = client[0];
            slot.upstream_fd = upstream[0];
            slot.peer_addr = net.ip4(.{ 127, 0, 0, 1 }, 12345);
            slot.created_at_ms = runtime_time.monotonicMilli();
            slot.last_activity_ms = slot.created_at_ms;
            slot.idle_timeout_ms = 60_000;
            defer if (slot.phase != .idle) loop.closeSlot(slot, "TCP HUP test cleanup");
            const receive_capacity: c_int = 1024 * 1024;
            try posix.setsockopt(upstream[0], posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&receive_capacity));
            if (backpressure) {
                const send_capacity: c_int = 4096;
                try posix.setsockopt(client[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&send_capacity));
            }
            try loop.addSlotFd(slot, client[0], .client, true, false, true);
            try loop.addSlotFd(slot, upstream[0], .upstream, true, false, true);
            try loop.syncInterests(slot);
            try shutdownWriteFd(client[1]);
            loop.processSlotEvent(slot, client[0], linux.EPOLL.IN | linux.EPOLL.RDHUP);
            try std.testing.expect(slot.client_read_closed and slot.upstream_write_shutdown);
            try std.testing.expectEqual(response.len, try socket_ops.writeFd(upstream[1], response));
            try shutdownWriteFd(upstream[1]);
            // Poll only unmaskable events: wait for FIN without consuming data.
            var hungup = [_]posix.pollfd{.{ .fd = upstream[0], .events = 0, .revents = 0 }};
            try std.testing.expect(try posix.poll(&hungup, 5000) > 0);
            try std.testing.expect((hungup[0].revents & linux.POLL.HUP) != 0);
            try std.testing.expect((hungup[0].revents & linux.POLL.ERR) == 0);

            var events: [8]linux.epoll_event = undefined;
            const initial = linux.epoll_wait(loop.epoll_fd, &events, events.len, 0);
            try std.testing.expect(linux.errno(initial) == .SUCCESS and initial > 0);
            var saw_hup = false;
            for (events[0..initial]) |ev| {
                const token = decodeSlotEventToken(ev.data.u64) orelse continue;
                if (token.role != .upstream) continue;
                saw_hup = (ev.events & linux.EPOLL.HUP) != 0;
                loop.processSlotEvent(slot, upstream[0], ev.events);
            }
            try std.testing.expect(saw_hup);
            try std.testing.expectEqual(phase, slot.phase);
            try std.testing.expect(!slot.upstream_read_closed);
            if (backpressure) {
                try std.testing.expect(slot.hasClientPending());
                try std.testing.expect(!slot.upstream_registered);
                const parked = linux.epoll_wait(loop.epoll_fd, &events, events.len, 0);
                try std.testing.expect(linux.errno(parked) == .SUCCESS);
                for (events[0..parked]) |ev| {
                    const token = decodeSlotEventToken(ev.data.u64) orelse continue;
                    try std.testing.expect(token.role != .upstream);
                }
            }

            var received_len: usize = 0;
            const deadline = runtime_time.monotonicMilli() + 5000;
            while (slot.phase != .idle or received_len < received.len) {
                try std.testing.expect(runtime_time.monotonicMilli() < deadline);
                if (received_len < received.len) {
                    const n = posix.read(client[1], received[received_len..]) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => return err,
                    };
                    received_len += n;
                }
                if (slot.phase == .idle) continue;
                const ready = linux.epoll_wait(loop.epoll_fd, &events, events.len, 10);
                try std.testing.expect(linux.errno(ready) == .SUCCESS);
                for (events[0..ready]) |ev| {
                    const token = decodeSlotEventToken(ev.data.u64) orelse continue;
                    const current = loop.pool.getByToken(token) orelse continue;
                    const fd = if (token.role == .client) current.client_fd else current.upstream_fd;
                    loop.processSlotEvent(current, fd, ev.events);
                }
            }
            try std.testing.expectEqualSlices(u8, response, received);
            try std.testing.expectEqual(@as(u32, 1), loop.pool.free_count);
            loop.drainPendingCloses();
        }
    }
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
    var state = try ProxyState.init(allocator, std.testing.io, cfg);
    defer state.deinit();
}

test "prepared user HMACs preserve key order, wipe storage and propagate allocation failure" {
    const secrets = [_]obfuscation.UserSecret{
        .{ .name = "alice", .secret = @as([16]u8, @splat(0x11)) },
        .{ .name = "bob", .secret = @as([16]u8, @splat(0x22)) },
    };
    const cache_bytes = secrets.len * @sizeOf(tls.PreparedHmacState);
    var backing: [cache_bytes + @alignOf(tls.PreparedHmacState)]u8 = @splat(0xa5);
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    const contexts = try prepareUserHmacs(fixed.allocator(), &secrets);
    defer freeUserHmacs(fixed.allocator(), contexts);
    for (&secrets, contexts) |*secret, context| {
        var clone = context;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&clone));
        clone.update("snapshot reuse");
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        clone.final(&digest);
        var expected = crypto.sha256Hmac(&secret.secret, "snapshot reuse");
        defer std.crypto.secureZero(u8, &expected);
        try std.testing.expectEqualSlices(u8, &expected, &digest);
    }
    wipeUserHmacs(contexts);
    // Check while owned: Allocator.free may replace wiped bytes with undefined.
    for (std.mem.sliceAsBytes(contexts)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, prepareUserHmacs(failing.allocator(), &secrets));
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
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

    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
    defer state.deinit();

    state.startMiddleProxyUpdater();
    try std.testing.expect(state.middle_proxy_updater_thread != null);
    state.stopMiddleProxyUpdater();
    try std.testing.expect(state.middle_proxy_updater_thread == null);
}

test "epoll hangup helper" {
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.HUP));
    try std.testing.expect(hasFatalEpollHangup(linux.EPOLL.ERR));
    try std.testing.expect(!hasFatalEpollHangup(linux.EPOLL.IN));
    try std.testing.expect(hasGracefulEpollReadHangup(linux.EPOLL.RDHUP));
    try std.testing.expect(hasGracefulEpollReadHangup(linux.EPOLL.RDHUP | linux.EPOLL.IN));
    try std.testing.expect(hasGracefulEpollReadHangup(linux.EPOLL.RDHUP | linux.EPOLL.HUP));
    try std.testing.expect(hasGracefulEpollReadHangup(linux.EPOLL.HUP | linux.EPOLL.IN));
    try std.testing.expect(!hasGracefulEpollReadHangup(linux.EPOLL.RDHUP | linux.EPOLL.ERR));
    try std.testing.expect(!hasGracefulEpollReadHangup(linux.EPOLL.HUP | linux.EPOLL.ERR));
}

test "fatal hangup close policy distinguishes client/upstream while connecting" {
    const client_fd = fakeFd(41);
    const upstream_fd = fakeFd(42);

    try std.testing.expect(shouldCloseOnFatalHangup(.connecting_upstream, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.reading_tls_header, client_fd, upstream_fd));
    try std.testing.expect(!shouldCloseOnFatalHangup(.idle, client_fd, upstream_fd));
}

test "fatal middle-proxy upstream hangup is recovery eligible" {
    const client_fd = fakeFd(41);
    const upstream_fd = fakeFd(42);

    try std.testing.expect(shouldRecoverMiddleProxyOnFatalHangup(.middle_proxy_handshake, upstream_fd, upstream_fd));
    try std.testing.expect(!shouldRecoverMiddleProxyOnFatalHangup(.middle_proxy_handshake, client_fd, upstream_fd));
    try std.testing.expect(!shouldRecoverMiddleProxyOnFatalHangup(.connecting_upstream, upstream_fd, upstream_fd));
    try std.testing.expect(shouldCloseOnFatalHangup(.middle_proxy_handshake, upstream_fd, upstream_fd));
}

test "fd requirement helpers" {
    try std.testing.expectEqual(@as(usize, 131582), requiredFdsForConnections(65535));
    try std.testing.expectEqual(@as(u32, 65535), maxConnectionsForNofile(131582));
    try std.testing.expectEqual(@as(u32, 32511), maxConnectionsForNofile(65535));
    try std.testing.expectEqual(@as(u32, 32), maxConnectionsForNofile(requiredFdsForConnections(32)));
    try std.testing.expectEqual(@as(u32, 0), maxConnectionsForNofile(requiredFdsForConnections(32) - 1));
}

test "FD capacity clamp is idempotent and independent of the RAM override" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 512,
        .unsafe_override_limits = true,
    };
    defer cfg.deinit(std.testing.allocator);

    try enforceNofileCapacityWithLimit(&cfg, 65535);
    try std.testing.expectEqual(@as(u32, 512), cfg.max_connections);
    try enforceNofileCapacityWithLimit(&cfg, 1024);
    try std.testing.expectEqual(@as(u32, 256), cfg.max_connections);
    try enforceNofileCapacityWithLimit(&cfg, 1024);
    try std.testing.expectEqual(@as(u32, 256), cfg.max_connections);
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

test "handshake budget is charged once after the first client byte" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 10,
        .mask = false,
        .datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, 443),
    };
    defer cfg.deinit(std.testing.allocator);

    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
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
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
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
        .digest = @as([32]u8, @splat(0x42)),
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
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
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
            _ = self.state.cooldownMiddleProxyCandidate(candidate, snapshot.secret_version);
            _ = self.state.promoteMiddleProxyCandidate(1, false, candidate, snapshot.secret_version);
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
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
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
    if (builtin.target.os.tag != .linux) return;

    const address = net.ip4(.{ 127, 0, 0, 1 }, 0);
    var listener = try net.listen(address, .{});
    defer listener.deinit();

    try std.testing.expectError(error.WouldBlock, net.acceptFd(listener.handle));
}

test "control broadcast wakes every worker eventfd" {
    if (builtin.target.os.tag != .linux) return;
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
    if (builtin.target.os.tag != .linux) return;
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .mask = false,
    };
    defer cfg.deinit(std.testing.allocator);
    var state = try ProxyState.init(std.testing.allocator, std.testing.io, cfg);
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
