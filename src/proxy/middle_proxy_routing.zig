const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const net = @import("../net_helpers.zig");
const constants = @import("../protocol/constants.zig");
const Config = @import("../config.zig").Config;
const runtime_sync = @import("../runtime/sync.zig");
const socketConnectSucceeded = @import("socket_ops.zig").socketConnectSucceeded;

pub const DcConnectPlan = struct {
    candidates: [16]net.Address = undefined,
    count: usize = 0,
    use_middle_proxy: bool = false,
    is_media_path: bool = false,
    direct_fallback: ?net.Address = null,
};

pub const MiddleProxyLock = struct {
    mutex: runtime_sync.BlockingMutex = .{},

    pub fn lock(self: *MiddleProxyLock) void {
        self.mutex.lock();
    }

    pub fn unlock(self: *MiddleProxyLock) void {
        self.mutex.unlock();
    }

    pub fn lockShared(self: *MiddleProxyLock) void {
        self.lock();
    }

    pub fn unlockShared(self: *MiddleProxyLock) void {
        self.unlock();
    }
};

pub const middle_proxy_connect_cooldown_ms: i64 = 60 * std.time.ms_per_s;
pub const middle_proxy_cooldown_slots = 32;

pub const MiddleProxyCooldown = struct {
    active: bool = false,
    addr: net.Address = undefined,
    until_ms: i64 = 0,
};

pub const MiddleProxySnapshot = struct {
    candidates: [16]net.Address,
    candidate_len: usize,
    secret_version: u64,
    nat_ip4: ?[4]u8 = null,

    pub fn selectedCandidates(self: *const MiddleProxySnapshot) []const net.Address {
        return self.candidates[0..self.candidate_len];
    }
};

pub fn isSameIpEndpoint(a: net.Address, b: net.Address) bool {
    // Native IpAddress.eql intentionally ignores IPv6 flow/scope, matching
    // the identity used for MiddleProxy endpoint promotion and cooldown.
    return net.Address.eql(&a, &b);
}

pub fn defaultMiddleProxyCandidateLists(primary: [5]net.Address) [5][16]net.Address {
    var lists: [5][16]net.Address = undefined;
    for (primary, 0..) |addr, i| {
        lists[i] = [_]net.Address{addr} ** 16;
    }
    return lists;
}

pub fn copyMiddleProxyCandidates(out: *[16]net.Address, candidates: []const net.Address, preferred: net.Address) usize {
    var count: usize = 0;
    appendUniqueAddress(out, &count, preferred);
    for (candidates) |addr| appendUniqueAddress(out, &count, addr);
    return count;
}

pub fn promoteMiddleProxyCandidateInList(candidates: *[16]net.Address, candidate_len: usize, addr: net.Address) bool {
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

pub fn prioritizeMiddleProxyCandidates(
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

pub fn prioritizeIpv4Addresses(addrs: []net.Address) void {
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

pub fn shouldUseMiddleProxySnapshot(cfg: *const Config, dc_abs: usize, dc_idx: i16) bool {
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

pub fn buildDcConnectPlan(
    cfg: *const Config,
    dc_abs: usize,
    dc_idx: i16,
    snapshot: ?*const MiddleProxySnapshot,
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

pub const DcSignFilter = enum {
    any,
    positive_only,
    negative_only,
};

pub fn parseMiddleProxyAddressesForDc(config_text: []const u8, target_dc: i16, sign: DcSignFilter, out: []net.Address) usize {
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

pub fn trySelectReachableMiddleProxy(
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

pub fn addressesEqual(a: []const net.Address, b: []const net.Address) bool {
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
    const regular_snapshot = MiddleProxySnapshot{
        .candidates = [_]net.Address{mp_dc4} ** 16,
        .candidate_len = 1,
        .secret_version = 1,
    };
    const media_203_snapshot = MiddleProxySnapshot{
        .candidates = [_]net.Address{mp_dc203} ** 16,
        .candidate_len = 1,
        .secret_version = 1,
    };
    const media_dc5_snapshot = MiddleProxySnapshot{
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
