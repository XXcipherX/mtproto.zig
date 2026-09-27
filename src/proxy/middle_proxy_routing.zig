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
pub const middle_proxy_health_slots = 192;
const health_sample_max_ms: i64 = 60 * std.time.ms_per_s;
const health_sample_ttl_ms: i64 = 10 * 60 * std.time.ms_per_s;
const health_failure_penalty_ms: i64 = 5 * 60 * std.time.ms_per_s;
const health_explore_every: u64 = 16;

pub const MiddleProxyCooldown = struct {
    active: bool = false,
    addr: net.Address = undefined,
    until_ms: i64 = 0,
};

pub const MiddleProxyHealth = struct {
    active: bool = false,
    addr: net.Address = undefined,
    connect_ewma_ms: u32 = 0,
    auth_ewma_ms: u32 = 0,
    connect_samples: u8 = 0,
    auth_samples: u8 = 0,
    failure_streak: u8 = 0,
    last_success_ms: i64 = 0,
    last_failure_ms: i64 = 0,
    last_observed_ms: i64 = 0,
};

/// Bounded, by-value endpoint history. The caller holds the existing MP lock;
/// neither routing nor health updates touch the relay data plane.
pub const MiddleProxyHealthStore = struct {
    entries: [middle_proxy_health_slots]MiddleProxyHealth = [_]MiddleProxyHealth{.{}} ** middle_proxy_health_slots,
    selections: u64 = 0,

    fn find(self: *MiddleProxyHealthStore, addr: net.Address) ?*MiddleProxyHealth {
        for (&self.entries) |*entry| {
            if (entry.active and isSameIpEndpoint(entry.addr, addr)) return entry;
        }
        return null;
    }

    fn findConst(self: *const MiddleProxyHealthStore, addr: net.Address) ?*const MiddleProxyHealth {
        for (&self.entries) |*entry| {
            if (entry.active and isSameIpEndpoint(entry.addr, addr)) return entry;
        }
        return null;
    }

    fn getOrCreate(self: *MiddleProxyHealthStore, addr: net.Address, now_ms: i64) *MiddleProxyHealth {
        if (self.find(addr)) |entry| return entry;
        var replacement = &self.entries[0];
        for (&self.entries) |*entry| {
            if (!entry.active) {
                replacement = entry;
                break;
            }
            if (entry.last_observed_ms < replacement.last_observed_ms) replacement = entry;
        }
        replacement.* = .{ .active = true, .addr = addr, .last_observed_ms = now_ms };
        return replacement;
    }

    fn sampleMs(duration_ms: i64) u32 {
        return @intCast(@min(@max(duration_ms, 1), health_sample_max_ms));
    }

    fn updateEwma(previous: u32, sample: u32, count: *u8) u32 {
        // One overloaded connect/auth must not erase an otherwise stable
        // route preference; sustained regressions still move the estimate.
        const bounded_sample = if (count.* == 0) sample else @min(sample, previous * 4);
        const estimate = if (count.* == 0) sample else @as(u32, @intCast((@as(u64, previous) * 7 + bounded_sample + 4) / 8));
        count.* +|= 1;
        return estimate;
    }

    pub fn noteConnect(self: *MiddleProxyHealthStore, addr: net.Address, duration_ms: i64, now_ms: i64) void {
        const entry = self.getOrCreate(addr, now_ms);
        entry.connect_ewma_ms = updateEwma(entry.connect_ewma_ms, sampleMs(duration_ms), &entry.connect_samples);
        entry.last_observed_ms = now_ms;
    }

    pub fn noteAuth(self: *MiddleProxyHealthStore, addr: net.Address, duration_ms: i64, now_ms: i64) void {
        const entry = self.getOrCreate(addr, now_ms);
        entry.auth_ewma_ms = updateEwma(entry.auth_ewma_ms, sampleMs(duration_ms), &entry.auth_samples);
        entry.failure_streak = 0;
        entry.last_success_ms = now_ms;
        entry.last_observed_ms = now_ms;
    }

    pub fn noteFailure(self: *MiddleProxyHealthStore, addr: net.Address, now_ms: i64) void {
        const entry = self.getOrCreate(addr, now_ms);
        entry.failure_streak +|= 1;
        entry.last_failure_ms = now_ms;
        entry.last_observed_ms = now_ms;
    }

    pub fn clear(self: *MiddleProxyHealthStore) void {
        self.* = .{};
    }

    pub fn retain(self: *MiddleProxyHealthStore, candidates: []const net.Address) void {
        for (&self.entries) |*entry| {
            if (!entry.active) continue;
            var present = false;
            for (candidates) |addr| {
                if (isSameIpEndpoint(entry.addr, addr)) {
                    present = true;
                    break;
                }
            }
            if (!present) entry.* = .{};
        }
    }

    const Grade = struct { tier: u8, latency_ms: u32 = 0 };

    fn grade(self: *const MiddleProxyHealthStore, addr: net.Address, now_ms: i64) Grade {
        const entry = self.findConst(addr) orelse return .{ .tier = 1 };
        if (entry.failure_streak > 0 and now_ms - entry.last_failure_ms < health_failure_penalty_ms)
            return .{ .tier = 2 };
        if (entry.connect_samples < 2 or entry.auth_samples < 2 or
            now_ms - entry.last_success_ms >= health_sample_ttl_ms)
            return .{ .tier = 1 };
        return .{ .tier = 0, .latency_ms = entry.connect_ewma_ms + entry.auth_ewma_ms };
    }

    fn precedes(a: Grade, b: Grade) bool {
        if (a.tier != b.tier) return a.tier < b.tier;
        if (a.tier != 0) return false;
        const margin = @max(@as(u32, 10), b.latency_ms / 5);
        return a.latency_ms + margin < b.latency_ms;
    }

    /// Preserve cooldown priority, then stably prefer confidently faster
    /// authenticated endpoints. Every sixteenth selection samples one healthy
    /// unknown/stale candidate so new metadata cannot remain unmeasured.
    pub fn rank(
        self: *MiddleProxyHealthStore,
        candidates: *[16]net.Address,
        candidate_len: usize,
        cooldowns: []const MiddleProxyCooldown,
        now_ms: i64,
    ) void {
        prioritizeMiddleProxyCandidates(candidates, candidate_len, cooldowns, now_ms);
        const len = @min(candidate_len, candidates.len);
        var healthy_len: usize = 0;
        while (healthy_len < len and middleProxyCooldownUntilMs(cooldowns, candidates[healthy_len], now_ms) == null) : (healthy_len += 1) {}
        self.selections +%= 1;
        if (healthy_len < 2) return;

        // Resolve the fixed-size history once per candidate while holding the
        // metadata lock; insertion sort must not rescan it for every compare.
        var grades: [16]Grade = undefined;
        for (candidates[0..healthy_len], 0..) |addr, i| grades[i] = self.grade(addr, now_ms);
        for (1..healthy_len) |i| {
            var j = i;
            while (j > 0 and precedes(grades[j], grades[j - 1])) : (j -= 1) {
                std.mem.swap(net.Address, &candidates[j], &candidates[j - 1]);
                std.mem.swap(Grade, &grades[j], &grades[j - 1]);
            }
        }

        if (self.selections % health_explore_every != 0) return;
        var unknown_count: usize = 0;
        for (grades[0..healthy_len]) |item| {
            if (item.tier == 1) unknown_count += 1;
        }
        if (unknown_count == 0) return;
        var selected_unknown: usize = @intCast((self.selections / health_explore_every) % @as(u64, @intCast(unknown_count)));
        for (grades[0..healthy_len], 0..) |item, i| {
            if (item.tier != 1) continue;
            if (selected_unknown > 0) {
                selected_unknown -= 1;
                continue;
            }
            const chosen = candidates[i];
            var j = i;
            while (j > 0) : (j -= 1) candidates[j] = candidates[j - 1];
            candidates[0] = chosen;
            break;
        }
    }
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

test "middle-proxy health prefers a stably faster authenticated endpoint" {
    const slow = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const fast = net.ip4(.{ 12, 12, 12, 12 }, 443);
    var health: MiddleProxyHealthStore = .{};
    for (0..2) |i| {
        const now_ms: i64 = @as(i64, @intCast(i)) + 1_000;
        health.noteConnect(slow, 180, now_ms);
        health.noteAuth(slow, 220, now_ms);
        health.noteConnect(fast, 40, now_ms);
        health.noteAuth(fast, 60, now_ms);
    }
    const none = [_]MiddleProxyCooldown{};
    var candidates = [_]net.Address{ slow, fast } ++ ([_]net.Address{slow} ** 14);
    health.rank(&candidates, 2, &none, 2_000);
    try std.testing.expect(net.exactAddressEql(candidates[0], fast));

    // A single transient delay is bounded and cannot flip the preference.
    health.noteConnect(fast, 60_000, 2_001);
    health.noteAuth(fast, 60_000, 2_001);
    candidates[0] = slow;
    candidates[1] = fast;
    health.rank(&candidates, 2, &none, 2_002);
    try std.testing.expect(net.exactAddressEql(candidates[0], fast));
}

test "middle-proxy health keeps cooldown authoritative and ages stale samples" {
    const first = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const second = net.ip4(.{ 12, 12, 12, 12 }, 443);
    var health: MiddleProxyHealthStore = .{};
    for (0..2) |i| {
        const now_ms: i64 = @as(i64, @intCast(i)) + 1_000;
        health.noteConnect(first, 30, now_ms);
        health.noteAuth(first, 30, now_ms);
        health.noteConnect(second, 200, now_ms);
        health.noteAuth(second, 200, now_ms);
    }
    var candidates = [_]net.Address{ first, second } ++ ([_]net.Address{first} ** 14);
    const cooled = [_]MiddleProxyCooldown{.{ .active = true, .addr = first, .until_ms = 3_000 }};
    health.rank(&candidates, 2, &cooled, 2_000);
    try std.testing.expect(net.exactAddressEql(candidates[0], second));

    const none = [_]MiddleProxyCooldown{};
    candidates[0] = second;
    candidates[1] = first;
    health.rank(&candidates, 2, &none, 2_000);
    try std.testing.expect(net.exactAddressEql(candidates[0], first));
    candidates[0] = second;
    candidates[1] = first;
    health.rank(&candidates, 2, &none, 2_000 + health_sample_ttl_ms);
    try std.testing.expect(net.exactAddressEql(candidates[0], second));
}

test "middle-proxy health explores unknown endpoints and discards rotated metadata" {
    const known = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const unknown = net.ip4(.{ 12, 12, 12, 12 }, 443);
    var health: MiddleProxyHealthStore = .{};
    health.noteConnect(known, 30, 1_000);
    health.noteAuth(known, 30, 1_000);
    health.noteConnect(known, 30, 1_001);
    health.noteAuth(known, 30, 1_001);
    const none = [_]MiddleProxyCooldown{};
    for (0..15) |_| {
        var candidates = [_]net.Address{ known, unknown } ++ ([_]net.Address{known} ** 14);
        health.rank(&candidates, 2, &none, 2_000);
        try std.testing.expect(net.exactAddressEql(candidates[0], known));
    }
    var candidates = [_]net.Address{ known, unknown } ++ ([_]net.Address{known} ** 14);
    health.rank(&candidates, 2, &none, 2_000);
    try std.testing.expect(net.exactAddressEql(candidates[0], unknown));

    health.retain(&.{unknown});
    try std.testing.expect(health.findConst(known) == null);
    health.noteFailure(unknown, 2_001);
    try std.testing.expectEqual(@as(u8, 1), health.findConst(unknown).?.failure_streak);
    health.clear();
    try std.testing.expect(health.findConst(unknown) == null);
}

test "middle-proxy health failure penalty ends after authenticated recovery" {
    const fast = net.ip4(.{ 11, 11, 11, 11 }, 443);
    const slow = net.ip4(.{ 12, 12, 12, 12 }, 443);
    var health: MiddleProxyHealthStore = .{};
    for (0..2) |i| {
        const now_ms: i64 = @as(i64, @intCast(i)) + 1_000;
        health.noteConnect(fast, 30, now_ms);
        health.noteAuth(fast, 30, now_ms);
        health.noteConnect(slow, 200, now_ms);
        health.noteAuth(slow, 200, now_ms);
    }
    const none = [_]MiddleProxyCooldown{};
    health.noteFailure(fast, 2_000);
    var candidates = [_]net.Address{ fast, slow } ++ ([_]net.Address{fast} ** 14);
    health.rank(&candidates, 2, &none, 2_001);
    try std.testing.expect(net.exactAddressEql(candidates[0], slow));

    health.noteAuth(fast, 30, 2_002);
    candidates[0] = slow;
    candidates[1] = fast;
    health.rank(&candidates, 2, &none, 2_003);
    try std.testing.expect(net.exactAddressEql(candidates[0], fast));
}
