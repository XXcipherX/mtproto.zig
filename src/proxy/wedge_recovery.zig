const std = @import("std");
const net = @import("../net_helpers.zig");

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

pub const WedgePhase = enum {
    inactive,
    request_pending_delivery,
    waiting_for_reply,
    reply_pending_delivery,
    waiting_for_client,
};

pub const WedgeCloseKind = enum {
    fresh,
    proven,
};

pub const WedgeResponseKind = enum {
    observing,
    fresh,
    proven,
};

pub fn wedgeClientIdentityKey(addr: net.Address, user: []const u8) u64 {
    var hash: u64 = 0xcbf2_9ce4_8422_2325;
    const mix = struct {
        fn byte(value: *u64, input: u8) void {
            value.* = (value.* ^ input) *% 0x0000_0100_0000_01b3;
        }

        fn bytes(value: *u64, input: []const u8) void {
            for (input) |b| byte(value, b);
        }
    };

    const normalized = switch (addr) {
        .ip4 => addr,
        .ip6 => |v6| net.Address.fromIp6(v6),
    };
    switch (normalized) {
        .ip4 => |v4| {
            mix.byte(&hash, 4);
            mix.bytes(&hash, &v4.bytes);
        },
        .ip6 => |v6| {
            mix.byte(&hash, 6);
            mix.bytes(&hash, &v6.bytes);
        },
    }

    mix.byte(&hash, @intCast(@min(user.len, std.math.maxInt(u8))));
    mix.bytes(&hash, user);
    return if (hash == 0) 1 else hash;
}

pub const WedgeGateTicket = struct {
    armed_ms: i64,
    timeout_ms: i64,
    penalty: u8,
};

pub const WedgeRecoveryGate = struct {
    const bucket_count = 1024;
    const max_probes = 12;
    const max_penalty = 3;
    pub const max_wave_closes = 4;

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

    pub fn prepare(
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
    pub fn suppressesNewCandidates(
        self: *WedgeRecoveryGate,
        client_key: u64,
        dc_abs: u16,
        now_ms: i64,
    ) bool {
        const entry = self.getEntry(client_key, dc_abs, now_ms, false) orelse return false;
        resetPenaltyAfterCooldown(entry, now_ms);
        return entry.penalty >= max_penalty and entry.suppression_reported;
    }

    pub fn reportSuppression(
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

    pub fn allowClose(
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

pub const WedgeTracker = struct {
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

    pub fn reset(self: *WedgeTracker) void {
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

    pub fn noteClientPayload(self: *WedgeTracker, now_ms: i64, relay_started_at_ms: i64) bool {
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

    pub fn cancelForClientProgress(self: *WedgeTracker, now_ms: i64, relay_started_at_ms: i64) bool {
        if (self.phase != .reply_pending_delivery and self.phase != .waiting_for_client) return false;
        const cancelled = self.response_kind != null and self.response_kind.? != .observing;
        if (self.phase == .waiting_for_client and relayCanBeProven(now_ms, relay_started_at_ms)) {
            self.proven = true;
        }
        self.fresh_available = false;
        self.resetExchange();
        return cancelled;
    }

    pub fn noteRequestDelivered(self: *WedgeTracker, now_ms: i64) void {
        if (self.phase != .request_pending_delivery) return;
        self.phase = .waiting_for_reply;
        self.request_ms = now_ms;
    }

    pub fn noteServerPayload(self: *WedgeTracker, now_ms: i64) bool {
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

    pub fn noteReplyDelivered(
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

    pub fn deferForClientBackpressure(self: *WedgeTracker) void {
        if (self.phase != .waiting_for_client) return;
        self.phase = .reply_pending_delivery;
        self.deadline_ms = 0;
        self.gate_ticket = null;
    }

    pub fn abandonCandidate(self: *WedgeTracker) void {
        self.resetExchange();
    }

    pub fn nextDeadlineMs(self: *const WedgeTracker) ?i64 {
        if (self.phase != .waiting_for_client or self.deadline_ms <= 0) return null;
        return self.deadline_ms;
    }

    pub fn closeKind(self: *const WedgeTracker, now_ms: i64) ?WedgeCloseKind {
        if (self.phase != .waiting_for_client or self.deadline_ms <= 0 or now_ms < self.deadline_ms) return null;
        const kind = self.response_kind orelse return null;
        return switch (kind) {
            .fresh => .fresh,
            .proven => .proven,
            .observing => null,
        };
    }
};

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
    const native_a = net.ip4(.{ 203, 0, 113, 7 }, 1000);
    const native_b = net.ip4(.{ 203, 0, 113, 7 }, 2000);
    const mapped_bytes = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ [_]u8{ 203, 0, 113, 7 };
    const mapped = net.ip6(mapped_bytes, 3000, 0, 0);

    const key = wedgeClientIdentityKey(native_a, "alice");
    try std.testing.expectEqual(key, wedgeClientIdentityKey(native_b, "alice"));
    try std.testing.expectEqual(key, wedgeClientIdentityKey(mapped, "alice"));
    try std.testing.expect(key != wedgeClientIdentityKey(native_a, "bob"));
}
