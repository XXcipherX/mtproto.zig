//! Configuration loading for MTProto proxy.
//!
//! Parses a simplified TOML config with user secrets and server settings.
//! Format is compatible with the Rust telemt config.toml.

const std = @import("std");
const net = @import("net_compat.zig");
const compat = @import("compat.zig");

pub const Config = struct {
    pub const UserSecret = struct { name: []const u8, secret: [16]u8 };

    /// Route regular DC traffic via Telegram MiddleProxy transport.
    /// Mirrors telemt's [general].use_middle_proxy behavior.
    use_middle_proxy: bool = false,
    /// Force media-path traffic (DC203 / negative dc_idx) through MiddleProxy,
    /// even when use_middle_proxy is false.
    force_media_middle_proxy: bool = true,
    port: u16 = 443,
    /// Explicit public IP address. If set, bypasses detection via external services.
    public_ip: ?[]const u8 = null,
    /// Explicit IPv4 to use in Telegram MiddleProxy AES key derivation.
    /// Useful when `public_ip` is a domain name or when tunnel egress differs
    /// from generic "what is my IP" services.
    middle_proxy_nat_ip: ?[]const u8 = null,
    /// TCP listen(2) backlog for client-facing sockets
    backlog: u32 = 4096,
    /// Hard cap for concurrently handled client connections
    /// Default tuned for 1 vCPU / 1 GB VPS profile.
    max_connections: u32 = 512,
    /// Pre-handshake idle timeout: wait for first client byte
    idle_timeout_sec: u32 = 120,
    /// Per-connection idle timeout jitter in percent; 0 disables.
    idle_timeout_jitter_pct: u8 = 15,
    /// Close a relay when the server has replied but the client stays silent for
    /// this many seconds; 0 = disabled. This bounds an iOS MtProtoKit bad_salt
    /// wedge where the client stops sending until the DC closes the socket.
    client_silence_close_sec: u32 = 0,
    /// Handshake read timeout after first byte arrives
    handshake_timeout_sec: u32 = 15,
    /// Per-endpoint TCP connect deadline for Telegram DC candidates.
    /// 0 disables it and relies only on the global handshake timeout.
    dc_connect_timeout_sec: u32 = 10,
    tag: ?[16]u8 = null,
    /// FakeTLS SNI / fronting domain. Since the June-2026 TSPU rollout, the
    /// real masking endpoint for this domain should negotiate X25519MLKEM768
    /// (0x11ec) in one round. Classical-x25519-only domains can become a passive
    /// marker for iOS and for other clients sharing the same NAT egress IP.
    /// Changing this value changes every ee-secret link, so choose it carefully.
    tls_domain: []const u8 = "google.com",
    /// True when tls_domain was duplicated by the parser and must be freed.
    tls_domain_owned: bool = false,
    users: std.StringHashMap([16]u8),
    /// Users that always bypass MiddleProxy and connect to DC directly.
    /// Section: [access.direct_users] (alias: [access.admins])
    direct_users: std.StringHashMap(void),
    /// Whether to mask bad clients (forward to tls_domain)
    mask: bool = true,
    /// Test-only hook to override the mask port
    mask_port: u16 = 443,
    /// Maximum masking relay lifetime in seconds; 0 disables.
    mask_relay_max_secs: u32 = 0,
    /// TCP desync: split ServerHello into 1-byte + rest to evade DPI
    desync: bool = true,
    /// Base delay between first ServerHello byte and the rest.
    desync_split_delay_ms: u32 = 3,
    /// Random extra delay added to desync_split_delay_ms.
    desync_split_jitter_ms: u32 = 2,
    /// FakeTLS encrypted certificate AppData size.
    /// 0 keeps the built-in default that matches the static template.
    fake_cert_size: u32 = 0,
    /// Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes
    drs: bool = false,
    /// Fast mode: skip S2C encryption by passing client keys to DC directly
    fast_mode: bool = false,
    /// MiddleProxy stream buffer cap in KiB.
    /// Per-connection C2S/S2C buffers now start small and grow on demand up to
    /// this limit, while EventLoop keeps shared C2S/S2C scratch space for
    /// framing and decrypt/encrypt staging. The C2S scratch starts near 1x
    /// buffer size and grows on demand for pathological tiny-packet bursts.
    /// Minimum 1024 recommended; default 2048 leaves headroom for 1 MiB media parts.
    /// Lower caps still risk MiddleProxyBufferOverflow on media downloads
    /// (Stories, video messages) through middle proxy.
    middleproxy_buffer_kb: u32 = 2048,
    /// Runtime log level: "debug", "info" (default), "warn", "err"
    log_level: std.log.Level = .info,
    /// Max new connections per second per /24 subnet (0 = disabled).
    /// Limits scanner/flood/DPI-probe impact. Generous for legitimate Telegram clients
    /// which open 3-6 connections at startup and hold them.
    rate_limit_per_subnet: u8 = 30,
    /// When true, disables auto-clamping of max_connections to the RAM-safe estimate.
    /// Use only if you know your host has enough memory for the configured limits.
    unsafe_override_limits: bool = false,
    /// Test-only hook to redirect upstream connections locally
    datacenter_override: ?net.Address = null,

    pub const middle_proxy_c2s_scratch_headroom: usize = 256;
    pub const middle_proxy_stream_buffer_cap_bytes: usize = 1 << 24;

    pub fn middleProxyConfiguredBufferBytes(self: *const Config) usize {
        return @as(usize, self.middleproxy_buffer_kb) * 1024;
    }

    pub fn middleProxyBufferBytes(self: *const Config) usize {
        return @min(self.middleProxyConfiguredBufferBytes(), middle_proxy_stream_buffer_cap_bytes);
    }

    pub fn usesAnyMiddleProxy(self: *const Config) bool {
        return self.use_middle_proxy or self.force_media_middle_proxy;
    }

    pub fn middleProxyC2sScratchBytes(self: *const Config) usize {
        return self.middleProxyBufferBytes() + middle_proxy_c2s_scratch_headroom;
    }

    pub fn middleProxySharedScratchBytes(self: *const Config) usize {
        return self.middleProxyC2sScratchBytes() + self.middleProxyBufferBytes();
    }

    pub fn userBypassesMiddleProxy(self: *const Config, user_name: []const u8) bool {
        return self.users.contains(user_name) and self.direct_users.contains(user_name);
    }

    /// Emit startup warnings for configuration values known to cause issues.
    pub fn emitWarnings(self: *const Config) void {
        if (self.users.count() == 0) {
            const log = std.log.scoped(.config);
            log.warn("access.users is empty; no clients can authenticate until at least one user secret is configured", .{});
        }

        if (self.usesAnyMiddleProxy() and self.middleproxy_buffer_kb < 1024) {
            const log = std.log.scoped(.config);
            log.warn(
                "middleproxy_buffer_kb={d} is below recommended minimum (1024). " ++
                    "This may cause MiddleProxyBufferOverflow errors on media-heavy " ++
                    "traffic (Stories, video downloads). Consider increasing to 1024+.",
                .{self.middleproxy_buffer_kb},
            );
        }
        if (self.usesAnyMiddleProxy() and self.middleProxyConfiguredBufferBytes() > middle_proxy_stream_buffer_cap_bytes) {
            const log = std.log.scoped(.config);
            log.warn(
                "middleproxy_buffer_kb={d} exceeds runtime cap ({d} KiB); " ++
                    "effective per-direction buffer cap is {d} KiB.",
                .{
                    self.middleproxy_buffer_kb,
                    middle_proxy_stream_buffer_cap_bytes / 1024,
                    middle_proxy_stream_buffer_cap_bytes / 1024,
                },
            );
        }
        if (self.usesAnyMiddleProxy() and self.max_connections > 2000) {
            const log = std.log.scoped(.config);
            const mem_per_conn_mb = (self.middleProxyBufferBytes() * 2) / (1024 * 1024);
            const shared_mb = self.middleProxySharedScratchBytes() / (1024 * 1024);
            log.warn(
                "max_connections={d} with middleproxy_buffer_kb={d} should still plan for " ++
                    "up to {d} MB + {d} MB shared RAM at full capacity. Ensure your VPS has sufficient memory.",
                .{ self.max_connections, self.middleproxy_buffer_kb, mem_per_conn_mb * self.max_connections, shared_mb },
            );
        }

        if (self.direct_users.count() > 0) {
            const log = std.log.scoped(.config);
            var direct_users = self.direct_users;
            var it = direct_users.iterator();
            while (it.next()) |entry| {
                if (!self.users.contains(entry.key_ptr.*)) {
                    log.warn(
                        "access.direct_users contains unknown user '{s}' (missing in [access.users]); entry will be ignored",
                        .{entry.key_ptr.*},
                    );
                }
            }
        }
    }

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const content = try compat.readFileAlloc(allocator, path, 1024 * 1024);
        defer allocator.free(content);
        return parse(allocator, content);
    }

    fn stripInlineComment(value: []const u8) []const u8 {
        var in_quotes = false;
        var escaped = false;

        for (value, 0..) |ch, idx| {
            if (escaped) {
                escaped = false;
                continue;
            }

            if (in_quotes and ch == '\\') {
                escaped = true;
                continue;
            }

            if (ch == '"') {
                in_quotes = !in_quotes;
                continue;
            }

            if (!in_quotes and (ch == '#' or ch == ';')) {
                return std.mem.trimEnd(u8, value[0..idx], &[_]u8{ ' ', '\t' });
            }
        }

        return std.mem.trimEnd(u8, value, &[_]u8{ ' ', '\t' });
    }

    fn replaceOwnedOptionalString(allocator: std.mem.Allocator, field: *?[]const u8, value: []const u8) !void {
        if (field.*) |prev| allocator.free(prev);
        field.* = null;
        field.* = try allocator.dupe(u8, value);
    }

    fn warnInvalidValue(key: []const u8, value: []const u8, expected: []const u8) void {
        const log = std.log.scoped(.config);
        log.warn("invalid config value for {s}: '{s}' (expected {s}); keeping previous/default", .{
            key,
            value,
            expected,
        });
    }

    fn failConfigLine(err: anyerror, line_number: usize, line: []const u8) anyerror {
        const log = std.log.scoped(.config);
        log.warn("invalid config at line {d}: {s}", .{ line_number, line });
        return err;
    }

    fn parseBoolSetting(key: []const u8, value: []const u8) ?bool {
        if (std.mem.eql(u8, value, "true") or
            std.mem.eql(u8, value, "1") or
            std.mem.eql(u8, value, "yes") or
            std.mem.eql(u8, value, "on"))
        {
            return true;
        }
        if (std.mem.eql(u8, value, "false") or
            std.mem.eql(u8, value, "0") or
            std.mem.eql(u8, value, "no") or
            std.mem.eql(u8, value, "off"))
        {
            return false;
        }
        warnInvalidValue(key, value, "true/false");
        return null;
    }

    fn parseIntSetting(comptime T: type, key: []const u8, value: []const u8) ?T {
        return std.fmt.parseInt(T, value, 10) catch {
            warnInvalidValue(key, value, "decimal integer");
            return null;
        };
    }

    fn parseHex16Setting(key: []const u8, value: []const u8) ?[16]u8 {
        if (value.len != 32) {
            warnInvalidValue(key, value, "32 hex characters");
            return null;
        }
        var out: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, value) catch {
            warnInvalidValue(key, value, "32 hex characters");
            return null;
        };
        return out;
    }

    fn upsertOwnedEntry(
        comptime V: type,
        allocator: std.mem.Allocator,
        map: *std.StringHashMap(V),
        key: []const u8,
        value: V,
    ) !void {
        const owned_key = try allocator.dupe(u8, key);
        errdefer allocator.free(owned_key);

        const gop = try map.getOrPut(owned_key);
        if (gop.found_existing) {
            allocator.free(owned_key);
        }
        if (V != void) {
            gop.value_ptr.* = value;
        }
    }

    fn removeOwnedVoidEntry(allocator: std.mem.Allocator, map: *std.StringHashMap(void), key: []const u8) void {
        if (map.fetchRemove(key)) |entry| {
            allocator.free(entry.key);
        }
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Config {
        var cfg = Config{
            .users = std.StringHashMap([16]u8).init(allocator),
            .direct_users = std.StringHashMap(void).init(allocator),
        };
        errdefer cfg.deinit(allocator);

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_users_section = false;
        var in_direct_users_section = false;
        var in_censorship_section = false;
        var in_server_section = false;
        var in_general_section = false;
        var in_monitor_section = false;
        var server_tag_set = false;
        var line_number: usize = 0;

        while (lines.next()) |raw_line| {
            line_number += 1;
            var line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
            line = stripInlineComment(line);
            if (line.len == 0) continue;

            // Section headers
            if (line[0] == '[') {
                in_users_section = std.mem.eql(u8, line, "[access.users]");
                in_direct_users_section = std.mem.eql(u8, line, "[access.direct_users]") or std.mem.eql(u8, line, "[access.admins]");
                in_censorship_section = std.mem.eql(u8, line, "[censorship]");
                in_server_section = std.mem.eql(u8, line, "[server]");
                in_general_section = std.mem.eql(u8, line, "[general]");
                in_monitor_section = std.mem.eql(u8, line, "[monitor]");
                if (!in_users_section and !in_direct_users_section and !in_censorship_section and
                    !in_server_section and !in_general_section and !in_monitor_section)
                {
                    return failConfigLine(error.UnknownConfigSection, line_number, line);
                }
                continue;
            }

            // Key = value parsing
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
                var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });
                value = stripInlineComment(value);
                if (key.len == 0 or ((value.len > 0 and value[0] == '"') != (value.len > 0 and value[value.len - 1] == '"'))) {
                    return failConfigLine(error.MalformedConfigLine, line_number, line);
                }

                // Strip quotes from value
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }

                if (in_users_section) {
                    // Parse user secret (32 hex chars = 16 bytes)
                    if (parseHex16Setting(key, value)) |secret| {
                        try upsertOwnedEntry([16]u8, allocator, &cfg.users, key, secret);
                    }
                } else if (in_direct_users_section) {
                    if (parseBoolSetting(key, value)) |enabled| {
                        if (enabled) {
                            try upsertOwnedEntry(void, allocator, &cfg.direct_users, key, {});
                        } else {
                            removeOwnedVoidEntry(allocator, &cfg.direct_users, key);
                        }
                    }
                } else if (in_general_section) {
                    if (std.mem.eql(u8, key, "use_middle_proxy")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.use_middle_proxy = parsed;
                    } else if (std.mem.eql(u8, key, "force_media_middle_proxy")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.force_media_middle_proxy = parsed;
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        // telemt compatibility: [general].fast_mode
                        if (parseBoolSetting(key, value)) |parsed| cfg.fast_mode = parsed;
                    } else if (std.mem.eql(u8, key, "ad_tag")) {
                        // telemt compatibility: [general].ad_tag
                        // If [server].tag is present and valid, it has priority.
                        if (!server_tag_set) {
                            if (parseHex16Setting(key, value)) |tag| {
                                cfg.tag = tag;
                            }
                        }
                    } else {
                        return failConfigLine(error.UnknownConfigKey, line_number, line);
                    }
                } else if (in_server_section) {
                    if (std.mem.eql(u8, key, "port")) {
                        if (parseIntSetting(u16, key, value)) |parsed| {
                            if (parsed == 0) warnInvalidValue(key, value, "integer in 1..65535") else cfg.port = parsed;
                        }
                    } else if (std.mem.eql(u8, key, "backlog")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            if (parsed == 0 or parsed > std.math.maxInt(u31))
                                warnInvalidValue(key, value, "integer in 1..2147483647")
                            else
                                cfg.backlog = parsed;
                        }
                    } else if (std.mem.eql(u8, key, "max_connections")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.max_connections = @max(@as(u32, 32), parsed);
                        }
                    } else if (std.mem.eql(u8, key, "idle_timeout_sec")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.idle_timeout_sec = @max(@as(u32, 5), parsed);
                        }
                    } else if (std.mem.eql(u8, key, "idle_timeout_jitter_pct")) {
                        if (parseIntSetting(u8, key, value)) |parsed| {
                            cfg.idle_timeout_jitter_pct = @min(@as(u8, 100), parsed);
                        }
                    } else if (std.mem.eql(u8, key, "client_silence_close_sec")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.client_silence_close_sec = parsed;
                        }
                    } else if (std.mem.eql(u8, key, "handshake_timeout_sec")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.handshake_timeout_sec = @max(@as(u32, 5), parsed);
                        }
                    } else if (std.mem.eql(u8, key, "dc_connect_timeout_sec")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.dc_connect_timeout_sec = parsed;
                        }
                    } else if (std.mem.eql(u8, key, "tag")) {
                        if (parseHex16Setting(key, value)) |tag| {
                            cfg.tag = tag;
                            server_tag_set = true;
                        }
                    } else if (std.mem.eql(u8, key, "public_ip")) {
                        try replaceOwnedOptionalString(allocator, &cfg.public_ip, value);
                    } else if (std.mem.eql(u8, key, "middle_proxy_nat_ip")) {
                        try replaceOwnedOptionalString(allocator, &cfg.middle_proxy_nat_ip, value);
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.fast_mode = parsed;
                    } else if (std.mem.eql(u8, key, "middleproxy_buffer_kb")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.middleproxy_buffer_kb = @max(@as(u32, 64), parsed);
                        }
                    } else if (std.mem.eql(u8, key, "log_level")) {
                        if (std.mem.eql(u8, value, "debug")) {
                            cfg.log_level = .debug;
                        } else if (std.mem.eql(u8, value, "info")) {
                            cfg.log_level = .info;
                        } else if (std.mem.eql(u8, value, "warn")) {
                            cfg.log_level = .warn;
                        } else if (std.mem.eql(u8, value, "err")) {
                            cfg.log_level = .err;
                        } else {
                            warnInvalidValue(key, value, "debug/info/warn/err");
                        }
                    } else if (std.mem.eql(u8, key, "rate_limit_per_subnet")) {
                        if (parseIntSetting(u8, key, value)) |parsed| cfg.rate_limit_per_subnet = parsed;
                    } else if (std.mem.eql(u8, key, "unsafe_override_limits")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.unsafe_override_limits = parsed;
                    } else {
                        return failConfigLine(error.UnknownConfigKey, line_number, line);
                    }
                } else if (in_censorship_section) {
                    if (std.mem.eql(u8, key, "tls_domain")) {
                        if (cfg.tls_domain_owned) {
                            allocator.free(cfg.tls_domain);
                        }
                        cfg.tls_domain_owned = false;
                        cfg.tls_domain = try allocator.dupe(u8, value);
                        cfg.tls_domain_owned = true;
                    } else if (std.mem.eql(u8, key, "mask")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.mask = parsed;
                    } else if (std.mem.eql(u8, key, "mask_port")) {
                        if (parseIntSetting(u16, key, value)) |parsed| {
                            if (parsed == 0) warnInvalidValue(key, value, "integer in 1..65535") else cfg.mask_port = parsed;
                        }
                    } else if (std.mem.eql(u8, key, "mask_relay_max_secs")) {
                        if (parseIntSetting(u32, key, value)) |parsed| cfg.mask_relay_max_secs = parsed;
                    } else if (std.mem.eql(u8, key, "desync")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.desync = parsed;
                    } else if (std.mem.eql(u8, key, "desync_split_delay_ms")) {
                        if (parseIntSetting(u32, key, value)) |parsed| cfg.desync_split_delay_ms = parsed;
                    } else if (std.mem.eql(u8, key, "desync_split_jitter_ms")) {
                        if (parseIntSetting(u32, key, value)) |parsed| cfg.desync_split_jitter_ms = parsed;
                    } else if (std.mem.eql(u8, key, "fake_cert_size")) {
                        if (parseIntSetting(u32, key, value)) |parsed| {
                            cfg.fake_cert_size = if (parsed == 0)
                                0
                            else
                                @min(@as(u32, 16 * 1024), @max(@as(u32, 256), parsed));
                        }
                    } else if (std.mem.eql(u8, key, "drs")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.drs = parsed;
                    } else if (std.mem.eql(u8, key, "fast_mode")) {
                        if (parseBoolSetting(key, value)) |parsed| cfg.fast_mode = parsed;
                    } else {
                        return failConfigLine(error.UnknownConfigKey, line_number, line);
                    }
                } else if (in_monitor_section) {
                    if (!std.mem.eql(u8, key, "host") and !std.mem.eql(u8, key, "port")) {
                        return failConfigLine(error.UnknownConfigKey, line_number, line);
                    }
                } else {
                    return failConfigLine(error.ConfigKeyOutsideSection, line_number, line);
                }
            } else {
                return failConfigLine(error.MalformedConfigLine, line_number, line);
            }
        }

        return cfg;
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        var it = self.users.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.users.deinit();

        var direct_it = self.direct_users.iterator();
        while (direct_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        self.direct_users.deinit();

        if (self.tls_domain_owned) {
            allocator.free(self.tls_domain);
        }
        if (self.public_ip) |ip| {
            allocator.free(ip);
        }
        if (self.middle_proxy_nat_ip) |ip| {
            allocator.free(ip);
        }
    }

    /// Get user secrets as a flat slice for handshake validation.
    pub fn getUserSecrets(self: *const Config, allocator: std.mem.Allocator) ![]const UserSecret {
        var list: std.ArrayList(UserSecret) = .empty;
        var users = self.users;
        var it = users.iterator();
        while (it.next()) |entry| {
            try list.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }
        return try list.toOwnedSlice(allocator);
    }
};

// ============= Tests =============

test "parse config - valid complete" {
    const content =
        \\[general]
        \\use_middle_proxy = true
        \\
        \\[server]
        \\port = 8443
        \\backlog = 8192
        \\max_connections = 6000
        \\idle_timeout_sec = 180
        \\idle_timeout_jitter_pct = 25
        \\handshake_timeout_sec = 30
        \\dc_connect_timeout_sec = 7
        \\fast_mode = true
        \\
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\mask_relay_max_secs = 30
        \\desync = true
        \\desync_split_delay_ms = 4
        \\desync_split_jitter_ms = 6
        \\fake_cert_size = 4096
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqual(@as(u32, 8192), cfg.backlog);
    try std.testing.expectEqual(@as(u32, 6000), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 180), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u8, 25), cfg.idle_timeout_jitter_pct);
    try std.testing.expectEqual(@as(u32, 30), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 7), cfg.dc_connect_timeout_sec);
    try std.testing.expectEqualStrings("example.com", cfg.tls_domain);
    try std.testing.expect(cfg.use_middle_proxy);
    try std.testing.expect(cfg.mask);
    try std.testing.expectEqual(@as(u32, 30), cfg.mask_relay_max_secs);
    try std.testing.expect(cfg.desync);
    try std.testing.expectEqual(@as(u32, 4), cfg.desync_split_delay_ms);
    try std.testing.expectEqual(@as(u32, 6), cfg.desync_split_jitter_ms);
    try std.testing.expectEqual(@as(u32, 4096), cfg.fake_cert_size);
    try std.testing.expect(cfg.fast_mode);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());

    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual([_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, alice_secret);
}

test "parse config - missing fields defaults" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expectEqual(@as(u32, 4096), cfg.backlog); // Default is 4096
    try std.testing.expectEqual(@as(u32, 512), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 120), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u8, 15), cfg.idle_timeout_jitter_pct);
    try std.testing.expectEqual(@as(u32, 15), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 10), cfg.dc_connect_timeout_sec);
    try std.testing.expectEqualStrings("google.com", cfg.tls_domain);
    try std.testing.expect(!cfg.use_middle_proxy); // Default is false
    try std.testing.expect(cfg.mask); // Default is true
    try std.testing.expectEqual(@as(u32, 0), cfg.mask_relay_max_secs);
    try std.testing.expect(cfg.desync); // Default is true
    try std.testing.expectEqual(@as(u32, 3), cfg.desync_split_delay_ms);
    try std.testing.expectEqual(@as(u32, 2), cfg.desync_split_jitter_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.fake_cert_size);
    try std.testing.expect(!cfg.fast_mode); // Default is false
    try std.testing.expectEqual(@as(u32, 2048), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 2048 * 1024), cfg.middleProxyBufferBytes());
    try std.testing.expectEqual(@as(u8, 30), cfg.rate_limit_per_subnet);
    try std.testing.expect(!cfg.unsafe_override_limits);
    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    try std.testing.expectEqual(@as(usize, 0), cfg.direct_users.count());
}

test "parse config - direct users allowlist" {
    const content =
        \\[access.users]
        \\admin = "00112233445566778899aabbccddeeff"
        \\regular = "aabbccddeeff00112233445566778899"
        \\[access.direct_users]
        \\admin = true
        \\regular = false
        \\ghost = true
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), cfg.direct_users.count());
    try std.testing.expect(cfg.userBypassesMiddleProxy("admin"));
    try std.testing.expect(!cfg.userBypassesMiddleProxy("regular"));
    try std.testing.expect(!cfg.userBypassesMiddleProxy("ghost"));
}

test "parse config - direct users duplicate false overrides true" {
    const content =
        \\[access.users]
        \\admin = "00112233445566778899aabbccddeeff"
        \\[access.direct_users]
        \\admin = true
        \\admin = false
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), cfg.direct_users.count());
    try std.testing.expect(!cfg.userBypassesMiddleProxy("admin"));
}

test "parse config - access admins alias" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\[access.admins]
        \\alice = true
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.userBypassesMiddleProxy("alice"));
}

test "middle proxy scratch helpers cover media-only mode" {
    var cfg = Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = true,
        .middleproxy_buffer_kb = 1024,
    };
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.usesAnyMiddleProxy());
    try std.testing.expectEqual(@as(usize, 1024 * 1024 + Config.middle_proxy_c2s_scratch_headroom), cfg.middleProxyC2sScratchBytes());
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024 + Config.middle_proxy_c2s_scratch_headroom), cfg.middleProxySharedScratchBytes());
}

test "parse config - middleproxy buffer size" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 192
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 192), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(usize, 192 * 1024), cfg.middleProxyBufferBytes());
}

test "parse config - middleproxy buffer lower bound" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 16
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 64), cfg.middleproxy_buffer_kb);
}

test "parse config - middleproxy buffer runtime cap" {
    const content =
        \\[server]
        \\middleproxy_buffer_kb = 32768
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 32768), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(Config.middle_proxy_stream_buffer_cap_bytes, cfg.middleProxyBufferBytes());
}

test "parse config - log_level debug" {
    const content =
        \\[server]
        \\log_level = "debug"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.debug, cfg.log_level);
}

test "parse config - log_level warn" {
    const content =
        \\[server]
        \\log_level = "warn"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.warn, cfg.log_level);
}

test "parse config - log_level default is info" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
}

test "parse config - server runtime tunables lower bounds" {
    const content =
        \\[server]
        \\max_connections = 1
        \\idle_timeout_sec = 1
        \\handshake_timeout_sec = 1
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 32), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 5), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u32, 5), cfg.handshake_timeout_sec);
}

test "parse config - idle timeout jitter clamps to 100 percent" {
    const content =
        \\[server]
        \\idle_timeout_jitter_pct = 150
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 100), cfg.idle_timeout_jitter_pct);
}

test "parse config - spaces and tabs" {
    const content =
        \\[server]
        \\  port   =   9999   
        \\[censorship]
        \\  tls_domain= "test.com"  
        \\[access.users]
        \\  user  = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 9999), cfg.port);
    try std.testing.expectEqualStrings("test.com", cfg.tls_domain);
    try std.testing.expect(cfg.users.contains("user"));
}

test "parse config - inline comments after values" {
    const content =
        \\[server]
        \\port = 8443 # dashboard port
        \\middleproxy_buffer_kb = 192 ; keep below default in test
        \\unsafe_override_limits = true # explicit override
        \\public_ip = "proxy.example.com" # keep quoted strings working
        \\[general]
        \\force_media_middle_proxy = false ; disable media MP
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff" # main user
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqual(@as(u32, 192), cfg.middleproxy_buffer_kb);
    try std.testing.expect(cfg.unsafe_override_limits);
    try std.testing.expect(!cfg.force_media_middle_proxy);
    try std.testing.expectEqualStrings("proxy.example.com", cfg.public_ip.?);
    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
}

test "parse config - invalid hex secret skipped" {
    const content =
        \\[access.users]
        \\valid = "00112233445566778899aabbccddeeff"
        \\invalid_len = "001122"
        \\invalid_hex = "zz112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    try std.testing.expect(cfg.users.contains("valid"));
}

test "parse config - getUserSecrets" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    const secrets = try cfg.getUserSecrets(std.testing.allocator);
    defer std.testing.allocator.free(secrets);

    try std.testing.expectEqual(@as(usize, 1), secrets.len);
    try std.testing.expectEqualStrings("alice", secrets[0].name);
}

test "parse config - tag parsing" {
    const content =
        \\[server]
        \\port = 443
        \\tag = 1234567890abcdef1234567890abcdef
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - tag default null" {
    const content =
        \\[server]
        \\port = 443
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - invalid tag ignored" {
    const content =
        \\[server]
        \\tag = tooshort
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag == null);
}

test "parse config - general ad_tag alias" {
    const content =
        \\[general]
        \\ad_tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - server tag overrides general ad_tag" {
    const content =
        \\[general]
        \\ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\
        \\[server]
        \\tag = "1234567890abcdef1234567890abcdef"
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.tag != null);
    const expected_tag = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    try std.testing.expectEqual(expected_tag, cfg.tag.?);
}

test "parse config - rate_limit_per_subnet custom" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = 20
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 20), cfg.rate_limit_per_subnet);
}

test "parse config - rate_limit_per_subnet disabled" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = 0
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 0), cfg.rate_limit_per_subnet);
}

test "parse config - unsafe_override_limits true" {
    const content =
        \\[server]
        \\unsafe_override_limits = true
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.unsafe_override_limits);
}

test "parse config - unsafe_override_limits default false" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.unsafe_override_limits);
}

test "parse config - full production-like config" {
    const content =
        \\[general]
        \\use_middle_proxy = true
        \\
        \\[server]
        \\port = 443
        \\tag = 9649114fbafd6fe2ae98ca635c4e4007
        \\middleproxy_buffer_kb = 2048
        \\max_connections = 512
        \\idle_timeout_sec = 120
        \\idle_timeout_jitter_pct = 15
        \\handshake_timeout_sec = 15
        \\dc_connect_timeout_sec = 10
        \\backlog = 8192
        \\log_level = "info"
        \\rate_limit_per_subnet = 30
        \\
        \\[censorship]
        \\tls_domain = "wb.ru"
        \\mask = true
        \\fast_mode = true
        \\mask_port = 8443
        \\mask_relay_max_secs = 45
        \\desync_split_delay_ms = 3
        \\desync_split_jitter_ms = 2
        \\fake_cert_size = 0
        \\drs = true
        \\
        \\[access.users]
        \\alexander = "0b513f6e83524354984a8835939fa9af"
        \\debug_user = "c8f31d0a8b7f4d2c91e6a5b3d4f8e102"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(cfg.use_middle_proxy);
    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expect(cfg.tag != null);
    try std.testing.expectEqual(@as(u32, 2048), cfg.middleproxy_buffer_kb);
    try std.testing.expectEqual(@as(u32, 512), cfg.max_connections);
    try std.testing.expectEqual(@as(u32, 120), cfg.idle_timeout_sec);
    try std.testing.expectEqual(@as(u8, 15), cfg.idle_timeout_jitter_pct);
    try std.testing.expectEqual(@as(u32, 15), cfg.handshake_timeout_sec);
    try std.testing.expectEqual(@as(u32, 10), cfg.dc_connect_timeout_sec);
    try std.testing.expectEqual(@as(u32, 8192), cfg.backlog);
    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
    try std.testing.expectEqual(@as(u8, 30), cfg.rate_limit_per_subnet);
    try std.testing.expect(!cfg.unsafe_override_limits);
    try std.testing.expectEqualStrings("wb.ru", cfg.tls_domain);
    try std.testing.expect(cfg.mask);
    try std.testing.expect(cfg.fast_mode);
    try std.testing.expectEqual(@as(u16, 8443), cfg.mask_port);
    try std.testing.expectEqual(@as(u32, 45), cfg.mask_relay_max_secs);
    try std.testing.expectEqual(@as(u32, 3), cfg.desync_split_delay_ms);
    try std.testing.expectEqual(@as(u32, 2), cfg.desync_split_jitter_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.fake_cert_size);
    try std.testing.expect(cfg.drs);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());
    try std.testing.expect(cfg.users.contains("alexander"));
    try std.testing.expect(cfg.users.contains("debug_user"));
}

test "parse config - log_level err" {
    const content =
        \\[server]
        \\log_level = "err"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.err, cfg.log_level);
}

test "parse config - invalid log_level keeps default" {
    const content =
        \\[server]
        \\log_level = "banana"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(std.log.Level.info, cfg.log_level);
}

test "parse config - invalid rate_limit keeps default" {
    const content =
        \\[server]
        \\rate_limit_per_subnet = notanumber
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u8, 30), cfg.rate_limit_per_subnet);
}

test "parse config - rejects unknown sections keys and malformed lines" {
    try std.testing.expectError(
        error.UnknownConfigSection,
        Config.parse(std.testing.allocator, "[serve]\nport = 443\n"),
    );
    try std.testing.expectError(
        error.UnknownConfigKey,
        Config.parse(std.testing.allocator, "[server]\nprot = 443\n"),
    );
    try std.testing.expectError(
        error.MalformedConfigLine,
        Config.parse(std.testing.allocator, "[server]\nport 443\n"),
    );
}

test "parse config - unsafe socket ranges keep safe defaults" {
    const content =
        \\[server]
        \\port = 0
        \\backlog = 4294967295
        \\[censorship]
        \\mask_port = 0
    ;
    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expectEqual(@as(u32, 4096), cfg.backlog);
    try std.testing.expectEqual(@as(u16, 443), cfg.mask_port);
}

test "parse config - censorship section booleans" {
    const content =
        \\[censorship]
        \\mask = false
        \\desync = false
        \\drs = true
        \\fast_mode = true
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expect(!cfg.mask);
    try std.testing.expect(!cfg.desync);
    try std.testing.expect(cfg.drs);
    try std.testing.expect(cfg.fast_mode);
}

test "parse config - mask relay max lifetime" {
    const content =
        \\[censorship]
        \\mask_relay_max_secs = 60
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 60), cfg.mask_relay_max_secs);
}

test "parse config - fake_cert_size bounds" {
    const low_content =
        \\[censorship]
        \\fake_cert_size = 12
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var low = try Config.parse(std.testing.allocator, low_content);
    defer low.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 256), low.fake_cert_size);

    const high_content =
        \\[censorship]
        \\fake_cert_size = 99999
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var high = try Config.parse(std.testing.allocator, high_content);
    defer high.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 16 * 1024), high.fake_cert_size);

    const default_content =
        \\[censorship]
        \\fake_cert_size = 0
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;
    var default_cfg = try Config.parse(std.testing.allocator, default_content);
    defer default_cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 0), default_cfg.fake_cert_size);
}

test "parse config - desync split timing" {
    const content =
        \\[censorship]
        \\desync_split_delay_ms = 5
        \\desync_split_jitter_ms = 9
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 5), cfg.desync_split_delay_ms);
    try std.testing.expectEqual(@as(u32, 9), cfg.desync_split_jitter_ms);
}

test "parse config - deinit frees explicitly configured default tls_domain" {
    const content =
        \\[censorship]
        \\tls_domain = "google.com"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("google.com", cfg.tls_domain);
    try std.testing.expect(cfg.tls_domain_owned);
}

fn parseConfigAndDeinit(allocator: std.mem.Allocator, content: []const u8) !void {
    var cfg = try Config.parse(allocator, content);
    defer cfg.deinit(allocator);
}

test "parse config - repeated owned fields replace previous values" {
    const content =
        \\[server]
        \\public_ip = "one.example.com"
        \\public_ip = "two.example.com"
        \\middle_proxy_nat_ip = "203.0.113.10"
        \\middle_proxy_nat_ip = "203.0.113.11"
        \\[censorship]
        \\tls_domain = "one.example.com"
        \\tls_domain = "two.example.com"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("two.example.com", cfg.public_ip.?);
    try std.testing.expectEqualStrings("203.0.113.11", cfg.middle_proxy_nat_ip.?);
    try std.testing.expectEqualStrings("two.example.com", cfg.tls_domain);
}

test "parse config - duplicate user entries overwrite without leaking keys" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\alice = "ffeeddccbbaa99887766554433221100"
        \\[access.direct_users]
        \\alice = true
        \\alice = true
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), cfg.users.count());
    try std.testing.expectEqual(@as(usize, 1), cfg.direct_users.count());
    try std.testing.expect(cfg.userBypassesMiddleProxy("alice"));
    try std.testing.expectEqual([_]u8{ 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 }, cfg.users.get("alice").?);
}

test "parse config - allocation failures clean up partial state" {
    const content =
        \\[server]
        \\public_ip = "proxy.example.com"
        \\middle_proxy_nat_ip = "203.0.113.10"
        \\[censorship]
        \\tls_domain = "proxy.example.com"
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
        \\[access.direct_users]
        \\alice = true
    ;

    try std.testing.checkAllAllocationFailures(std.testing.allocator, parseConfigAndDeinit, .{content});
}

test "parse config - multiple users" {
    const content =
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "aabbccddeeff00112233445566778899"
        \\charlie = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), cfg.users.count());
    try std.testing.expect(cfg.users.contains("alice"));
    try std.testing.expect(cfg.users.contains("bob"));
    try std.testing.expect(cfg.users.contains("charlie"));

    // Verify secret bytes are correct
    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual(@as(u8, 0x00), alice_secret[0]);
    try std.testing.expectEqual(@as(u8, 0xff), alice_secret[15]);
}
