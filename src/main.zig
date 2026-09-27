//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const runtime_io = @import("runtime/io.zig");
const resources = @import("runtime/resources.zig");
const signals = @import("runtime/signals.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const net = @import("net_helpers.zig");
const proxy = @import("proxy/proxy.zig");
const web_capability = @import("web/capability.zig");
const web_relay = @import("web/relay.zig");
const web_probe_material = @import("web/probe_material.zig");

// Custom lock-free log function: formats into a stack buffer and writes
// to stderr in a single write() syscall. On Linux, write() is atomic for
// sizes <= PIPE_BUF (4096 bytes), so messages from different threads
// don't interleave. This avoids the global stderr_mutex that Zig's
// default logger uses, which causes catastrophic contention under
// hundreds of concurrent threads.
// Runtime log level, set from config.toml at startup.
// Checked by lockFreeLog to filter messages without recompilation.
pub var runtime_log_level: std.log.Level = .info;

pub const std_options = std.Options{
    // Set comptime level to .debug so all log calls are compiled in.
    // Runtime filtering is done in lockFreeLog via runtime_log_level.
    .log_level = .debug,
    .logFn = lockFreeLog,
};

// Left-align the standard Zig level name to the longest built-in label. This
// keeps the level, scope, and message columns aligned without padding after
// the scope.
const log_level_field_width: usize = "warning".len;

fn formatLogPrefix(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    out: []u8,
) []u8 {
    const level_txt = comptime message_level.asText();
    const suffix_txt = comptime if (scope == .default) ":" else " (" ++ @tagName(scope) ++ "):";
    const prefix_len = log_level_field_width + suffix_txt.len;

    std.debug.assert(out.len >= prefix_len + 1);
    @memcpy(out[0..level_txt.len], level_txt);
    @memset(out[level_txt.len..log_level_field_width], ' ');
    @memcpy(out[log_level_field_width..prefix_len], suffix_txt);
    out[prefix_len] = ' ';
    return out[0 .. prefix_len + 1];
}

fn lockFreeLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime filter: skip messages below configured level
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log_level)) return;

    var buf: [4096]u8 = undefined;
    const prefix = formatLogPrefix(message_level, scope, &buf);
    const body = std.fmt.bufPrint(buf[prefix.len..], format ++ "\n", args) catch return;
    runtime_io.writeStderr(buf[0 .. prefix.len + body.len]);
}

const log = std.log.scoped(.mtproto);

// ============= Output Helpers =============

threadlocal var stdout_accumulator: ?*std.Io.Writer = null;

fn writeStdoutBytes(bytes: []const u8) void {
    if (stdout_accumulator) |writer| {
        writer.writeAll(bytes) catch {};
        return;
    }
    runtime_io.writeStdout(bytes);
}

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeStdoutBytes(slice);
}

/// Write a formatted string to stderr.
fn writeStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    runtime_io.writeStderr(slice);
}

/// Write a hex byte to stdout.
fn writeHexByte(byte: u8) void {
    const hex = "0123456789abcdef";
    const out = [2]u8{ hex[byte >> 4], hex[byte & 0x0f] };
    writeStdoutBytes(&out);
}

fn writeWebServerParameter(domain: []const u8, base_path: []const u8) void {
    writeRaw(domain);
    if (base_path.len == 0) return;
    writeRaw("%2F");
    for (base_path) |byte| {
        if (byte == '/') writeRaw("%2F") else writeStdoutBytes(&.{byte});
    }
}

fn writeWebLinkSecret(secret: [16]u8, base_path: []const u8) void {
    if (base_path.len == 0) {
        writeRaw("dd");
        for (secret) |byte| writeHexByte(byte);
        return;
    }
    var marked = web_capability.encodeMarkedPaddedSecret(secret);
    defer std.crypto.secureZero(u8, &marked);
    writeStdoutBytes(&marked);
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    writeStdoutBytes(s);
}

fn writeUsage() void {
    writeStderr(
        "\n  Usage: mtproto-proxy [config.toml] [--show-secrets | --print-links]\n" ++
            "         mtproto-proxy --check-config [config.toml]\n" ++
            "         mtproto-proxy web-relay [config.toml]\n" ++
            "         mtproto-proxy web-probe-material [config.toml]\n\n",
        .{},
    );
}

const CapacityEstimate = struct {
    effective_memory_bytes: u64,
    allocatable_bytes: u64,
    per_conn_bytes: u64,
    managed_initial_per_conn_bytes: u64,
    managed_burst_reserve_bytes: u64,
    safe_connections: u32,
};

fn percentOfMemory(value: u64, percent: u8) u64 {
    return @intCast((@as(u128, value) * @as(u128, percent)) / 100);
}

fn estimateCapacity(cfg: *const config.Config, total_ram_bytes: u64) CapacityEstimate {
    // Guaranteed per-connection baseline in the epoll model. Relay queue pages,
    // MiddleProxy growth and its scratch are charged to one process
    // runtime-enforced managed budget (partitioned if workers > 1) instead of
    // multiplying their rare maxima by every slot.
    // Deliberately keep the admission estimate conservative even though relay
    // reads now use one scratch buffer per event loop rather than 4 KiB/slot.
    const tls_working_bytes: u64 = @intCast(6 * 1024);
    const requires_middle_proxy_runtime = cfg.requiresMiddleProxyRuntime();
    const managed_initial_per_conn_bytes: u64 = if (requires_middle_proxy_runtime)
        @intCast(config.Config.middle_proxy_initial_stream_buffer_bytes * 2)
    else
        0;
    const overhead_bytes: u64 = 2 * 1024;
    const per_conn_bytes =
        tls_working_bytes +
        managed_initial_per_conn_bytes +
        overhead_bytes;

    // Keep safety headroom for kernel TCP memory, page cache, and baseline process state.
    const usable_bytes = percentOfMemory(total_ram_bytes, 70);
    const reserve_bytes = @max(
        @as(u64, 256 * 1024 * 1024),
        percentOfMemory(total_ram_bytes, 10),
    );
    const allocatable_bytes = if (usable_bytes > reserve_bytes) usable_bytes - reserve_bytes else 0;

    // Half of the post-reserve budget is a shared hard ceiling for queue pages,
    // MP stream-buffer capacity, and MP scratch. The other half guarantees the
    // fixed baseline for every admitted connection.
    const managed_burst_reserve_bytes = allocatable_bytes / 2;
    const connection_budget_bytes = allocatable_bytes - managed_burst_reserve_bytes;

    const raw_cap = if (per_conn_bytes > 0) connection_budget_bytes / per_conn_bytes else 0;
    const safe_connections_u64 = @min(raw_cap, @as(u64, std.math.maxInt(u32)));

    return .{
        .effective_memory_bytes = total_ram_bytes,
        .allocatable_bytes = allocatable_bytes,
        .per_conn_bytes = per_conn_bytes,
        .managed_initial_per_conn_bytes = managed_initial_per_conn_bytes,
        .managed_burst_reserve_bytes = managed_burst_reserve_bytes,
        .safe_connections = @intCast(safe_connections_u64),
    };
}

fn managedBufferLimitForConnections(
    capacity_estimate: ?CapacityEstimate,
    max_connections: u32,
) u64 {
    const est = capacity_estimate orelse return proxy.default_managed_buffer_limit_bytes;
    if (est.per_conn_bytes < est.managed_initial_per_conn_bytes) return 0;
    const unmanaged_per_conn_bytes =
        est.per_conn_bytes - est.managed_initial_per_conn_bytes;
    const unmanaged_total_wide =
        @as(u128, unmanaged_per_conn_bytes) * @as(u128, max_connections);
    if (unmanaged_total_wide >= @as(u128, est.allocatable_bytes)) return 0;

    const max_managed_bytes =
        est.allocatable_bytes - @as(u64, @intCast(unmanaged_total_wide));
    const managed_initial_wide =
        @as(u128, est.managed_initial_per_conn_bytes) * @as(u128, max_connections);
    const desired_wide =
        @as(u128, est.managed_burst_reserve_bytes) + managed_initial_wide;
    return @intCast(@min(
        desired_wide,
        @as(u128, max_managed_bytes),
    ));
}

fn enforceCapacitySafety(cfg: *config.Config, capacity_estimate: ?CapacityEstimate) !void {
    const est = capacity_estimate orelse {
        if (builtin.os.tag == .linux and !cfg.unsafe_override_limits) {
            const log_main = std.log.scoped(.config);
            log_main.warn(
                "could not detect total RAM; skipping max_connections RAM admission clamp. " ++
                    "set a conservative [server].max_connections to avoid OOM.",
                .{},
            );
        }
        return;
    };

    if (est.safe_connections < 32) {
        const log_main = std.log.scoped(.config);
        if (cfg.unsafe_override_limits) {
            log_main.warn(
                "baseline RAM ceiling is only {d} connections; " ++
                    "unsafe_override_limits=true, keeping configured limit {d}",
                .{ est.safe_connections, cfg.max_connections },
            );
            return;
        }
        log_main.warn(
            "baseline RAM ceiling is {d} connections, below the minimum supported capacity of 32",
            .{est.safe_connections},
        );
        return error.InsufficientMemoryBudget;
    }

    if (cfg.max_connections <= est.safe_connections) return;

    const log_main = std.log.scoped(.config);
    if (cfg.unsafe_override_limits) {
        log_main.warn(
            "max_connections={d} exceeds baseline RAM ceiling ({d}); " ++
                "unsafe_override_limits=true, keeping configured limit.",
            .{ cfg.max_connections, est.safe_connections },
        );
        return;
    }

    const configured_limit = cfg.max_connections;
    cfg.max_connections = est.safe_connections;

    log_main.warn(
        "auto-clamping max_connections from {d} to baseline RAM ceiling {d} " ++
            "(effective memory limit {d} MiB, ~{d} KiB baseline/connection). " ++
            "To disable this RAM admission clamp, set unsafe_override_limits = true in [server].",
        .{
            configured_limit,
            est.safe_connections,
            est.effective_memory_bytes / (1024 * 1024),
            est.per_conn_bytes / 1024,
        },
    );
}

// ============= Startup Banner =============

fn writeConnectionLinkEntries(cfg: config.Config) void {
    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const magenta = "\x1b[35m";
    const red = "\x1b[31m";

    // Public discovery used by MiddleProxy runs is intentionally not available
    // while rendering links, so they require an explicitly configured address.
    const has_ip = cfg.public_ip != null;
    const server_ip = cfg.public_ip orelse "<SERVER_IP>";
    const web_only = cfg.web.onlyActive();
    if (!has_ip and !web_only) {
        writeRaw("      " ++ red ++ "⚠  public_ip is not configured; replace <SERVER_IP> manually." ++ R ++ "\n");
    }

    var web_domain_buf: [web_capability.max_host_len]u8 = undefined;
    const web_domain: ?[]const u8 = blk: {
        if (!cfg.web.enabled) break :blk null;
        const raw = cfg.web.domain orelse break :blk null;
        break :blk web_capability.normalizeHost(raw, &web_domain_buf) catch null;
    };

    var users = cfg.users;
    var it = users.iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ B ++ magenta ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});

        if (!web_only) {
            writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "proxy?server={s}&port={d}&secret=", .{ server_ip, cfg.port });
            writeRaw(green ++ "ee");
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");

            writeStdout("      " ++ D ++ "t.me/proxy?server={s}&port={d}&secret=ee", .{ server_ip, cfg.port });
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
            for (cfg.tls_domain) |byte| {
                writeHexByte(byte);
            }
            writeRaw(R ++ "\n");
        }

        if (web_domain) |domain| {
            const base_path = cfg.web.effectiveBasePath();
            writeRaw("      " ++ cyan ++ "tg://" ++ R ++ "webproxy?server=");
            writeWebServerParameter(domain, base_path);
            writeRaw("&secret=" ++ green);
            writeWebLinkSecret(entry.value_ptr.*, base_path);
            writeRaw(R ++ "\n");

            writeRaw("      " ++ D ++ "t.me/webproxy?server=");
            writeWebServerParameter(domain, base_path);
            writeRaw("&secret=");
            writeWebLinkSecret(entry.value_ptr.*, base_path);
            writeRaw(R ++ "\n");
        }
    }
}

fn runWebRelay(allocator: std.mem.Allocator, io: std.Io, cfg: *const config.Config) !void {
    var domain_buf: [web_capability.max_host_len]u8 = undefined;
    var opts = web_relay.Options.fromConfig(cfg, &domain_buf) catch |err| {
        const hint = switch (err) {
            error.WebProxyDisabled => "set [web].enabled = true",
            error.MissingDomain => "set [web].domain to the public WEB hostname",
            error.InvalidDomain => "[web].domain must be an ASCII DNS hostname, not an IP",
            error.InvalidBasePath => "[web].base_path must use canonical slash-separated segments",
            error.InvalidBackend => "[web].backend must be host:port",
            error.NoUsersConfigured => "add at least one [access.users] entry",
        };
        writeStderr("web relay cannot start: {s} ({s})\n", .{ @errorName(err), hint });
        return err;
    };
    opts.backend = web_relay.resolveBackend(allocator, io, cfg) catch |err| {
        writeStderr("web relay cannot resolve [web].backend: {s}\n", .{@errorName(err)});
        return err;
    };

    var relay = try web_relay.Relay.init(allocator, io, opts, cfg);
    defer relay.deinit();
    try relay.run();
}

/// Print connection links and return without starting the proxy.
fn printConnectionLinks(cfg: config.Config) void {
    var output = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer output.deinit();
    stdout_accumulator = &output.writer;
    defer stdout_accumulator = null;

    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const yellow = "\x1b[33m";

    writeRaw("\n  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CONNECTION LINKS" ++ R ++ " " ++ D ++ "────────────────────────────" ++ R ++ "\n");
    writeConnectionLinkEntries(cfg);
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ yellow ++ "Links contain access secrets; keep this terminal private." ++ R ++ "\n\n");

    stdout_accumulator = null;
    runtime_io.writeStdout(output.written());
}

/// Print a stylish startup banner with config summary.
fn printBanner(
    cfg: config.Config,
    capacity_estimate: ?CapacityEstimate,
    managed_buffer_limit_bytes: u64,
    show_secrets: bool,
) void {
    var output = std.Io.Writer.Allocating.init(std.heap.page_allocator);
    defer output.deinit();
    stdout_accumulator = &output.writer;
    defer stdout_accumulator = null;

    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const white = "\x1b[97m";

    // Public discovery used by MiddleProxy runs after the listener is ready.
    // Connection links therefore use only an explicitly configured address.
    const has_ip = cfg.public_ip != null;
    const server_ip = cfg.public_ip orelse "<SERVER_IP>";

    // Logo
    writeRaw("\n" ++ B ++ cyan);
    writeRaw("       __  __ _____ ____            _\n");
    writeRaw("      |  \\/  |_   _|  _ \\ _ __ ___ | |_ ___\n");
    writeRaw("      | |\\/| | | | | |_) | '__/ _ \\| __/ _ \\\n");
    writeRaw("      | |  | | | | |  __/| | | (_) | || (_) |\n");
    writeRaw("      |_|  |_| |_| |_|   |_|  \\___/ \\__\\___/\n");
    writeRaw(R);
    writeStdout("      {s}{s}zig edition{s}\n\n", .{ D, white, R });

    // ─── SERVER ─────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SERVER" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    writeStdout("      Listen       " ++ B ++ green ++ "0.0.0.0:{d}" ++ R ++ "\n", .{cfg.port});
    writeStdout("      Public IP    " ++ B ++ "{s}{s}" ++ R ++ "\n", .{
        if (has_ip) green else yellow,
        server_ip,
    });
    writeStdout("      TLS Domain   " ++ B ++ yellow ++ "{s}" ++ R ++ "\n", .{cfg.tls_domain});
    writeRaw("      Masking      " ++ B);
    if (cfg.mask) {
        writeRaw(green ++ "enabled");
    } else {
        writeRaw(yellow ++ "disabled");
    }
    writeRaw(R ++ "\n");
    writeRaw("      WEB Proxy    " ++ B);
    if (cfg.web.enabled) {
        writeStdout(
            green ++ "{s}" ++ R ++ " ({s})",
            .{ if (cfg.web.onlyActive()) "WEB-only" else "enabled", cfg.web.domain orelse "domain missing" },
        );
    } else {
        writeRaw(D ++ "disabled" ++ R);
    }
    writeRaw("\n\n");

    if (capacity_estimate) |est| {
        const capacity_mode = if (cfg.use_middle_proxy)
            "middleproxy mode"
        else if (cfg.force_media_middle_proxy)
            "media middleproxy mode"
        else
            "direct DC1..5 + required DC203 middleproxy";
        writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "CAPACITY" ++ R ++ " " ++ D ++ "────────────────────────────────────" ++ R ++ "\n");
        writeStdout("      Memory limit " ++ B ++ "{d} MiB" ++ R ++ "\n", .{est.effective_memory_bytes / (1024 * 1024)});
        writeStdout("      Baseline     ~{d} KiB/connection ({s})\n", .{
            est.per_conn_bytes / 1024,
            capacity_mode,
        });
        writeStdout("      Dynamic pool ~{d} MiB shared hard limit\n", .{
            managed_buffer_limit_bytes / (1024 * 1024),
        });
        writeStdout("      RAM ceiling  " ++ B ++ "~{d}" ++ R ++ " baseline connections\n", .{est.safe_connections});
        writeStdout("      Configured   " ++ B ++ "{d}" ++ R ++ " connections\n", .{cfg.max_connections});
        if (cfg.web.enabled) {
            const web_slots = @as(u64, cfg.web.max_sessions) * (@as(u64, cfg.web.max_streams) + 1);
            writeStdout("      WEB budget   up to {d} slots ({d} sessions × ({d} streams + carrier))\n", .{
                web_slots,
                cfg.web.max_sessions,
                cfg.web.max_streams,
            });
        }
        writeRaw("      Admission    pauses at 90%, resumes at 80%\n");
        if (cfg.max_connections > est.safe_connections) {
            writeStdout("      " ++ yellow ++ "configured limit exceeds baseline RAM ceiling" ++ R ++ "\n", .{});
        }
        writeRaw("\n");
    }

    // ─── USERS ──────────────────────────────────────
    writeStdout("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "USERS" ++ R ++ " ({d}) " ++ D ++ "────────────────────────────────────" ++ R ++ "\n", .{cfg.users.count()});
    var users = cfg.users;
    var it = users.iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ green ++ "●" ++ R ++ " " ++ B ++ "{s}" ++ R, .{entry.key_ptr.*});
        if (show_secrets) {
            writeRaw("  " ++ D);
            for (entry.value_ptr.*) |byte| {
                writeHexByte(byte);
            }
        } else {
            writeRaw("  " ++ D ++ "secret redacted");
        }
        writeRaw(R ++ "\n");
    }
    writeRaw("\n");

    // ─── LINKS ──────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "LINKS" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    if (!show_secrets) {
        writeRaw("      Secrets and connection links are hidden by default.\n");
        writeRaw("      Use --print-links only in a private terminal.\n");
    } else {
        writeConnectionLinkEntries(cfg);
    }

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Waiting for connections..." ++ R ++ "\n\n");

    stdout_accumulator = null;
    runtime_io.writeStdout(output.written());
}

pub fn main(init: std.process.Init) !void {
    // Use page_allocator instead of GeneralPurposeAllocator for production.
    // GPA has an internal mutex that causes deadlocks under heavy thread contention
    // (1000+ simultaneous connections all doing TLS validation allocations).
    const allocator = std.heap.page_allocator;
    const io = init.io;
    signals.ignoreSigpipe();

    // Parse config path and explicit secret-display modes.
    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    var config_path: []const u8 = "config.toml";
    var config_path_set = false;
    var show_secrets = false;
    var print_links = false;
    var check_config = false;
    var web_relay_mode = false;
    var web_probe_material_mode = false;
    var e2e_dc_port: ?u16 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "web-relay") and !config_path_set and !web_relay_mode and !web_probe_material_mode) {
            web_relay_mode = true;
        } else if (std.mem.eql(u8, arg, "web-probe-material") and !config_path_set and !web_relay_mode and !web_probe_material_mode) {
            web_probe_material_mode = true;
        } else if (std.mem.eql(u8, arg, "--show-secrets")) {
            show_secrets = true;
        } else if (std.mem.eql(u8, arg, "--print-links")) {
            print_links = true;
        } else if (std.mem.eql(u8, arg, "--check-config")) {
            check_config = true;
        } else if (build_options.e2e_test_hooks and std.mem.startsWith(u8, arg, "--e2e-dc-port=")) {
            const value = arg["--e2e-dc-port=".len..];
            const parsed = std.fmt.parseInt(u16, value, 10) catch {
                writeUsage();
                return error.InvalidArguments;
            };
            if (parsed == 0) {
                writeUsage();
                return error.InvalidArguments;
            }
            e2e_dc_port = parsed;
        } else if (!config_path_set) {
            config_path = arg;
            config_path_set = true;
        } else {
            writeUsage();
            return error.InvalidArguments;
        }
    }

    if ((show_secrets and print_links) or
        (check_config and (show_secrets or print_links or web_relay_mode or web_probe_material_mode)) or
        (web_probe_material_mode and (show_secrets or print_links)))
    {
        writeUsage();
        return error.InvalidArguments;
    }

    // Parse config
    var cfg = config.Config.loadFromFile(allocator, io, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeUsage();
        return err;
    };
    defer cfg.deinit(allocator);

    if (build_options.e2e_test_hooks) {
        if (e2e_dc_port) |port| {
            cfg.datacenter_override = net.ip4(.{ 127, 0, 0, 1 }, port);
        }
    }

    // Apply runtime log level from config
    runtime_log_level = cfg.log_level;

    cfg.validate() catch |err| {
        writeStderr(
            "\x1b[1m\x1b[31m  ✗ Invalid config '{s}': {s} ({s})\x1b[0m\n",
            .{ config_path, config.Config.validationErrorMessage(err), @errorName(err) },
        );
        return err;
    };

    if (check_config) {
        writeStdout("Config '{s}' is valid\n", .{config_path});
        return;
    }

    if (web_relay_mode) {
        if (show_secrets or print_links) return error.InvalidArguments;
        cfg.emitWarnings();
        return runWebRelay(allocator, io, &cfg);
    }

    if (web_probe_material_mode) {
        const material = try web_probe_material.render(allocator, io, &cfg);
        defer {
            std.crypto.secureZero(u8, material);
            allocator.free(material);
        }
        writeStdoutBytes(material);
        return;
    }

    if (print_links) {
        printConnectionLinks(cfg);
        return;
    }

    var shutdown_signals = try signals.ShutdownSignalBridge.init();
    defer shutdown_signals.deinit();

    if (!std.crypto.core.aes.has_hardware_support and (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)) {
        const log_main = std.log.scoped(.config);
        log_main.warn(
            "AES backend is software-only for this build/target. MiddleProxy video traffic will be CPU-heavy. " ++
                "Rebuild with CPU features enabled (example: -Dcpu=native or -Dcpu=x86_64_v3+aes).",
            .{},
        );
    }

    const capacity_estimate = if (resources.detectEffectiveMemoryBytes(allocator, io)) |memory_limit|
        estimateCapacity(&cfg, memory_limit)
    else
        null;

    try enforceCapacitySafety(&cfg, capacity_estimate);
    const managed_buffer_limit_bytes =
        managedBufferLimitForConnections(capacity_estimate, cfg.max_connections);

    // Print the startup banner without blocking on external discovery.
    printBanner(
        cfg,
        capacity_estimate,
        managed_buffer_limit_bytes,
        show_secrets,
    );

    // Emit config warnings (e.g. buffer too small, memory concerns)
    cfg.emitWarnings();

    // Create shared state (DI — no globals)
    var state = try proxy.ProxyState.initWithManagedBufferLimit(
        allocator,
        io,
        cfg,
        managed_buffer_limit_bytes,
    );
    defer state.deinit();

    // Run the proxy
    try state.run(shutdown_signals.fd);
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = resources;
    _ = signals;
    _ = @import("proxy/limits.zig");
    _ = @import("proxy/middle_proxy_handshake.zig");
    _ = @import("proxy/timeout_policy.zig");
    _ = proxy;
    _ = @import("proxy/web_support.zig");
    _ = @import("web/frame.zig");
    _ = @import("web/capability.zig");
    _ = @import("web/ws.zig");
    _ = @import("web/http.zig");
    _ = @import("web/page.zig");
    _ = @import("web/tokens.zig");
    _ = @import("web/site.zig");
    _ = web_probe_material;
    _ = web_relay;
}

test "capacity safety clamp enforces safe cap when override disabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 2 * 1024 * 1024 * 1024,
        .allocatable_bytes = 1200 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 256 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 585), cfg.max_connections);
}

test "capacity safety clamp keeps configured limit when override enabled" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 4096,
        .unsafe_override_limits = true,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 2 * 1024 * 1024 * 1024,
        .allocatable_bytes = 1200 * 1024 * 1024,
        .per_conn_bytes = 2 * 1024 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 256 * 1024 * 1024,
        .safe_connections = 585,
    };

    try enforceCapacitySafety(&cfg, est);
    try std.testing.expectEqual(@as(u32, 4096), cfg.max_connections);
}

test "capacity estimate accounts for mandatory DC 203 MiddleProxy overhead" {
    var direct_cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
        .middleproxy_buffer_kb = 1024,
    };
    defer direct_cfg.deinit(std.testing.allocator);

    var media_cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = true,
        .middleproxy_buffer_kb = 1024,
    };
    defer media_cfg.deinit(std.testing.allocator);

    const total_ram_bytes: u64 = 2 * 1024 * 1024 * 1024;
    const direct_est = estimateCapacity(&direct_cfg, total_ram_bytes);
    const media_est = estimateCapacity(&media_cfg, total_ram_bytes);

    try std.testing.expectEqual(media_est.managed_initial_per_conn_bytes, direct_est.managed_initial_per_conn_bytes);
    try std.testing.expectEqual(media_est.per_conn_bytes, direct_est.per_conn_bytes);
    try std.testing.expectEqual(media_est.safe_connections, direct_est.safe_connections);
}

test "capacity estimate reserves one shared managed buffer pool" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .use_middle_proxy = false,
        .force_media_middle_proxy = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const total_ram_bytes: u64 = 960 * 1024 * 1024;
    const est = estimateCapacity(&cfg, total_ram_bytes);

    try std.testing.expectEqual(@as(u64, 416 * 1024 * 1024), est.allocatable_bytes);
    try std.testing.expectEqual(@as(u64, 208 * 1024 * 1024), est.managed_burst_reserve_bytes);

    try std.testing.expectEqual(
        @as(u64, 2 * config.Config.middle_proxy_initial_stream_buffer_bytes),
        est.managed_initial_per_conn_bytes,
    );
    try std.testing.expectEqual(@as(u64, 40 * 1024), est.per_conn_bytes);
    try std.testing.expectEqual(@as(u32, 5_324), est.safe_connections);
    try std.testing.expectEqual(
        @as(u64, 216 * 1024 * 1024),
        managedBufferLimitForConnections(est, 256),
    );

    const unmanaged_per_conn =
        est.per_conn_bytes - est.managed_initial_per_conn_bytes;
    const safe_limit =
        managedBufferLimitForConnections(est, est.safe_connections);
    try std.testing.expect(
        safe_limit +
            @as(u64, est.safe_connections) * unmanaged_per_conn <=
            est.allocatable_bytes,
    );

    const overridden_connections = est.safe_connections + 1;
    try std.testing.expectEqual(
        est.allocatable_bytes -
            @as(u64, overridden_connections) * unmanaged_per_conn,
        managedBufferLimitForConnections(est, overridden_connections),
    );
    try std.testing.expectEqual(
        proxy.default_managed_buffer_limit_bytes,
        managedBufferLimitForConnections(null, 256),
    );
}

test "capacity estimate handles the largest finite cgroup v2 limit" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
    };
    defer cfg.deinit(std.testing.allocator);

    const est = estimateCapacity(&cfg, std.math.maxInt(u64));
    try std.testing.expectEqual(std.math.maxInt(u64), est.effective_memory_bytes);
    try std.testing.expectEqual(std.math.maxInt(u32), est.safe_connections);
}

test "capacity safety refuses a budget below the supported minimum" {
    var cfg = config.Config{
        .users = std.StringHashMap([16]u8).init(std.testing.allocator),
        .direct_users = std.StringHashMap(void).init(std.testing.allocator),
        .max_connections = 32,
        .unsafe_override_limits = false,
    };
    defer cfg.deinit(std.testing.allocator);

    const est = CapacityEstimate{
        .effective_memory_bytes = 128 * 1024 * 1024,
        .allocatable_bytes = 0,
        .per_conn_bytes = 8 * 1024,
        .managed_initial_per_conn_bytes = 0,
        .managed_burst_reserve_bytes = 0,
        .safe_connections = 0,
    };
    try std.testing.expectError(error.InsufficientMemoryBudget, enforceCapacitySafety(&cfg, est));
}
