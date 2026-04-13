---
name: MTProto Proxy Architecture
description: Core architecture, DPI evasion techniques, client behavior matrix, and networking rules for the Zig MTProto proxy.
---

# MTProto Proxy Architecture and Core Concepts

Production MTProto proxy implemented in Zig with FakeTLS entry, obfuscated MTProto relay, and optional AmneziaWG tunnel deployment for blocked regions.

## Tech Stack

- Language: Zig 0.15.2
- Networking: `std.net` sockets + Linux `epoll`
- Cryptography: `std.crypto` primitives (SHA256/HMAC/AES-CTR) plus project protocol layers
- Build: `build.zig` + `Makefile`
- Deployment: Linux VPS + systemd (`deploy/mtproto-proxy.service`), with optional tunnel setup from `deploy/setup_tunnel.sh`

## Runtime Model

- Relay path is a single-threaded Linux `epoll` event loop.
- Connections are represented by pooled `ConnectionSlot` state objects.
- File descriptors are tracked via epoll + fd-to-slot mapping.
- Recent runtime changes added safer failed-connect cleanup, bounded timer scanning, fd-budget clamping, 90%/80% saturation hysteresis, and low-noise periodic connection stats.
- A background updater thread refreshes MiddleProxy metadata from Telegram core endpoints once per 24h.

Code anchors:

- `src/proxy/proxy.zig` (`EventLoop`, `ConnectionSlot`, `runTimers`, `logPeriodicStats`, `requiredFdsForConnections`, `buildDcConnectPlan`)
- `src/main.zig` (startup banner, capacity estimate, lock-free logger)
- `deploy/setup_tunnel.sh` (namespace + AmneziaWG deployment path)

## Connection Flow

1. Client connects to proxy listener (`[::]:port` with IPv4 fallback).
2. Proxy reads TLS record header/body and validates FakeTLS digest against configured user secrets.
3. On valid auth:
- Builds fake `ServerHello` from template.
- Optional desync mode splits write into `1 byte + ~3ms + rest`.
4. Proxy assembles 64-byte MTProto obfuscation handshake from TLS appdata records.
5. Proxy derives MTProto crypto params and chooses upstream strategy:
- Direct DC path.
- MiddleProxy path (`use_middle_proxy=true` and endpoint available).
- Media path (`dc=203` or negative index) prefers MiddleProxy endpoint when available.
6. If MiddleProxy connect/handshake fails, proxy can reconnect directly to the same DC fallback endpoint.
7. Bidirectional relay starts (`relaying` phase).

## MiddleProxy Routing and Refresh

- Config text source: `https://core.telegram.org/getProxyConfig`
- Secret source: `https://core.telegram.org/getProxySecret`
- Refresh cadence: every 24h in updater thread.
- Bundled defaults are used when refresh fails.
- Candidate sets are kept for DC4 and DC203; selection can test reachability.

Important behavior:

- If a MiddleProxy endpoint is unavailable, direct path is allowed by the current connect-plan logic to avoid dropping valid users.
- `force_media_middle_proxy=true` is the default, so `direct` only affects regular DC traffic; media path still prefers MiddleProxy when available unless that knob is disabled.
- `[access.direct_users]` / `[access.admins]` bypass MiddleProxy entirely, including media paths.
- `server.middle_proxy_nat_ip` can pin the IPv4 used for MiddleProxy NAT/AES derivation when AWG/public-IP detection would choose the wrong address.
- Tunnel deployment supports `direct`, `preserve`, and `middleproxy` modes.

## Fast Mode

`fast_mode` applies to direct path (non-MiddleProxy) and delegates S2C crypto work to Telegram DC by embedding client S2C key material into outbound nonce flow. MiddleProxy relay stays encapsulated in its own framing/crypto path.

## Timeout Model

Current runtime timeout control is event-loop based:

- `idle_timeout_sec`: pre-first-byte wait and relay idle timeout.
- `handshake_timeout_sec`: timeout for handshake stages after first byte.

There is no active `SO_RCVTIMEO`-driven relay timeout model in current code.

## Capacity Model (as implemented)

Startup banner computes a safety estimate from host RAM:

```text
tls_working_bytes = ~6 KiB
middleproxy_per_conn_bytes = middleproxy_buffer_kb * 1024 * 2 (if ME enabled)
middleproxy_shared_bytes   = middleproxy_buffer_kb * 1024 * 2 (if ME enabled)
overhead_bytes    = ~2 KiB
per_conn_bytes    = tls_working_bytes + middleproxy_per_conn_bytes + overhead_bytes

usable_bytes  = RAM * 70%
reserve_bytes = max(256 MiB, RAM * 10%)
budget_bytes  = max(0, usable_bytes - reserve_bytes - middleproxy_shared_bytes)
safe_connections = max(32, budget_bytes / per_conn_bytes)
```

If `max_connections` exceeds the RAM-safe estimate, startup auto-clamps it before the proxy starts unless `[server].unsafe_override_limits = true`. With the override enabled, startup keeps the configured value and logs a RAM-safety warning. If `/proc/meminfo` cannot be read on Linux, startup logs that the RAM clamp was skipped.

`ProxyState.run` then applies a second, independent `RLIMIT_NOFILE` clamp before creating the event loop when the process soft fd limit cannot cover the effective connection cap.

## DPI Evasion Components

- FakeTLS ServerHello template with runtime digest patching.
- Anti-replay cache keyed by canonical HMAC digest.
- Masking target selection for unauthenticated clients: `mask_port=443` resolves/connects to `tls_domain:443`; non-443 `mask_port` connects to a local address on that port (`127.0.0.1` in the init namespace, `10.200.200.1` inside the tunnel netns), so that port must be served by Nginx or another local masking backend.
- TCPMSS clamping and optional zapret/nfqws integration via deploy scripts.
- Split-TLS desync (`desync=true`) as split write of fake ServerHello.
- Self-domain masking setup (`setup_masking.sh`) configures Nginx on `127.0.0.1:8443` and, in tunnel netns mode, `10.200.200.1:8443`; non-proxy requests receive 404.

## What To Verify During Changes

- `epoll` interests and queue flushing remain non-blocking and symmetric.
- Direct/MiddleProxy fallback logic still preserves media and non-media expectations.
- Timeout behavior remains controlled by config timers.
- Deploy docs remain aligned with current tunnel/direct-mode behavior.
- Docs remain aligned with code paths and log messages.
