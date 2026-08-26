---
name: MTProto Proxy Architecture
description: Core architecture, DPI evasion techniques, client behavior matrix, and networking rules for the Zig MTProto proxy.
---

# MTProto Proxy Architecture and Core Concepts

Production MTProto proxy implemented in Zig with FakeTLS entry, obfuscated MTProto relay, and optional AmneziaWG tunnel deployment for blocked regions.

## Tech Stack

- Language: Zig 0.16.0
- Networking: Linux sockets + `epoll` via a local Zig 0.16 `net_compat` facade
- Cryptography: `std.crypto` primitives (SHA256/HMAC/AES-CTR/AES-CBC) plus project protocol layers
- Optional WEB carrier: a separate `mtproto-proxy web-relay` process behind the existing Caddy service; ordinary FakeTLS and WEB links share the public proxy listener and user secrets
- HTTP metadata fetch: `src/http_fetch.zig` wraps `std.http` with bounded response sizes, whole-request timeout behavior, redirect-by-redirect resolver preflight, and owner-thread cancellation
- Build: `build.zig` + `Makefile`
- Deployment: Linux VPS + systemd (`deploy/mtproto-proxy.service`), with optional tunnel setup from `deploy/setup_tunnel.sh`

## Runtime Model

- Relay path is a single-threaded Linux `epoll` event loop. The large `EventLoop` container (including fixed admission tables) is allocated once on the heap and initialized in place so Debug builds do not reserve multi-megabyte stack frames.
- `SIGINT` and `SIGTERM` use a minimal `sigaction` handler that writes to a non-blocking `eventfd` registered in epoll. Shutdown work never runs in signal context: the event loop exits first, closes active slots, then the listener closes before the discovery updater is canceled and joined.
- Connections are represented by pooled `ConnectionSlot` state objects.
- Epoll payloads encode slot index, generation, and client/upstream role directly in `epoll_event.data.u64`; dispatch has no fd hash lookup, and generation checks reject stale events after slot/fd reuse.
- Connection deadlines live in an indexed min-heap with one entry per active slot. A monotonic `timerfd` is armed to the earliest slot, accept-backoff, or stats deadline, eliminating the historical full-slot timer scan.
- Outbound data uses intrusive `MessageQueue` blocks whose allocation occupies one page, served by one capped event-loop-wide free list. Queue pages, retained free-list pages, MiddleProxy stream buffers, and shared scratch are charged to one hard `ManagedBufferAllocator` budget. Appends pack the current tail before acquiring another block; bounded `writev` flushing and a 4 MiB pending-byte cap apply per direction queue. Read/drain/write loops have explicit byte and operation budgets per dispatch.
- Relay slots track client/upstream read EOF and write shutdown independently. A frame-aligned EOF stops only that source read; after its destination queue drains, `shutdown(SHUT_WR)` propagates FIN without disabling the reverse direction. EOF inside a FakeTLS or MiddleProxy frame fails closed.
- A joinable background updater starts after the listener when MiddleProxy or masking discovery is needed. It refreshes MiddleProxy metadata, detects the NAT IPv4, re-resolves all masking candidates hourly, probes endpoints in cancellable batches of four, can wake early after stalled MiddleProxy handshakes, and is stopped cooperatively on `ProxyState.deinit`. DNS, built-in HTTPS, and curl fallback operations race an atomic stop watcher inside an owner-thread `std.Io.Select`; every late allocated result is drained before the updater is joined.
- MiddleProxy handshakes copy only the selected route candidates and a secret version/NAT value, release handshake-only storage at relay start, and parse each C2S frame header once. Current and immediately previous secrets live centrally under the metadata lock, so selector/KDF inputs stay consistent without a per-handshake secret copy. Runtime CBC state is direction-specific; high-frequency protocol randomness comes from a per-thread ChaCha20 DRBG reseeded from the OS CSPRNG.
- WEB mode keeps failure isolation by running its HTTP/WebSocket multiplexer in a second process with its own single-threaded, level-triggered epoll loop. Caddy terminates the real browser TLS carrier on an internal listener; each logical WEB stream then returns to the ordinary proxy data plane as a PROXY-v2-prefixed direct-obfuscated connection.

Code anchors:

- `src/proxy/proxy.zig` (`EventLoop`, `ConnectionSlot`, `runTimers`, `logPeriodicStats`, `requiredFdsForConnections`, `buildDcConnectPlan`)
- `src/main.zig` (startup banner, capacity estimate, lock-free logger, public-IP detection)
- `src/http_fetch.zig` (bounded HTTPS fetch helper for background public-IPv4 and MiddleProxy metadata discovery)
- `deploy/setup_tunnel.sh` (namespace + AmneziaWG deployment path)

## Connection Flow

1. Client connects to proxy listener (`[::]:port` with IPv4 fallback).
2. Proxy reads TLS record header/body and validates FakeTLS digest against configured user secrets. The current FakeTLS template requires a 32-byte ClientHello Session ID and echoes it in ServerHello.
3. On valid auth:
- Builds fake `ServerHello` from template.
- Optional desync mode splits write into `1 byte + ~3ms + rest`.
4. Proxy assembles 64-byte MTProto obfuscation handshake from TLS appdata records. Extra client appdata bytes pipelined after the nonce are buffered up to one max TLS ciphertext and forwarded after upstream setup.
5. Proxy derives MTProto crypto params and chooses upstream strategy:
- Direct DC path.
- MiddleProxy path (`use_middle_proxy=true` and endpoint available).
- Media path (`dc=203` or negative index) prefers MiddleProxy endpoint when available; DC203 has no real direct endpoint.
6. If MiddleProxy connect/handshake fails, proxy can reconnect directly when the selected DC has a real fallback endpoint. DC203 never uses a raw direct fallback.
7. Bidirectional relay starts (`relaying` phase).

## WEB Proxy Flow (Telegram Desktop 7.1+)

1. Telegram Desktop opens a browser HTTPS carrier to `[web].domain` on public `:443`; ordinary FakeTLS clients continue to use the same listener with `censorship.tls_domain`.
2. The proxy recognizes the WEB SNI and relays the untouched TLS connection to `[web].mask_backend`, prefixing PROXY v2 with the kernel-reported browser address.
3. The existing Caddy service terminates TLS, serves the capability-gated bridge page, and reverse-proxies the same-origin WebSocket to the loopback WEB relay.
4. The relay authenticates the bridge capability derived from the configured user secret and multiplexes logical streams with the Telegram Desktop WEB frame protocol.
5. Every logical stream connects back to `[web].backend`, prefixes PROXY v2 with the browser address, and carries the client's `dd` direct-obfuscated MTProto stream into the normal DC/MiddleProxy routing path.

Trust is fixed from the kernel-reported peer at `accept()`: only loopback plus explicit `[web].relay_sources` may enter the direct-obfuscated path. A PROXY header may replace the diagnostic/client address but must never grant trust. WEB-domain masking carriers are deliberately exempt from `mask_relay_max_secs`; ordinary masking/probe relays retain that lifetime cap.

## MiddleProxy Routing and Refresh

- Config text source: `https://core.telegram.org/getProxyConfig`
- Secret source: `https://core.telegram.org/getProxySecret`
- Refresh cadence: hourly in the updater thread, with debounced reactive refresh after stalled MiddleProxy handshakes.
- Bundled defaults are used when refresh fails.
- Candidate sets are kept separately for regular DC1..5, media-path DC1..5, DC4 candidate lists, and DC203; selection can test reachability.

Important behavior:

- If a MiddleProxy endpoint is unavailable, direct path is allowed by the current connect-plan logic when that DC has a real direct endpoint; DC203 is excluded.
- Each MiddleProxy handshake stage has a 5-second deadline. A stalled or malformed endpoint is cooled for 60 seconds, triggers reactive refresh, and falls back directly when possible, except for DC203.
- `force_media_middle_proxy=true` is the default, so `direct` only affects regular DC traffic; media path still prefers MiddleProxy when available unless that knob is disabled.
- `[access.direct_users]` / `[access.admins]` bypass MiddleProxy for regular and media paths with real direct endpoints. DC203 still uses MiddleProxy when its route is available.
- `datacenter_override` is test-only and disables MiddleProxy snapshot/updater routing.
- `server.middle_proxy_nat_ip` can pin the IPv4 used for MiddleProxy NAT/AES derivation when AWG/public-IP detection would choose the wrong address.
- `middleproxy_buffer_kb` is a per-direction cap. Each MiddleProxy context starts with 16 KiB C2S/S2C buffers and grows on demand up to `min(middleproxy_buffer_kb, 3840)` KiB; event-loop scratch buffers are lazy and reused. The effective cap reserves 256 KiB for MP/TLS framing before the 4 MiB relay-queue limit.
- MiddleProxy handshake/read failures and upstream fatal hangups can fall back to direct when the connect plan has a direct fallback address.
- Tunnel deployment supports `direct`, `preserve`, and `middleproxy` modes.

## Fast Mode

`fast_mode` applies to direct path (non-MiddleProxy) and delegates S2C crypto work to Telegram DC by embedding client S2C key material into outbound nonce flow. MiddleProxy relay stays encapsulated in its own framing/crypto path.

For config compatibility, `fast_mode` is accepted in `[general]`, `[server]`, or `[censorship]`; all three set the same `Config.fast_mode` flag.

## Timeout Model

Current runtime timeout control is event-loop based:

- Pre-first-byte wait: fixed 10 seconds.
- `idle_timeout_sec`: established relay idle timeout.
- `handshake_timeout_sec`: timeout for handshake stages after first byte.
- `client_silence_close_sec`: conservative unanswered-reply fallback on generic DC relays, enabled only after at least 30 seconds in relay and a delivered reply followed by further client traffic on the same connection.
- `client_silence_fast_close_sec`: optional fast unanswered-reply close after an established generic relay resumes from `client_silence_fast_after_idle_sec` of silence.

Each slot stores one current absolute deadline in the indexed heap. Idle jitter is computed once at admission and reused when activity moves that deadline. iOS wedge candidates use the same heap, exclude media relays, require a server response within the 12-second client response window, and start only after the userspace client queue drains. The conservative fallback cannot become eligible during the first 30 seconds of relay; after that maturity floor, the client must still continue after an earlier delivered reply. This keeps normal startup exchanges from arming breaker-driven reconnect loops.

There is no active `SO_RCVTIMEO`-driven relay timeout model in current code.

## Capacity Model (as implemented)

Startup computes a baseline RAM admission ceiling from the effective process memory limit:

```text
tls_working_bytes = ~6 KiB
overhead_bytes = ~2 KiB
managed_initial_per_conn = 2 * 16 KiB (if any MiddleProxy mode is enabled)
per_conn_bytes = tls_working_bytes + overhead_bytes + managed_initial_per_conn

effective_memory = min(host RAM, all visible limits in the active cgroup v2/v1 hierarchy)
usable_bytes  = effective_memory * 70%
reserve_bytes = max(256 MiB, effective_memory * 10%)
allocatable_bytes = max(0, usable_bytes - reserve_bytes)
managed_burst_reserve = allocatable_bytes / 2
connection_budget = allocatable_bytes - managed_burst_reserve
safe_connections = connection_budget / per_conn_bytes

unmanaged_per_conn = per_conn_bytes - managed_initial_per_conn
managed_buffer_limit =
    min(managed_burst_reserve + max_connections * managed_initial_per_conn,
        allocatable_bytes - max_connections * unmanaged_per_conn)
```

The startup ceiling no longer multiplies every connection by two full 4 MiB relay queues and two full MiddleProxy caps. Those are independent protective maxima, not simultaneous guaranteed resident memory. The ceiling therefore guarantees baseline admission under the enforced shared budget; it is not a simultaneous full-buffer throughput claim. The event loop routes queue blocks, retained free-list blocks, MiddleProxy C2S/S2C buffers, and shared scratch through `ManagedBufferAllocator`. It tracks requested live bytes, refuses remap so allocate-before-free growth is charged at its transient peak, and keeps recycled queue pages charged until they are actually destroyed. Budget exhaustion follows existing OOM handling: optional shrink retains the existing buffer, while required growth closes the requesting connection or falls back to the direct path where possible. Every denial is reported as `memory_pressure+=...` in periodic stats.

The runtime limit includes the 16 KiB-per-direction MiddleProxy baseline for every configured slot plus the shared burst reserve, but is capped so the unmanaged baseline and managed allocation ceiling cannot exceed `allocatable_bytes` together. When effective memory cannot be detected, the managed pool uses a 64 MiB default. For a 960 MiB limit with media MiddleProxy enabled and `max_connections=256`, the banner reports a ~40 KiB baseline, ~216 MiB shared dynamic-pool limit, a baseline RAM ceiling of ~5324, the separately configured cap, and the 90%/80% admission hysteresis.

The cgroup detector resolves the process membership through `/proc/self/cgroup` and `/proc/self/mountinfo`, then takes the lowest readable leaf or ancestor limit. In cgroup v2 a numeric `0` is a real hard limit; only `max` means unlimited. Conventional `/sys/fs/cgroup` paths remain a fallback when procfs mount metadata is unavailable.

If `max_connections` exceeds the baseline RAM ceiling, startup auto-clamps it before the proxy starts unless `[server].unsafe_override_limits = true`. If the ceiling is below the supported minimum of 32 slots, safe mode fails startup instead of forcing 32. With the override enabled, startup keeps the configured value and logs a warning; the shared dynamic-pool hard limit remains active. If neither host nor cgroup memory can be read on Linux, startup logs that the RAM admission clamp was skipped.

`ProxyState.run` then applies a second, independent `RLIMIT_NOFILE` clamp before creating the event loop when the process soft fd limit cannot cover the effective connection cap. If the fd budget cannot support the minimum 32 slots (576 descriptors including overhead), startup fails instead of advertising an impossible capacity.

## DPI Evasion Components

- FakeTLS ServerHello template with runtime digest patching.
- FakeTLS uses one strict ClientHello framing parser for authentication, SNI, cipher, and PQ key-share reads. It accepts only 32-byte Session IDs, stores the Session ID by value, and securely releases the full ClientHello as soon as the synthetic ServerHello is built.
- Anti-replay cache compares the full canonical HMAC digest, retains entries for the maximum FakeTLS timestamp-validity horizon, and replaces the oldest entry in a saturated bounded probe window so cache pressure cannot masquerade as a proven replay.
- MTProto obfuscation rejects reserved nonces before decrypting protocol tags.
- Unknown MTProto DC indices are rejected before endpoint planning; modulo fallback is not part of the connection path.
- Masking target selection for unauthenticated clients: `mask_port=443` resolves every address for `tls_domain:443` in the background, prefers IPv4, and fails over across candidates; non-443 `mask_port` connects to a local address on that port (`127.0.0.1` in the init namespace, `10.200.200.1` inside the tunnel netns). Hostname candidates are re-resolved hourly.
- Config parsing is strict for proxy-owned sections/keys and malformed lines; `[monitor].host`/`port` remain accepted for the external dashboard. Config load errors propagate as a non-zero process exit.
- TCPMSS clamping, SYN pacing, and zapret/nfqws integration are external-path mitigations; deploy rules exclude loopback so WEB relay streams never enter pacing, tiny-MSS, or NFQUEUE processing.
- Split-TLS desync (`desync=true`) as split write of fake ServerHello.
- Self-domain masking setup (`setup_masking.sh`) configures Caddy 2.10+ on `127.0.0.1:8443` and, in tunnel netns mode, `10.200.200.1:8443`; non-proxy requests receive 404. Optional WEB setup extends that same Caddy instance with an internal PROXY-protocol listener on `8444` and a loopback relay on `8081`. Source installs use `mtproto-mask-caddy.service`; Docker Compose installs use the `mtproto-mask-caddy` service/container.

## What To Verify During Changes

- `epoll` interests and queue flushing remain non-blocking and symmetric.
- FakeTLS validation keeps the 32-byte Session ID contract with `src/protocol/tls.zig` templates.
- Pipelined appdata after the 64-byte MTProto nonce is preserved across direct and MiddleProxy startup.
- Direct/MiddleProxy fallback logic still preserves media and non-media expectations.
- MiddleProxy buffer changes preserve 16 KiB initial allocation, on-demand growth, and the 3840 KiB effective cap derived from the 4 MiB relay queue minus framing headroom.
- Timeout behavior remains controlled by config timers.
- WEB carrier requests remain capability-gated, WELCOME stays alone in the first binary carrier message, trusted relay status cannot be forged through PROXY v2, and direct-obfuscated RDHUP follows the direct relay path rather than FakeTLS record parsing.
- CI remains green across `zig fmt --check`, Debug tests, ReleaseSafe tests, daemon smoke with positive and bad-secret paths, ReleaseFast builds, cross-builds, ShellCheck, Python syntax checks, Docker build smoke, bench, and soak.
- Deploy docs remain aligned with current tunnel/direct-mode behavior.
- Docs remain aligned with code paths and log messages.
