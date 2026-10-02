---
name: MTProto Proxy Architecture
description: Core architecture, DPI evasion techniques, client behavior matrix, and networking rules for the Zig MTProto proxy.
---

# MTProto Proxy Architecture and Core Concepts

Production MTProto proxy implemented in Zig with FakeTLS entry, obfuscated MTProto relay, and optional AmneziaWG tunnel deployment for blocked regions.

## Tech Stack

- Language: Zig 0.16.0
- Networking: canonical Zig 0.16 `std.Io.net.IpAddress`; `src/net_helpers.zig` contains DNS policy and the narrow Linux sockaddr/listener boundary, while the proxy data plane retains epoll/timerfd/eventfd.
- Runtime: Zig 0.16 `main(init).io` is borrowed for config, bounded pseudo-file reads, DNS, HTTPS, and WEB startup/runtime helpers. `ProxyState`, WEB `Relay`, and the joinable WEB DNS cache retain only borrowed `std.Io` handles and join their workers before `main` exits. `src/runtime/` keeps intentional synchronous Linux clocks, futex locking, direct daemon output, and the thread-local secure DRBG; the epoll data plane does not use `std.Io`.
- Cryptography: `std.crypto` primitives (SHA256/HMAC/AES-CTR/AES-CBC) plus project protocol layers
- Optional WEB carrier: a separate `mtproto-proxy web-relay` process behind the existing Caddy service; ordinary FakeTLS and WEB links share the public proxy listener and user secrets by default, while `[web].only=true` can mask the direct door and retain only the relay path
- HTTP metadata fetch: `src/http_fetch.zig` wraps `std.http` with bounded response sizes, whole-request timeout behavior, redirect-by-redirect resolver preflight, and owner-thread cancellation
- Build: `build.zig` + `Makefile`
- Deployment: Linux VPS + systemd (`deploy/mtproto-proxy.service`), with optional tunnel setup from `deploy/setup_tunnel.sh`

## Runtime Model

- Relay path defaults to one Linux `epoll` event loop. `server.workers=0` selects a bounded CPU-based count; explicit `2..16` uses one `SO_REUSEPORT` listener, loop, `timerfd`, deadline heap, connection pool, queue free list, and 32 KiB relay-read scratch per worker. `EventLoop` is allocated on the heap; admission/replay tables are one shared heap allocation, not copied per worker. Every scratch consumer finishes or copies bytes before that worker dispatches another event.
- `SIGINT` and `SIGTERM` use a minimal `sigaction` handler that writes to a non-blocking `eventfd`. For multiple workers, only the control thread reads it and broadcasts to separate worker eventfds; a shared eventfd would not wake all epoll waiters. First notification removes each listener's interest and drains that worker's slots for `graceful_shutdown_timeout_sec`; another notification or the deadline closes its remaining slots. The control thread joins every worker before the discovery updater is canceled and joined. A failed worker closes its listener before teardown; a stale worker heartbeat exits the process so no dead reuseport group member persists.
- Connections are represented by pooled `ConnectionSlot` state objects.
- Epoll payloads encode slot index, generation, and client/upstream role directly in `epoll_event.data.u64`; dispatch has no fd hash lookup, and generation checks reject stale events after slot/fd reuse.
- Ordinary `net_helpers.acceptFd` and WEB `socket_utils.acceptClient` share `acceptNeedsRetry`, a pure Linux errno policy: EINTR retries with fresh sockaddr capacity, while EAGAIN and the documented TCP pending network errors end the accept round. Abort/reset remain caller retries, fd/resource errors still invoke their existing pause/resume logic, and EPERM is surfaced as `BlockedByFirewall`. Unknown errno retain `posix.unexpectedErrno` diagnostics (WEB translates the domain error to `UnexpectedAccept`); listener saturation and batching are unchanged.
- Connection deadlines live in an indexed min-heap with one scheduled wakeup per active slot. A monotonic `timerfd` is armed to the earliest slot, accept-backoff, process-shutdown, or stats deadline, eliminating the historical full-slot timer scan. A selected sliding relay-idle extension may retain an earlier wakeup; selected absolute limits update eagerly.
- Outbound data uses intrusive `MessageQueue` blocks whose allocation occupies one page, served by a capped worker-local free list. Queue pages, retained free-list pages, MiddleProxy stream buffers, and scratch are charged to that worker's partition of the original process `ManagedBufferAllocator` budget; partition sums equal the original cap. Connection-slot and deadline-heap capacities are partitioned the same way. Appends pack the current tail before acquiring another block; bounded `writev` flushing and a 4 MiB pending-byte cap apply per direction queue. Read/drain/write loops have explicit byte and operation budgets per dispatch.
- `ProxyState` remains process-global: config and user secrets are immutable while workers run; MiddleProxy and masking address snapshots use the existing metadata lock, WEB DNS has its own synchronization, and connection/handshake/stat totals use relaxed atomics for numeric accounting. A shared security allocation locks subnet rate, subnet handshake, and replay tables; a separate lock covers the optional iOS wedge-recovery gate. Ordinary relay byte I/O takes no global lock. No SIGHUP/live config reload is implemented; config strings outlive all joined workers.
- Relay slots track client/upstream read EOF and write shutdown independently. The first frame-aligned EOF is retained as client/upstream initiator, without conflating it with a fatal close or later opposite-side EOF. After its destination queue drains, `shutdown(SHUT_WR)` propagates FIN without disabling the reverse direction. EOF inside a FakeTLS or MiddleProxy frame fails closed. Close diagnostics derive lifetime from the existing monotonic admission timestamp; only worker 0 delta-logs process-wide first-EOF counters.
- Ordinary `EPOLLIN`, graceful `RDHUP` and error-free established-relay `HUP` use the same bounded drain through FakeTLS, direct-obfuscated or masking handlers. Reads/writes share 256 KiB/64 operations; pending destination output, EOF, or phase/fd/generation changes stop reading. Because HUP is unmaskable, interest sync removes its fd while backpressure prevents reads and re-adds it with a fresh generation once output drains. Fully read-closed/write-shut fds remain removed until slot cleanup. Keep frame-boundary EOF checks, queued-byte delivery, fatal ERR handling and MP handshake recovery; epoll stays level-triggered and deadlines update at dispatch boundaries.
- A joinable background updater starts during startup without waiting for discovery before the listener. It refreshes MiddleProxy metadata, detects the NAT IPv4, re-resolves all masking candidates hourly, probes endpoints in cancellable batches of four, can wake early after stalled MiddleProxy handshakes, and is stopped cooperatively after all data-plane workers join. DNS, built-in HTTPS, and curl fallback operations race an atomic stop watcher inside an owner-thread `std.Io.Select`; every late allocated result is drained before the updater is joined.
- `ProxyState.io` borrows the `std.process.Init.io` backend for startup DNS and discovery only; its updater and any WEB mask DNS worker are joined during state teardown. The separate WEB relay process borrows its own `main` Io for bounded site loading, DNS/getent, token entropy, and HTTP Date timestamps; its DNS cache worker is joined before that process returns. No borrowed Io escapes its process entry point.
- Ordinary native DNS uses a scope-owned `std.Io.concurrent` producer plus cancelable draining of its 32-result queue. Actual Zig 0.16 Threaded DNS/hosts loops can emit more results despite HostName.lookup's capacity-16 comment. OOM suppresses further consumer allocations but drains to closure and joins; external cancellation cancels/joins the producer before queue/hostname state leaves scope. The producer owns queue closure, including failure/cancellation. Resolver preflight, literal fast path and the updater's outer Select/late-result cleanup remain intact; WEB's joined native fallback and bounded Linux getent path are unchanged.
- MiddleProxy handshakes copy only the selected route candidates and a secret version/NAT value, release handshake-only storage at relay start, and parse each C2S frame header once. Candidate sets of up to four addresses use inline slot storage; larger DNS/failover sets use owned heap fallback and must preserve replacement/failure cleanup. Current and immediately previous secrets live centrally under the metadata lock, so selector/KDF inputs stay consistent without a per-handshake secret copy. A bounded endpoint-health table under that same lock ranks the snapshot using TCP/auth timing and failure history; the established relay has no health lookup. Runtime CBC state is direction-specific; high-frequency protocol randomness comes from a per-thread ChaCha20 DRBG reseeded from the OS CSPRNG.
- WEB mode keeps failure isolation by running its HTTP/WebSocket multiplexer in a second process with its own single-threaded, level-triggered epoll loop. Caddy terminates the real browser TLS carrier on an internal listener; each logical WEB stream then returns to the ordinary proxy data plane as a PROXY-v2-prefixed direct-obfuscated connection. The optional WEB-only gate stays in that ordinary data plane, where trust is already fixed from the accepted peer.
- WEB carrier preflight validates all shapes and per-stream transitions before mutation. Its fixed scratch holds at most 4096 batch IDs, heap-sorts/deduplicates them, and uses binary searches through one scan of the bounded closed history. Control-only batches skip stream/history lookup. Preserve late DATA/WINDOW/CLOSE handling and refused-OPEN tombstones; do not restore the client-controlled multiplicative hash or rebuild closed IDs into a temporary hash table on every message.

Code anchors:

- `src/proxy/proxy.zig` (`ProxyState`, worker startup/shutdown, `EventLoop` dispatch, timeout actions, MiddleProxy metadata publication)
- `src/proxy/connection.zig`, `connection_pool.zig`, `deadline_queue.zig` (slot ownership and wiping, generation-tagged fd roles, indexed deadlines)
- `src/proxy/limits.zig`, `message_queue.zig`, `managed_buffer_allocator.zig`, `relay_io.zig` (shared fixed queue/ME headroom budgets, worker-local queue pages, managed accounting, budgeted relay reads/writes and frame-aligned half-close checks)
- `src/proxy/security_state.zig`, `wedge_recovery.zig` (process-shared admission tables/gate and per-slot recovery tracker)
- `src/proxy/middle_proxy_nat.zig`, `middle_proxy_routing.zig`, `middle_proxy_handshake.zig`, `timeout_policy.zig` (egress discovery, route/cooldown policy, handshake KDF/frame preparation, pure slot-deadline calculations)
- `src/proxy/socket_ops.zig`, `src/runtime/tcp_options.zig`, `src/runtime/linux_events.zig` (proxy-specific socket errors, shared best-effort TCP tuning, and epoll/timerfd/eventfd primitives)
- `src/main.zig` (CLI/startup orchestration, capacity policy/banner, lock-free logger, public-IP detection)
- `src/runtime/io.zig` shares the startup-only runtime log level between the logger and `logEnabled(level, scope)` guards. Set it before starting workers; guard diagnostic-only address formatting, clocks and divisions before computing their arguments. Preserve functional preparation and enabled log contents.
- `src/runtime/resources.zig`, `src/runtime/signals.zig` (host/cgroup memory detection and the process signal/eventfd bridge; neither owns the application `std.Io` backend)
- `src/http_fetch.zig` (bounded HTTPS fetch helper for background public-IPv4 and MiddleProxy metadata discovery)
- `deploy/setup_tunnel.sh` (namespace + AmneziaWG deployment path)

## Proxy Module Ownership

`proxy.zig` is the orchestration layer, not the owner of every data structure it
operates on. `ProxyState` owns the immutable configuration and secrets, shared
security allocation, mutable MiddleProxy metadata and updater, and workers. It
outlives every worker and joins them before stopping discovery or freeing shared
state. Its security pointer is allocated once for the process: subnet rate,
unauthenticated-slot and replay tables must never be copied per worker. The
optional group-wide wedge gate lives behind its own shared lock; the
`WedgeTracker` embedded in each connection remains worker-local.

Each worker exclusively owns its `EventLoop`, reuseport listener, control fd,
`ConnectionPool`, `DeadlineQueue`, `MessageBlockPool`, managed allocator
partition, and relay scratch. The pool heap-creates `ConnectionSlot` objects on
demand and destroys them after `resetOwnedBuffers()`; slot close removes its
single indexed deadline before pool release. The deadline queue borrows the
worker's slot pointers only during insert/update/remove and never retains an
`EventLoop` or pool-field pointer. `timeout_policy.zig` calculates slot and
handshake deadlines from a slot plus narrow configuration inputs; `EventLoop`
selects those inputs and arms the monotonic `timerfd`. The heap only maintains
order and slot indices.

Both per-slot queues own their intrusive page chains; the worker block pool may
retain wiped pages until teardown. Queue pages, retained free pages, MiddleProxy
stream buffers, and scratch charge the worker's `ManagedBufferAllocator`
partition. `proxy/limits.zig` is the single source of truth for the fixed 4 MiB
queue ceiling, 256 KiB ME framing headroom, and resulting stream cap; the queue
and MiddleProxy protocol no longer import the config schema for those values.
`ConnectionSlot.releaseHandshakeOnly()` drops temporary handshake
storage at relay start, while `resetOwnedBuffers()` wipes all remaining owned
secrets and buffers at close. Candidate addresses are inline for up to four
entries or owned heap fallback; `ProxyState` copies the selected route into a
local snapshot under the MiddleProxy metadata lock, then the slot copies its
candidate list from that snapshot. The protocol wire/crypto
implementation remains in `src/protocol/middleproxy.zig`; NAT detection and
route/cooldown selection live in the proxy modules named above. The pure
`middle_proxy_handshake.zig` derives directional keys from already selected
nonce/address/secret inputs and encodes outgoing handshake frames.
`MiddleProxyTransport` owns the client-independent nonce/auth state machine,
CBC chaining, RPC sequence numbers, and bounded nonblocking frame parser.
The cold `ConnectionSlot` embeds it; after authentication the CBC/sequence
state transfers once into the client-specific `MiddleProxyContext`.
`EventLoop` still owns fd/epoll registration, socket address queries, the
versioned-secret read lock, stage deadlines, fallback, and phase transitions;
`ProxyState` still owns refresh and publication. There is no warm pool yet.

`relay_io.zig` performs bounded fd operations, queue writes/flushes, TLS record
wrapping, and frame-boundary checks without new locks or packet-path
allocations. `EventLoop` keeps the actual phase transitions, FIN propagation,
epoll interest updates, and timeout actions. The proxy and WEB relay share
`epollCreate` in `runtime/linux_events.zig` and TCP_NODELAY/keepalive/
TCP_USER_TIMEOUT values in `runtime/tcp_options.zig`. The per-fd first-probe
delay is staggered across 30–60 seconds so mass admission does not synchronize
kernel probes. The 90-second user timeout covers the latest first probe plus
10 × 3-second keepalive probe window; otherwise Linux can
abort an idle connection after only one lost probe. Socket tuning remains
best-effort: proxy keeps trying keepalive options after one failure, while WEB
stops that keepalive sequence; both still attempt TCP_USER_TIMEOUT. Their
connect-error mapping, address formatting, and relay policy remain separate.
Dependencies point from runtime/protocol/config through queue,
security, connection and routing components toward `proxy.zig`, never back
from a low-level module into `EventLoop`.

## Connection Flow

1. Client connects to proxy listener (`[::]:port` with IPv4 fallback).
2. Proxy reads TLS record header/body and validates FakeTLS digest against configured user secrets. The current FakeTLS template requires a 32-byte ClientHello Session ID and echoes it in ServerHello.
3. On valid auth:
- Builds fake `ServerHello` from template.
- `desync=false` by default sends the complete fake ServerHello without an intentional pause. Explicit `desync=true` splits it into `1 byte + delay/jitter + rest` (3–5 ms with default timing). `TCP_NODELAY` is configured immediately after admission for either mode.
4. Proxy assembles 64-byte MTProto obfuscation handshake from TLS appdata records. Extra client appdata bytes pipelined after the nonce are buffered up to one max TLS ciphertext and forwarded after upstream setup.
5. Proxy derives MTProto crypto params and chooses upstream strategy:
- Direct DC path.
- MiddleProxy path (`use_middle_proxy=true` and endpoint available).
- Negative DC1..5 media paths may prefer MiddleProxy; DC203 always requires it because it has no real direct endpoint.
6. MiddleProxy TCP and endpoint-specific handshake failures try the next candidate within the original client handshake deadline. After candidates are exhausted, the proxy can reconnect directly only when the selected DC has a real fallback endpoint. Shared-secret/metadata failures skip futile same-version MP retries; DC203 never uses a raw direct fallback.
7. Bidirectional relay starts (`relaying` phase).

## Offline Relay Stress Boundary

`test/stress_ci.py` and `.github/workflows/stress-ci.yml` exercise this same
FakeTLS → obfuscated MTProto → direct-DC relay path with thousands of complete
synthetic sessions, not merely TCP/FakeTLS capacity. The asyncio fake DC derives
the direct nonce ciphers and validates connection-ID/sequence/checksum-bound
intermediate frames; each client verifies its own decrypted response. The
batch nonce generator uses the production obfuscation implementation. The
loopback DC override exists only in `mtproto-proxy-e2e` under compile-time
`e2e_test_hooks`; normal shipping `mtproto-proxy` cannot select it. The harness
keeps production worker-local epoll/queues/deadlines and process-wide admission
tables intact, including the 128 in-flight per-subnet handshake bound. A
64-connection opening gate avoids making valid load appear hostile. Stress CI
derives capacity from the seeded population with headroom above the 90%
admission-pause threshold, checks the live reuseport group
for multi-worker runs, and records worker-local stats and resource recovery.
The resource timeline also records Linux TCP keepalive/abort and softnet
receive-drop/budget counters to help diagnose socket timeout under load.
The test-generated proxy idle timeout is at least one hour, beyond the hosted
workflow's 45-minute limit, so intentionally idle held relays cannot expire
before later stress phases; production idle settings are unchanged.
The fake DC waits up to 61 minutes for a new frame's first byte; the remainder
of its header and body each retain a 30-second timeout. Idle endurance peers
are not protocol failures.
The `queue_pressure` stress phase forces C2S and S2C backpressure only at
synthetic peer sockets, below each 4 MiB relay-queue ceiling. S2C fake-DC
responses are held until every request has been validated, separating its
managed-peak increase from C2S congestion. Each direction must increase the
historical worker-local managed peak and subsequently verify the full drained
response stream; retained `MessageBlockPool` pages may keep current managed
usage nonzero. Optional `endurance` holds a full persistent population over
seeded, jittered light traffic and gradual full-relay reconnects, with periodic
TCP/DC population and worker-heartbeat reconciliation. Its 20-minute default
is manual only; the validation branch does not make the workflow's UI button or
weekly schedule available without a default-branch workflow file.
Its live-population invariant uses per-client Linux TCP inode/state plus
proxy-side `ESTABLISHED` and fake-DC active logical IDs; retained Python session
objects alone never prove liveness. Failure-time evidence must be captured
before bounded cancellation/teardown, otherwise self-induced shutdown is
misreported as a proxy failure. Targeted manual `proxy_log_level=debug` runs
can correlate close reasons without making scheduled full load depend on debug
logging overhead.
Historical idle/TLS-auth capacity probes and the one-connection process E2E
prove different, narrower properties; neither substitutes for this suite.

## WEB Proxy Flow (Telegram Desktop 7.1+)

1. Telegram Desktop opens a browser HTTPS carrier to `[web].domain` on public `:443`; with the default `[web].only=false`, ordinary FakeTLS clients continue to use the same listener with `censorship.tls_domain`.
2. The proxy recognizes the WEB SNI with a bounds-checked routing parser that is independent of FakeTLS key-share/cipher policy, then relays the untouched TLS connection to `[web].mask_backend`, prefixing PROXY v2 with the kernel-reported browser address.
3. The existing Caddy service terminates TLS and sends the entire WEB hostname through one loopback relay handler; it does not route on unauthenticated carrier-looking paths and removes the reverse-proxy `Via` header.
4. The permanent secret-derived capability authenticates only the exact canonical bridge bootstrap. That response mints a bounded, short-lived token carried solely as `Sec-WebSocket-Protocol: tproxy-v1.<token>` on the exact WebSocket path, never in its URL. Empty `[web].base_path` keeps root v1 routes; a non-empty path moves both routes below `/<base_path>/` and uses the v2 HMAC context bound to hostname + exact case-sensitive path. Ordinary requests use the optional startup-loaded `[web].public_dir` or the fork's bodyless 404; a genuine capability in a malformed request always fails closed.
5. Every logical stream connects back to `[web].backend`, prefixes PROXY v2 with the browser address, and carries the client's `dd` direct-obfuscated MTProto stream into the normal DC/MiddleProxy routing path.

Trust is fixed from the kernel-reported peer at `accept()`: only loopback plus explicit `[web].relay_sources` may enter the direct-obfuscated path. A PROXY header may replace the diagnostic/client address but must never grant trust. When both `[web].enabled` and `[web].only` are true, every untrusted peer reaching the ordinary FakeTLS SNI is sent to the normal Caddy masking backend before secret validation, including clients holding a formerly valid direct link; the trusted relay remains admitted. `only` is inert when WEB is disabled. WEB-domain masking carriers and authenticated MTProto relays are exempt from `mask_relay_max_secs`. Ordinary masking/probe relays default to a 300-second absolute cap from admission, independent of activity and sliding idle timeout; explicit zero disables the cap and explicit nonzero values are preserved. Source/Compose installers and the Docker entrypoint omit this key, inheriting the runtime default while retaining existing operator settings.

## WEB Relay Invariants (upstream PR #429 adaptation)

- WEB backend queues fit the full 4 MiB granted stream window plus PROXY-v2 metadata.
  Incoming WebSocket messages fit a maximum 1 MiB relay payload plus its frame header.
- The relay accounts retained input, fragment, batch and queue allocations, including
  queue blocks, freelists and pointer capacities. Growth is reserved before allocation
  and drained idle capacity is reclaimed. `web.max_buffer_mb` is not a whole-process RSS
  limit; unrelated metadata and kernel socket buffers remain outside it.
- DATA/WINDOW frames batch within an event-loop pass; timer-generated frames flush
  before waiting again. WebSocket input compacts once per read pass and processing
  stops after CLOSE. Recently closed stream IDs use a fixed 4096-entry bounded circular
  history; duplicate IDs do not evict other tombstones.
- Deferred fd/object teardown capacity is reserved before publishing a connection,
  so OOM cannot cause an fd reuse or free inside the current epoll batch.
- `src/web/dns_cache.zig` refreshes hostname backends and WEB Caddy targets every
  minute, preserves the last good snapshot, and joins on shutdown. Literal-only caches
  spawn no thread. Linux uses a five-second-bounded NSS/getent child, with inherited
  signalfd masks reset in that child; DNS work never runs in a relay event callback.
- Each connect freezes up to 16 candidates. Failed backend connects retain queued
  PROXY and MTProto bytes; established streams are never replayed to another backend.
  WEB Caddy candidates use the data plane's existing mask-connect retry machinery.
- Only loopback and explicit `[web].trusted_http_sources` peers may supply forwarded
  client IPs; use the last matching field line and its right-most value. This HTTP
  terminator trust never grants data-plane relay privilege, which remains fixed at
  accept time. IPv6 trusted-peer comparison includes the interface scope.
- The hidden bridge always uses same-origin WSS, validates complete downlink batches,
  and retries only before adoption. It must not attempt cross-origin requests; client
  WebView isolation limits access to off-origin response data but is not a promise that
  every browser engine emits no off-origin packet. Keep the fork's empty Caddy 404 when
  no operator public directory is configured, not an upstream generated cover page.
- Caddy must proxy the whole WEB hostname to the relay rather than selecting
  carrier-looking paths before authentication. Strip its outer `Via` header, map relay
  failures to the common empty 404, and accept only the exact root or base-prefixed
  `GET <base>/?bridge=<43>` bootstrap plus a query-free WebSocket
  `GET <base><ws_path>` carrying one canonical token subprotocol. `/<base_path>` without
  the trailing slash is not redirected. Random invalid capabilities behave like public
  traffic; a genuine capability in any noncanonical request must fail closed.
- The bundled Caddy vhost has no request access log. Any replacement terminator must not
  log bridge request URIs or WebSocket subprotocol headers, which contain credentials.
- WEB base paths use the shared maximum-128-byte segment grammar
  `[A-Za-z0-9][A-Za-z0-9_-]*` joined by `/`, stored without surrounding slashes.
  Root capabilities retain the frozen `tdesktop-web-proxy-bridge-v1\nH` context;
  non-root capabilities use `tdesktop-web-proxy-bridge-v2\nH\nP`. Path links encode
  `server=H%2FP` and unpadded base64url `secret=0x70 || complete decoded secret`;
  never substitute `0xdd` for this link-version marker.
- Relay `/metrics` is restricted to direct loopback GET/HEAD requests with a loopback
  Host and without forwarding/Origin headers; never publish it through Caddy.
- WEB capabilities/config are startup snapshots. Restart both processes for access
  changes; relay SIGHUP only reports that a restart is required.
- WEB credential lookup uses `credential_index.PrefixIndex`, a membership-only
  `HashMapUnmanaged(u64, usize)` with independently seeded SipHash-2-4 context. Its
  keys are the first 64 decoded credential bits, not eleven complete base64 symbols.
  `Relay.init` builds the immutable capability index; the existing `caps` array
  remains authoritative. Unknown prefixes do zero full comparisons without lookup
  allocations; every hit retains the complete constant-time scan and user selection.
  This permits whole-prefix hit/miss timing, never prefix-only authentication.
- The token Store owns a separate mutable prefix index on the same relay thread.
  Reference counts preserve prefix collisions. Reserve entry capacity before adding
  a prefix, then append without failure; expiry and consumed release share
  `removeEntry`, which removes one reference after `swapRemove`. No entry positions
  or credential slices are borrowed by either index. Preserve expiry, active fd,
  failed-upgrade retry and post-WELCOME consumption. Both indices release their maps
  and erase their ephemeral hash salts at teardown; these salts are not token MAC
  keys and do not alter wire credentials.
- Token-prefix deletions bound native-map tombstones: in-place `rehash` after at
  most `max(1, capacity / 16)` distinct-key removals, or `clearRetainingCapacity` when
  empty. Maintenance runs only on mutation and allocates nothing; keep collision
  references and the hash context intact through rehash. Long-running Store churn
  must not degrade random misses into full-table probes.

## MiddleProxy Routing and Refresh

- Config text source: `https://core.telegram.org/getProxyConfig`
- Secret source: `https://core.telegram.org/getProxySecret`
- Refresh cadence: hourly in the updater thread, with debounced reactive refresh after stalled MiddleProxy handshakes.
- Bundled defaults are used when refresh fails.
- Candidate sets are kept separately for regular DC1..5, media-path DC1..5, DC4 candidate lists, and DC203; selection can test reachability.

Important behavior:

- If a MiddleProxy endpoint is unavailable, direct path is allowed by the current connect-plan logic only when that DC has a real direct endpoint. DC203 fails closed and requests a debounced metadata refresh.
- Each MiddleProxy handshake stage has a 5-second deadline. A stalled or malformed endpoint is cooled for 60 seconds, triggers reactive refresh, and falls back directly when possible, except for DC203.
- `force_media_middle_proxy=true` is the default preference for negative DC1..5 media paths. Disabling it makes those paths direct but never changes DC203 routing.
- `[access.direct_users]` / `[access.admins]` bypass MiddleProxy for regular and media paths with real direct endpoints. DC203 always uses MiddleProxy.
- Promotion tags are metadata in MiddleProxy `RPC_PROXY_REQ` only. Direct DC
  nonce/relay, per-user bypass and direct fallback omit them. Keep direct users
  eligible when a global tag is configured; do not restore a synthetic promotion
  RPC or an owned nonce-tail buffer on the direct path. A MiddleProxy media/CDN
  route carries the same configured tag as a regular MiddleProxy route.
- `datacenter_override` is test-only and disables MiddleProxy snapshot/updater routing.
- `server.middle_proxy_nat_ip` can pin the IPv4 used for MiddleProxy NAT/AES derivation. `server.public_ip` is client-facing link metadata and is never assumed to be DC egress. Automatic detection trusts an AWG endpoint only while the proxy runs inside the active tunnel network namespace; direct mode probes the process's public egress instead.
- `middleproxy_buffer_kb` is a per-direction cap. Each MiddleProxy context starts with 16 KiB C2S/S2C buffers and grows on demand up to `min(middleproxy_buffer_kb, 3840)` KiB; event-loop scratch buffers are lazy and reused. The effective cap reserves 256 KiB for MP/TLS framing before the 4 MiB relay-queue limit.
- Endpoint-specific MiddleProxy handshake/read failures and upstream fatal hangups try remaining MP candidates first, then can fall back to direct when the connect plan has a real direct fallback address. Local resource errors do not cool or retry remote endpoints.
- Route health requires two successful connect/auth samples, uses bounded EWMA and 20%/10 ms ordering hysteresis, and explores unknown/stale endpoints on every sixteenth selection. Existing 60-second cooldown always outranks scores; failure penalties last five minutes and successful authentication clears them. Secret changes clear health/cooldowns, metadata changes discard removed endpoints, and in-flight observations from an old secret epoch cannot repopulate current health.
- Tunnel deployment supports `direct`, `preserve`, and `middleproxy` modes.

## Fast Mode

`fast_mode` applies to direct path (non-MiddleProxy) and delegates S2C crypto work to Telegram DC by embedding client S2C key material into outbound nonce flow. MiddleProxy relay stays encapsulated in its own framing/crypto path.

For config compatibility, `fast_mode` is accepted in `[general]`, `[server]`, or `[censorship]`; all three set the same `Config.fast_mode` flag.

## Timeout Model

Current runtime timeout control is event-loop based:

- Pre-first-byte wait: fixed 10 seconds.
- `idle_timeout_sec`: established relay idle timeout.
- `handshake_timeout_sec`: timeout for handshake stages after first byte.
- `graceful_shutdown_timeout_sec`: process-wide drain deadline after the first `SIGINT`/`SIGTERM`; a second signal forces immediate completion.
- `client_silence_close_sec`: the only public iOS silence-recovery control. `0` disables it; enabled values must be at least 10 seconds and lower than `idle_timeout_sec`. All generic-relay recoveries share an internal per-real-IP/access-user/DC `T`/`2T`/`4T` budget. A mature relay that has already continued after a delivered reply is labeled `proven`, but does not bypass that budget.

Each slot stores one scheduled wakeup in the indexed heap. Idle jitter is computed once at admission and reused when activity moves the live idle deadline. `timeout_policy.nextSlotDeadline` classifies the selected minimum: only `relay_idle` can extend lazily, while absolute deadlines win ties and use exact heap updates. A retained entry is always at or before the live minimum; `popExpired` clears its index before `runSlotTimer` checks actual activity and reinserts a surviving slot, so lazy extension permits early wakeups without postponing mandatory timeouts. Close removes the entry before pool release; acquisition resets the heap index while fd generation checks remain unchanged. Admission, handshake, connect, MP stages, desync, mask max lifetime and wedge limits stay absolute; shutdown, accept-backoff and stats still compete independently for timerfd rearm. iOS wedge candidates use the same heap: client request timing begins only after upstream delivery, the response must start inside the 12-second client window, and silence timing begins only after the userspace client queue drains. Any client progress cancels the candidate. Media/DC203, masking, half-closed, backpressured, and graceful-shutdown paths are excluded. Recovery permits at most three group-wide backoff waves (and four parallel relays per wave) before ordinary idle timeout takes over for 30 minutes from the most recent actual breaker close; healthy matching traffic does not postpone restoration, and suppression diagnostics are emitted once per episode. Table saturation also fails safe by suppressing recovery. The `proven` label still requires the 30-second relay maturity floor plus client continuation after an earlier delivered reply.

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

The startup ceiling no longer multiplies every connection by two full 4 MiB relay queues and two full MiddleProxy caps. Those are independent protective maxima, not simultaneous guaranteed resident memory. The ceiling therefore guarantees baseline admission under the enforced shared budget; it is not a simultaneous full-buffer throughput claim. Each worker routes queue blocks, retained free-list blocks, MiddleProxy C2S/S2C buffers, and scratch through its partition of `ManagedBufferAllocator`; the partitions sum exactly to the original process cap. It tracks requested live bytes, refuses remap so allocate-before-free growth is charged at its transient peak, and keeps recycled queue pages charged until they are actually destroyed. Budget exhaustion follows existing OOM handling: optional shrink retains the existing buffer, while required growth closes the requesting connection or falls back to the direct path where possible. Every denial is reported as worker-local `memory_pressure+=...` in periodic stats.

The runtime limit includes the 16 KiB-per-direction MiddleProxy baseline for every configured slot plus the shared burst reserve, but is capped so the unmanaged baseline and managed allocation ceiling cannot exceed `allocatable_bytes` together. This baseline applies to every normal runtime because CDN DC203 can require MiddleProxy independently of the optional DC1..5 routing preferences; only the test-only `datacenter_override` bypasses it. The 6 KiB TLS working allowance remains intentionally conservative after the relay read buffer becomes event-loop-wide; do not raise the advertised RAM ceiling merely by subtracting that former per-slot allocation. When effective memory cannot be detected, the managed pool uses a 64 MiB default. For a 960 MiB limit and `max_connections=256`, the banner reports a ~40 KiB baseline, ~216 MiB shared dynamic-pool limit, a baseline RAM ceiling of ~5324, the separately configured cap, and the 90%/80% admission hysteresis.

`runtime/resources.zig` resolves the process membership through `/proc/self/cgroup` and `/proc/self/mountinfo`, then takes the lowest readable leaf or ancestor limit. In cgroup v2 a numeric `0` is a real hard limit; only `max` means unlimited. Conventional `/sys/fs/cgroup` paths remain a fallback when procfs mount metadata is unavailable. `main.zig` retains the application capacity formula and startup policy.

If `max_connections` exceeds the baseline RAM ceiling, startup auto-clamps it before the proxy starts unless `[server].unsafe_override_limits = true`. If the ceiling is below the supported minimum of 32 slots, safe mode fails startup instead of forcing 32. With the override enabled, startup keeps the configured value and logs a warning; the shared dynamic-pool hard limit remains active. If neither host nor cgroup memory can be read on Linux, startup logs that the RAM admission clamp was skipped.

`ProxyState.run` then applies a second, independent `RLIMIT_NOFILE` clamp before creating workers when the process soft fd limit cannot cover the effective connection cap. If the fd budget cannot support the minimum 32 slots (576 descriptors including overhead), startup fails instead of advertising an impossible capacity. Worker selection follows both clamps; explicit workers need at least 32 slots and the greater of 8 MiB or MiddleProxy shared scratch plus 4 MiB of managed budget each, while auto also considers CPU affinity and falls back to one. The cap of 16 workers bounds extra listener/epoll/timer/control fds and worker-local scratch; default `workers=1` retains the prior execution path.

## Handshake Performance Signals

`src/bench.zig` keeps handshake measurements explicit and ReleaseFast-only. The
`handshake` mode authenticates a complete structurally valid FakeTLS ClientHello;
`handshake-path` combines obfuscated-nonce parsing with the production candidate
staging path exposed through `BenchCandidatePath`. Counts 1 and 4 exercise inline
storage, while 8 deliberately crosses into heap fallback. CI records all four
signals (FakeTLS plus 1/4/8 candidates) as artifacts without hard timing gates,
because shared-runner variance must not create false failures. Authentication,
allocation, vector or process failures still fail the job.

## DPI Evasion Components

- FakeTLS ServerHello template with runtime digest patching.
- FakeTLS authentication is bounded to 4096 bytes including the record header, before strict parsing, wall-clock reads or per-secret HMAC work. Existing X25519/PQ fixtures (even both shares) fit below 2 KiB; this is an authentication-work cap, not a reduced TLS read/parser limit. Larger ClientHellos keep their complete bytes through ordinary masking with `oversized_client_hello` diagnostics.
- FakeTLS uses one strict ClientHello parser for authentication, cipher, and PQ key-share reads. WEB SNI routing has an independent bounds-checked extension walker so unrelated TLS evolution cannot select the wrong Caddy certificate. FakeTLS accepts only 32-byte Session IDs, stores the Session ID by value, and securely releases the full ClientHello as soon as the synthetic ServerHello is built.
- Successful authentication retains `ClientKeyShare` and the first TLS 1.3 cipher for ServerHello selection; never rescan raw ClientHello in that path. PQ `0x11ec` (1216 client bytes) wins over X25519 `0x001d` (32 bytes); neither offered means `unsupported_key_share` masking before secret hashing. Preserve duplicate-extension/PQ rejection and the existing acceptance of repeated valid X25519 entries. Synthetic probes/benchmarks must offer a supported share before signing.
- Ordinary `desync=false` ServerHello uses the heap-owned worker's fixed scratch, sized from `max(X25519 prefix, PQ prefix) + max_fake_cert_size` (17610 bytes). Allocating and into builders share the existing framing, canonical X25519 generation, cipher/session echo and HMAC implementation. The synchronous client queue owns any unsent suffix before scratch wiping/reuse; only explicit desync retains `slot.server_hello` across callbacks, using the existing timer and cleanup phases.
- `fake_cert_size=0` resolves once in `ProxyState.init` to a random size in 2400..3600, then the shared template fixes it for every classical/PQ connection and worker. Explicit nonzero sizes take priority and retain the 256..16384 clamp. This range is a fallback heuristic, not evidence of a masking-origin match or anti-DPI effectiveness; per-response AppData randomization remains intact. The legacy 2878-byte static helper/fixture is not the runtime zero-setting policy, and no backend profiling/probing is added.
- Anti-replay cache compares the full canonical HMAC digest, retains entries for the maximum FakeTLS timestamp-validity horizon, and replaces the oldest entry in a saturated bounded probe window so cache pressure cannot masquerade as a proven replay.
- MTProto obfuscation rejects reserved nonces before decrypting protocol tags. Secret trials decrypt only the AES block containing tag/DC (`48..64`, tag at block offset 8, DC at 12), deriving its start/index from protocol constants and checking their common-block layout at comptime. `AesCtr` counters are big-endian u128 with wrapping addition, so the trial starts at `IV +% 3`; returned traffic params keep the original IV. `finishParsedClientHandshake` still advances the client decryptor by four blocks; no trial state escapes into traffic.
- Unknown MTProto DC indices are rejected before endpoint planning; modulo fallback is not part of the connection path.
- Masking target selection for unauthenticated clients: `mask_port=443` resolves every address for `tls_domain:443` in the background, prefers IPv4, and fails over across candidates; non-443 `mask_port` connects to a local address on that port (`127.0.0.1` in the init namespace, `10.200.200.1` inside the tunnel netns). Hostname candidates are re-resolved hourly.
- Config parsing is strict for proxy-owned sections/keys and malformed lines; `[monitor].host`/`port` remain accepted for the external dashboard. Config load errors propagate as a non-zero process exit.
- TCPMSS clamping, SYN pacing, and zapret/nfqws integration are external-path mitigations; deploy rules exclude loopback so WEB relay streams never enter pacing, tiny-MSS, or NFQUEUE processing.
- Split-TLS desync remains opt-in (`desync=true`, default false), with its existing delay/jitter and timer phases. Source/Compose installers and the Docker entrypoint omit the key and inherit the default; an existing explicit true value stays enabled. The Compose installer summary reads the actual config key with fallback false and reports enabled/disabled accordingly. OS-level zapret/nfqws policy is separate.
- FakeTLS C2S parses all TLS records in each bounded 32 KiB socket read in userspace; only partial framing positions survive between reads. AES and MiddleProxy process borrowed payload slices before scratch reuse, while pending upstream output stops the next read and frame-boundary EOF rules remain authoritative.
- Readable handlers do not sample time or refresh activity before I/O. Real relay progress samples fresh `monotonicMilli` after transform/queueing and reuses it for wedge observations; each drain iteration samples independently. Raw masking records progress after queueing; MTProto/MP handshake drains sample once on return only if they consumed bytes. First-byte and activity share one sample for a successful WEB/TLS prefix read. Writable flushes already sample once after sent bytes; preserve separate stage/connect/desync clocks and one-time relay EOF activity.
- Direct FakeTLS C2S batches at most 64 transformed application-payload pieces from the current read through `relay_io.queueUpstreamParts`, reusing the S2C multipart primitive. Flush at the scatter limit or read end, including partial TLS bodies; never wait for another read. The shared event budget and exact owned suffix queueing apply unchanged, and the rest of an already-read chunk is processed even after output queues. `c2s_bytes` and `wedge_forwarded_c2s_seq` account accepted payload pieces, not physical writes. Forward valid prefixes before rejecting later malformed TLS headers. MiddleProxy still consumes each encapsulated output immediately because the next call reuses MP scratch.
- The shared multipart helper chooses `writeSlotFd` for exactly one part and `writevSlotFd` for two or more. Both retain the original pre-write byte-cap check and atomic `appendParts` suffix reservation, including pending-output ordering, WouldBlock and shared event-budget accounting. Do not replace this with `queueUpstream` blindly: its older `appendCopy` fallback can partially mutate a queue on OOM.
- FakeTLS S2C groups up to 32 TLS records into one bounded scatter write. Queued suffixes own their bytes in the existing page-block queue; multipart reservation preserves queue contents on OOM/overflow and charges the worker's managed allocator, including retained pool blocks.
- The S2C encoder caps FakeTLS application payloads at 16367 bytes for both DRS policies, avoiding repeated bulk wire length `0x4000`. DRS still requests 16384 after its unchanged warmup. The 17-byte content-type/tag margin is a sizing heuristic, not a TLS restriction: real TLS 1.3 can legally produce ciphertext length `0x4000`. General inbound TLS limits and encrypted-certificate sizing remain separate.
- Self-domain masking setup (`setup_masking.sh`) configures Caddy 2.10+ on `127.0.0.1:8443` and, in tunnel netns mode, `10.200.200.1:8443`; non-proxy requests receive 404. Optional WEB setup extends that same Caddy instance with an internal PROXY-protocol listener on `8444` and a loopback relay on `8081`. Both local TLS listeners are limited to HTTP/1.1 and HTTP/2 so Caddy cannot advertise the non-public UDP `8443` or `8444` as an HTTP/3 alternative. Source installs use `mtproto-mask-caddy.service`; Docker Compose installs use the `mtproto-mask-caddy` service/container.

## What To Verify During Changes

- `epoll` interests and queue flushing remain non-blocking and symmetric.
- FakeTLS validation keeps the 32-byte Session ID contract with `src/protocol/tls.zig` templates.
- Pipelined appdata after the 64-byte MTProto nonce is preserved across direct and MiddleProxy startup.
- Direct/MiddleProxy fallback logic still preserves media and non-media expectations.
- MiddleProxy buffer changes preserve 16 KiB initial allocation, on-demand growth, and the 3840 KiB effective cap derived from the 4 MiB relay queue minus framing headroom.
- Timeout behavior remains controlled by config timers.
- Graceful process shutdown disables new accepts on the first signal, preserves existing relay progress until the configured deadline, and force-closes only after another signal or timeout.
- Permanent WEB capabilities gate only canonical bridge bootstrap requests; carrier URLs remain bearer-free and one bounded, expiring token subprotocol can attach only one pre-adoption carrier. WELCOME stays alone in the first binary carrier message, supplied Origin must match exactly, trusted relay status cannot be forged through PROXY v2, and direct-obfuscated RDHUP follows the direct relay path rather than FakeTLS record parsing. WEB-only must continue to admit the trusted relay, mask every direct peer even with a valid secret, stay inert when WEB is disabled, and suppress ordinary connection links while active.
- CI remains green across `zig fmt --check`, Debug/ReleaseSafe/ReleaseFast tests, daemon smoke with positive, bad-secret, and graceful-SIGTERM paths, Debug plus default shipping ReleaseFast and optional hardened ReleaseSafe real-process FakeTLS/obfuscation/direct-relay E2E against a compile-time-only loopback DC, production ReleaseFast+PIE and optional ReleaseSafe+PIE builds, cross-builds plus native ARM64 runtime checks, a compile-time hardware-AES assertion tied to the optimized Docker workflow profile, ShellCheck, Python syntax, offline probe-helper tests, WEB bridge contract tests, and local TLS/WSS full-probe fixtures, Docker build plus safe-default smoke, the Debian/Ubuntu installer E2E matrix pulling and verifying an image built from the current checkout, genuine ReleaseFast encapsulation/FakeTLS/1-4-8-candidate benchmarks plus soak, bounded fuzzing with crash-artifact preservation, and scheduled/manual ThreadSanitizer, Valgrind Memcheck, plus extended fuzz checks.
- Deploy docs remain aligned with current tunnel/direct-mode behavior.
- Docs remain aligned with code paths and log messages.
