---
name: MTProto Proxy Zig Gotchas
description: Critical Zig-specific execution gotchas, profiling, stability fixes, and development conventions for this project.
---

# Zig Gotchas and Stability Notes

This file tracks practical pitfalls and current runtime constraints for `mtproto.zig`.

## Current Architecture Baseline

- Relay core is Linux `epoll` event loop, single-threaded on hot path.
- The large `EventLoop` container and its fixed subnet tables are heap-allocated and initialized in place; returning it by value can overflow the Debug daemon stack. Connection pools allocate slot indexes and a deadline-heap entry per active slot, while `ConnectionSlot` objects are heap-created on demand. Epoll payloads carry index/generation/role directly; do not reintroduce an fd hash map.
- Non-blocking writes are queue-based (`MessageQueue`) and flushed with `writev`.
- `MessageQueue` has intrusive page-sized storage blocks from one capped event-loop-wide pool and a 4 MiB pending-byte cap; queue overflow is a close-worthy backpressure signal.
- Runtime discovery runs in a joinable updater thread after the listener is ready when MiddleProxy or masking resolution is active; shutdown is cooperative, DNS/HTTPS/curl tasks are canceled in their owning thread, and endpoint probes run in cancellable batches of at most four sockets.
- Keep `SIGINT`/`SIGTERM` cleanup out of async signal context. The production handler may only notify the non-blocking `eventfd`; allocator, socket, epoll, listener, and updater cleanup belongs to the event-loop/defer path. The first notification disables listener interest and begins the configured graceful drain; accepts must never resume while `shutting_down`, and another notification or the deadline force-closes remaining slots. The signal bridge must outlive every runtime worker and is dismantled only after the updater is joined. Do not permanently block these signals process-wide for `signalfd`: Zig 0.16's POSIX child-spawn path preserves the caller's signal mask across `exec`, which would also block `std.process` cancellation signals in curl fallback children.
- Zig 0.16 `Io.Future.cancel` and `Io.Group.cancel` are not thread-safe, while `Io.Select.cancel` is explicitly thread-safe. Runtime discovery nevertheless keeps cancellation with the Select owner because its tasks borrow scope-local buffers and arguments; `Select.cancel()` must be drained until `null` so late successful tasks cannot leak allocated results.
- Before Zig 0.16's resolver reads `/etc/resolv.conf`, enforce nonzero final `attempts`, its 255-byte search buffer, its 512-byte line bound, and the 253-byte DNS wire-name limit for the base host plus any applied search suffix.

Do not reintroduce thread-per-connection or blocking relay loops.

## Logging Gotchas

- `std.log.defaultLog` can serialize on global stderr lock and hurt throughput under load.
- Project uses custom lock-free `logFn` in `src/main.zig`.
- Left-align standard log level names to Zig's longest built-in label (`warning`), then print ` (scope):` and exactly one separator space. This aligns the left edge, scope, and message columns for every level within any scope without enumerating or constraining scope names; keep message text free of manual leading padding.
- Keep hot-path logging minimal (`debug` only where needed, avoid noisy per-packet logs).
- Do not force global `.log_level = .debug` in production builds.
- The authenticated `valid FakeTLS ClientHello` debug line includes the real client IP (without its ephemeral source port) from `slot.peer_addr`; keep this address-bearing diagnostic at debug level and never move it into normal production logs.
- Startup output redacts user secrets and connection links by default. Prefer `--print-links`, whose one-shot path must return after config parsing and before daemon signal/listener initialization; it is safe to invoke inside a running container. `--show-secrets` is only an explicit opt-in for a full foreground daemon run. Never add secrets back to normal service logs. When WEB-only is active, every banner, one-shot, and installer summary must suppress ordinary `tg://proxy`/`t.me/proxy` links and emit only the WEB link.
- The Docker image ships `config.toml.example` as documentation only. If the selected config path is absent, `docker-entrypoint.sh` must create it atomically with a fresh 32-hex secret and mode `0600`, without writing the secret to container logs. Inspection options must stay read-only, and the `web-relay` subcommand must pass through without implicit config creation.
- HTTP discovery handles redirects explicitly and validates the resolved URI as HTTPS before opening the next request; never restore automatic `std.http` redirects, which also accept HTTP targets.

## Allocator and Concurrency

- Runtime uses `std.heap.page_allocator` to avoid allocator mutex contention seen with GPA under heavy connection churn.
- Keep ownership boundaries explicit and wipe crypto material on teardown (`resetOwnedBuffers` paths).
- Avoid hidden allocations inside event callbacks when possible.

## Socket and I/O Realities

- Sockets are non-blocking and epoll-driven.
- `SO_SNDTIMEO` and TCP keepalive are configured for relay sockets.
- Handshake/idle behavior is driven by monotonic `timerfd` plus an indexed min-heap (`idle_timeout_sec`, `handshake_timeout_sec`); each active slot owns at most one heap entry.
- Pre-first-byte admission has a separate fixed 10-second deadline, and unauthenticated sockets are capped concurrently per IPv4 `/24` or IPv6 `/48`.
- IPv6 subnet keys preserve all 48 prefix bits; IPv4-mapped IPv6 intentionally shares the corresponding native IPv4 `/24` key.
- `SIGPIPE` is ignored process-wide before socket relay starts; write paths must continue handling `EPIPE` as a normal connection failure.
- There is no active `SO_RCVTIMEO`-based relay timeout path in current code.
- `EPOLLRDHUP` is only a hint to drain until `read()==0`; do not detach that fd while its write half is still carrying the reverse relay. Track both directions separately, flush the destination queue before `shutdown(SHUT_WR)`, and accept graceful EOF only at FakeTLS/MiddleProxy frame boundaries.
- FakeTLS validation requires a 32-byte ClientHello Session ID. Authentication, SNI, TLS 1.3 cipher, and PQ key-share detection share one strict outer parser, so do not introduce a second path with different nested-length rules. The Session ID is stored by value and echoed into the fixed browser-like ServerHello template; the complete ClientHello is securely zeroed/freed immediately after response construction.
- WEB relay trust is fixed from the kernel-reported address at accept time. PROXY v2 may replace the client address for accounting but must never grant direct-obfuscated access. Keep WEB RDHUP reads on the direct-obfuscated crypto/framing path; the ordinary relay-step helpers expect FakeTLS records. `[web].only` is active only together with `[web].enabled`; in that mode apply the gate to the accepted peer before FakeTLS secret validation so every direct peer is masked while the trusted relay still reaches direct-obfuscated handling.
- Extra TLS appdata bytes after the 64-byte MTProto obfuscation nonce are buffered as `pipelined_data` and flushed after the DC/MiddleProxy path is ready.

## Queueing and Partial Write Model

- Outbound data is queued in intrusive page-sized blocks served by the shared `MessageBlockPool`; append into the current tail before acquiring a new page.
- Recycled/destroyed queue blocks are securely wiped. If appending an acquired block pointer fails, return it to the shared pool (or destroy it) before propagating OOM.
- Flush path uses scatter-gather `writev` with explicit queue consumption.
- Backpressure is represented by pending queue state and epoll `OUT` interest toggles.
- Keep per-dispatch byte/operation budgets on queue flushes and RDHUP drains so one fd cannot monopolize the single event-loop thread.
- Legacy `writeAll` assumptions are outdated for this codebase.
- Avoid owned-slice queue helpers that require later freeing; current queue paths copy into block storage and keep ownership local.

## MiddleProxy Specific Notes

- Endpoints and secret are refreshed from Telegram core endpoints; bundled defaults remain fallback.
- Candidate rotation and direct fallback behavior are part of normal operation.
- MiddleProxy handshake stages have a 5-second deadline; protocol/read stalls cool the endpoint, request refresh, and use direct fallback when available.
- Direct fallback can happen for both regular and media traffic when MiddleProxy candidates are missing or ME transport fails.
- MiddleProxy connect and stage deadlines must reserve part of the still-live global handshake budget for direct fallback. Never start fallback after that global deadline has already expired.
- `middleproxy_buffer_kb` is a per-direction cap, not an eager allocation. Each MiddleProxy context starts with 16 KiB C2S/S2C buffers and grows on demand up to `min(middleproxy_buffer_kb, 3840)` KiB. That cap is the 4 MiB relay-queue limit minus 256 KiB reserved for MP/TLS framing; do not raise it independently.
- Abridged `RPC_PROXY_ANS` data must be 4-byte aligned before its word-count header is encoded; reject an unaligned upstream payload instead of truncating the byte length.
- Secure/padded-intermediate S2C frames may add only 0..3 bytes of padding. The receiver truncates the declared length down to a multiple of four and has no padding-length field, so wider padding leaves random bytes attached to the MTProto message.
- The event loop keeps lazy reusable C2S/S2C scratch buffers. C2S scratch is `effective_cap + 256 KiB`; S2C scratch is `effective_cap`.
- The startup capacity clamp budgets the guaranteed connection baseline and reserves half of post-headroom memory for one shared `ManagedBufferAllocator`. Relay blocks (including retained pool pages), MiddleProxy C2S/S2C buffers, shared scratch, and allocate-before-free growth all use that allocator. Do not bypass it for dynamically growing relay/ME storage or multiply every connection by its independent worst-case caps.
- `force_media_middle_proxy` defaults to true and controls negative DC1..5 media paths. CDN DC203 is not optional: it always uses ME because its `proxy_for 203` address does not accept raw MTProto.
- `middle_proxy_nat_ip` can override the IPv4 embedded into MiddleProxy NAT/AES derivation. Never derive this value from client-facing `public_ip`, and only trust an AWG endpoint while the proxy is running inside the active tunnel network namespace; a stale host-side AWG config does not prove tunnel egress.
- A connection snapshots the MiddleProxy secret version and NAT IPv4 together with its endpoint plan. The current and immediately previous secrets remain centrally available under the metadata lock, so rotation cannot split key-selector and KDF inputs mid-handshake without copying the secret into every slot.
- The snapshot contains only the selected route candidates, not every DC/media list. C2S scratch sizing is a constant-time upper bound; frame headers are parsed once by encapsulation.
- CBC encrypt/decrypt state is direction-specific, and high-frequency random output uses the thread-local DRBG. New entropy-sensitive code must preserve periodic OS-CSPRNG reseeding.

## Protocol Validation Notes

- Replay detection compares the full canonical HMAC digest even when the hash-table key collides. Its retention horizon must cover every still-valid FakeTLS timestamp, while saturation must never be reported as a proven replay.
- `prepareTgNonce` accepts exactly a 48-byte key+IV pointer, MiddleProxy KDF rejects inputs that exceed its fixed transcript buffer, and unknown DC indices are rejected before routing.
- Reserved MTProto obfuscation nonces are rejected before protocol-tag decryption.
- Direct-user bypass only applies when the name exists in `[access.users]`; unknown names in `[access.direct_users]` warn and are ignored. DC203 is always exempt from the bypass because it has no direct DC endpoint.
- Duplicate user/direct-user/config string entries are last-write-wins. Direct users accept `false`/`0`/`no` to remove a previous duplicate entry.
- Unknown proxy sections/keys and malformed config lines are fatal parse errors. `[monitor].host` and `[monitor].port` are the intentional externally consumed exception.
- `Config.validate()` runs after parsing for the daemon, WEB relay, link output, and `--check-config`. Keep it offline and deterministic: validate syntax and cross-field relationships without DNS or socket operations. Fatal diagnostics may identify fields and error classes but must not echo raw values.
- Config diagnostics may name a key, line number, and parse error, but must never echo raw values or source lines because malformed input can still contain user secrets.

## Timeout and Lifetime Notes

- Current runtime enforces a fixed 10-second pre-first-byte timeout, configured handshake timeout after first byte, and configured relay idle timeout.
- Process shutdown has a separate `graceful_shutdown_timeout_sec` deadline. It is armed in the existing `timerfd`; it is not a per-connection lifetime and must not be lost when slot deadlines or accept backoff are rearmed.
- iOS silence recovery is an encrypted-stream heuristic, not MTProto parsing: preserve upstream request-delivery accounting, the 12-second response window, client-queue delivery accounting, cancellation on any client progress, fresh-reconnect backoff keyed by real IP/access user/DC, the cooldown anchored to the most recent actual breaker close, one arm/suppression diagnostic per logical episode, and exclusions for media/DC203, masking, half-close, backpressure, and graceful shutdown. `client_silence_close_sec` is the only public control; do not reintroduce separate fast-path tuning keys.
- Fixed max connection lifetime (for example "30 minutes hard cap") is not implemented in current code.

## Practical Change Guardrails

- Keep epoll interest synchronization correct (`IN`/`OUT` toggles per phase).
- Preserve handshake assembly correctness for fragmented TLS records.
- Preserve replay-cache behavior (`canonical_hmac` keying).
- Keep docs aligned with real log messages and runtime flow.

## Development Conventions

- Pass allocators explicitly and free deterministically.
- Securely wipe secret-bearing and plaintext buffers before allocator release, including Config user-secret values, queue blocks, MiddleProxy stream/scratch buffers, nonce/KDF state, and cipher contexts.
- Avoid value captures and optional-unwrapping copies for secret-bearing records. Use pointer captures where ownership permits, clear named handshake/KDF/hash/cipher temporaries with `std.crypto.secureZero`, and wipe only the sensitive fields of structs that also contain enums or pointers.
- Use error unions and avoid swallowing critical errors on control-path boundaries.
- Keep tests close to protocol primitives and relay helpers.
- For substantial behavior changes, update `README.md` and relevant `.agent` docs in the same change.
- Keep CI expectations in mind: formatting, Debug tests, ReleaseSafe tests, bounded coverage-guided security fuzzing, real daemon smoke (valid FakeTLS, bad-secret rejection, and graceful SIGTERM drain), cross-builds, ShellCheck, Python harness syntax, Docker build plus safe-default smoke, the Debian/Ubuntu Docker Compose installer E2E matrix, bench, and soak.
