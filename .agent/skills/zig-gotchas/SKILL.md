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
- `MessageQueue` has classed storage blocks from one event-loop-wide pool and a 4 MiB pending-byte cap; queue overflow is a close-worthy backpressure signal.
- Runtime discovery runs in a joinable updater thread after the listener is ready when MiddleProxy or masking resolution is active; shutdown is cooperative and endpoint probes run in cancellable batches of at most four sockets.

Do not reintroduce thread-per-connection or blocking relay loops.

## Logging Gotchas

- `std.log.defaultLog` can serialize on global stderr lock and hurt throughput under load.
- Project uses custom lock-free `logFn` in `src/main.zig`.
- Keep hot-path logging minimal (`debug` only where needed, avoid noisy per-packet logs).
- Do not force global `.log_level = .debug` in production builds.
- Startup output redacts user secrets and connection links by default. `--show-secrets` is an explicit private-terminal opt-in; never add secrets back to normal service logs.

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
- FakeTLS validation requires a 32-byte ClientHello Session ID. Authentication, SNI, TLS 1.3 cipher, and PQ key-share detection share one strict outer parser, so do not introduce a second path with different nested-length rules. The Session ID is stored by value and echoed into the fixed Nginx-like ServerHello template; the complete ClientHello is securely zeroed/freed immediately after response construction.
- Extra TLS appdata bytes after the 64-byte MTProto obfuscation nonce are buffered as `pipelined_data` and flushed after the DC/MiddleProxy path is ready.

## Queueing and Partial Write Model

- Outbound data is queued in block classes (tiny/small/standard) served by the shared `MessageBlockPool`.
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
- `middleproxy_buffer_kb` is a per-direction cap, not an eager allocation. Each MiddleProxy context starts with 16 KiB C2S/S2C buffers and grows on demand up to `min(middleproxy_buffer_kb, 16384)` KiB.
- The event loop keeps lazy reusable C2S/S2C scratch buffers. C2S scratch is `effective_cap + 256`; S2C scratch is `effective_cap`.
- The startup capacity clamp intentionally budgets the full effective MiddleProxy cap per direction, so it is more conservative than the idle memory footprint.
- `force_media_middle_proxy` defaults to true, so media traffic keeps preferring ME unless explicitly disabled.
- `middle_proxy_nat_ip` can override the IPv4 embedded into MiddleProxy NAT/AES derivation when AWG/public-IP detection is not the address you want.
- A connection snapshots the MiddleProxy secret version and NAT IPv4 together with its endpoint plan. The current and immediately previous secrets remain centrally available under the metadata lock, so rotation cannot split key-selector and KDF inputs mid-handshake without copying the secret into every slot.
- The snapshot contains only the selected route candidates, not every DC/media list. C2S scratch sizing is a constant-time upper bound; frame headers are parsed once by encapsulation.
- CBC encrypt/decrypt state is direction-specific, and high-frequency random output uses the thread-local DRBG. New entropy-sensitive code must preserve periodic OS-CSPRNG reseeding.

## Protocol Validation Notes

- Replay detection compares the full canonical HMAC digest even when the hash-table key collides. Its retention horizon must cover every still-valid FakeTLS timestamp, while saturation must never be reported as a proven replay.
- `prepareTgNonce` accepts exactly a 48-byte key+IV pointer, MiddleProxy KDF rejects inputs that exceed its fixed transcript buffer, and unknown DC indices are rejected before routing.
- Reserved MTProto obfuscation nonces are rejected before protocol-tag decryption.
- Direct-user bypass only applies when the name exists in `[access.users]`; unknown names in `[access.direct_users]` warn and are ignored.
- Duplicate user/direct-user/config string entries are last-write-wins. Direct users accept `false`/`0`/`no` to remove a previous duplicate entry.
- Unknown proxy sections/keys and malformed config lines are fatal parse errors. `[monitor].host` and `[monitor].port` are the intentional externally consumed exception.

## Timeout and Lifetime Notes

- Current runtime enforces a fixed 10-second pre-first-byte timeout, configured handshake timeout after first byte, and configured relay idle timeout.
- iOS silence recovery is an encrypted-stream heuristic, not MTProto parsing: it excludes media paths, accepts only server replies inside a 12-second response window, and arms after the userspace client queue drains. Preserve those guards when changing `client_silence_*` handling.
- Fixed max connection lifetime (for example "30 minutes hard cap") is not implemented in current code.

## Practical Change Guardrails

- Keep epoll interest synchronization correct (`IN`/`OUT` toggles per phase).
- Preserve handshake assembly correctness for fragmented TLS records.
- Preserve replay-cache behavior (`canonical_hmac` keying).
- Keep docs aligned with real log messages and runtime flow.

## Development Conventions

- Pass allocators explicitly and free deterministically.
- Securely wipe secret-bearing and plaintext buffers before allocator release, including Config user-secret values, queue blocks, MiddleProxy stream/scratch buffers, nonce/KDF state, and cipher contexts.
- Use error unions and avoid swallowing critical errors on control-path boundaries.
- Keep tests close to protocol primitives and relay helpers.
- For substantial behavior changes, update `README.md` and relevant `.agent` docs in the same change.
- Keep CI expectations in mind: formatting, Debug tests, ReleaseSafe tests, real daemon smoke (valid FakeTLS plus bad-secret rejection), cross-builds, ShellCheck, Python harness syntax, Docker build smoke, bench, and soak.
