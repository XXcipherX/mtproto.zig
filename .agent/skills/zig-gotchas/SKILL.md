---
name: MTProto Proxy Zig Gotchas
description: Critical Zig-specific execution gotchas, profiling, stability fixes, and development conventions for this project.
---

# Zig Gotchas and Stability Notes

This file tracks practical pitfalls and current runtime constraints for `mtproto.zig`.

## Current Architecture Baseline

- Relay core is Linux `epoll` event loop, single-threaded on hot path.
- Connection pools allocate slot indexes/fd maps for the configured cap, while `ConnectionSlot` objects are heap-created on demand.
- Non-blocking writes are queue-based (`MessageQueue`) and flushed with `writev`.
- `MessageQueue` has classed storage blocks and a 4 MiB pending-byte cap; queue overflow is a close-worthy backpressure signal.
- Runtime discovery runs in a joinable updater thread after the listener is ready when MiddleProxy or masking resolution is active; shutdown is cooperative and endpoint probes poll cancellation in short intervals.

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
- Handshake/idle behavior is timer-driven (`idle_timeout_sec`, `handshake_timeout_sec`) in `runTimers`.
- Pre-first-byte admission has a separate fixed 10-second deadline, and unauthenticated sockets are capped concurrently per IPv4 `/24` or IPv6 `/48`.
- `SIGPIPE` is ignored process-wide before socket relay starts; write paths must continue handling `EPIPE` as a normal connection failure.
- There is no active `SO_RCVTIMEO`-based relay timeout path in current code.
- FakeTLS validation requires a 32-byte ClientHello Session ID. The Session ID is stored by value and echoed into the fixed Nginx-like ServerHello template; the complete ClientHello is zeroed/freed immediately after response construction.
- Extra TLS appdata bytes after the 64-byte MTProto obfuscation nonce are buffered as `pipelined_data` and flushed after the DC/MiddleProxy path is ready.

## Queueing and Partial Write Model

- Outbound data is queued in block classes (tiny/small/standard).
- Flush path uses scatter-gather `writev` with explicit queue consumption.
- Backpressure is represented by pending queue state and epoll `OUT` interest toggles.
- Legacy `writeAll` assumptions are outdated for this codebase.
- Avoid owned-slice queue helpers that require later freeing; current queue paths copy into block storage and keep ownership local.

## MiddleProxy Specific Notes

- Endpoints and secret are refreshed from Telegram core endpoints; bundled defaults remain fallback.
- Candidate rotation and direct fallback behavior are part of normal operation.
- MiddleProxy handshake stages have a 5-second deadline; protocol/read stalls cool the endpoint, request refresh, and use direct fallback when available.
- Direct fallback can happen for both regular and media traffic when MiddleProxy candidates are missing or ME transport fails.
- `middleproxy_buffer_kb` is a per-direction cap, not an eager allocation. Each MiddleProxy context starts with 16 KiB C2S/S2C buffers and grows on demand up to `min(middleproxy_buffer_kb, 16384)` KiB.
- The event loop keeps lazy reusable C2S/S2C scratch buffers. C2S scratch is `effective_cap + 256`; S2C scratch is `effective_cap`.
- The startup capacity clamp intentionally budgets the full effective MiddleProxy cap per direction, so it is more conservative than the idle memory footprint.
- `force_media_middle_proxy` defaults to true, so media traffic keeps preferring ME unless explicitly disabled.
- `middle_proxy_nat_ip` can override the IPv4 embedded into MiddleProxy NAT/AES derivation when AWG/public-IP detection is not the address you want.
- A connection snapshots the MiddleProxy secret and NAT IPv4 together with its endpoint plan; secret rotation cannot split key-selector and KDF inputs mid-handshake.

## Protocol Validation Notes

- Replay detection compares the full canonical HMAC digest, even when the hash-table key collides.
- Reserved MTProto obfuscation nonces are rejected before protocol-tag decryption.
- Direct-user bypass only applies when the name exists in `[access.users]`; unknown names in `[access.direct_users]` warn and are ignored.
- Duplicate user/direct-user/config string entries are last-write-wins. Direct users accept `false`/`0`/`no` to remove a previous duplicate entry.
- Unknown proxy sections/keys and malformed config lines are fatal parse errors. `[monitor].host` and `[monitor].port` are the intentional externally consumed exception.

## Timeout and Lifetime Notes

- Current runtime enforces a fixed 10-second pre-first-byte timeout, configured handshake timeout after first byte, and configured relay idle timeout.
- Fixed max connection lifetime (for example "30 minutes hard cap") is not implemented in current code.

## Practical Change Guardrails

- Keep epoll interest synchronization correct (`IN`/`OUT` toggles per phase).
- Preserve handshake assembly correctness for fragmented TLS records.
- Preserve replay-cache behavior (`canonical_hmac` keying).
- Keep docs aligned with real log messages and runtime flow.

## Development Conventions

- Pass allocators explicitly and free deterministically.
- Use error unions and avoid swallowing critical errors on control-path boundaries.
- Keep tests close to protocol primitives and relay helpers.
- For substantial behavior changes, update `README.md` and relevant `.agent` docs in the same change.
- Keep CI expectations in mind: formatting, Debug tests, ReleaseSafe tests, real daemon smoke (valid FakeTLS plus bad-secret rejection), cross-builds, ShellCheck, Python harness syntax, Docker build smoke, bench, and soak.
