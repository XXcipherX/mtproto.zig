---
name: MTProto Proxy Zig Gotchas
description: Critical Zig-specific execution gotchas, profiling, stability fixes, and development conventions for this project.
---

# Zig Gotchas & Stability Fixes

This document records severe execution issues, profiling details, and project stability patches unique to the `mtproto.zig` project. 

## Critical Zig Gotchas

### 1. `log_level = .debug` Causes 99% CPU (Historical Context)
**THIS WAS THE #1 STABILITY KILLER in the legacy model.**

```zig
// BAD — forces ALL log.debug calls to execute even in ReleaseFast
pub const std_options = std.Options{
    .log_level = .debug,
};
```

Zig's default logger (`std.log.defaultLog`) acquires a global `stderr_mutex`. Under high concurrency, logging cascades into stalls.
**The Rule (Current):** Keep hot-path logs minimal. We now use a custom lock-free logger, but flooding `ReleaseFast` with `.debug` will still hurt event-loop latency.

**Evidence from `/proc` analysis:**
- 337 threads in `futex_wait_queue`.
- 1 thread in running state consumes 99% CPU.

**Fix:** Remove the `log_level` override. `ReleaseFast` default is `.info`, which compiles out all `log.debug` calls at comptime (zero overhead via dead code elimination).

### 2. Custom Lock-Free Logger
Replaced `std.log.defaultLog` with a custom `lockFreeLog` that:
- Formats into a stack buffer.
- Uses a single atomic `write()` syscall to `stderr`.
- **No mutex**: Eliminates all contention.
- Lines may interleave under extreme concurrency, which is acceptable for performance.

```zig
pub const std_options = std.Options{
    .logFn = lockFreeLog,
};
```

### 3. GPA Mutex Deadlock
`std.heap.GeneralPurposeAllocator` has an internal mutex. Under high thread contention, this caused deadlocks.
**Fix:** Switched to `std.heap.page_allocator`, which has no internal locking.

### 4. Log Level Strategy
Only 4 `log.info` messages survive in the hot path:
1. `"Listening on 0.0.0.0:{port}"` — startup
2. `"TLS auth OK: user={name}"` — successful authentication
3. `"Relaying traffic"` — relay start
4. `"Relay: max lifetime reached"` — operational event

Everything else is `log.debug` (compiled out in `ReleaseFast`).

### 5. Atomic Counter Races
**The Lesson**: Reserve slots proactively. `active_connections` must be incremented before accepting operations to prevent burst overshoots.

### 6. Epoll & Event Loop Transition
**The Problem**: The legacy model spawned threads with fixed `256KB` stacks, leading to large baseline memory usage (e.g. 144MB for 13k connections) and susceptibility to stack overflow under heavy buffers.
**The Fix**: The codebase transitioned entirely to an **epoll-based event loop**. Memory allocation is decoupled from connections, allowing robust scalability (49MB for 12,000 connections).
**Current Rule**: Do not re-introduce thread-per-connection features!

### 7. Zig stdlib Internals (Reference)
- `std/log.zig:122`: Comptime log level check.
- `std/log.zig:154`: `lockStderrWriter` acquires mutex.
- `std/Progress.zig:1560`: `var stderr_mutex = std.Thread.Mutex.Recursive.init`.
- `std/os/linux.zig`: `TCP.KEEPIDLE=4`, `TCP.KEEPINTVL=5`, `TCP.KEEPCNT=6`.
- Note: Zig's `posix.SOL` doesn't have `.TCP`, so TCP socket options use raw `sol_tcp: i32 = 6`.

## Stability Fixes Applied

### Socket Configuration
1. **TCP Keepalive**:
   - `TCP_KEEPIDLE = 60s`, `TCP_KEEPINTVL = 10s`, `TCP_KEEPCNT = 3`.
2. **`SO_SNDTIMEO = 30s`**: Prevents `writeAll` from hanging indefinitely.
3. **Max Connection Lifetime = 30 minutes**.
4. **Non-blocking sockets**: Used with `poll()` for bidirectional flow.

### Relay Loop Robustness
- **`POLLHUP` drain-before-close**: Drain readable data before closing on disconnect.
- **Progress-aware spin detection**: `RelayProgress` enum tracks none/partial/forwarded progress.
- **Improved `writeAll`**: Handles `WouldBlock` with `POLLOUT` and a spin counter (32 max).
- **Overload protection**: Configurable `max_connections` (default 65535) with atomic slot reservation in accept loop.

### MiddleProxy Fixes
- MiddleProxy buffers tuned via `[server].middleproxy_buffer_kb` and overflow checks built directly into memory spans.
- Caches DC endpoints and dynamically checks upstream configs every 24 hours. Candidate rotation parses multiple proxy endpoints.

### Chronological Bug Fixes (Summary)
1. `buildServerHello` fixed against Telegram client source.
2. `GPA` mutex deadlock → `page_allocator`.
3. Pipelined data loss handled.
4. Partial write bugs → `writeAll`.
5. `POLLHUP` drain-before-close.
6. CPU busy-loop → `RelayProgress` spin detection.
7. iOS pool connections killed → two-stage timeout.
8. 99% CPU from logging → removed `log_level = .debug`, custom lock-free logger.
9. TCP keepalive implemented.
10. `SO_SNDTIMEO` added.
11. Max connection lifetime (30-minute cap).
...
27. Fragmentation ClientHello read exact patched to assemble multiple TCP records and drop "short read" problems.

## Development Conventions

- **Memory Management**: Pass `Allocator` to functions; use `defer` for cleanup.
- **Error Handling**: Use Zig error unions (`!T`) with `try`/`catch`.
- **Testing**: Comprehensive E2E Integration tests + unit tests in `test` blocks at the bottom of `.zig` files. Includes fake localhost TCP servers directly communicating via background loopback sockets.
- **Logging**: Only `log.info` for essential events; `log.debug` for diagnostics.
- **No global mutable state**: Always pass `ProxyState` by reference.

### Repository Workflow Rule
- For every substantial code task, update `README.md` and the relevant `.agent/` documentation formats (Skills/Workflows) before finalizing, so user-facing docs and engineering notes stay in sync.
