# Bench & Validation Guide

This folder contains practical tools to validate **capacity**, **stability**, and **memory behavior** of `mtproto.zig` and reference implementations.

## Docker Compose installer E2E

`installer-e2e/run.sh` boots a privileged, isolated systemd container with its
own Docker daemon, runs the real Docker Compose installer twice, and verifies
the generated config, Caddy-only topology, WEB relay, service health, HTTPS
masking, SYN pacing, NFQUEUE loopback exclusions, persisted boot rules, and
reinstall idempotency.
GitHub Actions runs the scenario on Debian 12/13 and Ubuntu 24.04/26.04.

The Docker engine, CLI and Compose plugin are copied from the official
`docker:dind` image pinned by its multiarch image-index digest. Dependabot checks
this tooling image weekly; host distributions are selected separately by the
CI matrix or `MTPROTO_INSTALLER_E2E_IMAGE`.

The test uses a local short-lived certificate issuer and a sleeping `nfqws`
stand-in so it does not depend on public DNS, Let's Encrypt, or a source build
of zapret. Caddy, the proxy image, Docker Compose, systemd, and iptables remain
real. The proxy image is built from the current checkout, loaded into an isolated
registry, pulled by the real installer, and compared by image ID for both proxy
services. It never substitutes a previously published `latest` image for the code
under test. Run one image locally with:

```bash
MTPROTO_INSTALLER_E2E_IMAGE=debian:12 test/installer-e2e/run.sh
```

## WEB bridge contract

WEB output regressions use real nonblocking sockets to require zero queue
allocations for fully accepted pairs, reject insufficient budget before any
bytes are written, and verify ordered owned suffixes across partial header and
payload writes after source storage is overwritten. Connecting-backend retry
and retained-capacity regressions remain in place.

WEB queue coverage checks minimum-page block layout, block counts for 1 MiB,
tail packing, partial consumption and bounded recycling. On targets with a
4 KiB minimum page and 64-bit `usize`, each block carries 4088 bytes, so 1 MiB
needs 257 blocks instead of the former 512; these are layout counts, not an RSS
benchmark. Larger runtime pages can still round allocations further.

`zig build web-bridge` needs Python 3, Node.js and the configured Zig compiler. It
runs `web-bridge/render.zig` to render the production bridge and HELLO/WELCOME
vectors, then passes the actual script to the Node harness. Missing tools fail the
step. The harness checks native WebView startup, strict Android/MessagePort boundaries,
short-lived-token subprotocol use with no bearer URL, reconnect/adoption behavior,
downlink frame validation/splitting, byte/item bounds, `pagehide`, and terminal BYE.
This is an offline browser-contract check, not a live Telegram connectivity test.
The existing GitHub CI WEB-bridge step runs it separately from Zig unit tests.

WEB backend diagnostic regressions start read/stall counters just below their
maximum and exercise both zero-window and carrier-high-water guards twice. Totals
saturate while the recorded credit and backpressure behavior remain correct.

Carrier preflight regressions use 4096 IDs sharing the old validation hash buckets.
A deterministic comparison counter bounds work for a full late-CLOSE batch, one
late CLOSE and a control-only PONG; the latter performs no stream/history lookup.
Preflight allocates nothing and retains whole-batch rejection before live mutation.

WEB credential lookup unit regressions live in `src/web/credential_index.zig`,
`src/web/relay.zig` and `src/web/tokens.zig`, reached by the existing `zig build test`
target. They cover the decoded 64-bit/base64 boundary, genuine padded/bare root and
path capabilities for several users, shared-prefix collisions, wrong remainders,
and malformed/multiple bridge queries. Deterministic counters require zero full
comparisons on misses at 1/100/1000 users and 1/64/4096 tokens; no wall-clock threshold
is used. Token cases retain expiry, active-fd ownership, retry before WELCOME,
consumption, capacity reclamation and swap-removal consistency. Allocation-failure
sweeps exercise capability-index cleanup and transactional token/index growth;
repeated churn retains live collision references across in-place tombstone cleanup.

`python3 -m unittest discover -s test -p 'test_web_setup_probe.py'` exercises the installer gate against
local TLS/WSS fixtures. It proves that an ordinary HTTP 200, a wrong subprotocol,
WELCOME with a dead backend, an untrusted certificate, a wrong `resPQ` nonce and a
trickling response all fail, while root and `base_path` flows with a matching nonce
succeed. It never contacts Telegram.

## Real-process relay E2E

The direct nonce regression in `src/proxy/proxy.zig` checks nonce-only output and
pipelined AES-CTR continuity with and without a promotion tag, for all three
transport modes, fast mode on/off and signed media DC indices. Slot cleanup runs
after each case. `src/proxy/middle_proxy_routing.zig` separately covers
`direct_users` plus a tag, preserving the media bypass and mandatory MiddleProxy
for CDN DC203. Existing `src/protocol/middleproxy.zig` wire tests verify both the
tagged `RPC_PROXY_REQ` extension and its absence when no tag is configured.

FakeTLS size regressions authenticate X25519, PQ and combined-share fixtures,
including exactly 4096 bytes; correctly signed larger inputs are classified
before authentication. Strict parsing still accepts records up to the existing
TLS limit. A native masking regression forwards the complete oversized record
to a loopback backend after releasing the original handshake storage.

Key-share regressions cover PQ only, X25519 only, both (PQ priority), neither,
absent/unknown shares, malformed lengths and the existing duplicate policies.
The masking test also forwards a correctly signed hello without supported shares.
Shared Python TLS-auth probes and the Zig authentication benchmark now offer a
32-byte X25519 share before computing the digest, preserving the fixed digest and
Session ID offsets.

ServerHello regressions compare allocating and into-builder framing, Session ID,
cipher, canonical X25519 and HMAC invariants for normal/PQ responses at minimum,
legacy static, custom and maximum certificate sizes. The zero-setting fallback
is bounded to 2400..3600; explicit min/max/custom sizes keep their clamp policy.
Process initialization/preparation checks one stable size across repeated
classical/PQ connections for default and explicit settings. They check undersized
storage,
allocation-free normal preparation/full writes with a failing allocator, exact
partial/EAGAIN queue ownership after scratch overwrite, and persistent explicit
desync ownership together with the existing split write/timer regression.

Obfuscated-handshake regressions compare one-block secret trials with a full
64-byte decrypt for every supported protocol tag, signed DC indices (including
zero and i16 boundaries), big-endian counter carry and u128 wrap. They check
wrong-secret/malformed-tag rejection, both directional key/IV derivations and
post-handshake stream continuity across different chunk boundaries.

ClientHello ownership regressions drive the real TLS-header handler with a failing
allocator at the inline boundary and maximum TLS record. Inline storage remains
allocation-free; heap OOM closes and releases the slot without publishing a length
that exceeds the available storage or wiping unrelated inline bytes.

The shared Linux accept errno regression distinguishes EINTR retry, EAGAIN and
all eight documented pending TCP network errors, abort/reset, fd quotas, resource
exhaustion and explicit firewall rejection. Both ordinary and WEB listeners use
that mapping; existing loopback tests still cover nonblocking accept and peer
address ownership without needing synthetic kernel failures.

Native DNS regressions exercise the production collector with 97 addresses plus
a canonical name through its 32-result queue, preserving every address and order.
Injected initial/growth allocation failures still drain and join, release memory,
and report OOM ahead of a later producer failure. Further cases propagate lookup
errors, reject empty results, and cancel/join a parked producer through Io events
without sleeps, real DNS requests or resolver-file changes. Existing resolver
preflight, preset-stop and separate WEB/getent regressions remain in place.

Candidate traversal regressions retain all 255/256/257 snapshot addresses in order,
then check repeated exhaustion and empty replacement. Mask retries use an iterative
path bounded by the snapshot and original handshake deadline, without retrying
local socket/epoll resource failures.

The regression in `src/web/child_process.zig` blocks SIGTERM before initializing
the Io backend, then requires the child to terminate by that signal. This checks
GNU `env` signal unblocking through `/usr/bin/gnuenv` on Ubuntu 26.04 and
`/usr/bin/env` on Debian/Ubuntu 24.04; a normal exit is a failure, even if its
status encodes SIGTERM.

Zig relay unit tests cover every pair of TCP split positions through multiple
FakeTLS application records and an intervening CCS, using the real AES-CTR states.
They also cover one-byte segmentation, malformed headers, and incomplete framing
at EOF. C2S consumes all records in one bounded read chunk before reusing scratch.

One-part C2S batches use `writeSlotFd`; multipart batches use `writevSlotFd` inside
the same suffix-owning helper. Regressions compare their exact streams and budget
charges at every partial prefix, plus empty input, real one-part EAGAIN, queue
overflow and atomic OOM preservation of existing queued bytes.

Direct C2S socketpair regressions use different client/upstream AES keys and a
two-operation budget to require one read plus one scatter write for three records
with an intervening CCS. They check a partial write inside the second payload,
real socket EAGAIN, read-exhausted byte/operation budgets, exact owned suffixes
after scratch overwrite, and later queue flushing. Further cases forward partial
record bodies immediately across reads, preserve a valid prefix before a malformed
record, and split 131 tiny records into bounded batches without losing order when
the first batch exhausts output capacity. Counters retain per-payload-piece units.

S2C unit tests check exact multi-record wire bytes, a single budgeted scatter
write, partial writes at every iovec boundary, ordered fallback, and stack-header
reuse across batches. Queue tests inject allocation failures during multipart
reservation and preserve existing data, the byte cap, and managed pool accounting.
Large-payload tests also cross the 32-record batch boundary with DRS enabled and
disabled, verify the 16367-byte bulk cap and unchanged warmup, and reconstruct all
payload bytes through the receiving TLS parser. The cap avoids repeated `0x4000`
FakeTLS lengths; that length is legal in real TLS 1.3, so this is a sizing heuristic.

Deterministic deadline tests distinguish the selected sliding idle minimum from
absolute admission/handshake, connect, MP-stage, desync, mask-lifetime and wedge
deadlines, with absolute priority on ties. They check idle extension and shortening,
early wakeup/recomputation without premature close, multiple heap entries, exact
absolute stage changes, expiry/close, slot reuse and generation rejection. Native
timerfd tests inspect rearm selection for slots, shutdown, accept backoff and stats
using supplied timestamps, without sleeping or depending on wall-clock precision.

Mask-lifetime regressions parse omitted/zero/custom settings as 300/0/custom.
Native timer tests simulate continuous activity with heap refresh/wakeups: ordinary
masking closes exactly at the default/custom absolute limit, while explicit opt-out,
WEB carriers and authenticated relays remain active beyond 300 seconds and still
close later on idle expiry. Config generators omit the key and inherit the runtime
default; existing explicit values are retained.

Activity regressions cover FakeTLS/direct/mask reads in both directions, partial
handshake and MP framing, real EAGAIN, exhausted budgets and blocked/empty writes.
They verify progress semantics and a shared first-byte/activity sample, without
requiring exact clock values. Drain backpressure and duplicate EOF preserve the
previous activity value; each successful iteration keeps a fresh sample.

Relay-drain socketpair tests exercise multiple chunks in one call, the shared
read/write byte and operation limits in both directions, unread bytes under queue
backpressure, and exactly one first-EOF notification with the reverse half still
usable. They need no daemon, listener or updater. The existing stress scenarios
cover burst, slow client/DC, queue pressure, half-close, and endurance traffic;
the drain keeps their existing queue, crypto and lifecycle handlers.

The TCP HUP regression receives a response larger than a dispatch budget after
client FIN and upstream FIN, then drives actual epoll events through slot dispatch.
It covers raw masking and direct-obfuscated relay, with and without a restricted
client send buffer. It checks exact delivery, HUP parking under queued-output
backpressure, resumption with generation tokens, and final graceful slot release.

Config regressions cover the disabled Split-TLS default, explicit `desync=true`,
and timing settings that leave it disabled. The ServerHello write/timer regression
opts in explicitly and retains the existing split-delay behavior.

`zig build e2e` builds a dedicated non-shipping proxy executable and a small
obfuscated-handshake generator. The Python harness starts both the real proxy and
a deterministic loopback DC, authenticates with FakeTLS, supplies a valid
64-byte MTProto nonce, and checks complete C2S and S2C relay progress. The local
DC override exists only in that dedicated executable; normal builds cannot accept
the test-only command-line option. This Linux-only scenario needs Python 3 but no
Telegram connectivity or elevated privileges.

`zig build e2e -- --workers=2` additionally verifies two live listening
socket inodes on the same address/port (a real `SO_REUSEPORT` group), completes
the relay, and checks graceful process shutdown. CI executes the default,
two-worker, and `zig build -Doptimize=ReleaseFast e2e` variants. The ReleaseFast
variant matches the default production mode. CI also runs
`zig build -Doptimize=ReleaseFast -Ddataplane_safety=true e2e` for the optional
hardened ReleaseSafe mode. These scenarios catch runtime-only release defects that
a cross-compile or binary-exists check cannot detect. Deep CI retains the explicit
ReleaseSafe two-worker variant with ThreadSanitizer instrumentation.

## Offline full-relay Stress CI

`.github/workflows/stress-ci.yml` is a separate Ubuntu 26.04 job; it is **not**
part of each push/PR test. While this workflow lives only on the validation
branch, GitHub does not show its `Run workflow` button or run its weekly schedule:
those triggers require a workflow file on the default branch. The registered
workflow can instead be dispatched explicitly from the validation branch with
GitHub CLI (do not omit `--ref`):

```bash
gh workflow run stress-ci.yml --repo XXcipherX/mtproto.zig --ref stress-validation-36359107644 -f scenario=full
gh workflow run stress-ci.yml --repo XXcipherX/mtproto.zig --ref stress-validation-36359107644 -f scenario=endurance -f endurance_minutes=20
```

These commands start remote GitHub jobs; they do not build or test on the local
machine. `zig build -Doptimize=ReleaseFast
stress-tools` builds the same compile-time-hooked E2E proxy in genuine ReleaseFast,
matching the default production optimize mode, plus a batch-mode
obfuscated-handshake generator. The normal shipping executable has no DC
override. No Telegram, public endpoint, self-hosted runner, Python package
installation, or external network is used during the stress run.

`test/stress_ci.py` creates a seed-deterministic number of connections for each
virtual user, then ramps the population through 25/50/75/100%. Every counted
relay first completes a unique, authenticated FakeTLS ClientHello; a fresh Zig-
generated MTProto nonce; the real direct upstream connection; and a validated
encrypted C2S/S2C exchange. The asyncio fake DC verifies the intermediate
frame's connection ID, sequence, deterministic payload and checksum, and sends
a response bound to that exact request. The client decrypts and verifies the
complete response. Thus a held socket alone never counts as relay-ready.

The one workflow supports `quick`, `steady`, `churn`, `adversarial`, `full`, and
optional `endurance`, using shared ramp, steady traffic, burst, slow client/DC
reader, reconnect,
full-lifecycle churn, half-close, cleanup and graceful-shutdown phases. Both
`adversarial` and `full` also include `queue_pressure`: 12 C2S and 24 S2C
full-relay sessions use 252 validated 16,000-byte frames each. Only the
synthetic recipient's receive buffer is reduced (requested 4096 bytes; effective
Linux value is recorded) and its reads are paused. For S2C, the fake DC first
validates and buffers all requests, then releases the responses while client
reads are paused, so an increased worker managed-buffer peak is attributable to
the S2C queue rather than upstream request congestion. Each direction must
increase the historical worker peak relative to its own baseline, fully drain
and verify every response, and show no managed-budget denial. The queue block
pool intentionally retains freed pages, so nonzero managed *current* after
drain is not by itself a leak.

`endurance` uses the same seeded full-relay ramp and bounded cleanup, but holds
the persistent population for 1–30 minutes (default 20). A seed-derived schedule
varies the approximately 2-second traffic tick, selects a small set of distinct
sessions per tick, weights body sizes toward 256/1024 bytes with occasional
4096/16000-byte messages, and replaces roughly one connection every 9–18 seconds
through the complete handshake/relay path. The proxy's test configuration sets
idle timeout beyond the selected duration; it does not change production socket
policy. Every 30 seconds the harness reconciles real client/proxy/DC liveness,
worker heartbeats, pool drops, managed use and RSS. The report includes live
start/min/end, reconnect and payload counts, RSS/FD range, managed stats, and
Linux keepalive/abort and softnet-drop deltas. A nonzero system-wide TCP abort
counter alone is diagnostic, not proof that this proxy lost a relay.

Manual inputs are `scenario`, `proxy_log_level`, `users`, `connections_min`,
`connections_max`, `workers`,
`steady_seconds`, `active_percent`, `payload_bytes`, `traffic_interval_ms`,
`churn_total`, `churn_concurrency`, `slow_reader_percent`,
`reconnect_percent`, `success_threshold`, `seed`, and `endurance_minutes`.
Empty inputs (and the weekly schedule if the workflow is ever promoted to the
default branch) resolve to the single default set in `StressConfig`: `full`,
`info` proxy logs, 1000 users, 5–15 connections/user, 2 workers, 60 s steady, 10% active,
4096-byte bodies, 1000 ms interval, 20000 churn lifecycles, 500 churn task
workers, 5% slow readers, 20% reconnect, 99.5% minimum success, seed 1337;
`endurance_minutes=20` is used only for the optional endurance scenario.

The harness rejects a requested population above 15000 simultaneous full
relays or 200000 planned lifecycles, raises only its own soft `RLIMIT_NOFILE`
when the runner hard limit permits, opens at most 64 handshakes concurrently,
paces churn at 100 starts/s, and uses four loopback source /24s to reduce
client ephemeral-port reuse pressure. It does not change global sysctls. The
generated proxy config derives `max_connections` from the actual seeded total
plus reconnect/churn headroom and keeps the planned peak below the proxy's
90% admission-pause threshold. It disables only the per-subnet rate *rate* limit,
keeps the shared in-flight handshake admission path, and sets `fast_mode=false`
so both AES conversions execute. `workers=0` is auto, as in production. A
multi-worker run also proves the live `SO_REUSEPORT` listener group.
The generated proxy idle timeout is at least one hour, longer than the hosted
job's 45-minute limit. Ordinary held relays therefore remain eligible for the
later queue-pressure and churn checks even if those phases run slowly; this
test-only setting does not change the production idle policy.
The synthetic DC waits 61 minutes for the first byte of a *new* frame on an
otherwise idle relay; the remaining header and body each have a 30-second
completion timeout.

Artifacts contain exact population/settings, per-phase results, sampled RSS/
VM/FD/TCP, Linux TCP keepalive/abort and per-CPU receive-drop/budget counters,
worker managed-buffer stats,
proxy/fake-DC logs, and bounded
failure context. Held Python objects do not count as live relays: the harness
maps each client fd to its Linux TCP inode/state, cross-checks proxy-side
`ESTABLISHED` and fake-DC active logical IDs, and removes dead sessions after
each phase. Only deliberately slowed peers may be classified as expected
adversarial closures; ordinary losses fail the configured threshold. Failure-
time evidence is written before bounded teardown, separately from the post-
cleanup state. Manual `proxy_log_level=debug` captures close reasons for
targeted diagnosis; fake-DC peer-close reasons are recorded independently.
Scheduled runs keep `info` to avoid observer overhead.
Port/FD exhaustion on the generator is classified separately from proxy
corruption. There is no throughput or latency hard gate; latency is reported
only. MiddleProxy and WEB transport
stress are future extensions, not covered by this direct-DC suite.

The historical capacity numbers below are **idle sockets** or **FakeTLS-auth
only**. They do not establish any full-MTProto-relay stress capacity; consult
the actual Stress CI run artifact for that result.

## Handshake performance signals

The standalone `mtproto-bench` program has two handshake-specific modes in
addition to the encapsulation benchmark and soak test:

```bash
zig build -Doptimize=ReleaseFast bench -- handshake --iterations=500000
zig build -Doptimize=ReleaseFast bench -- handshake-path --iterations=500000 --candidate-count=4
```

`handshake` validates a complete, authenticated and structurally valid FakeTLS
ClientHello. `handshake-path` parses an obfuscated MTProto handshake and stages
the requested number of route candidates through the production candidate-store
implementation. Candidate counts 1 and 4 cover the allocation-free inline path;
8 covers its heap fallback. CI records 1/4/8 results as artifacts without applying
a hard timing threshold, because shared-runner timing is too noisy for a reliable
pass/fail gate. A malformed benchmark vector, failed authentication, allocation
failure or crash still fails the job.

## Optimized-image AES assertion

`bash test/check_hardware_aes.sh` extracts the actual `MTPROTO_CPU` argument from
the amd64-v3 publishing workflow and compiles `hardware_aes_probe.zig` for that
target. Its compile-time assertion requires Zig's hardware AES backend. This is
stronger than checking that the CPU-profile text contains `aes`, while keeping the
generic amd64/arm64 images free to target baseline-compatible CPUs.
The optimized publishing job runs in parallel with the native generic-image
matrix. Keep its literal `MTPROTO_CPU` build argument discoverable by this check.

## Tools

- `capacity_connections_probe.py` — concurrent connection sweeps with RSS tracking.
- `connection_stability_check.py` — churn + idle-pool stability harness (leak/regression detector).
- `daemon_smoke.py` — Linux-only real-daemon FakeTLS smoke used by CI; validates a good secret and rejects the same SNI with a bad secret.

## Probe-helper unit tests

Run the offline helper regressions with:

```bash
python3 -m unittest discover -s test -p 'test_probe_helpers.py'
```

They require neither a proxy process nor network access. The cases guard complete
`/proc` snapshots, immediate EMFILE/ENFILE termination, a fresh payload from a
callable for every churn connection, and hostname-keyed caching of realistic TLS
ClientHello templates.

## What We Measure

The capacity probe reports, per target level:

- `connect_ok` — successful TCP connect attempts from the probe client.
- `payload_ok` — successful payload submission for selected traffic mode.
- `established_server_side` — server-side held `ESTABLISHED` sockets.
- `rss_kb` — process-tree RSS (listener process + children).
- `conn stats ... managed_buf=<used>/<limit>KiB peak=<peak>KiB` — runtime use of the proxy's shared relay/MiddleProxy buffer budget, not whole-process RSS or kernel socket memory.
- `drops: ... memory_pressure+=...` — allocations rejected at that hard budget; optional shrink can retain its old buffer, while required growth sheds the requesting path. Sustained increments identify pressure even when total RSS still includes ample kernel/process headroom.
- `stable` — level considered stable per probe criteria.

This is a capacity/memory harness, not an end-user Telegram UX benchmark.

## Traffic Modes

- `idle`
  - Connect and hold sockets without payload.
  - Best for FD/socket ceilings and idle memory.
- `tls-auth`
  - Sends MTProto TLS-auth ClientHello with valid SNI and digest layout.
  - Best for apples-to-apples active auth memory comparison.
- `tls-auth-full`
  - Same as `tls-auth`, plus checks proxy response framing (`ServerHello + CCS + AppData` header sequence).
  - Best for strict handshake sanity smoke checks.
- `tls-clienthello`
  - Sends realistic TLS ClientHello synthesized via Python `ssl` with SNI.
  - Useful for strict parser/masking behavior checks.

## Environment

- Linux host with `/proc` and `ss` (`iproute2`).
- Python 3.10+.
- For `capacity_connections_probe.py`, a benchmark workspace under `/root/benchmarks` by default, including the expected `bin/`, `configs/`, and `work/` assets. These binaries/configs are not shipped in this repository.
- `daemon_smoke.py` only needs a locally built `zig-out/bin/mtproto-proxy`; it creates a temporary config itself and does not use the benchmark workspace.

## Quick Start

```bash
# CI-style daemon handshake smoke
zig build
python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy

# Show available profiles
python3 test/capacity_connections_probe.py --list-profiles

# Single profile, default mode (idle)
sudo -E python3 test/capacity_connections_probe.py --profile mtproto.zig

# Full matrix run
sudo -E python3 test/capacity_connections_probe.py --profile all --sysctl-tune
```

The `make capacity-probe-idle` and `make capacity-probe-active` targets select the `mtproto.zig` profile but do not build or populate `/root/benchmarks`; prepare that workspace before using them.

## Recommended Runs

### 1) Final cross-proxy TLS-auth comparison

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile all \
  --traffic-mode tls-auth \
  --tls-domain google.com \
  --levels 500,1000,1500,2000 \
  --open-budget-sec 14 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000 \
  --output /root/benchmarks/results/capacity_connections_tls_auth.final_all.json
```

### 2) Final cross-proxy idle comparison

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile all \
  --traffic-mode idle \
  --levels 4000,8000,12000 \
  --open-budget-sec 24 \
  --hold-seconds 0.8 \
  --settle-seconds 1.0 \
  --connect-timeout-sec 0.1 \
  --nofile 300000 \
  --nproc 20000 \
  --output /root/benchmarks/results/capacity_connections_idle.final_all.json
```

### 3) Strict handshake smoke (`tls-auth-full`)

```bash
sudo -E python3 test/capacity_connections_probe.py \
  --profile mtproto.zig \
  --traffic-mode tls-auth-full \
  --tls-domain google.com \
  --levels 100,200 \
  --open-budget-sec 8 \
  --hold-seconds 0.5 \
  --settle-seconds 0.8 \
  --connect-timeout-sec 0.1 \
  --nofile 200000 \
  --nproc 12000 \
  --output /root/benchmarks/results/capacity_connections_mtproto_zig.tls_auth_full_smoke_v2.json
```

## Final Snapshot (Current)

Host: (1 vCPU / 1 GB RAM)

Notes:

- Startup failures are now classified as `startup_exited` vs `startup_timeout` and include `log_tail` for root-cause visibility.

### TLS-auth @ 2000

| Proxy | RSS (KB) | Established | Stable |
|---|---:|---:|---|
| **mtproto.zig** | **8,832** | **2,000** | ✅ |
| Official MTProxy | 23,296 | 2,000 | ✅ |
| Teleproxy | 20,952 | 2,000 | ✅ |
| Telemt | 38,272 | 2,000 | ✅ |
| mtg | 55,296 | 0 | ⚠ partial (payload_ok=2000, established=0) |
| mtprotoproxy | 50,944 | 2,000 | ✅ |
| mtproto_proxy | startup_exited | - | - |

`mtproto.zig` vs historical baseline (`84,544 KB`): **-89.55% RSS** at 2000.

### Idle @ 12000

| Proxy | RSS (KB) | Established | Stable |
|---|---:|---:|---|
| **mtproto.zig** | **49,024** | **12,000** | ✅ |
| Telemt | 70,032 | 11,023 | ⚠ partial @12000 (stable up to 8000) |
| Official MTProxy | 74,116 | 12,000 | ✅ |
| Teleproxy | 77,864 | 12,000 | ✅ |
| mtg | 97,792 | 7,287 | ⚠ partial @12000 (stable up to 4000) |
| mtprotoproxy | 123,724 | 12,000 | ✅ |
| mtproto_proxy | 396,328 | 12,000 | ✅ (idle-only; TLS-auth startup_exited) |

## Interpreting Results Correctly

- Compare proxies at the **same target level**.
- Prefer **total RSS at level** over only delta-per-conn.
- Watch both `payload_ok` and `established_server_side`.
- For strict parser checks, use `tls-auth-full` or `tls-clienthello`.

## Stability Harness

`connection_stability_check.py` is useful for leak-like regressions after churn and idle pressure.

Example:

```bash
python3 test/connection_stability_check.py \
  --host 127.0.0.1 --port 443 --pid <proxy_pid> \
  --idle-connections 6000 --idle-cycles 3 \
  --churn-total 30000 --churn-concurrency 300
```

## Practical Tuning Notes

Primary bottlenecks typically are:

1. `max_connections` runtime cap.
2. Host FD limits (`ulimit -n`, systemd `LimitNOFILE`).
3. Available RAM and the `managed_buf` high-water mark; repeated `memory_pressure` drops mean the shared burst budget is saturated.

When pushing higher levels, tune config and probe limits together.
