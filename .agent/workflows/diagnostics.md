---
description: Useful commands for diagnosing proxy anomalies or connection issues.
---

# Proxy Diagnostics Workflow

Use these checks on the deployed VPS to inspect service health, routing, and fallback behavior.

## Service and Process Health

```bash
# Service status
ssh root@<SERVER_IP> 'systemctl status mtproto-proxy --no-pager'

# Active sockets
ssh root@<SERVER_IP> 'ss -tnp | grep mtproto'

# Process footprint
ssh root@<SERVER_IP> 'ps -o pid,pcpu,pmem,nlwp,rss,vsz,args -p $(pgrep -f mtproto-proxy)'

# Current open-files limit seen by the process
ssh root@<SERVER_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/limits | grep "open files"'
```

## Log Checks (current message patterns)

```bash
# Recent logs
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager'

# WEB source install: data plane, relay, and shared Caddy terminator
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy -u mtproto-web-relay -u mtproto-mask-caddy --since "1 hour ago" --no-pager'

# WEB Docker install
ssh root@<SERVER_IP> 'cd /opt/mtproto-proxy && docker compose --env-file .env -f compose.yml logs --since 1h mtproto-proxy mtproto-web-relay mtproto-mask-caddy'

# WEB-only activation and direct-client masking counter
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "\[web\]\.only=true|WEB-only mode active|web_only: direct clients masked"'
ssh root@<SERVER_IP> 'cd /opt/mtproto-proxy && docker compose --env-file .env -f compose.yml logs --since 1h mtproto-proxy | grep -E "\[web\]\.only=true|WEB-only mode active|web_only: direct clients masked"'

# Runtime capacity / fd-pressure signals
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "MTProto worker|conn stats|global drops:|memory_pressure|auto-clamping max_connections|baseline RAM ceiling|RAM admission clamp|max_connections clamped|fd quota reached|failed to resume accepts|connection saturation|saturation eased"'

# Connect-path and fallback signals
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "middle-proxy exhausted|middle-proxy handshake failed|media path connect failed|epoll hup/err"'

# Timeout signals from event-loop timers
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "idle pre-first-byte timeout|handshake timeout|relay idle timeout"'

# Graceful process shutdown state
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "graceful shutdown started|graceful shutdown complete|graceful shutdown timeout reached|forcing immediate shutdown"'

# MiddleProxy metadata refresh state
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "24 hours ago" --no-pager | grep -E "Middle-proxy cache updated|Middle-proxy reactive refresh|Initial middle-proxy refresh failed|Middle-proxy refresh failed"'

# Startup masking / NAT translation decisions
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy -n 120 --no-pager | grep -E "Mask target|mask_port=.*netns|middle-proxy NAT translation|will be detected in the background"'
```

Note:

- Older grep patterns like `DIAG: Short read`, `DC4 MiddleProxy timeout`, `DC203 MiddleProxy timeout` are legacy and not emitted by current code.
- `conn stats: worker=... local_active=... global_active=... global_hs=... accepted+=... closed+=... local_pool_drops+=... tracked_fds=... global_total=... paused=<fd>/<saturation> worker_managed_buf=...` is the 10s heartbeat per worker. Worker 0 alone emits process-wide degradation deltas. Repeated local pool drops while the global cap has space indicate reuseport skew or slot-allocation pressure.
- `paused=true/false` means fd-quota backoff is active; `paused=false/true` means 90%/80% saturation hysteresis is active.
- Fatal hangups during `connecting_upstream` are now cleaned through the connect-completion path; repeated CPU spin on dead upstream sockets should no longer be expected.
- `global drops: ... hs_budget+=...` means the global handshake-inflight budget or the process-wide per-subnet unauthenticated concurrency allowance rejected a new handshake.
- `global drops: ... mp_fallback+=...` means MiddleProxy degraded and the proxy recovered by reconnecting directly to the same DC.
- `global drops: ... rate+=...` means the process-wide per-subnet token bucket rejected new connections; IPv4-mapped IPv6 addresses are grouped with their native IPv4 `/24`.
- At debug level, `valid FakeTLS ClientHello: ... client=<ip>` identifies the authenticated client's IP without its ephemeral source port; unauthenticated and invalid-secret probes do not emit this line.
- A `phase=mask_relaying` close reports `mask_cause`, the client IP without its source port, and `raw_c2s`/`raw_s2c` (raw bytes queued toward and received from the mask backend). `reason` describes how that relay later ended; `mask_cause` records why it entered masking in the first place. `web_carrier` is the expected WEB-domain path; `sni_mismatch`, `secret_mismatch`, `timestamp_skew`, `replay`, `invalid_session_id`, and `malformed_client_hello` isolate ordinary FakeTLS rejection classes without repeating HMAC work. A `timestamp_skew` line also carries `skew_s=<server timestamp - authenticated client timestamp>`; positive means the client timestamp is behind the server and negative means it is ahead.
- A healthy WEB carrier logs `web session opened ... (client address: real)` in the relay. `loopback` there means the browser address was not preserved through the Caddy/PROXY-v2 hop; inspect `[web].mask_backend`, Caddy listener wrappers, `X-Forwarded-For`, and `[web].trusted_http_sources`. That HTTP-terminator list is intentionally separate from data-plane `[web].relay_sources`.
- WEB stream failures should be correlated across `mtproto-web-relay` and the main proxy. The relay opens one backend connection per logical stream, so those streams also appear in the proxy's ordinary connection and close statistics.
- In WEB-only mode, `web_only: direct clients masked+=N` counts external peers sent to Caddy instead of MTProto. It does not count trusted relay streams. If relay streams are also rejected, verify that `[web].backend` reaches the proxy from loopback or an explicit `[web].relay_sources` address; a PROXY header cannot grant trust.
- `graceful shutdown started` means listener interest is already disabled while existing connections drain. `graceful shutdown complete` is a natural drain; `graceful shutdown timeout reached` means the remaining slots were force-closed. A second signal intentionally produces `forcing immediate shutdown`.

## WEB Metrics and DNS

For a local WEB relay snapshot (adjust the configured port):

```bash
curl -fsS http://127.0.0.1:8081/metrics
```

This endpoint requires a direct loopback peer and loopback Host, with no forwarded
or Origin headers; do not expose it through Caddy. It reports WEB sessions, streams,
refused admissions, forwarded byte counters, and retained userspace buffer capacity.
Its buffer gauge is not whole-process RSS and is independent of the main process's
`managed_buf`: unrelated metadata and kernel socket buffers are excluded. Repeated refusals indicate pressure
against the configured WEB limits, not necessarily a main-proxy capacity problem.

`mtproto_web_sessions` counts carriers across users, not devices or accounts. The
main Android carrier serves its application accounts, while a same-server availability
check can temporarily add a second carrier. Reconnect/teardown overlap also needs
headroom; do not diagnose a session-count increase as another user by itself.
`mtproto_web_streams_refused_total` counts OPENs rejected at `[web].max_streams`.
The relay sends CLOSE for that stream and keeps the carrier and other streams alive.
Use the first `refused a stream over the [web].max_streams cap` warning and the
session-close `peak N/cap streams, M refused` summary to assess sustained pressure.
The default 32 is server policy; Android's client cap of 64 does not require raising
it. Review the WEB slot budget and admission headroom before increasing either cap.

For the pinned Desktop profile, 3-second JavaScript probes and a 10-second native
health timeout check the local WebView. Native handshake/write acknowledgement,
browser-fallback and MTProto response timers are separate; see
`../skills/client-behavior/SKILL.md`. Do not use those local health values to tune
server PING/PONG or infer a client engine. The relay itself probes after 20 seconds
without received carrier bytes and closes after 90 seconds without received bytes;
one late PONG alone is not a close condition. Keep MtProtoKit and optional Rust
watchdogs separate even though their Swift WEB carrier is shared.

In the pinned iOS profile, carrier demand aggregates per-account `shouldKeepConnection`
and the client's background grace windows; app extensions do not start the carrier.
Check client connection demand when correlating background stops or reconnects.
Server keepalive cannot override a client-requested carrier stop.

MtProtoKit's legacy WEB adapter can also stall if an exact-length packet-remainder
read exceeds the 4 MiB stream window: it returns credit only after the read completes.
This is a source-derived edge case, with no confirmed occurrence in captures; see
`../skills/client-behavior/SKILL.md`. Collect client read/credit evidence before
attributing a stall to it. Keep the granted credit; raising the 2 MiB message cap or
changing native batching does not repair client consumption.

Hostname WEB backend/mask targets refresh every minute, retain the last successful
DNS snapshot on failure, and freeze candidate lists for each connect attempt.

## IPv6 Hopping and DNS

Installer-managed cron invokes `ipv6-hop.sh` without arguments every five minutes, so each run rotates IPv6 unconditionally. The script's `--auto` mode is a separate foreground ban-detection loop and is not installed as a service/cron job.

```bash
# Last hop log lines
ssh root@<SERVER_IP> 'tail -20 /var/log/mtproto-ipv6-hop.log'

# Current active IPv6
ssh root@<SERVER_IP> 'cat /tmp/mtproto-ipv6-current'

# Cron wiring
ssh root@<SERVER_IP> 'cat /etc/cron.d/mtproto-ipv6'
```

## Low-level Network Checks

```bash
# CLOSE-WAIT sockets
ssh root@<SERVER_IP> 'ss -tnp state close-wait | grep mtproto'

# Process state summary
ssh root@<SERVER_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/status | grep -E "Threads|State"'

# TCPMSS clamp rule
ssh root@<SERVER_IP> 'iptables -t mangle -L OUTPUT -n -v | grep TCPMSS'
```

## Tunnel-Specific Checks (AmneziaWG / netns mode)

Run these only when the server was prepared with `make deploy-tunnel` or `make deploy-tunnel-only`.

```bash
# Tunnel status inside namespace
ssh root@<SERVER_IP> 'ip netns exec tg_proxy_ns awg show'

# DNAT forwarding into namespace
ssh root@<SERVER_IP> 'iptables -t nat -L PREROUTING -n -v | grep 10.200.200.2'

# Namespace-side route policy
ssh root@<SERVER_IP> 'ip netns exec tg_proxy_ns ip rule show'
ssh root@<SERVER_IP> 'ip netns exec tg_proxy_ns ip route show table 100'

# DC reachability through tunnel
ssh root@<SERVER_IP> 'ip netns exec tg_proxy_ns nc -zw3 149.154.167.50 443 && echo OK'
```

## Capacity and Stability

These Python harnesses are repo-local tools. `deploy/install.sh` and `make deploy` do **not** copy `test/` into `/opt/mtproto-proxy`, so run them from a separate checkout (or benchmark workspace), not from the install directory. Replace `/root/mtproto.zig` below with your actual checkout path.

```bash
# Startup banner with RAM/capacity estimate
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy -n 80 --no-pager'

# Idle capacity probe (from a repo checkout on the server)
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && sudo python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode idle'

# Active (TLS-auth) capacity probe (from a repo checkout on the server)
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && sudo python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain proxy.example.com --levels 500,1000,1500,2000 --open-budget-sec 14 --hold-seconds 0.8 --settle-seconds 1.0 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'

# Stability harness (from a repo checkout on the server)
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && sudo python3 test/connection_stability_check.py --host 127.0.0.1 --port 443 --pid $(pgrep -f mtproto-proxy | head -n1) --idle-connections 6000 --idle-cycles 3 --churn-total 30000 --churn-concurrency 300'

# Real daemon smoke from a Linux checkout: positive FakeTLS, bad-secret rejection, and graceful SIGTERM drain
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && zig build && python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy'
```

Interpretation helpers:

- `RAM ceiling` is the startup baseline-admission ceiling, not simultaneous full-buffer capacity. `Configured` is the effective connection cap after both startup RAM and FD clamps; the managed pool is sized from this final cap. `auto-clamping max_connections ...` identifies the RAM reduction; `max_connections clamped ... due to RLIMIT_NOFILE` identifies the FD reduction. Direct `ProxyState.run` callers retain the same FD guard.
- `WEB budget` is streams plus the bounded HTTP count, which already includes carriers: default `8 × 32` is 320 potential slots when HTTP crosses the masking listener. Warnings compare this with the 90% pause threshold. Slots are shared with ordinary clients, not reserved, and teardown can overlap reconnects. `web.max_buffer_mb` belongs to the separate relay process and is additional to the main proxy's managed pool; neither is total stack RSS.
- `fd quota reached ...` means the listener paused accepts; expect the first `paused=` flag to flip to `true` in nearby `conn stats` lines until the retry window clears.
- `worker_managed_buf=<used>/<limit>KiB peak=<peak>KiB` in `conn stats` reports that worker's dynamic-storage usage, hard partition, and peak. Partition limits sum to the process cap; this is not whole-process RSS and excludes kernel socket memory and non-managed allocations.
- `memory_pressure+=...` means this hard buffer limit rejected allocations; an optional shrink may keep its existing allocation, while required growth sheds only the requesting path. Repeated increments indicate that the configured connection/traffic target exceeds the available burst budget.
- `hs_budget+=...` means connection churn is exhausting either the global handshake budget or a source subnet's unauthenticated concurrency allowance before established relays become the bottleneck.
- `mp_fallback+=...` means users are still being served, but MiddleProxy path quality is degraded enough to trigger direct fallback.
- `ios_wedge: candidates+=... cancelled+=... fresh_close+=... proven_close+=... suppressed+=...` is emitted only when `client_silence_close_sec` is enabled. `fresh_close` is a bounded first-exchange recovery, `proven_close` follows an earlier mature healthy continuation, and `suppressed` counts transitions into a per-client/DC backoff, idle-deadline, or fixed-table fail-safe episode rather than every matching exchange left to ordinary idle timeout. `armed fresh` is emitted once for the fresh candidate, while `armed proven` is emitted once per connection and backoff stage; later proven candidates remain fully tracked but do not repeat the same diagnostic.
- A valid Telegram-style FakeTLS ClientHello must have a 32-byte Session ID; non-32-byte test clients are expected to be rejected/masked.
- `connection saturation ...` / `saturation eased ...` is connection-occupancy admission control, not a measurement of RAM usage or an fd-limit incident. The banner prints rounded pause/resume counts; accept batching can overshoot the soft 90% point while preserving the hard cap.
- A healthy idle box should keep both `paused=` flags at `false`. `tracked_fds` counts registered slot client/upstream sockets, excluding listener/control fds and sockets awaiting deferred close; use process FD counts when investigating `RLIMIT_NOFILE`.
- For TLS-auth probes, replace `proxy.example.com` with the deployed `[censorship].tls_domain`; SNI mismatch is intentionally masked by the proxy.
