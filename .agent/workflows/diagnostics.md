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
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "conn stats|drops:|auto-clamping max_connections|baseline RAM ceiling|RAM admission clamp|max_connections clamped|fd quota reached|failed to resume accepts|connection saturation|saturation eased"'

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
- `conn stats: active=... hs_inflight=... accepted+=... closed+=... tracked_fds=... total=... paused=<fd>/<saturation>` is the current 10s heartbeat for production visibility.
- `paused=true/false` means fd-quota backoff is active; `paused=false/true` means 90%/80% saturation hysteresis is active.
- Fatal hangups during `connecting_upstream` are now cleaned through the connect-completion path; repeated CPU spin on dead upstream sockets should no longer be expected.
- `drops: ... hs_budget+=...` means the global handshake-inflight budget or the per-subnet unauthenticated concurrency allowance rejected a new handshake.
- `drops: ... mp_fallback+=...` means MiddleProxy degraded and the proxy recovered by reconnecting directly to the same DC.
- `drops: ... rate+=...` means the per-subnet token bucket rejected new connections; IPv4-mapped IPv6 addresses are grouped with their native IPv4 `/24`.
- At debug level, `valid FakeTLS ClientHello: ... client=<ip>` identifies the authenticated client's IP without its ephemeral source port; unauthenticated and invalid-secret probes do not emit this line.
- A `phase=mask_relaying` close reports `mask_cause`, the client IP without its source port, and `raw_c2s`/`raw_s2c` (raw bytes queued toward and received from the mask backend). `reason` describes how that relay later ended; `mask_cause` records why it entered masking in the first place. `web_carrier` is the expected WEB-domain path; `sni_mismatch`, `secret_mismatch`, `timestamp_skew`, `replay`, `invalid_session_id`, and `malformed_client_hello` isolate ordinary FakeTLS rejection classes without repeating HMAC work. A `timestamp_skew` line also carries `skew_s=<server timestamp - authenticated client timestamp>`; positive means the client timestamp is behind the server and negative means it is ahead.
- A healthy WEB carrier logs `web session opened ... (client address: real)` in the relay. `loopback` there means the browser address was not preserved through the Caddy/PROXY-v2 hop; inspect `[web].mask_backend`, Caddy listener wrappers, and `X-Forwarded-For` handling.
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
buffered payload, refused admissions and forwarded byte counters. Its buffer gauge
is not RSS and is independent of the main process's `managed_buf`: retained
allocations and kernel sockets are excluded. Repeated refusals indicate pressure
against the configured WEB limits, not necessarily a main-proxy capacity problem.
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

- `RAM ceiling` is the startup baseline-admission ceiling, not simultaneous full-buffer capacity. `Configured` is the requested connection cap before any later fd clamp. `auto-clamping max_connections ...` means the effective-memory clamp reduced that configured cap to the RAM ceiling. `max_connections clamped ... due to RLIMIT_NOFILE` means the later fd-budget clamp reduced it again.
- `fd quota reached ...` means the listener paused accepts; expect the first `paused=` flag to flip to `true` in nearby `conn stats` lines until the retry window clears.
- `managed_buf=<used>/<limit>KiB peak=<peak>KiB` in `conn stats` reports the current, hard-limit, and process-lifetime peak for relay/MiddleProxy dynamic storage. It is not whole-process RSS and excludes kernel socket memory and non-managed allocations.
- `memory_pressure+=...` means this hard buffer limit rejected allocations; an optional shrink may keep its existing allocation, while required growth sheds only the requesting path. Repeated increments indicate that the configured connection/traffic target exceeds the available burst budget.
- `hs_budget+=...` means connection churn is exhausting either the global handshake budget or a source subnet's unauthenticated concurrency allowance before established relays become the bottleneck.
- `mp_fallback+=...` means users are still being served, but MiddleProxy path quality is degraded enough to trigger direct fallback.
- `ios_wedge: candidates+=... cancelled+=... fresh_close+=... proven_close+=... suppressed+=...` is emitted only when `client_silence_close_sec` is enabled. `fresh_close` is a bounded first-exchange recovery, `proven_close` follows an earlier mature healthy continuation, and `suppressed` counts transitions into a per-client/DC backoff, idle-deadline, or fixed-table fail-safe episode rather than every matching exchange left to ordinary idle timeout. `armed fresh` is emitted once for the fresh candidate, while `armed proven` is emitted once per connection and backoff stage; later proven candidates remain fully tracked but do not repeat the same diagnostic.
- A valid Telegram-style FakeTLS ClientHello must have a 32-byte Session ID; non-32-byte test clients are expected to be rejected/masked.
- `connection saturation ...` / `saturation eased ...` is RAM/capacity admission control, not an fd-limit incident.
- A healthy idle box should keep both `paused=` flags at `false` and `tracked_fds` close to active socket count plus listener/upstream overhead.
- For TLS-auth probes, replace `proxy.example.com` with the deployed `[censorship].tls_domain`; SNI mismatch is intentionally masked by the proxy.
