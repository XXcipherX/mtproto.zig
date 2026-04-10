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

# Runtime capacity / fd-pressure signals
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "conn stats|drops:|max_connections clamped|fd quota reached|failed to resume accepts|connection saturation|saturation eased"'

# Connect-path and fallback signals
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "middle-proxy exhausted|middle-proxy handshake failed|media path connect failed|epoll hup/err"'

# Timeout signals from event-loop timers
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "1 hour ago" --no-pager | grep -E "idle pre-first-byte timeout|handshake timeout|relay idle timeout"'

# MiddleProxy metadata refresh state
ssh root@<SERVER_IP> 'journalctl -u mtproto-proxy --since "24 hours ago" --no-pager | grep -E "Middle-proxy cache updated|Initial middle-proxy refresh failed|Middle-proxy refresh failed"'
```

Note:

- Older grep patterns like `DIAG: Short read`, `DC4 MiddleProxy timeout`, `DC203 MiddleProxy timeout` are legacy and not emitted by current code.
- `conn stats: active=... hs_inflight=... accepted+=... closed+=... tracked_fds=... total=... paused=<fd>/<saturation>` is the current 10s heartbeat for production visibility.
- `paused=true/false` means fd-quota backoff is active; `paused=false/true` means 90%/80% saturation hysteresis is active.
- Fatal hangups during `connecting_upstream` are now cleaned through the connect-completion path; repeated CPU spin on dead upstream sockets should no longer be expected.
- `drops: ... hs_budget+=...` means the handshake-inflight budget (30% of `max_connections`) rejected excess new handshakes.
- `drops: ... mp_fallback+=...` means MiddleProxy degraded and the proxy recovered by reconnecting directly to the same DC.

## IPv6 Hopping and DNS

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
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && sudo python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth --tls-domain google.com --levels 500,1000,1500,2000 --open-budget-sec 14 --hold-seconds 0.8 --settle-seconds 1.0 --connect-timeout-sec 0.1 --nofile 200000 --nproc 12000'

# Stability harness (from a repo checkout on the server)
ssh root@<SERVER_IP> 'cd /root/mtproto.zig && sudo python3 test/connection_stability_check.py --host 127.0.0.1 --port 443 --pid $(pgrep -f mtproto-proxy | head -n1) --idle-connections 6000 --idle-cycles 3 --churn-total 30000 --churn-concurrency 300'
```

Interpretation helpers:

- `max_connections clamped ...` means the configured connection cap was reduced to fit current `RLIMIT_NOFILE`.
- `fd quota reached ...` means the listener paused accepts; expect the first `paused=` flag to flip to `true` in nearby `conn stats` lines until the retry window clears.
- `hs_budget+=...` means connection churn is exhausting the handshake budget before established relays become the bottleneck.
- `mp_fallback+=...` means users are still being served, but MiddleProxy path quality is degraded enough to trigger direct fallback.
- `connection saturation ...` / `saturation eased ...` is RAM/capacity admission control, not an fd-limit incident.
- A healthy idle box should keep both `paused=` flags at `false` and `tracked_fds` close to active socket count plus listener/upstream overhead.
