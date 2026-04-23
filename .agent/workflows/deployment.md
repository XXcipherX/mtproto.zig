---
description: How to build, run, and deploy the MTProto Zig proxy.
---

# Deployment Workflow

This workflow documents current build and deploy paths as implemented in `Makefile`, `deploy/install.sh`, and `deploy/setup_tunnel.sh`.

## Prerequisites

- Zig 0.15.2 for local builds
- SSH access to VPS
- systemd on target host
- Ubuntu 24.04 + root access for blocked-region tunnel mode
- AmneziaWG client config (`.conf`) when using tunnel deploys

## Key Commands

- `make build` : debug build
- `make release` : release build (`ReleaseFast`)
- `make run CONFIG=<path>` : run proxy with selected config
- `make test` : run unit tests
- `make bench` : encapsulation microbench
- `make soak` : 30s multithreaded soak
- `make stability-check PID=<pid> [HOST=127.0.0.1 PORT=443]` : churn + idle-pool stability harness
- `make stability-check-load [HOST=127.0.0.1 PORT=443]` : load-only stability smoke
- `make capacity-probe-idle` : idle-socket capacity probe
- `make capacity-probe-active` : TLS-auth capacity probe
- `make deploy SERVER=<ip>` : cross-compile and deploy to VPS
- `make migrate SERVER=<ip> [PASSWORD=<pass>]` : bootstrap + push config + deploy
- `make update-dns SERVER=<ip>` : run Cloudflare DNS updater helper
- `make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>] [TUNNEL_MODE=direct|preserve|middleproxy]` : full migration + AmneziaWG tunnel
- `make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path> [TUNNEL_MODE=direct|preserve|middleproxy]` : add tunnel to an already-installed node
- `make deploy-monitor SERVER=<ip>` : deploy optional monitoring dashboard
- `make monitor SERVER=<ip>` : open SSH tunnel to optional monitoring dashboard

## CI-Parity Validation

Before merging behavior changes, match the GitHub workflow as closely as practical:

```bash
zig fmt --check build.zig src test_addr.zig test_al.zig
python3 -m py_compile test/*.py
shellcheck --severity=error deploy/*.sh deploy/monitor/*.sh
zig build test
zig build -Doptimize=ReleaseSafe test
zig build
python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux
docker build --build-arg ZIG_VERSION=0.15.2 -t mtproto-zig-smoke .
```

The daemon smoke launches a real localhost proxy, verifies a valid FakeTLS handshake, and checks that the same SNI with a bad secret does not receive a valid FakeTLS response.

## `make deploy` (current behavior)

1. Builds Linux target: `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3`.
2. Stops remote service (`systemctl stop mtproto-proxy`).
3. Uploads binary and `deploy/*.sh` via `scp`.
4. Uploads config when local config file exists.
5. Uploads `.env` as `/opt/mtproto-proxy/env.sh` when present locally.
6. Starts service and prints status.

Why service stop is required:

- Unit file contains `ProtectSystem=strict` and `ReadOnlyPaths=/opt/mtproto-proxy`.
- Replacing binaries safely is simplest when service is stopped first.

## `make migrate`

1. Optionally seeds the root SSH authorized key when `PASSWORD=` is provided.
2. Runs `deploy/install.sh` remotely.
3. Uploads local `config.toml`.
4. Calls `make deploy`.
5. Optionally runs `make update-dns` when `UPDATE_DNS=1|true`.

Fresh self-domain installs need a masking domain during `deploy/install.sh`. `make migrate` currently streams the installer over non-interactive SSH, so for a brand-new host either run the one-line `MASK_DOMAIN=...` installer first or invoke the installer manually with `ssh root@<ip> 'MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com bash -s' < deploy/install.sh`, then use `make deploy`.

## Tunnel Workflows

`make deploy-tunnel` first runs `make migrate`, then uploads the AmneziaWG client config plus `deploy/setup_tunnel.sh` and executes the script remotely with the selected `TUNNEL_MODE`.

`make deploy-tunnel-only` skips bootstrap/redeploy and only applies the tunnel plumbing to an existing installation.

Remote tunnel setup currently:

- Installs `amneziawg-tools`.
- Creates network namespace `tg_proxy_ns` plus a `veth_main`/`veth_ns` pair and namespace-local DNS.
- Brings up `awg0` inside the namespace only.
- Adds host DNAT `:443 -> 10.200.200.2:443` and namespace policy routing so replies go back through the veth path, not the tunnel.
- Rewrites the systemd unit to `ip netns exec tg_proxy_ns /opt/mtproto-proxy/mtproto-proxy ...`.
- Applies one of three modes: `direct` (`use_middle_proxy=false` for regular traffic), `preserve` (leave config as-is), or `middleproxy` (`use_middle_proxy=true`).
- Preserves an existing promotion `tag`, and may restore it from `env.sh`.
- Validates all 5 Telegram DCs through the tunnel before finishing.

Important operational notes:

- `direct` is only the default. Media path still prefers MiddleProxy when available, and `middleproxy` mode is supported when you want regular traffic to stay on ME too.
- Host SSH and host-network services stay outside the namespace; only proxy traffic is redirected through AWG.

## One-line operator update path

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The installer is idempotent and preserves `config.toml` on update; existing `env.sh` stays untouched unless install is rerun with fresh `CF_TOKEN` / `CF_ZONE`.

For a fresh self-domain masking install, prefer:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo env MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com bash
```

Current installer behavior also:

- refreshes self-domain Nginx 404 masking (`setup_masking.sh`) and the masking health timer when available;
- attempts optional `zapret` / `nfqws` setup;
- refreshes optional `proxy-monitor` files on disk and restarts that service if it is already active.

Self-domain masking notes:

- Preferred setup is `MASK_DOMAIN=proxy.example.com`, with DNS `A` pointing to the VPS.
- Public `:443` stays owned by `mtproto-proxy`; Nginx listens on `127.0.0.1:8443` and returns 404 for non-proxy requests.
- Public `:80` must be reachable for Let's Encrypt HTTP-01 unless the operator provisions certificates manually.
- `setup_masking.sh` disables `/etc/nginx/sites-enabled/default` by default and makes `mtproto-masking` the default public `:80` server, so unmatched HTTP `Host`/IP requests return 404. Set `MASK_KEEP_NGINX_DEFAULT=1` only when intentionally keeping an existing default site.
- `setup_masking.sh` installs a Let's Encrypt renewal hook that reloads Nginx after certificate renewal.
- `MASK_ALLOW_SELF_SIGNED=1` is available only as a dev/test fallback; the default flow fails closed when Let's Encrypt cannot issue a certificate.
- `MASK_SET_PUBLIC_IP=0` skips rewriting `[server].public_ip`; otherwise `setup_masking.sh` sets it to the masking domain.
- Cloudflare records for the proxy domain must be DNS-only, not proxied.

## Systemd Unit Notes (`deploy/mtproto-proxy.service`)

- Default unit ships with `LimitNOFILE=131582` and `TasksMax=65535`.
- Startup first auto-clamps `max_connections` to the RAM-safe estimate from `/proc/meminfo` unless `unsafe_override_limits=true`; `ProxyState.run` then clamps again if `RLIMIT_NOFILE` cannot cover the resulting fd budget.
- Runtime relay model is still single-thread `epoll` in proxy core.
- Default unit keeps `ReadOnlyPaths=/opt/mtproto-proxy` and only `CAP_NET_BIND_SERVICE`.
- Tunnel-patched unit adds `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` and uses `ExecStartPre=/usr/local/bin/setup_netns.sh` to recreate the namespace on every restart.
