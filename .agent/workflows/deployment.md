---
description: How to build, run, and deploy the MTProto Zig proxy.
---

# Deployment Workflow

This workflow documents current build and deploy paths as implemented in `Makefile`, `deploy/install.sh`, and `deploy/setup_tunnel.sh`.

## Prerequisites

- Zig 0.16.0 for local builds
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
- `make update-dns SERVER=<ip>` : run Cloudflare DNS updater helper; `.env` must provide `DNS_NAME`, `CF_TOKEN`, and `CF_ZONE`
- `make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>] [TUNNEL_MODE=direct|preserve|middleproxy]` : full migration + AmneziaWG tunnel
- `make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path> [TUNNEL_MODE=direct|preserve|middleproxy]` : add tunnel to an already-installed node
- `make deploy-monitor SERVER=<ip>` : deploy optional monitoring dashboard
- `make monitor SERVER=<ip>` : open SSH tunnel to optional monitoring dashboard

The capacity-probe targets expect the external `/root/benchmarks` layout used by `test/capacity_connections_probe.py`; the repository does not ship the required comparison binaries/configs. Always pass `SERVER=<ip>` explicitly to remote Make targets because the current `Makefile` contains a repository-specific default address.

## CI-Parity Validation

Before merging behavior changes, match the GitHub workflow as closely as practical:

```bash
zig fmt --check build.zig src
python3 -m py_compile test/*.py
shellcheck --severity=error deploy/*.sh deploy/monitor/*.sh
zig build test
zig build -Doptimize=ReleaseSafe test
zig build
python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux
docker build --build-arg ZIG_VERSION=0.16.0 -t mtproto-zig-smoke .
zig build -Doptimize=ReleaseFast bench
zig build -Doptimize=ReleaseFast soak -- --seconds=10
```

The default install graph contains only `mtproto-proxy`. Use `zig build install-bench` only when the standalone `mtproto-bench` binary is required; `bench` and `soak` build it explicitly without coupling `run` to the global install step.

The daemon smoke launches a real localhost proxy, verifies a valid FakeTLS handshake, and checks that the same SNI with a bad secret does not receive a valid FakeTLS response. CI uses a shorter soak for pull requests and a longer soak on pushes.

## `make deploy` (current behavior)

1. Builds Linux target: `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3`.
2. Stops remote service (`systemctl stop mtproto-proxy`).
3. Uploads binary and `deploy/*.sh` via `scp`.
4. Uploads config when local config file exists.
5. Uploads `.env` as `/opt/mtproto-proxy/env.sh` when present locally.
6. Starts service and prints status.

This Make target is x86_64-only and uses `x86_64_v3` without an explicit `+aes`. The CI deploy-target check and optimized amd64 Docker image use `x86_64_v3+aes`; use those/manual commands when hardware AES must be guaranteed. Use the manual or Docker build paths for aarch64.

Why service stop is required:

- Unit file contains `ProtectSystem=strict` and `ReadOnlyPaths=/opt/mtproto-proxy`.
- Replacing binaries safely is simplest when service is stopped first.

## `make migrate`

1. Optionally seeds the root SSH authorized key when `PASSWORD=` is provided.
2. Runs `deploy/install.sh` remotely.
3. Uploads local `config.toml`.
4. Calls `make deploy`.
5. Optionally runs `make update-dns` when `UPDATE_DNS=1|true`; this now requires `DNS_NAME` in `.env`.

Fresh self-domain installs need a masking domain during `deploy/install.sh`. `make migrate` currently streams the installer over non-interactive SSH, so for a brand-new host either run the one-line `MASK_DOMAIN=...` installer first or invoke the installer manually with `ssh root@<ip> 'MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com bash -s' < deploy/install.sh`, then use `make deploy`.

## Tunnel Workflows

`make deploy-tunnel` first runs `make migrate`, then uploads the AmneziaWG client config plus `deploy/setup_tunnel.sh` and executes the script remotely with the selected `TUNNEL_MODE`.

`make deploy-tunnel-only` skips bootstrap/redeploy and only applies the tunnel plumbing to an existing installation.

Remote tunnel setup currently:

- Installs `amneziawg-tools`.
- Creates network namespace `tg_proxy_ns` plus a `veth_main`/`veth_ns` pair and namespace-local DNS.
- Brings up `awg0` inside the namespace only.
- Adds host DNAT for the configured proxy port (default `:443`) to `10.200.200.2:<port>` and namespace policy routing so replies go back through the veth path, not the tunnel.
- Rewrites the systemd unit to run as `mtproto:mtproto` through `ip netns exec tg_proxy_ns /opt/mtproto-proxy/mtproto-proxy ...`, with `Restart=always`, `RestartSec=3`, and the same strict filesystem hardening as the normal unit.
- Applies one of three modes: `direct` (`use_middle_proxy=false` for regular traffic), `preserve` (leave config as-is), or `middleproxy` (`use_middle_proxy=true`).
- Preserves an existing promotion `tag`, and may restore it from `env.sh`.
- Installs/refreshes the masking health monitor helper when available.
- Validates all 5 Telegram DCs through the tunnel before finishing.

Important operational notes:

- `direct` is only the default. Media path still prefers MiddleProxy when available, and `middleproxy` mode is supported when you want regular traffic to stay on ME too.
- Host SSH and host-network services stay outside the namespace; only proxy traffic is redirected through AWG.

## One-line operator update path

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The installer is idempotent and preserves `config.toml` on update; existing `env.sh` stays untouched unless install is rerun with fresh `CF_TOKEN` / `CF_ZONE` / `IPV6_PREFIX` settings.

For a fresh self-domain masking install, prefer:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo env MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com bash
```

Current installer behavior also:

- refreshes self-domain Caddy 404 masking (`setup_masking.sh`) and the masking health timer when available;
- attempts optional `zapret` / `nfqws` setup;
- refreshes optional `proxy-monitor` files on disk and restarts that service if it is already active.
- prints a connection link only when it can find a valid 32-hex secret in `[access.users]`.

Fresh source installs omit `[general].use_middle_proxy`, so regular DC traffic uses the parser default `false`; `force_media_middle_proxy=true` still keeps media paths on MiddleProxy when possible. `config.toml.example` and the Docker Compose installer explicitly enable regular MiddleProxy routing instead.

Self-domain masking notes:

- Preferred setup is `MASK_DOMAIN=proxy.example.com`, with DNS `A` pointing to the VPS.
- Public `:443` stays owned by `mtproto-proxy`; Caddy listens on `127.0.0.1:8443` and returns 404 for non-proxy requests.
- Public `:80` must be reachable for Let's Encrypt HTTP-01 unless the operator provisions certificates manually.
- `setup_masking.sh` requires Caddy 2.10+ for `x25519mlkem768`, uses public `:80` for ACME HTTP-01, and configures all non-ACME HTTP/HTTPS requests to return 404.
- `setup_masking.sh` installs a Let's Encrypt renewal hook that reloads the host Caddy service or recreates the Compose Caddy service after certificate renewal.
- `MASK_ALLOW_SELF_SIGNED=1` is available only as a dev/test fallback; the default flow fails closed when Let's Encrypt cannot issue a certificate.
- `MASK_SET_PUBLIC_IP=0` skips rewriting `[server].public_ip`; otherwise `setup_masking.sh` sets it to the masking domain.
- Cloudflare records for the proxy domain must be DNS-only, not proxied.

IPv6 hopping installed by both source and Docker Compose installers is a root cron job that calls `ipv6-hop.sh` without arguments every five minutes, causing an unconditional rotation. `ipv6-hop.sh --auto` is instead a long-running foreground ban-detection loop and is not enabled by the installers.

The tracked `deploy/compose.yml` is a minimal proxy-only example. `deploy/install_docker_compose.sh` generates the operational `/opt/mtproto-proxy/compose.yml` with Caddy and install-specific settings.

## Systemd Unit Notes (`deploy/mtproto-proxy.service`)

- Default and tunnel-patched units run as `mtproto:mtproto`, use `Restart=always` with `RestartSec=3`, and ship with `LimitNOFILE=131582` plus `TasksMax=65535`.
- Startup first auto-clamps `max_connections` to an effective-memory estimate using the lower of host RAM and every visible limit in the process's cgroup v2/v1 hierarchy (leaf plus parents, including non-standard mount points) unless `unsafe_override_limits=true`; it fails safe if fewer than 32 slots fit. `ProxyState.run` then clamps again if `RLIMIT_NOFILE` can cover at least 32 slots, otherwise it also fails startup safely.
- The daemon banner redacts user secrets and proxy links. Use `--show-secrets` only for an intentional foreground run in a private terminal.
- Runtime relay model is still single-thread `epoll` in proxy core.
- Default unit keeps `ReadOnlyPaths=/opt/mtproto-proxy` and only `CAP_NET_BIND_SERVICE`.
- Tunnel-patched unit keeps the hardening settings, adds `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`, and uses `ExecStartPre=/usr/local/bin/setup_netns.sh` to recreate the namespace on every restart.
