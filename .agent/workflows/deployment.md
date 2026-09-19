---
description: How to build, run, and deploy the MTProto Zig proxy.
---

# Deployment Workflow

This workflow documents current build and deploy paths as implemented in `Makefile`, `deploy/install.sh`, and `deploy/setup_tunnel.sh`.

## Prerequisites

- Zig 0.16.0 for local builds
- SSH access to VPS
- systemd on target host
- Caddy 2.10+ masking enabled when the optional WEB carrier is deployed
- Ubuntu 24.04 + root access for blocked-region tunnel mode
- AmneziaWG client config (`.conf`) when using tunnel deploys

## Key Commands

- `make build` : debug build
- `make release` : production proxy (`ReleaseSafe` data plane + PIE); benchmark targets remain `ReleaseFast`
- `make run CONFIG=<path>` : run proxy with selected config
- `make test` : run unit tests
- `make fuzz [FUZZ_ITERATIONS=100K]` : bounded ReleaseSafe security fuzz campaign (64-bit Linux)
- `make bench` : encapsulation microbench
- `make soak` : 30s multithreaded soak
- `mtproto-proxy --check-config <path>` : parse and semantically validate a config without opening a listener
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
zig fmt --check build.zig src test/hardware_aes_probe.zig
python3 -m py_compile deploy/web_probe.py test/*.py test/web-bridge/*.py
python3 -m unittest discover -s test -p 'test_probe_helpers.py'
python3 -m unittest discover -s test -p 'test_web_setup_probe.py'
shellcheck --severity=error docker-entrypoint.sh deploy/*.sh deploy/monitor/*.sh test/check_hardware_aes.sh test/run_fuzz.sh test/installer-e2e/run.sh test/installer-e2e/fake-*
zig build test
zig build -Doptimize=ReleaseSafe test
zig build -Doptimize=ReleaseFast test
bash test/run_fuzz.sh 100K fuzz-artifacts 12m
zig build
python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy
zig build e2e
zig build -Doptimize=ReleaseFast e2e
zig build -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes
bash test/check_hardware_aes.sh
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux
docker build --build-arg ZIG_VERSION=0.16.0 -t mtproto-zig-smoke .
zig build -Doptimize=ReleaseFast bench
zig build -Doptimize=ReleaseFast soak -- --seconds=10
```

`-Doptimize=ReleaseFast` is intentionally still used by release/deploy commands:
the build policy promotes only `mtproto-proxy` to `ReleaseSafe` while leaving
bench/soak in the requested mode. `-Ddataplane_safety=false` is an explicit unsafe
benchmark opt-out and must not be used for an exposed production service. The proxy
ELF is always PIE.

The default install graph contains only `mtproto-proxy`. Use `zig build install-bench` only when the standalone `mtproto-bench` binary is required; `bench` and `soak` build it explicitly without coupling `run` to the global install step.

The offline `test_probe_helpers.py` suite validates the measurement code before
expensive load jobs use it. Keep incomplete process snapshots non-authoritative,
stop immediately on process/system FD exhaustion, resolve callable churn payloads
inside each connection attempt, and retain the bounded hostname cache for the
realistic TLS template.

The daemon smoke launches a real localhost proxy, verifies a valid FakeTLS handshake, checks that the same SNI with a bad secret does not receive a valid FakeTLS response, and holds an authenticated connection across `SIGTERM` until the configured graceful-shutdown deadline forces a clean exit. `zig build e2e` goes further: a compile-time test-only loopback DC override drives the real daemon through FakeTLS, the obfuscated MTProto nonce, upstream setup, and C2S/S2C relay without exposing that override in the installed binary. CI repeats that process scenario with `-Doptimize=ReleaseFast`, which exercises the effective shipping data-plane mode (`ReleaseSafe` unless explicitly opted out) rather than treating a successful release link as runtime evidence. CI uses a shorter soak for pull requests and a longer soak on pushes. In addition to the aarch64 cross-build, the official `ubuntu-24.04-arm` runner executes unit tests, this daemon smoke and a short four-worker soak natively so architecture-specific runtime defects cannot hide behind successful cross-compilation.

The separate `.github/workflows/deep-ci.yml` workflow runs weekly and through `workflow_dispatch`. Its `-Dtsan=true` option applies ThreadSanitizer only to the `src/main.zig` and `src/bench.zig` test artifacts plus the benchmark executable used by soak; it never instruments the normal production proxy build. Keep `TSAN_OPTIONS=halt_on_error=1:exitcode=66` so a reported race fails the job instead of becoming advisory output.

Deep CI also runs the real ReleaseSafe daemon smoke under Valgrind Memcheck. It deliberately builds with `-Dcpu=baseline`: GitHub hosts can expose SHA-NI while Ubuntu 24.04's Valgrind 3.22 cannot decode `SHA256RNDS2`, so a native-CPU build would die inside Valgrind despite being valid on the host. `--max-stackframe=8388608` classifies the proxy's roughly 3.6 MiB initialization frame as a normal Linux stack frame instead of producing false invalid-access reports. The harness's `--launcher` option consumes the remainder of the command line and must therefore be last; it prepends those arguments without a shell. Memcheck reports every leak category to an artifact and uses `--errors-for-leak-kinds=definite,indirect --error-exitcode=97`, so invalid accesses and actionable leaks fail without treating `possible` or `reachable` runtime allocations as proven project defects. Do not add suppressions without a reproduced and documented toolchain false positive.

The third Deep CI job runs `bash test/run_fuzz.sh 1M deep-fuzz-artifacts 40m`. The wrapper exists because Zig 0.16 bounded fuzzing can leave `.zig-cache/f/crash` while returning a successful build status. It treats that file or the corresponding crash message as a failure, copies the crash input plus available fuzzer logs into a non-hidden artifact directory, and rejects a pre-existing crash instead of deleting evidence or misattributing it to a later campaign. Keep the inner 40-minute limit below the 50-minute job timeout so the artifact upload step can still run.

Installer changes also require the separate `.github/workflows/installer-e2e.yml` matrix. It boots privileged systemd containers for Debian 12/13 and Ubuntu 24.04/26.04, runs the real Docker Compose installer twice, and checks the private config, Caddy-only topology, WEB relay, service health, HTTPS masking, external-only SYNFIX/NFQUEUE rules, their saved IPv4 boot snapshot plus enabled `netfilter-persistent`, disabled-by-default TCPMSS, and idempotent reinstall. Before installation, the harness builds the proxy image from the current checkout and publishes it to a registry inside the isolated host. The real installer pulls that local tag, and verification requires both proxy services to run its exact image ID; never replace this with the public `latest` tag. Docker, Compose, Caddy, the proxy image, systemd, and iptables remain real; only public ACME and the external `nfqws` implementation use deterministic test substitutes. Source/build/image changes trigger this matrix as well as installer changes. Run one case locally with:

```bash
MTPROTO_INSTALLER_E2E_IMAGE=debian:12 test/installer-e2e/run.sh
```

## Docker Image Defaults

`config.toml.example` is documentation, not a live container configuration. When a container starts without the selected config path, `docker-entrypoint.sh` atomically creates a private minimal config with a random 16-byte user secret and mode `0600`; the generated secret is never printed to Docker logs. A mounted config always takes precedence. Inspection options such as `--check-config` and `--print-links` remain read-only, while the `web-relay` subcommand is passed through unchanged because its Compose service mounts the shared config explicitly.

The Docker Compose installer defaults `CADDY_IMAGE` to `caddy:2-alpine`. This follows stable Caddy 2 minor and patch releases while preventing an implicit jump to a future Caddy 3; operators who require a fully controlled rollout can override the variable with an exact image tag or digest. A floating tag changes a server only when the image is pulled and the Caddy container is recreated.

The main CI workflow builds the image and starts it without a mounted config, then verifies the generated file permissions, 32-hex secret shape, and absence of that secret from container logs.

## WEB Proxy Deployment

WEB mode is additive by default: ordinary `tg://proxy` FakeTLS traffic remains on public `:443`, while a second DNS-only hostname selects the browser carrier and the existing Caddy service. Optional `[web].only=true` instead masks the direct MTProto door and serves only the trusted WEB relay. The WEB hostname must differ from `censorship.tls_domain`, public TCP `80` must remain reachable for HTTP-01, and no extra public data port is required.

For an existing Docker Compose installation created by this repository, update the installer and enable WEB in one idempotent pass:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
  | sudo env ENABLE_WEB=true WEB_DOMAIN=web.example.com bash
```

This preserves `config.toml` and user secrets, adds the `mtproto-web-relay` profile service, and extends the existing `mtproto-mask-caddy` container. Without `[web].public_dir`, ordinary requests to both the WEB and MTProto masking hostnames receive the same bodyless 404; an optional operator directory is loaded once and served only as bounded exact public routes. The directory path is evaluated inside the relay process/container and must be readable there. Caddy sends the whole WEB hostname to one relay handler without pre-routing carrier-looking URLs, strips `Via`, maps relay failures to the common 404, and has no request access-log directive that could record credential-bearing URIs or subprotocols. The permanent capability authenticates only the exact bridge bootstrap; the query-free WebSocket carries a newly minted two-minute token in one `tproxy-v1.<token>` subprotocol value. The local masking and WEB Caddy listeners enable only HTTP/1.1 and HTTP/2: HTTP/3 would advertise UDP `8443` or `8444`, but those ports are deliberately local and have no public QUIC path. Source/systemd installations use `sudo /opt/mtproto-proxy/setup_web.sh web.example.com`. In tunnel-netns mode, rerunning `setup_tunnel.sh` refreshes the WEB backend/listener addresses automatically.

Fresh WEB enablement generates a lowercase RFC 4648 base32 path from 10 random
bytes (16 characters). `WEB_BASE_PATH=<path>` pins a canonical value and
`WEB_BASE_PATH=none` explicitly selects the historical root. An existing setup
keeps its current value when the variable/flag is omitted; a config predating
`base_path` therefore remains at root on update. The source helper accepts the
equivalent `--base-path <path|none>`. Reissuing a different path requires
`--force` or `WEB_FORCE_BASE_PATH_CHANGE=true`, because it changes capabilities,
links and live carrier sessions.

To make WEB the only admitted transport in Docker Compose, pass the explicit gate together with WEB enablement:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
  | sudo env ENABLE_WEB=true WEB_ONLY=true WEB_DOMAIN=web.example.com bash
```

For source/systemd installs, use `sudo /opt/mtproto-proxy/setup_web.sh --only web.example.com`; restore the additive mode with `--no-only`. Reinstall preserves an already active gate unless explicitly disabled. A new gate stays disabled while setup runs a certificate- and hostname-verified end-to-end probe through Caddy: canonical bootstrap metadata, token subprotocol upgrade, HELLO/WELCOME, logical OPEN/DATA, and a real MTProto `req_pq` whose `resPQ` echoes the nonce. Probe material is generated internally and piped over stdin, so permanent and short-lived credentials never appear in argv or failure output. Only after success does setup write `only=true` and restart the main proxy; failure leaves direct MTProto available. Additive setup runs the same probe as a non-fatal diagnostic. While active, formerly valid direct links are masked and output commands print only `tg://webproxy`; disabling WEB makes `only` inert.

Changing an existing WEB domain requires `--force` or `WEB_FORCE_DOMAIN_CHANGE=true`
because installed links keep the old hostname; base-path changes use the separate
guard above. WEB setup checks certificate expiry
before reuse and gives Caddy read/traverse access to the HTTP-01 webroot. It validates
the existing Caddy tree and backs up the WEB config/certificate pair and `config.toml`
before replacement; failures before successful Caddy activation restore those files.
This is not a rollback of subsequent container/service startup or ACME issuance.

WEB hostname backends refresh about once per minute; IP literals spawn no DNS
thread. Changing user secrets or WEB configuration still requires restarting both
the main proxy and WEB relay, not sending SIGHUP. `zig build web-bridge` renders
the production Zig bridge and protocol vectors before running the Node harness;
missing Zig/Node dependencies fail the step rather than silently skipping it.

To disable only WEB while preserving ordinary MTProto and Caddy masking:

```bash
sudo env MTPROTO_DOCKER_INSTALL=1 bash /opt/mtproto-proxy/setup_web.sh --remove
```

## `make deploy` (current behavior)

1. Builds Linux target: `zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3`.
2. Stops remote service (`systemctl stop mtproto-proxy`).
3. Uploads binary and `deploy/*.sh` via `scp`.
4. Uploads config when local config file exists.
5. Uploads `.env` as `/opt/mtproto-proxy/env.sh` when present locally.
6. Starts service and prints status.

This Make target is x86_64-only and uses `x86_64_v3` without an explicit `+aes`. The CI deploy-target check and optimized amd64 Docker image use `x86_64_v3+aes`; use those/manual commands when hardware AES must be guaranteed. Use the manual or Docker build paths for aarch64.

`test/check_hardware_aes.sh` reads the optimized Docker build argument from the
publishing workflow itself and compiles a target-specific assertion against
`std.crypto.core.aes.has_hardware_support`. Keep that linkage intact: a hardcoded
test profile could pass while the image workflow accidentally shipped another
profile. Baseline generic images are intentionally outside this assertion.

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

Firewall snapshots in the source/Compose installers and SYNFIX/NFQUEUE helpers
are written to private temporary files beside `/etc/iptables/rules.v4` or
`rules.v6`, then renamed only after a successful nonempty dump. Failed saves
preserve the old snapshot; required IPv4 persistence or boot-service enablement
failure is fatal to that script, while unavailable IPv6 is reported explicitly.
Boot-service enablement first accepts an already enabled unit and otherwise retries
for the short systemd manager restart window that can follow package installation.
`netfilter-persistent` remains the only boot-restoration mechanism; do not add a
second TCPMSS service. Rule operations wait up to ten seconds for the xtables
lock, and inserted TCPMSS/NFQUEUE rules and SYNFIX entry/mark rules are read back.
Standalone SYNFIX setup requires `iptables-persistent`/`netfilter-persistent` to
be installed; the main installers and NFQUEUE setup install these dependencies.
These are whole-host snapshots, as before, not a firewall transaction or rollback
of already applied live rules. Preserve all loopback exclusions and optional
TCPMSS defaults.

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
- attempts optional `zapret` / `nfqws` setup; SYNFIX, NFQUEUE, and TCPMSS rules exclude loopback so local WEB relay streams remain untouched;
- refreshes optional `proxy-monitor` files on disk and restarts that service if it is already active.
- prints connection links only when it can find a valid 32-hex secret in `[access.users]`; active WEB-only emits the WEB link and suppresses ordinary direct links.

Fresh source installs omit `[general].use_middle_proxy`, so regular DC traffic uses the parser default `false`; `force_media_middle_proxy=true` still prefers MiddleProxy for negative DC1..5 media paths. CDN DC203 always uses MiddleProxy independently of both preferences. `config.toml.example` and the Docker Compose installer explicitly enable regular MiddleProxy routing instead.

Self-domain masking notes:

- The OpenSSL masking probe reads the negotiated group from modern `Negotiated TLS1.3 group` and legacy `Server Temp Key`/`Peer Temp Key` output. Offered groups, null groups, and failed ciphers are not negotiation evidence. This is advisory diagnostics, not proof of single-round TLS or a runtime routing gate.

- Preferred setup is `MASK_DOMAIN=proxy.example.com`, with DNS `A` pointing to the VPS.
- Public `:443` stays owned by `mtproto-proxy`; Caddy listens on `127.0.0.1:8443` and returns 404 for non-proxy requests.
- Public `:80` must be reachable for Let's Encrypt HTTP-01 unless the operator provisions certificates manually.
- `setup_masking.sh` requires Caddy 2.10+ for `x25519mlkem768`, uses public `:80` for ACME HTTP-01, and configures all non-ACME HTTP/HTTPS requests to return 404.
- `setup_masking.sh` installs a Let's Encrypt renewal hook that reloads the host Caddy service or recreates the Compose Caddy service after certificate renewal.
- `setup_web.sh` obtains a separate certificate for `[web].domain`, validates the combined Caddy configuration before replacement, and installs a renewal hook for the WEB certificate.
- Masking setup, WEB setup, monitor installation, and both renewal hooks serialize Caddy mutations through `/run/mtproto-mask-caddy.lock`. The periodic health process takes the same lock without waiting and treats a busy lock as an intentional maintenance window, preventing concurrent Compose recreations while preserving installer-owned image/config updates.
- `setup_web.sh` preserves root v1 routing on pre-path updates and generates a
  path only for a genuinely new WEB setup. It writes `[web].base_path`, prints a
  percent-encoded `server=domain/path` address, and uses the `0x70`-marked secret
  only for path links. Caddy continues forwarding the complete WEB hostname to
  the relay in either mode.
- `MASK_ALLOW_SELF_SIGNED=1` is available only as a dev/test fallback; the default flow fails closed when Let's Encrypt cannot issue a certificate.
- `MASK_SET_PUBLIC_IP=0` skips rewriting `[server].public_ip`; otherwise `setup_masking.sh` sets it to the masking domain.
- Cloudflare records for the proxy domain must be DNS-only, not proxied.

IPv6 hopping installed by both source and Docker Compose installers is a root cron job that calls `ipv6-hop.sh` without arguments every five minutes, causing an unconditional rotation. `ipv6-hop.sh --auto` is instead a long-running foreground ban-detection loop and is not enabled by the installers.

The tracked `deploy/compose.yml` is a minimal proxy-only example. `deploy/install_docker_compose.sh` generates the operational `/opt/mtproto-proxy/compose.yml` with Caddy and install-specific settings.

## Systemd Unit Notes (`deploy/mtproto-proxy.service`)

- Default and tunnel-patched units run as `mtproto:mtproto`, use `Restart=always` with `RestartSec=3`, send `SIGTERM`, allow 25 seconds with `TimeoutStopSec`, and ship with `LimitNOFILE=131582` plus `TasksMax=65535`.
- The tracked and installer-generated Compose proxy service uses `stop_grace_period: 25s`. This leaves headroom around the proxy's default 15-second `graceful_shutdown_timeout_sec`; keep the supervisor allowance above any configured drain deadline.
- Startup first auto-clamps `max_connections` to an effective-memory estimate using the lower of host RAM and every visible limit in the process's cgroup v2/v1 hierarchy (leaf plus parents, including non-standard mount points) unless `unsafe_override_limits=true`; it fails safe if fewer than 32 slots fit. `ProxyState.run` then clamps again if `RLIMIT_NOFILE` can cover at least 32 slots, otherwise it also fails startup safely.
- The daemon banner redacts user secrets and proxy links. Prefer the one-shot `--print-links` mode: it loads the config, prints links in the current private terminal, and exits before initializing signals or opening the listener. In a running Compose install, execute `/usr/local/bin/mtproto-proxy /etc/mtproto-proxy/config.toml --print-links` inside the `mtproto-proxy` container. `--show-secrets` remains an explicit opt-in for a full foreground daemon run. WEB-only intentionally omits all direct links from either output path.
- Runtime relay model is still single-thread `epoll` in proxy core.
- Default unit keeps `ReadOnlyPaths=/opt/mtproto-proxy` and only `CAP_NET_BIND_SERVICE`.
- Tunnel-patched unit keeps the hardening settings, adds `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`, and uses `ExecStartPre=/usr/local/bin/setup_netns.sh` to recreate the namespace on every restart.
