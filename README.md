<div align="center">

# mtproto.zig

**High-performance Telegram MTProto proxy written in Zig**

Disguises Telegram traffic as standard TLS 1.3 HTTPS to bypass network censorship.

<p align="center">
  <strong>12,000 stable idle connections on 1GB RAM in the current benchmark snapshot. Zero third-party Zig dependencies.</strong>
</p>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.16.0-f7a41d.svg?logo=zig&logoColor=white)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/platform-linux-blueviolet.svg?logo=linux&logoColor=white)](#-quick-start)
[![Dependencies](https://img.shields.io/badge/dependencies-0-success)](build.zig)

---

[Features](#-features) &nbsp;&bull;&nbsp;
[Quick Start](#-quick-start) &nbsp;&bull;&nbsp;
[Update](#-update-existing-server) &nbsp;&bull;&nbsp;
[Docker](#docker-image) &nbsp;&bull;&nbsp;
[Deploy](#-deploy-to-server) &nbsp;&bull;&nbsp;
[Monitoring](#-monitoring) &nbsp;&bull;&nbsp;
[Tunnel](#-amneziawg-tunnel-blocked-regions) &nbsp;&bull;&nbsp;
[Configuration](#-configuration) &nbsp;&bull;&nbsp;
[Troubleshooting](#-troubleshooting-updating)

</div>

## &nbsp; Features

| | Feature | Description |
|---|---------|-------------|
| **TLS 1.3** | Fake Handshake | Connections are indistinguishable from normal HTTPS to DPI systems |
| **MTProto v2** | Obfuscation | AES-256-CTR encrypted tunneling (abridged, intermediate, secure) |
| **DRS** | Dynamic Record Sizing | Mimics real browser TLS behavior (Chrome/Firefox) to resist fingerprinting |
| **Multi-user** | Access Control | Independent secret-based authentication per user |
| **Anti-replay** | Timestamp + Digest Cache | Rejects replayed handshakes outside ±2 min window AND detects ТСПУ Revisor active probes |
| **Masking** | Connection Cloaking | Forwards unauthenticated clients either to `tls_domain:443` or, for self-domain installs, to a local Caddy 404 backend |
| **PQ FakeTLS** | DPI Evasion | Echoes `X25519MLKEM768` (`0x11ec`) ServerHello key_share for modern Desktop/Android ClientHellos |
| **Fast Mode** | Direct-Path S2C Offload | Reduces CPU usage by delegating S2C AES work to Telegram DCs on direct paths (non-MiddleProxy) |
| **MiddleProxy** | Telemt-Compatible ME | Optional ME transport for DC1..5 (`use_middle_proxy`); retries TCP candidates, applies a 5-second per-stage handshake deadline, cools failed endpoints for 60 seconds, and falls back directly when ME stalls |
| **Auto Refresh** | Runtime Discovery | Periodically updates regular/media MiddleProxy metadata and re-resolves all masking DNS candidates without delaying listener startup |
| **Promotion** | Tag Support | Optional promotion tag for sponsored proxy channel registration |
| **IPv6 Hopping** | DPI Evasion | Rotates IPv6 from a routed /64 and updates Cloudflare AAAA records; installers schedule a hop every 5 minutes, while `--auto` provides foreground ban-detection mode |
| **Optional TCPMSS=88** | Legacy DPI fallback | Disabled by default; can force tiny ClientHello fragmentation when explicitly enabled |
| **TCP Desync** | DPI Evasion | Integrated `zapret` (`nfqws`) OS-level desynchronization (fake packets + TTL spoofing); NFQUEUE queue-bypass preserves traffic while `nfqws` restarts |
| **Split-TLS** | DPI Evasion | Splits fake `ServerHello` write into `1 byte + short pause + rest` to desynchronize passive DPI |
| **Zero-RTT** | DPI Evasion | Local self-domain Caddy 404 masking (`127.0.0.1:8443`, with tunnel netns auto-routing and PQ TLS groups) to defeat active probing timing analysis |
| **0 deps** | Stdlib Only | No third-party Zig packages (proxy core uses Zig standard library only) |
| **Explicit State** | Runtime Ownership | Proxy state is passed explicitly; runtime log level is the only mutable global knob |

> **Engineering Notes:** For deep technical details, cryptography internals, systemd hardening, and benchmarks, refer to the `.agent/skills` and `.agent/workflows` directories.

Connection-capacity methodology and command profiles: `test/README.md`.

## Runtime Model

- Client relay is handled by a single-threaded Linux `epoll` event loop. `epoll_event.data.u64` carries the slot index, generation, and fd role, so dispatch does not need an fd hash lookup and stale events cannot attach to a reused slot.
- External discovery never delays the listening socket: MiddleProxy metadata/NAT detection and hostname-based masking resolution run in a joinable background worker. Metadata and masking candidates refresh hourly, reachability probes run in cancellable batches of at most four sockets, and stalled MiddleProxy handshakes can request an early refresh.
- FakeTLS validation expects Telegram-style 32-byte ClientHello Session IDs and copies the Session ID into the synthetic ServerHello.
- Handshake and relay lifetimes are controlled by monotonic `timerfd` deadlines in an indexed min-heap (`handshake_timeout_sec`, `idle_timeout_sec`), not by periodic slot scans or `SO_RCVTIMEO`; a silent connection gets at most 10 seconds to send its first byte.
- Unauthenticated sockets share a per-/24 or per-/48 concurrent allowance (`clamp(max_connections / 8, 16, 128)`). The global handshake-inflight budget is charged after the first byte and released after authentication.
- Graceful `EPOLLRDHUP` is drained to EOF before the source fd is detached, preserving data queued immediately before a peer half-closes.
- Failed non-blocking upstream connects are reclaimed immediately on fatal hangup events; the relay loop should not spin on dead upstream sockets.
- The timerfd wakes only for the earliest connection/admission deadline or the 10-second aggregated `conn stats` report; timer maintenance does not scan the slot pool.
- Client payload bytes pipelined after the 64-byte MTProto obfuscation nonce are buffered and forwarded once the upstream path is ready.
- Outbound client/upstream writes use classed block queues backed by one event-loop block pool, bounded `writev` dispatches, and a 4 MiB pending-byte cap per queue. Per-event byte/operation budgets prevent one ready fd from monopolizing the loop.
- MiddleProxy per-direction C2S/S2C buffers start at 16 KiB and grow on demand up to the effective `middleproxy_buffer_kb` cap; shared event-loop scratch buffers are allocated lazily and reused. C2S headers are parsed once during encapsulation, and completed handshakes release route candidates, validation state, and ME handshake buffers immediately.
- MiddleProxy route snapshots contain only candidates for the selected DC/path plus a versioned secret reference and NAT address. The current and immediately previous secrets are retained centrally, so concurrent rotations do not copy a 256-byte secret into every handshake or split selector/KDF inputs.
- Runtime AES-CBC state keeps only the key schedule required by its direction, CTR and CBC decryption use four-block AES batches where chaining permits, XOR runs a full 128-bit block at a time, and high-frequency FakeTLS/ME randomness comes from a thread-local ChaCha20 DRBG periodically reseeded from the OS CSPRNG.

## &nbsp; Quick Start

### Prerequisites

- **Linux** (x86_64 or aarch64) — the proxy uses `epoll` and does not support macOS, FreeBSD, or OpenBSD at runtime
- [Zig](https://ziglang.org/download/) **0.16.0** (the version pinned by CI, Docker, and installers; macOS is fine for cross-compilation)

### Build & Run locally

```bash
# Clone
git clone https://github.com/XXcipherX/mtproto.zig.git
cd mtproto.zig

# Build (debug)
make build

# Build (optimized for production)
make release

# Create a local config (replace example secrets/domain before exposing it)
cp config.toml.example config.toml

# Run with config.toml (or pass CONFIG=<path>)
make run
```

The binary defaults to `config.toml`; the repository intentionally ships `config.toml.example` instead of a real local config.

The example listens on privileged port `443`. Run locally with sufficient bind permissions (for example, as root) or change `[server].port` to a port above `1024`. The systemd unit uses `CAP_NET_BIND_SERVICE`, but `make run` does not grant that capability.

### Run Tests

```bash
make test
```

CI also runs the stricter local checks below:

```bash
zig fmt --check build.zig src
python3 -m py_compile test/*.py
shellcheck --severity=error deploy/*.sh deploy/monitor/*.sh
zig build -Doptimize=ReleaseSafe test
```

### Performance & Stability Checks

```bash
# Fast microbenchmark for C2S encapsulation
make bench

# 30-second multithreaded soak (crash/stability guard)
make soak

# Real daemon smoke: launches the binary, verifies a valid FakeTLS handshake,
# and rejects the same SNI with a bad secret
zig build
python3 test/daemon_smoke.py --binary zig-out/bin/mtproto-proxy

# Custom soak shape
zig build -Doptimize=ReleaseFast soak -- --seconds=120 --threads=8 --max-payload=131072
```

The GitHub workflow additionally verifies native `ReleaseFast`, Linux `x86_64`, deploy-target `x86_64_v3+aes`, Linux `aarch64`, Docker build smoke, and bench/soak paths.

`zig build test` runs the tests reachable from `src/main.zig` plus `src/bench.zig`. A normal `zig build` installs only `mtproto-proxy`; benchmark execution remains explicit through `bench`/`soak`, and `zig build install-bench` installs `mtproto-bench` when a standalone benchmark binary is needed.

`bench` prints per-payload throughput (`in_mib_per_s`, `out_mib_per_s`) and `ns_per_op`.
`soak` prints aggregate `ops/s`, throughput, and `errors`; non-zero errors fail the step.

<details>
<summary>All Make targets</summary>

| Target | Description |
|--------|-------------|
| `make build` | Debug build |
| `make release` | Optimized build (`ReleaseFast`) |
| `make run CONFIG=<path>` | Run proxy (default: `config.toml`) |
| `make test` | Run unit tests |
| `make bench` | Run ReleaseFast encapsulation microbenchmarks |
| `make soak` | Run ReleaseFast multithreaded soak stress test (30s default) |
| `make capacity-probe-idle` | Run the idle-socket capacity profile; requires the external `/root/benchmarks` workspace described in `test/README.md` |
| `make capacity-probe-active` | Run the TLS-auth capacity profile; requires the same external benchmark workspace |
| `make stability-check PID=<pid> [HOST=127.0.0.1 PORT=443]` | Run churn + idle-pool stability harness against an existing proxy process |
| `make stability-check-load [HOST=127.0.0.1 PORT=443]` | Run load-only stability smoke without `/proc` assertions |
| `make clean` | Remove build artifacts |
| `make fmt` | Format Zig files under `src/` |
| `make deploy SERVER=<ip>` | Build `x86_64-linux` with the `x86_64_v3` CPU baseline, upload binary/scripts/config to VPS, restart service |
| `make migrate SERVER=<ip> [PASSWORD=<pass>]` | Bootstrap server, push local `config.toml`, then run `make deploy` |
| `make update-dns SERVER=<ip>` | Run the Cloudflare DNS update helper on demand (`DNS_NAME`, `CF_TOKEN`, `CF_ZONE` come from `.env`) |
| `make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>] [TUNNEL_MODE=direct\|preserve\|middleproxy]` | Full migration + AmneziaWG tunnel for blocked regions |
| `make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path> [TUNNEL_MODE=direct\|preserve\|middleproxy]` | Add AmneziaWG tunnel to existing installation |
| `make deploy-monitor SERVER=<ip>` | Deploy monitoring dashboard to server |
| `make monitor SERVER=<ip>` | Open SSH tunnel to monitoring dashboard |

</details>

Always pass `SERVER=<ip>` explicitly to remote Make targets. The current `Makefile` contains a repository-specific default address, so omitting `SERVER` does not fail safely. `make deploy` is x86_64-only and uses `-Dcpu=x86_64_v3`; use the manual build/Docker paths for aarch64 or when you specifically require `x86_64_v3+aes`.

## &nbsp; Update existing server

To update an already installed proxy, simply re-run the same install command:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

The script is **idempotent**: it rebuilds from latest source, replaces the binary, and preserves your existing `config.toml`. Host installs keep `config.toml` as `mtproto:mtproto` with mode `0640`; `env.sh` stays root-only (`0600`) and is untouched unless you rerun install with new `CF_TOKEN` / `CF_ZONE` / `IPV6_PREFIX` settings. User secrets and connection links remain unchanged.

For a fresh self-domain install, pass `MASK_DOMAIN` as shown below or enter the domain at the installer prompt. Non-interactive bootstrap paths must pass `MASK_DOMAIN` explicitly.

## Docker image

The repository includes a **multi-stage Dockerfile**: Zig is bootstrapped from the official tarball inside the build stage; the runtime image is Debian **bookworm-slim** with `curl` and CA certs. The proxy binary performs background HTTPS public-IPv4 detection for MiddleProxy NAT derivation and refreshes Telegram metadata itself, so CA certs are required; `curl` is kept for container-side diagnostics and as a fallback when the Zig resolver rejects a malformed `/etc/resolv.conf`. That fallback follows only a bounded number of HTTPS-to-HTTPS redirects. The process runs as **root** inside the container (simple bind to port 443). The image ships `config.toml.example` as `/etc/mtproto-proxy/config.toml` for a quick start; mount your own file for real secrets and settings.

### Build

```bash
docker build -t mtproto-zig .
```

### Build arguments

| Argument       | Default   | Description |
|----------------|-----------|-------------|
| `ZIG_VERSION`  | `0.16.0`  | Version string passed to `ziglang.org/download/…/zig-<arch>-linux-<version>.tar.xz`. Must match a published Zig release. |
| `ZIG_SHA256`   | _(empty)_ | Optional pinned SHA256 for the downloaded Zig tarball. If set, Docker build verifies integrity before extraction. |
| `MTPROTO_CPU`  | `x86_64` on `amd64`, Zig default on `arm64` | Optional Zig CPU baseline. Use `x86_64_v3+aes` on modern `amd64` hosts to enable hardware AES and avoid software-only AES builds. |

Example:

```bash
docker build --build-arg ZIG_VERSION=0.16.0 -t mtproto-zig .
docker build --platform linux/amd64 --build-arg MTPROTO_CPU=x86_64_v3+aes -t mtproto-zig:amd64-v3 .
```

### Architecture (`TARGETARCH`)

The **builder** stage maps Docker’s auto-injected `TARGETARCH` to Zig’s Linux tarball name:

| `TARGETARCH` (BuildKit) | Zig tarball |
|-------------------------|-------------|
| `amd64`                 | `x86_64`    |
| `arm64`                 | `aarch64`   |

You normally **do not** pass `TARGETARCH` yourself; BuildKit sets it from the requested platform.  
If BuildKit auto-args are unavailable, the Dockerfile falls back to host architecture detection.

**Build for a specific CPU architecture** (e.g. from an Apple Silicon Mac to run on an `amd64` VPS):

```bash
docker build --platform linux/amd64 -t mtproto-zig:amd64 .
docker build --platform linux/arm64 -t mtproto-zig:arm64 .
```

**Multi-platform image** (push requires a registry and `buildx`):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/mtproto-zig:latest \
  --push .
```

### Publish from GitHub Actions

The repository includes a manual workflow: **Actions -> Publish Docker image -> Run workflow**.
It builds the Dockerfile with Buildx and pushes to GitHub Container Registry:

```text
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:<tag>
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:latest-amd64-v3
ghcr.io/<owner>/<repo>:<tag>-amd64-v3
```

For this repository, the default public image name is:

```text
ghcr.io/xxcipherx/mtproto.zig:latest
```

The `*-amd64-v3` tags are built with `-Dcpu=x86_64_v3+aes` for modern x86_64 CPUs and enable Zig's hardware AES backend. The generic tags stay baseline-compatible. The workflow lowercases the repository path automatically because GHCR image names must be lowercase. If the package is private, log in on the server before pulling, or pass `GHCR_USER` and `GHCR_TOKEN` to the Compose installer below.

### Run

Publish the listen port from your config (the bundled example listens on `443`). For production, mount your `config.toml` over the default:

```bash
docker run --rm \
  -p 443:443 \
  -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" \
  mtproto-zig
```

`docker run --rm -p 443:443 mtproto-zig` also works using the in-image example config (replace example user secrets before exposing the service).

If your config sets `server.port = 8443`, publish `-p 8443:8443` instead.

OS-level mitigations from `deploy/` (iptables `nfqws`, optional `TCPMSS`, etc.) are **not** applied inside the container; only the proxy binary runs there.

### Docker Compose install

For VPS installs from a prebuilt image, use the Docker Compose installer. It mirrors the one-line source installer for host-level setup: creates `/opt/mtproto-proxy/config.toml`, writes `/opt/mtproto-proxy/compose.yml`, installs a `mtproto-proxy.service` Docker Compose wrapper, configures self-domain Caddy masking as a Compose service, removes legacy TCPMSS unless explicitly enabled, optionally installs inbound SYN pacing, installs nfqws, pulls the images, starts the proxy and Caddy containers, and prints the `tg://` link:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
  | sudo env TLS_DOMAIN=proxy.example.com IMAGE=ghcr.io/xxcipherx/mtproto.zig:latest bash
```

Useful environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAGE` | auto | Explicit Docker image to pull; when set, disables automatic CPU image selection |
| `AUTO_IMAGE_CPU_VARIANT` | `true` | When `IMAGE` is not set, use `latest-amd64-v3` automatically on compatible x86_64 hosts |
| `TLS_DOMAIN` | _(required on first install)_ | Domain encoded into the `ee` secret and used as FakeTLS SNI |
| `PUBLIC_IP` | `TLS_DOMAIN` | Host/domain shown in generated Telegram links |
| `PORT` | `443` | Listen port in generated config |
| `SECRET` | random | 32-hex user secret; generated once when config is absent |
| `USE_MIDDLE_PROXY` | `true` | Initial `use_middle_proxy` value |
| `ENABLE_MASKING` | `true` | Install Caddy/certbot masking and set `mask = true`; Docker installs run Caddy in Compose |
| `ENABLE_TCPMSS` | `false` | Enable legacy `TCPMSS=88` ClientHello fragmentation fallback; disabled by default with PQ-capable Caddy masking |
| `ENABLE_SYNFIX` | `false` | Install inbound SYN pacing rules for Android/Desktop routes that need it |
| `SYNFIX_RATE` | `30/minute` | Per-source SYN rate for non-iOS-like fingerprints |
| `SYNFIX_BURST` | `1` | Per-source SYN burst for non-iOS-like fingerprints |
| `SYNFIX_ACTION` | `drop` | Over-limit SYN action: `drop` is quiet, `reject` sends TCP reset, `icmp-host-unreachable` fails the attempt immediately without an RST |
| `MASK_PORT` | `8443` | Local Caddy HTTPS masking backend port |
| `CADDY_IMAGE` | `caddy:2.10-alpine` | Caddy image used by the Docker Compose installer |
| `GHCR_USER` / `GHCR_TOKEN` | _(empty)_ | Optional login for private GHCR packages |

The installer requires Docker Compose v2 (`docker compose`) and installs Docker Engine + the Compose plugin via Docker's convenience script if either Docker or the plugin is missing. When `IMAGE` is not set, compatible x86_64 hosts automatically pull the `latest-amd64-v3` image; if that tag is unavailable, the installer falls back to generic `latest`. The proxy and Caddy Compose services use `network_mode: host`, so the proxy binds public `:443` and Caddy binds local masking/ACME ports directly on the VPS. Re-run the installer to pull and restart with newer images, or update manually:

The tracked `deploy/compose.yml` is only a minimal proxy-service example. The installer generates a richer `/opt/mtproto-proxy/compose.yml` containing Caddy, resource limits, and install-specific settings; do not treat the tracked example as the installer's exact output.

```bash
cd /opt/mtproto-proxy
docker compose --env-file .env -f compose.yml pull
sudo systemctl restart mtproto-proxy
docker compose --env-file .env -f compose.yml logs -f
```

## &nbsp; Deploy to Server

### One-line install (Ubuntu/Debian)

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

This will:
1. Install **Zig 0.16.0** (if not present)
2. Clone and build the proxy with `ReleaseFast` for the native CPU
3. Generate a random 16-byte secret on first install
4. Create a `systemd` service (`mtproto-proxy`)
5. Open the configured proxy port in `ufw` (if active)
6. Remove legacy **TCPMSS=88** iptables/ip6tables rules unless `ENABLE_TCPMSS=true` is set
7. Optionally install inbound SYN pacing for Android/Desktop handshake stability (`ENABLE_SYNFIX=true`)
8. Install **IPv6 hop script** when `CF_TOKEN`+`CF_ZONE`+`IPV6_PREFIX` are provided
9. Set up self-domain Caddy 404 masking on `127.0.0.1:8443`, including Let's Encrypt on TCP/80, X25519MLKEM768 TLS groups, and the masking health timer
10. Attempt OS-level `zapret` / `nfqws` TCP desync setup
11. Refresh optional monitor files if `proxy-monitor` already exists
12. Print a ready-to-use `tg://` connection link when `[access.users]` contains a valid 32-hex secret

On a fresh source install the generated config omits `[general].use_middle_proxy`, so regular DC1..5 traffic uses the parser default `false`; media traffic still prefers MiddleProxy because `force_media_middle_proxy=true` by default. This differs from `config.toml.example` and the Docker Compose installer, both of which enable regular MiddleProxy routing explicitly.

Inbound SYN pacing is disabled by default. Enable it only on filtered routes where Android/Desktop clients open too many parallel handshakes:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh \
  | sudo env ENABLE_SYNFIX=true bash
```

The SYN pacing default is `SYNFIX_RATE=30/minute SYNFIX_BURST=1 SYNFIX_ACTION=drop`. This keeps excess Android/Desktop retry bursts quiet instead of feeding immediate tcp-reset retries. Use `SYNFIX_ACTION=reject` only when you intentionally want fast reset feedback. `SYNFIX_ACTION=icmp-host-unreachable` immediately rejects excess attempts without encouraging the same TCP-reset retry loop; it can be paired with a cautiously higher rate such as `54/minute` when filtered Android/Desktop routes need faster primary and media connections. Installers persist SYNFIX and optional TCPMSS iptables state with `netfilter-persistent` so it is restored after reboot.

Legacy `TCPMSS=88` ClientHello fragmentation is disabled by default for PQ-capable Caddy masking setups. Re-enable it only as an explicit fallback with `ENABLE_TCPMSS=true`.

### Self-Domain 404 Masking

For the recommended Reality-style self-domain masking flow, use a domain you own:

1. Create an `A` record, for example `proxy.example.com -> <VPS_IP>`.
2. If you use Cloudflare, keep this record **DNS only** (gray cloud), not proxied.
3. Keep public TCP `443` for `mtproto-proxy`; Caddy will answer `404` locally on `127.0.0.1:8443` for non-proxy clients.
4. Keep public TCP `80` reachable for Let's Encrypt HTTP-01 certificate issuance.

Fresh install with a self-domain masking domain:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | \
  sudo env MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com bash
```

The installer writes `server.public_ip = "proxy.example.com"` and `censorship.tls_domain = "proxy.example.com"` on first install, configures Caddy on `127.0.0.1:8443` to return `404` for non-proxy requests, obtains a Let's Encrypt certificate via `:80`, configures X25519MLKEM768 (`0x11ec`) before x25519, installs a renewal hook that reloads Caddy, and generates links that use the domain. Docker Compose installs run Caddy as the `mtproto-mask-caddy` container; source installs run it as `mtproto-mask-caddy.service`. Existing installs can be converted with:

```bash
sudo env MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com \
  bash /opt/mtproto-proxy/setup_masking.sh
sudo systemctl restart mtproto-proxy
```

The Caddy backend intentionally does not publish a site body. Only `/.well-known/acme-challenge/` on port `80` is served for Let's Encrypt; all other HTTP/HTTPS requests receive `404`. If another service already owns public `:80`, stop it before running `setup_masking.sh` so Caddy can serve the ACME challenge.

To enable IPv6 hopping, provide Cloudflare API credentials plus your routed `/64` prefix. The installer stores these values in root-owned `/opt/mtproto-proxy/env.sh` (`0600`) and installs a root cron job that invokes `ipv6-hop.sh` without arguments every five minutes. Each cron invocation performs an unconditional rotation and updates the domain's AAAA record. The separate `ipv6-hop.sh --auto` mode is a long-running foreground loop that rotates only after its handshake-timeout heuristic reaches the ban threshold; installers do not enable that mode. `DNS_NAME` defaults to the masking TLS domain when omitted.

#### Obtaining Cloudflare Credentials

1. **`CF_ZONE` (Zone ID)**:
   - Go to your Cloudflare dashboard and select your active domain.
   - On the right sidebar of the Overview page, scroll down to the "API" section and copy the **Zone ID**.
2. **`CF_TOKEN` (API Token)**:
   - Click "Get your API token" below the Zone ID (or go to *My Profile -> API Tokens*).
   - Click **Create Token** -> **Create Custom Token**.
   - Permissions: `Zone` | `DNS` | `Edit`.
   - Zone Resources: `Include` | `Specific zone` | `<Your Domain>`.
   - Create the token and copy the secret string.
3. **`IPV6_PREFIX`**:
   - Use the routed `/64` prefix assigned to your VPS, without a trailing `::` (for example, `2001:db8:1234:5678`).
   - Optionally set `IPV6_INTERFACE` if your public interface is not `eth0`.

#### Enabling the Bypass during Installation

You can either pass variables directly inline:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | \
  sudo CF_TOKEN=<your_cf_token> CF_ZONE=<your_zone_id> DNS_NAME=proxy.example.com IPV6_PREFIX=2001:db8:1234:5678 bash
```

Or, for a cleaner and more secure approach, create a `.env` file first (you can copy `.env.example` as a template):

```bash
export $(cat .env | xargs)
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo -E bash
```

### Manual deploy

<details>
<summary>Step-by-step instructions</summary>

**1. Install Zig on the server**

```bash
# x86_64
curl -sSfL https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz | \
  sudo tar xJ -C /usr/local
sudo ln -sf /usr/local/zig-x86_64-linux-0.16.0/zig /usr/local/bin/zig

# Verify
zig version   # → 0.16.0
```

**2. Build the proxy**

```bash
git clone https://github.com/XXcipherX/mtproto.zig.git
cd mtproto.zig
zig build -Doptimize=ReleaseFast
```

Or cross-compile on your Mac for a baseline-compatible x86_64 target:

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
scp zig-out/bin/mtproto-proxy root@<SERVER_IP>:/opt/mtproto-proxy/
```

For a modern x86_64 VPS where AES-NI support is known, use `-Dcpu=x86_64_v3+aes` to match the optimized CI/Docker variant and avoid the software-only AES backend warning.

**3. Configure**

```bash
sudo mkdir -p /opt/mtproto-proxy
sudo cp zig-out/bin/mtproto-proxy /opt/mtproto-proxy/

# Generate a random secret
SECRET=$(openssl rand -hex 16)
echo $SECRET

sudo tee /opt/mtproto-proxy/config.toml <<EOF
[general]
# use_middle_proxy = true               # Enable if you use @MTProxybot promo tags

[server]
port = 443
public_ip = "proxy.example.com"
# tag = "<your-promotion-tag>"   # Optional: 32 hex-char promotion tag from @MTProxybot
# max_connections = 10000        # Optional high-capacity override; startup auto-clamps unless unsafe_override_limits=true
# client_silence_close_sec = 0             # Fallback after a mature (30s+) proven healthy relay exchange
# client_silence_fast_close_sec = 0        # Fast close after resumed generic relay traffic; 0 = off
# client_silence_fast_after_idle_sec = 30  # Quiet relay period required by the fast path

[censorship]
tls_domain = "proxy.example.com"
mask = true
mask_port = 8443
fast_mode = true

[access.users]
user = "$SECRET"
EOF
```

### &nbsp; Capacity & RAM Monitoring

On startup, the proxy uses the lower of host RAM and every visible limit from the process's active cgroup v2/v1 hierarchy, including parent groups and non-standard mount points, and prints a **CAPACITY** banner. If `max_connections` is above the safe estimate, it auto-clamps unless `unsafe_override_limits = true`; if the safe budget cannot support the minimum 32 slots, startup fails instead of forcing an unsafe minimum.

User secrets and `tg://`/`t.me` links are redacted from the daemon banner by default so they do not enter journald or container logs. To reveal them intentionally in a private terminal, run `mtproto-proxy [config.toml] --show-secrets`.

**4. Install the systemd service**

```bash
sudo cp deploy/mtproto-proxy.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mtproto
sudo chown mtproto:mtproto /opt/mtproto-proxy/config.toml
sudo chmod 0640 /opt/mtproto-proxy/config.toml

sudo systemctl daemon-reload
sudo systemctl enable mtproto-proxy
```

**5. Open ports 443 and 80**

```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp   # Let's Encrypt HTTP-01 for self-domain masking
```

**6. Set up self-domain masking and start the proxy**

```bash
sudo env MASK_DOMAIN=proxy.example.com LE_EMAIL=admin@example.com \
  bash deploy/setup_masking.sh
sudo systemctl start mtproto-proxy
```

`setup_masking.sh` installs Caddy/certbot, obtains or reuses a Let's Encrypt certificate, configures the local HTTPS masking backend on `127.0.0.1:8443`, and updates `config.toml` for self-domain masking.

**7. Generate connection link**

The proxy prints links on startup. Check them with:

```bash
journalctl -u mtproto-proxy | head -30
```

Or build it manually:

```
tg://proxy?server=<DOMAIN_OR_IP>&port=443&secret=ee<SECRET><HEX_DOMAIN>
```

Where `<HEX_DOMAIN>` is your `tls_domain` encoded as hex:

```bash
echo -n "proxy.example.com" | xxd -p
```

</details>

### Managing the service

```bash
# Status
sudo systemctl status mtproto-proxy

# Live logs
sudo journalctl -u mtproto-proxy -f

# Restart (e.g., after config change)
sudo systemctl restart mtproto-proxy

# Stop
sudo systemctl stop mtproto-proxy
```

## &nbsp; Monitoring

The project includes a lightweight, Zig-themed web dashboard for real-time server monitoring. It runs as a separate systemd service (~30 MB RAM). By default, it is accessible only via SSH tunnel — no ports are exposed to the internet, though this is configurable.

**Features:**
- **Interactive Charts** — glassmorphism hover tooltips with exact values and time
- **CPU & Memory** — live gauges with sparkline history charts (0–100% Y-axis)
- **Network** — realtime RX/TX throughput graph with X-axis timeline and auto-scaling Y-axis labels
- **Proxy stats** — active connections, handshakes, total served, drops breakdown
- **AmneziaWG** — tunnel status, endpoint, handshakes, transfer metrics (optional, auto-hides if not installed)
- **Live logs** — WebSocket-streamed `journalctl` output with color-coded log levels, search, and filters
- **Poll controls** — adjustable refresh interval (1s–10s), pause/resume, data freshness indicator

### Deploy

```bash
make deploy-monitor SERVER=<SERVER_IP>
```

This uploads `deploy/monitor/` (Python FastAPI backend + static frontend), installs Python dependencies (`fastapi`, `uvicorn`, `psutil`, `websockets`), creates a `proxy-monitor` systemd service, and starts it. By default, it binds to `127.0.0.1:61208`; the optional `[monitor]` section in `config.toml` is read by `deploy/monitor/server.py` only and is ignored by the `mtproto-proxy` binary itself.

### Access

By default, the dashboard binds to `127.0.0.1` only — access it via SSH tunnel:

```bash
make monitor SERVER=<SERVER_IP>
# Then open http://localhost:61208
```

Or manually:

```bash
ssh -L 61208:localhost:61208 root@<SERVER_IP>
# open http://localhost:61208
```

### Structure

```
deploy/monitor/
├── server.py          # FastAPI backend (stats API + WebSocket log streaming)
├── install.sh         # Server-side install script
└── static/
    ├── index.html     # Dashboard markup
    ├── style.css      # Zig-themed dark UI
    └── app.js         # Charts, gauges, live logs, poll controls
```

## &nbsp; AmneziaWG Tunnel (Blocked Regions)

If your server is in a country that blocks Telegram at the network level (e.g., Russia — ТСПУ blocks TCP to Telegram DCs), you can route proxy traffic through an **AmneziaWG VPN tunnel** inside an isolated **network namespace**.

```
Client ──→ VPS:443 ──→ [iptables DNAT] ──→ 10.200.200.2:443
              (host)        (host)              (tg_proxy_ns)
                                                     │
                                                mtproto-proxy
                                                     │
                                               awg0 (tunnel)
                                                     │
                                             Telegram DC servers
```

**Key design:** the tunnel runs strictly inside a network namespace. Host SSH and other services are completely unaffected.

### Prerequisites

- An **AmneziaWG client config file** (`.conf`) — export it from the AmneziaVPN app or get it from your VPN provider
- The `.conf` must contain `[Interface]` (with `PrivateKey`, AmneziaWG junk fields) and `[Peer]` (with `Endpoint`)
- A VPS with **Ubuntu 24.04** in the target region

### Tunnel deploy via Makefile

From your workstation:

```bash
make deploy-tunnel SERVER=<VPS_IP> AWG_CONF=awg.conf PASSWORD=<root_password>
```

For a brand-new self-domain install, bootstrap the server with `MASK_DOMAIN=proxy.example.com` first, then use `make deploy-tunnel-only`; the current `make deploy-tunnel` path goes through `make migrate`, whose installer step is non-interactive and does not pass `MASK_DOMAIN`. The command above is suitable when the server is already bootstrapped or when the existing config already has a masking domain.

Optionally choose tunnel mode for `use_middle_proxy` handling:

```bash
make deploy-tunnel SERVER=<VPS_IP> AWG_CONF=awg.conf TUNNEL_MODE=middleproxy
```

This will:
1. Set up SSH key, install deps, build and deploy the proxy (via `make migrate`)
2. Install **amneziawg-tools** (DKMS kernel module + userspace tools)
3. Create network namespace `tg_proxy_ns` with AmneziaWG tunnel inside
4. Set up **DNAT** (incoming proxy port, default `:443`, → namespace) and **policy routing** (responses go back to client, not into tunnel)
5. Patch the systemd service to run the proxy inside the namespace and apply selected tunnel mode (`direct` by default)
6. Validate connectivity to all 5 Telegram DCs through the tunnel
7. Print the ready-to-use `tg://` link

### Add tunnel to existing proxy

If the proxy is already installed and running:

```bash
make deploy-tunnel-only SERVER=<VPS_IP> AWG_CONF=awg.conf
```

With explicit mode:

```bash
make deploy-tunnel-only SERVER=<VPS_IP> AWG_CONF=awg.conf TUNNEL_MODE=preserve
```

### On the server directly

```bash
scp awg.conf root@<VPS_IP>:/tmp/awg.conf
ssh root@<VPS_IP> 'bash /opt/mtproto-proxy/setup_tunnel.sh /tmp/awg.conf middleproxy'
```

### How it works

| Component | Location | Purpose |
|-----------|----------|---------|
| `awg0` | Inside `tg_proxy_ns` | Encrypted tunnel to Telegram DCs |
| `veth_main` ↔ `veth_ns` | Host ↔ Namespace | Bridge for client traffic |
| iptables DNAT | Host | Forwards the configured proxy port (default `:443`) to `10.200.200.2:<port>` |
| Policy routing (`from 10.200.200.2 table 100`) | Inside namespace | Response packets return via veth (not via tunnel) |
| `mtproto-proxy` | Inside `tg_proxy_ns` | Listens on `:443`, connects to Telegram via `awg0` |

> **Note** &nbsp; Tunnel setup supports three modes: `direct` (default, regular DC traffic stays direct; media still prefers MiddleProxy when available), `preserve` (keeps current config), and `middleproxy` (sets `use_middle_proxy=true`). Use `middleproxy` if you want full promo-tag parity for regular traffic through the tunnel.

> **Note** &nbsp; For local masking (`mask_port = 8443`) in tunnel netns mode, masking is now auto-routed to host-side Caddy (`10.200.200.1:8443`) by deploy scripts/runtime — no extra config key is required.

> **Note** &nbsp; Deploy scripts also install a self-healing masking monitor (`mtproto-mask-health.timer`) that checks local masking endpoint reachability every minute and restarts `mtproto-mask-caddy`/`mtproto-proxy` on failures.

> **Note** &nbsp; To check tunnel status: `ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns awg show'`

### Managing the tunnel

```bash
# Check tunnel status
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns awg show'

# Check proxy logs
ssh root@<VPS_IP> 'journalctl -u mtproto-proxy -f'

# Check masking monitor status/logs
ssh root@<VPS_IP> 'systemctl status mtproto-mask-health.timer --no-pager'
ssh root@<VPS_IP> 'journalctl -t mtproto-mask-health -n 50 --no-pager'

# Restart (recreates namespace + tunnel)
ssh root@<VPS_IP> 'systemctl restart mtproto-proxy'

# Test DC connectivity through tunnel
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns nc -zw3 149.154.167.50 443 && echo OK'
```

## &nbsp; Configuration

Create a `config.toml` in the project root:

```toml
[general]
use_middle_proxy = true                         # Telemt-compatible ME mode for promo parity
force_media_middle_proxy = true                 # Default: keep media-path traffic on ME when endpoints are available
ad_tag = "1234567890abcdef1234567890abcdef"    # Optional alias for [server].tag

[server]
port = 443
public_ip = "proxy.example.com"             # Same domain as tls_domain for self-domain masking links
# middle_proxy_nat_ip = "203.0.113.10"      # Optional IPv4 override for MiddleProxy NAT/AES derivation
backlog = 4096                             # TCP listen queue size
middleproxy_buffer_kb = 2048               # ME C2S/S2C buffers grow on demand up to this cap; runtime caps effective value at 16384 KiB
max_connections = 512                      # Safe default for small (1 vCPU / ~1 GB) VPS
idle_timeout_sec = 120
# idle_timeout_jitter_pct = 15             # Per-connection idle timeout jitter in percent; 0 disables
# client_silence_close_sec = 0             # Fallback after a mature (30s+) proven healthy relay exchange
# client_silence_fast_close_sec = 0        # Fast close after resumed generic relay traffic; 0 = off
# client_silence_fast_after_idle_sec = 30  # Quiet relay period required by the fast path
handshake_timeout_sec = 15
# dc_connect_timeout_sec = 10              # Per-DC TCP connect ceiling; 0 still shares the global budget across candidates
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot
log_level = "info"                         # Runtime log level: debug, info, warn, err
rate_limit_per_subnet = 30                # Max new connections/sec per /24 subnet (0 = disabled)
# unsafe_override_limits = false           # Set true to disable auto-clamp of max_connections

[monitor]
# Optional: read only by the separate proxy-monitor service
# host = "127.0.0.1"                       # Bind address for dashboard. Use "0.0.0.0" to expose externally
# port = 61208                             # TCP port for the dashboard

[censorship]
tls_domain = "proxy.example.com"
mask = true
mask_port = 8443
# mask_relay_max_secs = 0                  # Max lifetime for masked Caddy relays; 0 disables
desync = true
# desync_split_delay_ms = 3                # Base delay between first ServerHello byte and the rest
# desync_split_jitter_ms = 2               # Random extra delay, 0..N ms, added to the base
# fake_cert_size = 0                       # Fake encrypted-cert AppData size; 0 keeps built-in default
drs = false
fast_mode = true

[access.users]
alice = "00112233445566778899aabbccddeeff"
bob   = "ffeeddccbbaa99887766554433221100"

[access.direct_users]
alice = true   # "alice" from [access.users]: always direct, keeps fast_mode eligible
# bob = true   # optional
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[general]` | `use_middle_proxy` | `false` | Telemt-compatible ME mode for regular DC1..5. Media-path requests still prefer ME endpoints when available; direct fallback can be used if ME endpoints are unavailable |
| `[general]` | `force_media_middle_proxy` | `true` | Keep media-path traffic (`dc=203` / negative `dc_idx`) on MiddleProxy when ME endpoints are available, even if regular DC traffic stays direct |
| `[general]` | `ad_tag` | _(none)_ | Telemt-compatible alias for promotion tag; ignored if `[server].tag` is set |
| `[server]` | `port` | `443` | TCP port to listen on |
| `[server]` | `public_ip` | _(none)_ | IP/domain shown in startup links. Set it explicitly when using `--show-secrets`; external discovery is intentionally not allowed to delay listener startup. For self-domain masking, use the same domain as `tls_domain`. Tunnel deploy scripts preserve an existing domain instead of replacing it with the tunnel exit IP |
| `[server]` | `middle_proxy_nat_ip` | _(auto-detect)_ | Optional IPv4 override used in MiddleProxy NAT/AES derivation. Useful when `public_ip` is a hostname or when tunnel egress/detection would choose the wrong IPv4 |
| `[server]` | `backlog` | `4096` | TCP listen queue size (for high-traffic loads) |
| `[server]` | `max_connections` | `512` | Concurrent connection cap (small-VPS tuned default, parser lower bound 32). On Linux, startup first auto-clamps this to the lower of host RAM and the lowest visible leaf/parent cgroup limit unless `unsafe_override_limits=true`; the proxy then clamps again if `RLIMIT_NOFILE` can support at least 32 slots, otherwise startup fails safely |
| `[server]` | `idle_timeout_sec` | `120` | Established relay idle timeout in seconds (parser lower bound 5). Pre-first-byte admission uses a separate fixed 10-second deadline |
| `[server]` | `idle_timeout_jitter_pct` | `15` | Per-connection random jitter applied once when the slot is admitted to `idle_timeout_sec` (`±N%`, clamped to `0..100`). The effective timeout is then reused for every deadline update, floored to at least 5 seconds and at least half the base timeout. Set `0` to disable |
| `[server]` | `client_silence_close_sec` | `0` | Conservative iOS MtProtoKit wedge fallback for proven generic DC relays. Eligibility requires at least 30 seconds in the relay phase and a delivered server reply followed by further client traffic, so startup exchanges on fresh reconnects cannot arm a close loop. A later server payload is considered a reply only when it arrives within the client's 12-second response window, and the timer starts after the userspace client queue drains. Media relays are excluded. `0` disables it; `15` is the recommended fallback |
| `[server]` | `client_silence_fast_close_sec` | `0` | Optional fast close for the same unanswered-reply pattern when an established generic relay has just resumed after `client_silence_fast_after_idle_sec` of silence. Any client payload cancels the candidate, and a fresh reconnect is not immediately eligible, preventing reconnect loops. `0` disables it; `2` is the recommended iOS value |
| `[server]` | `client_silence_fast_after_idle_sec` | `30` | Minimum quiet relay period before the fast iOS wedge path is eligible (parser lower bound 5). Has no effect while `client_silence_fast_close_sec=0` |
| `[server]` | `handshake_timeout_sec` | `15` | Timeout for completing handshake after first byte (parser lower bound 5) |
| `[server]` | `dc_connect_timeout_sec` | `10` | Per-endpoint TCP connect ceiling for Telegram DC and MiddleProxy candidates. Every attempt is also capped by its share of the remaining global handshake budget, including the final MiddleProxy candidate and reserved direct fallback. `0` disables only the configured ceiling; global budget sharing remains active |
| `[server]` | `middleproxy_buffer_kb` | `2048` | MiddleProxy per-direction buffer cap in KiB. Active ME connections start with 16 KiB C2S/S2C buffers and grow on demand up to `min(middleproxy_buffer_kb, 16384)` KiB; each event loop also keeps lazy shared scratch buffers. Default 2048 leaves headroom for 1 MiB media parts; values below 1024 may still cause `MiddleProxyBufferOverflow` on media-heavy traffic (Stories, video messages). Parser lower bound is 64 KiB |
| `[server]` | `tag` | _(none)_ | Optional 32 hex-char promotion tag from [@MTProxybot](https://t.me/MTProxybot) |
| `[server]` | `log_level` | `"info"` | Runtime log verbosity: `debug` (all DC routing, relay, close details), `info` (default — connection stats, warnings), `warn`, `err`. Change without recompilation; takes effect on restart |
| `[server]` | `rate_limit_per_subnet` | `30` | Max new connections per second per /24 (IPv4) or /48 (IPv6) subnet. Blocks scanner/DPI-probe flood. Set `0` to disable |
| `[server]` | `unsafe_override_limits` | `false` | Disable auto-clamping of `max_connections` to the effective-memory estimate. Use only when the container/service limit as well as host RAM are sufficient |
| `[monitor]` | `host` | `"127.0.0.1"` | Bind address for the optional monitoring dashboard HTTP server. This section is read by `proxy-monitor`, not by the proxy binary. Set to `"0.0.0.0"` to expose on all interfaces (warning: no built-in auth) |
| `[monitor]` | `port` | `61208` | TCP port for the optional monitoring dashboard HTTP server |
| `[censorship]` | `tls_domain` | `"google.com"` | FakeTLS SNI domain. With `mask_port=443`, unauthenticated clients are forwarded to this domain directly. For self-domain masking, set it to your own domain and point its DNS A record to the VPS. Since June 2026, the real masking endpoint should negotiate X25519MLKEM768 (`0x11ec`) in one round; classical-x25519-only domains can be a passive marker |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to the configured masking target to defeat active probing |
| `[censorship]` | `mask_port` | `443` | Masking target port. `443` connects to `tls_domain:443`; non-443 values connect to a local address on that port (`127.0.0.1:<mask_port>`, or `10.200.200.1:<mask_port>` inside tunnel netns), so that port must be served by Caddy or another local backend. Use `8443` for self-domain Caddy so public `443` remains owned by `mtproto-proxy` |
| `[censorship]` | `mask_relay_max_secs` | `0` | Maximum lifetime for masking relay connections to the configured backend. Limits active probes that keep the Caddy 404 connection open; `0` disables the cap |
| `[censorship]` | `desync` | `true` | Split fake `ServerHello` into `1 byte + short pause + rest` to desynchronize passive DPI |
| `[censorship]` | `desync_split_delay_ms` | `3` | Base delay between the first fake `ServerHello` byte and the remaining bytes |
| `[censorship]` | `desync_split_jitter_ms` | `2` | Random extra delay in milliseconds added to `desync_split_delay_ms` (`0..N` per connection) |
| `[censorship]` | `fake_cert_size` | `0` | Fake TLS encrypted-certificate AppData size in bytes. `0` keeps the built-in 2878-byte default; explicit values are clamped to `256..16384` |
| `[censorship]` | `drs` | `false` | Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes after warmup (mimics Chrome/Firefox) |
| `[censorship]` | `fast_mode` | `false` | **Recommended** for direct-path traffic. Delegates S2C AES encryption to Telegram DC and reduces proxy CPU/RAM pressure |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |
| `[access.direct_users]` | `<name> = true` | _(none)_ | Optional per-user MiddleProxy bypass. `<name>` must match a user from `[access.users]`; such users always connect directly to Telegram DCs (including media paths). Values `false`/`0`/`no` remove a previous duplicate entry. Alias section: `[access.admins]` |

</details>

> **Operational note** &nbsp; High-churn mobile networks can produce many normal disconnects (`ConnectionResetByPeer`/`EndOfStream`). In release builds these are logged at debug level to keep production logs signal-focused.

> **Operational note** &nbsp; `deploy/mtproto-proxy.service` ships with `LimitNOFILE=131582` to allow higher custom caps when needed. Default `max_connections=512` is tuned for small VPS profiles; increase it only after capacity testing.

> **Operational note** &nbsp; The FakeTLS path uses one strict ClientHello parser for validation, SNI, cipher selection, and PQ key-share detection. It rejects inconsistent nested lengths and non-32-byte Session IDs; current Telegram MTProto-over-TLS clients use a 32-byte Session ID, which the proxy echoes in its TLS-like ServerHello template.

> **Operational note** &nbsp; The parser rejects unknown sections, unknown proxy keys, keys outside a section, and malformed non-comment lines. `[monitor].host` and `[monitor].port` remain accepted for the separate dashboard service. Socket ports must be in `1..65535`, and `backlog` must fit Linux's signed listen backlog range; invalid numeric values keep their safe defaults with a warning. Config load failures exit non-zero.

> **Operational note** &nbsp; If `accept()` hits `EMFILE`/`ENFILE`, the listener temporarily disables `EPOLLIN`, waits 500ms, and retries. In periodic `conn stats`, the first `paused=` flag reflects this fd-quota backoff.

> **Operational note** &nbsp; On startup, `max_connections` is automatically clamped to an effective-memory estimate derived from host RAM and the lowest readable limit in the process's cgroup hierarchy. Set `unsafe_override_limits = true` to disable this. Admission control also pauses `accept()` at 90% capacity, resumes at 80%, and limits concurrent unauthenticated sockets per source subnet.

> **Operational note** &nbsp; The RAM-safety estimate intentionally budgets MiddleProxy at full configured per-direction cap even though active C2S/S2C buffers grow lazily from 16 KiB. Configured `middleproxy_buffer_kb` values above 16384 are accepted but the effective runtime cap is 16 MiB per direction and startup logs a warning.

> **Operational note** &nbsp; The proxy limits new connections to 30/sec per /24 subnet by default (`rate_limit_per_subnet`). Native IPv6 keys retain all 48 prefix bits, while IPv4-mapped IPv6 shares the native IPv4 `/24` key. This blocks ТСПУ scanners and DPI replay probes without affecting legitimate Telegram clients.

> **Operational note** &nbsp; Self-domain masking expects DNS `A proxy.example.com -> <VPS_IP>`, Cloudflare DNS-only mode if used, public TCP `80` for Let's Encrypt, public TCP `443` for `mtproto-proxy`, and local Caddy TLS on `127.0.0.1:8443` returning `404` for non-proxy requests. Docker Compose installs serve that local Caddy endpoint from the `mtproto-mask-caddy` container; source installs serve it from `mtproto-mask-caddy.service`. `setup_masking.sh` serves ACME HTTP-01 on `:80` and configures Caddy with `x25519mlkem768 x25519` curves. The `ee` link secret changes when `tls_domain` changes, so regenerate client links after changing the domain.

> **Tip** &nbsp; Generate a random secret: `openssl rand -hex 16`

> **Note** &nbsp; The documented sections and aliases are compatible with the Rust-based `telemt` proxy; unsupported keys are rejected instead of silently falling back to defaults.

> **Note** &nbsp; For compatibility, `fast_mode` is accepted in `[general]`, `[server]`, or `[censorship]`; all three set the same runtime flag.

> **Note** &nbsp; The parser supports inline `#` / `;` comments after values and treats duplicate owned string/user/direct-user entries as last-write-wins without leaking previous allocations.

> **Note** &nbsp; MiddleProxy settings (regular DC1..5 endpoints + media-path endpoints + shared secret), NAT discovery, and masking DNS resolution run after the listener is ready. Metadata and all masking candidates refresh hourly, with reactive early refresh after stalled MiddleProxy handshakes and bundled MiddleProxy defaults as fallback.

## &nbsp; Troubleshooting ("Updating...")

If your Telegram app is stuck on "Updating...", your provider or network is dropping the connection.

### 0. Runtime expectations (important)

This proxy uses a Linux `epoll` event loop (single-thread relay path). Timeouts use a monotonic `timerfd` plus an indexed min-heap with one current deadline per active slot; there is no fixed polling cadence or full-slot timeout scan. If you see stale guidance mentioning `poll()`/`SO_RCVTIMEO`/fixed max-lifetime, treat it as outdated.

### 1. Check runtime health and fd pressure first

Before chasing client/network hypotheses, inspect the new low-noise runtime signals:

```bash
ssh root@<VPS_IP> 'journalctl -u mtproto-proxy --since "30 min ago" --no-pager | grep -E "conn stats|drops:|auto-clamping max_connections|RAM-safe estimate|skipping max_connections safety clamp|max_connections clamped|fd quota reached|failed to resume accepts|connection saturation|saturation eased"'
ssh root@<VPS_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/limits | grep "open files"'
```

Interpretation:

- `auto-clamping max_connections ...` means startup reduced configured capacity to the host/cgroup-hierarchy effective-memory estimate. `max_connections clamped ... due to RLIMIT_NOFILE` means runtime reduced it again to fit the process fd limit.
- `fd quota reached ... pausing accepts for 500ms` means the listener hit `EMFILE`/`ENFILE` and intentionally backed off instead of busy-looping.
- `conn stats ... paused=<fd_pause>/<saturation_pause>` exposes two pause reasons: fd-quota backoff first, saturation hysteresis second.
- `drops: ... rate+=...` means the per-subnet rate limiter rejected excess new connections.
- `drops: ... hs_budget+=...` means either the global handshake-inflight budget or the per-subnet unauthenticated-socket allowance rejected a new handshake.
- `drops: ... mp_fallback+=...` means the MiddleProxy path degraded and the proxy recovered by reconnecting directly to the same DC.
- `connection saturation ...` and `saturation eased ...` are the 90%/80% admission-control logs; if the second `paused=` flag is `true`, raise capacity only after checking RAM and probe results.

If you use the AmneziaWG tunnel deployment path, also confirm the namespace tunnel is up:

```bash
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns awg show'
ssh root@<VPS_IP> 'ip netns exec tg_proxy_ns nc -zw3 149.154.167.50 443 && echo OK'
```

### 2. AAAA exists, but server IPv6 is not actually working

This proxy supports IPv6, but your VPS must have real end-to-end IPv6 routing.
If DNS has an `AAAA` record and the server has no usable global IPv6 route, iOS often tries IPv6 first, waits for timeout, then falls back to IPv4. This usually looks like a ~3-8 second connect delay.

Quick checks:

```bash
dig +short proxy.example.com A
dig +short proxy.example.com AAAA
ip -6 addr show scope global
ip -6 route
```

If `AAAA` exists but the server has no working global IPv6/default route, remove `AAAA` and keep only `A` until IPv6 is fully configured.

### 3. Home Wi-Fi restricts IPv4

Often, mobile networks will connect instantly because they use **IPv6**, but Home Wi-Fi internet providers block the destination's IPv4 address directly at the gateway.
**Solution:** Enable **IPv6 Prefix Delegation** on your home Wi-Fi router. 
- Go to your router's admin panel (e.g., `192.168.1.1`).
- Find the **IPv6** or **WAN/LAN** settings.
- Enable `IPv6`, and specifically check **IA_PD** (Prefix Delegation) for the WAN/DHCP client, and **IA_NA** for the LAN/DHCP Server.
- Reboot the router and verify your phone gets an IPv6 address at [test-ipv6.com](https://test-ipv6.com). 

### 4. Commercial / Premium VPNs Block Traffic

If your iPhone is connected to a **commercial/premium VPN** and stuck on "Updating...", the VPN provider is actively dropping the MTProto TLS traffic using their own DPI.
**Solutions**:
- **Switch Protocol**: Try switching the VPN protocol (e.g., Xray/VLESS to WireGuard).
- **Self-Host**: Use a self-hosted VPN (like AmneziaWG) on your own server.

### 5. Co-located WireGuard (Docker routing)

If you run both this proxy and AmneziaVPN (or a WireGuard Docker container) **on the same server**, iOS clients will route proxy traffic inside the VPN tunnel, and Docker will drop the bridge packets.
**Solution**: Allow traffic from the VPN Docker subnet:
```bash
iptables -I DOCKER-USER -s 172.29.172.0/24 -p tcp --dport 443 -j ACCEPT
```

### 6. DC203 media resets

If only media-heavy sessions fail on non-premium clients, check MiddleProxy logs first:

```bash
sudo journalctl -u mtproto-proxy --since "15 min ago" | grep -E "dc=203|Middle-proxy"
```

On startup the proxy now refreshes DC203 metadata from Telegram automatically. If your server cannot reach `core.telegram.org`, it falls back to bundled defaults.

## &nbsp; License

[MIT](LICENSE) &copy; 2026 Aleksandr Kalashnikov
