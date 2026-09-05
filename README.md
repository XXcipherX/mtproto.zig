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
| **WEB Proxy** | Browser HTTPS Carrier | Runs Telegram Desktop 7.1+ WEB links in parallel with ordinary MTProto, using the existing Caddy instance for real TLS/WebSocket termination |
| **PQ FakeTLS** | DPI Evasion | Echoes `X25519MLKEM768` (`0x11ec`) ServerHello key_share for modern Desktop/Android ClientHellos |
| **Fast Mode** | Direct-Path S2C Offload | Reduces CPU usage by delegating S2C AES work to Telegram DCs on direct paths (non-MiddleProxy) |
| **MiddleProxy** | Telemt-Compatible ME | Optional ME transport for DC1..5 (`use_middle_proxy`); retries TCP candidates, applies a 5-second per-stage handshake deadline, cools failed endpoints for 60 seconds, and falls back directly when a real DC endpoint exists (never for CDN DC203) |
| **Auto Refresh** | Runtime Discovery | Periodically updates regular/media MiddleProxy metadata and re-resolves all masking DNS candidates without delaying listener startup |
| **Promotion** | Tag Support | Optional promotion tag for sponsored proxy channel registration |
| **IPv6 Hopping** | DPI Evasion | Rotates IPv6 from a routed /64 and updates Cloudflare AAAA records; installers schedule a hop every 5 minutes, while `--auto` provides foreground ban-detection mode |
| **Optional TCPMSS=88** | Legacy DPI fallback | Disabled by default; can force tiny ClientHello fragmentation on external traffic when explicitly enabled; loopback is always excluded |
| **TCP Desync** | DPI Evasion | Integrated `zapret` (`nfqws`) OS-level desynchronization (fake packets + TTL spoofing); NFQUEUE queue-bypass preserves traffic while `nfqws` restarts, and loopback never enters the queue |
| **Split-TLS** | DPI Evasion | Splits fake `ServerHello` write into `1 byte + short pause + rest` to desynchronize passive DPI |
| **Zero-RTT** | DPI Evasion | Local self-domain Caddy 404 masking (`127.0.0.1:8443`, with tunnel netns auto-routing and PQ TLS groups) to defeat active probing timing analysis |
| **0 deps** | Stdlib Only | No third-party Zig packages (proxy core uses Zig standard library only) |
| **Explicit State** | Runtime Ownership | Proxy state is passed explicitly; runtime log level is the only mutable global knob |

> **Engineering Notes:** For deep technical details, cryptography internals, systemd hardening, and benchmarks, refer to the `.agent/skills` and `.agent/workflows` directories.

Connection-capacity methodology and command profiles: `test/README.md`.

## Runtime Model

- Client relay is handled by a single-threaded Linux `epoll` event loop. `epoll_event.data.u64` carries the slot index, generation, and fd role, so dispatch does not need an fd hash lookup and stale events cannot attach to a reused slot.
- `SIGINT` and `SIGTERM` are bridged into that event loop through a non-blocking `eventfd`; the async signal handler performs only the raw notification write. The first signal disables new accepts and drains active connections for `graceful_shutdown_timeout_sec`; a second signal or the deadline closes the remaining slots before the listener and joinable discovery worker are released in ownership order.
- External discovery never delays the listening socket: MiddleProxy metadata/NAT detection and hostname-based masking resolution run in a joinable background worker. Metadata and masking candidates refresh hourly, reachability probes run in cancellable batches of at most four sockets, in-flight DNS/HTTPS/curl work is canceled cooperatively during shutdown, and stalled MiddleProxy handshakes can request an early refresh.
- FakeTLS validation expects Telegram-style 32-byte ClientHello Session IDs and copies the Session ID into the synthetic ServerHello.
- Handshake and relay lifetimes are controlled by monotonic `timerfd` deadlines in an indexed min-heap (`handshake_timeout_sec`, `idle_timeout_sec`), not by periodic slot scans or `SO_RCVTIMEO`; a silent connection gets at most 10 seconds to send its first byte.
- Unauthenticated sockets share a per-/24 or per-/48 concurrent allowance (`clamp(max_connections / 8, 16, 128)`). The global handshake-inflight budget is charged after the first byte and released after authentication.
- Graceful `EPOLLRDHUP` is treated as a read-side hint and drained to actual EOF. Client and upstream read/write halves remain independent: queued data is flushed before `shutdown(SHUT_WR)` propagates FIN, while the reverse relay direction stays active.
- Failed non-blocking upstream connects are reclaimed immediately on fatal hangup events; the relay loop should not spin on dead upstream sockets.
- The timerfd wakes only for the earliest connection/admission deadline or the 10-second aggregated `conn stats` report; timer maintenance does not scan the slot pool.
- Client payload bytes pipelined after the 64-byte MTProto obfuscation nonce are buffered and forwarded once the upstream path is ready.
- WEB mode runs as a separate `mtproto-proxy web-relay` process. Caddy terminates the browser TLS/WebSocket carrier, while the public `:443` data plane continues to serve ordinary FakeTLS links and admits direct-obfuscated WEB streams only from trusted relay source addresses.
- Outbound client/upstream writes use intrusive page-sized block queues backed by one event-loop free list and one shared hard buffer-memory budget, bounded `writev` dispatches, and a 4 MiB pending-byte cap per queue. Tail packing avoids one page allocation per small write, recycled pages are wiped, and per-event byte/operation budgets prevent one ready fd from monopolizing the loop.
- MiddleProxy per-direction C2S/S2C buffers start at 16 KiB and grow on demand up to the effective `middleproxy_buffer_kb` cap; shared event-loop scratch buffers are allocated lazily and reused. Queue pages, retained free-list pages, stream buffers, scratch, and transient growth are all charged to the same runtime budget. C2S headers are parsed once during encapsulation, padded-intermediate S2C replies use only 0..3 padding bytes so the receiver's truncate-to-4 rule cannot retain garbage, and completed handshakes release route candidates, validation state, and ME handshake buffers immediately.
- MiddleProxy route snapshots contain only candidates for the selected DC/path plus a versioned secret reference and NAT address. The current and immediately previous secrets are retained centrally, so concurrent rotations do not copy a 256-byte secret into every handshake or split selector/KDF inputs.
- Secret-bearing handshake, KDF, hash, and cipher temporaries are traversed by pointer where possible and explicitly cleared with `std.crypto.secureZero`; cleanup is field-wise for mixed structs so enum and pointer fields are never overwritten with invalid representations.
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

Production release commands continue to request `ReleaseFast`, but the build policy
compiles the internet-facing `mtproto-proxy` executable as `ReleaseSafe` by default.
The parser data plane therefore retains bounds, overflow and null checks, while
`bench` and `soak` stay genuinely `ReleaseFast`. The proxy is also emitted as PIE so
Linux ASLR can randomize its load address. A deliberate benchmark-only comparison
against the unsafe mode is available with
`zig build -Doptimize=ReleaseFast -Ddataplane_safety=false`; do not use that opt-out
for an exposed production proxy.

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

On a 64-bit Linux development host, Zig 0.16 can drive the security parser
harnesses with coverage-guided input generation. Use a finite per-target budget
for a bounded local/CI campaign:

```bash
make fuzz                       # 100K iterations per target
make fuzz FUZZ_ITERATIONS=1M   # deeper bounded campaign
```

Omit the limit only for an intentional interactive campaign, then stop it with
`Ctrl+C`:

```bash
zig build -Doptimize=ReleaseSafe fuzz --fuzz
```

The dedicated `fuzz` build step covers FakeTLS and obfuscated handshakes,
MiddleProxy stream framing, and the public WEB HTTP, WebSocket, PROXY-protocol
and multiplexed-frame parsers without pulling the benchmark test binary into the
campaign. CI runs 25K iterations per target for pull requests and 100K per target
for pushes to `main`, in a separate parallel job with a 15-minute hard timeout.

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

The GitHub workflow additionally verifies the production safety policy, PIE output,
Linux `x86_64`, deploy-target `x86_64_v3+aes`, Linux `aarch64`, Docker build smoke,
and genuine `ReleaseFast` bench/soak paths.

`zig build test` runs the tests reachable from `src/main.zig` plus `src/bench.zig`. A normal `zig build` installs only `mtproto-proxy`; benchmark execution remains explicit through `bench`/`soak`, and `zig build install-bench` installs `mtproto-bench` when a standalone benchmark binary is needed.

`bench` prints per-payload throughput (`in_mib_per_s`, `out_mib_per_s`) and `ns_per_op`.
`soak` prints aggregate `ops/s`, throughput, and `errors`; non-zero errors fail the step.

<details>
<summary>All Make targets</summary>

| Target | Description |
|--------|-------------|
| `make build` | Debug build |
| `make release` | Production build (`ReleaseSafe` data plane + PIE by default) |
| `make run CONFIG=<path>` | Run proxy (default: `config.toml`) |
| `make test` | Run unit tests |
| `make fuzz [FUZZ_ITERATIONS=100K]` | Run bounded ReleaseSafe security fuzzing (64-bit Linux) |
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

The repository includes a **multi-stage Dockerfile**: Zig is bootstrapped from the official tarball inside the build stage; the runtime image is Debian **bookworm-slim** with `curl` and CA certs. The proxy binary performs background HTTPS public-IPv4 detection for MiddleProxy NAT derivation and refreshes Telegram metadata itself, so CA certs are required; `curl` is kept for container-side diagnostics and as a fallback when a bounded preflight rejects `/etc/resolv.conf` before Zig 0.16 can reach its unsafe `attempts:0`, oversized search, or overlong DNS-name paths. Both the built-in client and that fallback follow only a bounded number of HTTPS-to-HTTPS redirects; a redirect to plain HTTP is rejected before the next request. The process runs as **root** inside the container (simple bind to port 443). `config.toml.example` is shipped as documentation only. On a first start without a mounted config, the entrypoint creates `/etc/mtproto-proxy/config.toml` with mode `0600` and a random user secret without printing that secret into Docker logs. Mount your own file for production settings; the Compose installer always does so.

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
| `ENABLE_WEB` | `false` | Enable the Telegram Desktop WEB relay alongside ordinary MTProto; an existing enabled WEB setup is preserved when this variable is omitted |
| `WEB_DOMAIN` | _(required with `ENABLE_WEB=true`)_ | Separate public DNS hostname used by `tg://webproxy` links; it must differ from `TLS_DOMAIN` |
| `WEB_ONLY` | `false` | With `ENABLE_WEB=true`, mask all direct MTProto clients and serve only the trusted WEB relay; an existing value is preserved when omitted |
| `ENABLE_TCPMSS` | `false` | Enable legacy `TCPMSS=88` ClientHello fragmentation fallback for external traffic; disabled by default with PQ-capable Caddy masking |
| `ENABLE_SYNFIX` | `false` | Install inbound SYN pacing rules for external Android/Desktop routes that need it; loopback is excluded |
| `SYNFIX_RATE` | `30/minute` | Per-source SYN rate for non-iOS-like fingerprints |
| `SYNFIX_BURST` | `1` | Per-source SYN burst for non-iOS-like fingerprints |
| `SYNFIX_ACTION` | `drop` | Over-limit SYN action: `drop` is quiet, `reject` sends TCP reset, `icmp-host-unreachable` fails the attempt immediately without an RST |
| `MASK_PORT` | `8443` | Local Caddy HTTPS masking backend port |
| `CADDY_IMAGE` | `caddy:2-alpine` | Caddy image used by the Docker Compose installer; follows stable Caddy 2 releases without crossing into a future major version |
| `GHCR_USER` / `GHCR_TOKEN` | _(empty)_ | Optional login for private GHCR packages |

The installer requires Docker Compose v2 (`docker compose`) and installs Docker Engine + the Compose plugin via Docker's convenience script if either Docker or the plugin is missing. When `IMAGE` is not set, compatible x86_64 hosts automatically pull the `latest-amd64-v3` image; if that tag is unavailable, the installer falls back to generic `latest`. The proxy, WEB relay, and Caddy Compose services use `network_mode: host`; the proxy owns public `:443`, Caddy owns public ACME `:80` plus local masking/WEB listeners, and the relay stays on loopback. Re-run the installer to pull and restart with newer images, or update manually:

The tracked `deploy/compose.yml` is only a minimal proxy plus optional WEB-relay example. The installer generates a richer `/opt/mtproto-proxy/compose.yml` containing Caddy, resource limits, and install-specific settings; do not treat the tracked example as the installer's exact output.

```bash
cd /opt/mtproto-proxy
docker compose --env-file .env -f compose.yml pull
sudo systemctl restart mtproto-proxy
docker compose --env-file .env -f compose.yml logs -f
```

To print the connection links again without starting a second proxy listener:

```bash
docker exec -it mtproto-proxy \
  /usr/local/bin/mtproto-proxy \
  /etc/mtproto-proxy/config.toml \
  --print-links
```

The one-shot process reads the container's mounted config, writes the secret links only to the current terminal, and exits while the main proxy process keeps running.

## WEB proxy (Telegram Desktop 7.1+)

By default, WEB mode is an additional transport rather than a replacement for the ordinary proxy. Existing `tg://proxy` FakeTLS clients continue to use public TCP `443`; Telegram Desktop can additionally use a `tg://webproxy` link whose traffic is carried by a real browser HTTPS/WebSocket session. Optional WEB-only mode disables that direct door.

```text
ordinary client ───────────────────────────────▶ mtproto-proxy :443 ─▶ Telegram

Telegram Desktop WEB ─▶ mtproto-proxy :443 ─▶ Caddy :8444
                                               └─ WebSocket ─▶ web-relay :8081
                                                                  └─ MTProto streams ─▶ mtproto-proxy :443 ─▶ Telegram
```

The deployment uses the existing `mtproto-mask-caddy` instance only. Caddy's built-in PROXY-protocol listener wrapper preserves the real browser address across the proxy-to-Caddy hop; the relay then prefixes every backend MTProto stream with PROXY v2. No additional public port is opened: Caddy `8444` and relay `8081` remain local. Both local Caddy TLS listeners are restricted to HTTP/1.1 and HTTP/2 so responses do not advertise unreachable public HTTP/3 endpoints on UDP `8443` or `8444`. Host SYN pacing, NFQUEUE desync, and optional TCPMSS rules explicitly exclude loopback, so internal WEB streams never consume external-client limits or DPI processing.

An ordinary request to the WEB hostname receives the same bodyless `404` generated by Caddy for the MTProto masking hostname. The post-setup HTTPS probe treats that expected `404` as a healthy proxy-to-Caddy route instead of relying on curl's generic 2xx success policy. Caddy forwards only the `/?bridge=...` page and `/api/v1/socket?b=...` carrier routes to the relay; an invalid capability also returns an empty `404`. Only a valid secret-derived capability receives the visually empty bridge page required by Telegram Desktop.

Requirements:

1. Create a second DNS-only `A` record such as `web.example.com -> <VPS_IP>`.
2. Keep it distinct from `[censorship].tls_domain` (for example `proxy.example.com`). The two SNI names select different local Caddy paths on the same public `:443` listener.
3. Keep public TCP `80` reachable while Certbot issues or renews the WEB certificate.
4. Keep Caddy masking enabled; the WEB setup extends that same Caddy configuration.

For an existing Docker Compose installation made by this repository's installer, run:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
  | sudo env ENABLE_WEB=true WEB_DOMAIN=web.example.com bash
```

The installer preserves the existing proxy config and user secrets, updates the image and Compose definition, adds `mtproto-web-relay`, extends `mtproto-mask-caddy`, obtains the certificate, and restarts the affected containers. On a fresh Docker install, add `TLS_DOMAIN=proxy.example.com` to the same command.

For an updated source/systemd installation:

```bash
sudo /opt/mtproto-proxy/setup_web.sh web.example.com
```

Inspect all three processes with:

```bash
cd /opt/mtproto-proxy
docker compose --env-file .env -f compose.yml logs -f \
  mtproto-proxy mtproto-web-relay mtproto-mask-caddy
```

Print both ordinary and WEB links without starting another listener:

```bash
docker exec -it mtproto-proxy \
  /usr/local/bin/mtproto-proxy \
  /etc/mtproto-proxy/config.toml \
  --print-links
```

WEB links use the same 16-byte `[access.users]` secret encoded as `dd<secret>`; FakeTLS links keep their existing `ee<secret><hex-domain>` encoding. The public proxy still rejects direct-obfuscated traffic from untrusted Internet peers: only loopback and explicit `[web].relay_sources` may carry WEB streams into that path.

WEB relay hardening is adapted from upstream PR #408. Backend queues now accommodate
the protocol's full 4 MiB receive window, and WebSocket messages can carry one maximum
1 MiB relay payload plus its header. Outbound DATA/WINDOW frames are batched within an
event-loop pass; input frames are consumed with one buffer compaction per pass.
Pre-adoption browser reconnects replay the initial handshake only once, and the bridge
always uses same-origin WSS. Forwarded client addresses are accepted only from a
loopback terminator, using the right-most value of the last matching header line.

`[web].max_buffer_mb` limits buffered payload across HTTP/WebSocket input, fragmented
messages, outbound batches, and socket queues at every append. It is **not** a process
RSS limit: retained allocation capacity, queue freelists, metadata and kernel socket
buffers are separate. Soft throttling stops backend reads and new credit before the
payload ceiling; reaching the hard ceiling closes the affected path.

Hostname-based `[web].backend` and `mask_backend` addresses refresh every minute,
retain the last successful DNS answer, and provide up to 16 candidates per connect
attempt. Literal addresses do not start a DNS worker. Failed backend connects preserve
queued PROXY metadata and MTProto bytes until a candidate connects. The relay listener
itself requires an IP literal. Changing access users or other relay settings requires
restarting both proxy processes; SIGHUP reports that a restart is required.

WEB metrics are available only by directly querying the loopback relay:

```bash
curl -sS http://127.0.0.1:8081/metrics
```

They report sessions, streams, refused streams/accepts, throttling, buffered payload
and outgoing bytes. The public Caddy routes do not expose this endpoint.
Existing Docker/source configurations need no new parameters for these changes.

Re-running WEB setup preserves an existing WEB-only gate. Activating a new gate
requires successful HTTPS and loopback relay checks. Setup validates Caddy before
replacing its WEB files and restores the previous files/config if candidate validation
fails. It also checks certificate expiry. Changing an existing WEB domain invalidates
distributed links and requires explicit `--force` for `setup_web.sh`, or
`WEB_FORCE_DOMAIN_CHANGE=true` in the install environment.

### WEB-only mode

Set `[web].only = true` when a direct Telegram connection itself triggers blocking of the server IP. The data plane then answers MTProto only for the relay address trusted at `accept()` time. Every external FakeTLS client—including one with a valid old `ee` link—is sent to the same Caddy masking backend used for an invalid secret. Client-provided PROXY metadata cannot grant relay trust.

For an existing Docker Compose installation:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
  | sudo env ENABLE_WEB=true WEB_ONLY=true WEB_DOMAIN=web.example.com bash
```

For a source/systemd installation:

```bash
sudo /opt/mtproto-proxy/setup_web.sh --only web.example.com
```

For first activation, setup keeps direct MTProto available until Caddy and `mtproto-web-relay` pass their checks, then activates the gate in a final proxy-only restart. Reinstall preserves an already active gate. `--print-links` and installer summaries emit only `tg://webproxy` links while the gate is active. To restore ordinary MTProto without removing WEB support, run `setup_web.sh --no-only web.example.com` (or rerun the Docker installer with `ENABLE_WEB=true WEB_ONLY=false`).

WEB-only requires Caddy masking and an enabled WEB relay. It is ignored if `[web].enabled=false`, so removing WEB support cannot leave an unreachable all-masked proxy. Existing ordinary `tg://proxy` links do not work until WEB-only is disabled, and `[web].max_sessions` becomes the effective desktop-session ceiling.

Capacity is deliberately separate from the relay's queue-memory limit. One WEB desktop session can occupy one front/masking connection plus up to `max_streams` backend proxy connections. The Caddy installer defaults to `max_sessions=8` and `max_streams=32`, a worst-case 264 proxy slots, which fits the default `max_connections=512`; increase these values together only after accounting for ordinary clients and relay memory.

To remove WEB mode while leaving ordinary MTProto and Caddy masking intact:

```bash
sudo env MTPROTO_DOCKER_INSTALL=1 \
  bash /opt/mtproto-proxy/setup_web.sh --remove
```

## &nbsp; Deploy to Server

### One-line install (Ubuntu/Debian)

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
```

This will:
1. Install **Zig 0.16.0** (if not present)
2. Clone and build the proxy with the production `ReleaseSafe` data-plane policy for the native CPU
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

On a fresh source install the generated config omits `[general].use_middle_proxy`, so regular DC1..5 traffic uses the parser default `false`; negative DC1..5 media traffic still prefers MiddleProxy because `force_media_middle_proxy=true` by default, while CDN DC203 always requires MiddleProxy. This differs from `config.toml.example` and the Docker Compose installer, both of which enable regular MiddleProxy routing explicitly.

Inbound SYN pacing is disabled by default. Enable it only on filtered routes where Android/Desktop clients open too many parallel handshakes:

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh \
  | sudo env ENABLE_SYNFIX=true bash
```

The SYN pacing default is `SYNFIX_RATE=30/minute SYNFIX_BURST=1 SYNFIX_ACTION=drop`. This keeps excess Android/Desktop retry bursts quiet instead of feeding immediate tcp-reset retries. Use `SYNFIX_ACTION=reject` only when you intentionally want fast reset feedback. `SYNFIX_ACTION=icmp-host-unreachable` immediately rejects excess attempts without encouraging the same TCP-reset retry loop; it can be paired with a cautiously higher rate such as `54/minute` when filtered Android/Desktop routes need faster primary and media connections. The INPUT jump excludes `lo`, so WEB relay backend connections never share the `127.0.0.1` hashlimit bucket. Installers persist SYNFIX and optional TCPMSS iptables state with `netfilter-persistent` so it is restored after reboot.

Legacy `TCPMSS=88` ClientHello fragmentation is disabled by default for PQ-capable Caddy masking setups. Re-enable it only as an explicit fallback with `ENABLE_TCPMSS=true`. TCPMSS and nfqws rules use `! -o lo`; rerunning either installer removes the older loopback-inclusive spelling before applying the corrected rule.

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

Although the command requests the common release profile, the default
`dataplane_safety=true` policy promotes the proxy executable itself to `ReleaseSafe`;
the same policy applies to the source installer and Docker image.

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
# client_silence_close_sec = 0      # Unified bounded iOS wedge recovery; use 15 to enable

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

On startup, the proxy uses the lower of host RAM and every visible limit from the process's active cgroup v2/v1 hierarchy, including parent groups and non-standard mount points, and prints a **CAPACITY** banner. The estimate reserves fixed headroom, splits the remaining allowance between guaranteed connection baselines and a shared dynamically allocated buffer pool, and enforces that pool as a hard runtime limit. Because every normal runtime may receive mandatory CDN DC203 traffic, the baseline includes initial MiddleProxy buffers even when both optional DC1..5 routing preferences are disabled; the banner labels that case `direct DC1..5 + required DC203 middleproxy`. The displayed **RAM ceiling** is a baseline admission ceiling, not a promise that every admitted connection can simultaneously grow all MiddleProxy buffers and relay queues to their independent maxima. The banner reports the separately configured connection limit and the 90%/80% admission hysteresis. If `max_connections` exceeds the RAM ceiling, it auto-clamps unless `unsafe_override_limits = true`; if the ceiling cannot support the minimum 32 slots, startup fails instead of forcing an unsafe minimum.

User secrets and `tg://`/`t.me` links are redacted from the daemon banner by default so they do not enter journald or container logs. Use the one-shot `--print-links` mode in a private terminal to load the config, print the links, and exit before opening the listener. The existing `--show-secrets` flag remains available for an intentional foreground daemon run with secrets included in its startup banner.

Validate TOML syntax and cross-field semantics without opening a listener:

```bash
/opt/mtproto-proxy/mtproto-proxy --check-config /opt/mtproto-proxy/config.toml
```

The same validation runs automatically on every ordinary proxy and WEB-relay startup. It rejects unusable configurations such as an empty user set, invalid FakeTLS/WEB domains, a non-IPv4 `middle_proxy_nat_ip`, missing WEB masking backend, or colliding WEB listener ports.

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

For a source/systemd installation:

```bash
sudo /opt/mtproto-proxy/mtproto-proxy \
  /opt/mtproto-proxy/config.toml \
  --print-links
```

For a running Docker Compose installation:

```bash
docker exec -it mtproto-proxy \
  /usr/local/bin/mtproto-proxy \
  /etc/mtproto-proxy/config.toml \
  --print-links
```

This command does not start a second listener, so it can run while the service is active. It prints the access secrets only to the current terminal and exits. Keep the terminal and its scrollback private.

You can also build a link manually:

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

> **Note** &nbsp; If WEB mode is already enabled, `setup_tunnel.sh` also refreshes its Caddy listener and relay backend automatically (`10.200.200.1:8444` → `10.200.200.2:443`). Ordinary MTProto and WEB links remain active together.

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
force_media_middle_proxy = true                 # Prefer ME for negative DC1..5 media paths; DC203 always uses ME
ad_tag = "1234567890abcdef1234567890abcdef"    # Optional alias for [server].tag

[server]
port = 443
public_ip = "proxy.example.com"             # Same domain as tls_domain for self-domain masking links
# middle_proxy_nat_ip = "203.0.113.10"      # Optional IPv4 override for MiddleProxy NAT/AES derivation
backlog = 4096                             # TCP listen queue size
middleproxy_buffer_kb = 2048               # ME C2S/S2C buffers grow on demand up to this cap; runtime caps effective value at 3840 KiB
max_connections = 512                      # Safe default for small (1 vCPU / ~1 GB) VPS
idle_timeout_sec = 120
# idle_timeout_jitter_pct = 15             # Per-connection idle timeout jitter in percent; 0 disables
# client_silence_close_sec = 0             # Unified bounded iOS wedge recovery; use 15 to enable
handshake_timeout_sec = 15
# graceful_shutdown_timeout_sec = 15       # Drain active connections after SIGINT/SIGTERM; a second signal forces exit
# dc_connect_timeout_sec = 10              # Per-DC TCP connect ceiling; 0 still shares the global budget across candidates
tag = "1234567890abcdef1234567890abcdef"   # Optional: promotion tag from @MTProxybot
log_level = "info"                         # Runtime log level: debug, info, warn, err
rate_limit_per_subnet = 30                # Max new connections/sec per /24 subnet (0 = disabled)
# unsafe_override_limits = false           # Set true to disable auto-clamp of max_connections

[monitor]
# Optional: read only by the separate proxy-monitor service
# host = "127.0.0.1"                       # Bind address for dashboard. Use "0.0.0.0" to expose externally
# port = 61208                             # TCP port for the dashboard

[web]
# Optional Telegram Desktop 7.1+ WEB transport. setup_web.sh writes these
# values and extends the existing Caddy instance; ordinary MTProto remains on
# unless only=true is selected.
# enabled = true
# only = false                              # Mask direct MTProto and serve only the trusted WEB relay
# domain = "web.example.com"               # Must differ from censorship.tls_domain
# Ordinary requests receive the same empty 404 as the masking domain
# listen = "127.0.0.1"                     # Plain HTTP/WebSocket relay, local only
# port = 8081
# backend = "127.0.0.1:443"                # Use 10.200.200.2:443 in tunnel-netns mode
# mask_backend = "127.0.0.1:8444"          # Caddy listener with PROXY v2 support
# ws_path = "/api/v1/socket"
# trust_forwarded_for = true
# client_ip_header = "x-forwarded-for"
# check_origin = true
# max_sessions = 8
# max_streams = 32
# max_buffer_mb = 128
# relay_sources = []                       # Extra trusted relay IP literals; loopback is implicit

[censorship]
tls_domain = "proxy.example.com"
mask = true
mask_port = 8443
# mask_relay_max_secs = 0                  # Probe-cover lifetime; WEB carriers are exempt
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
alice = true   # direct where possible; CDN DC203 still requires MiddleProxy
# bob = true   # optional
```

<details>
<summary>Configuration reference</summary>

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[general]` | `use_middle_proxy` | `false` | Telemt-compatible ME mode for regular DC1..5. Optional ME routes can fall back only when the requested DC has a real direct endpoint; CDN DC203 is always MiddleProxy |
| `[general]` | `force_media_middle_proxy` | `true` | Prefer MiddleProxy for negative DC1..5 media paths even if regular DC traffic stays direct. It does not control CDN DC203, which has no raw direct endpoint |
| `[general]` | `ad_tag` | _(none)_ | Telemt-compatible alias for promotion tag; ignored if `[server].tag` is set |
| `[server]` | `port` | `443` | TCP port to listen on |
| `[server]` | `public_ip` | _(none)_ | IP/domain used in generated links. Set it explicitly when using `--print-links` or `--show-secrets`; external discovery is intentionally unavailable in the one-shot path and is not allowed to delay listener startup. For self-domain masking, use the same domain as `tls_domain`. Tunnel deploy scripts preserve an existing domain instead of replacing it with the tunnel exit IP |
| `[server]` | `middle_proxy_nat_ip` | _(auto-detect)_ | Optional IPv4 override used in MiddleProxy NAT/AES derivation. `public_ip` is client-facing and is not reused as DC egress; auto-detection trusts an AWG endpoint only inside the active tunnel network namespace, otherwise it probes the process's public egress IPv4 |
| `[server]` | `backlog` | `4096` | TCP listen queue size (for high-traffic loads) |
| `[server]` | `max_connections` | `512` | Configured concurrent connection cap (small-VPS tuned default, parser lower bound 32), distinct from the banner's baseline RAM ceiling. On Linux, startup first auto-clamps this to that effective-memory ceiling unless `unsafe_override_limits=true`; the proxy then clamps again if `RLIMIT_NOFILE` can support at least 32 slots, otherwise startup fails safely |
| `[server]` | `idle_timeout_sec` | `120` | Established relay idle timeout in seconds (parser lower bound 5). Pre-first-byte admission uses a separate fixed 10-second deadline |
| `[server]` | `idle_timeout_jitter_pct` | `15` | Per-connection random jitter applied once when the slot is admitted to `idle_timeout_sec` (`±N%`, clamped to `0..100`). The effective timeout is then reused for every deadline update, floored to at least 5 seconds and at least half the base timeout. Set `0` to disable |
| `[server]` | `client_silence_close_sec` | `0` | Unified proxy-side recovery for the field-captured iOS `bad_server_salt` silence pattern on generic DC relays. A request must first reach the upstream socket, subsequent server payload must begin within the [source-backed 12-second client window](https://github.com/TelegramMessenger/Telegram-iOS/blob/b16d9acdffa9b3f88db68e26b77a3713e87a92e3/submodules/MtProtoKit/Sources/MTTcpConnection.m#L980), and the response timer starts only after the client output queue drains. Because MTProto payload and client platform are not visible to the relay, this is a bounded timing heuristic applied to the same pattern from any client, not iOS identification or message matching. Any client progress cancels it; media/DC203, masking, half-closed, backpressured, and graceful-shutdown paths are excluded. Every recovery is bounded per real client IP + access user + DC to `T`, `2T`, `4T` (up to four parallel relays per wave); after three waves, ordinary idle timeout takes over for 30 minutes from the most recent actual breaker close. Normal matching traffic does not extend that cooldown. A mature healthy continuation upgrades only the diagnostic confidence (`proven`), never bypasses the group budget. `0` disables it; values below `10` or not below `idle_timeout_sec` are rejected; `15` is recommended |
| `[server]` | `handshake_timeout_sec` | `15` | Timeout for completing handshake after first byte (parser lower bound 5) |
| `[server]` | `graceful_shutdown_timeout_sec` | `15` | Drain deadline after the first SIGINT/SIGTERM (parser lower bound 1). New accepts stop immediately; a second signal or expiry forcibly closes remaining connections |
| `[server]` | `dc_connect_timeout_sec` | `10` | Per-endpoint TCP connect ceiling for Telegram DC and MiddleProxy candidates. Every attempt is also capped by its share of the remaining global handshake budget, including the final MiddleProxy candidate and reserved direct fallback. `0` disables only the configured ceiling; global budget sharing remains active |
| `[server]` | `middleproxy_buffer_kb` | `2048` | MiddleProxy per-direction buffer cap in KiB. Active ME connections start with 16 KiB C2S/S2C buffers and grow on demand up to `min(middleproxy_buffer_kb, 3840)` KiB; each event loop also keeps lazy shared scratch buffers. The effective cap leaves 256 KiB for MP/TLS framing inside the 4 MiB relay-queue limit. Default 2048 leaves headroom for 1 MiB media parts; values below 1024 may still cause `MiddleProxyBufferOverflow` on media-heavy traffic (Stories, video messages). Parser lower bound is 64 KiB |
| `[server]` | `tag` | _(none)_ | Optional 32 hex-char promotion tag from [@MTProxybot](https://t.me/MTProxybot) |
| `[server]` | `log_level` | `"info"` | Runtime log verbosity: `debug` (authenticated client IPs plus all DC routing, relay, and close details), `info` (default — connection stats, warnings), `warn`, `err`. Change without recompilation; takes effect on restart |
| `[server]` | `rate_limit_per_subnet` | `30` | Max new connections per second per /24 (IPv4) or /48 (IPv6) subnet. Blocks scanner/DPI-probe flood. Set `0` to disable |
| `[server]` | `unsafe_override_limits` | `false` | Disable auto-clamping of `max_connections` to the baseline RAM admission ceiling. The shared dynamic-buffer hard limit remains enforced. Use only when the container/service limit as well as host RAM are sufficient |
| `[monitor]` | `host` | `"127.0.0.1"` | Bind address for the optional monitoring dashboard HTTP server. This section is read by `proxy-monitor`, not by the proxy binary. Set to `"0.0.0.0"` to expose on all interfaces (warning: no built-in auth) |
| `[monitor]` | `port` | `61208` | TCP port for the optional monitoring dashboard HTTP server |
| `[web]` | `enabled` | `false` | Enable the separate Telegram Desktop WEB relay process and the trusted relay path in the data plane |
| `[web]` | `only` / `web_only` | `false` | When WEB is enabled, mask direct MTProto for every non-relay peer. Existing `tg://proxy` links stop working; relay trust comes only from the address returned by `accept()` |
| `[web]` | `domain` | _(none)_ | Public ASCII DNS hostname placed in `tg://webproxy` links. It must differ from `censorship.tls_domain`; changing it invalidates existing WEB capabilities/links |
| `[web]` | `listen` / `host` | `"127.0.0.1"` | Plain HTTP/WebSocket relay bind address behind Caddy. Keep it on loopback for the bundled deployment |
| `[web]` | `port` | `8081` | Local relay listener port |
| `[web]` | `backend` | `127.0.0.1:<server.port>` | MTProto data-plane endpoint opened for each logical WEB stream. Tunnel-netns installs use `10.200.200.2:443` |
| `[web]` | `mask_backend` | _(none)_ | Local Caddy TLS listener that accepts PROXY v2 for WEB-domain SNI, normally `127.0.0.1:8444` or `10.200.200.1:8444` from the tunnel namespace |
| `[web]` | `ws_path` | `"/api/v1/socket"` | Same-origin WebSocket endpoint embedded in the bridge page |
| `[web]` | `trust_forwarded_for` | `true` | Read the real browser address from the configured forwarded header; the right-most entry is used |
| `[web]` | `client_ip_header` | `"x-forwarded-for"` | Header Caddy uses to pass the real browser address to the relay |
| `[web]` | `check_origin` | `true` | Require the WebSocket `Origin` to equal `https://<web.domain>` |
| `[web]` | `max_sessions` | `8` | Concurrent WEB desktop sessions; the default is sized for the repository's 512-slot small-VPS profile |
| `[web]` | `max_streams` | `32` | Logical MTProto streams per WEB session; each consumes one data-plane connection |
| `[web]` | `max_buffer_mb` | `128` | Aggregate hard ceiling for queued WEB-relay data |
| `[web]` | `relay_sources` | `[]` | Extra IP literals trusted to send PROXY-prefixed direct-obfuscated WEB streams; loopback is implicit while WEB is enabled |
| `[censorship]` | `tls_domain` | `"google.com"` | FakeTLS SNI domain. With `mask_port=443`, unauthenticated clients are forwarded to this domain directly. For self-domain masking, set it to your own domain and point its DNS A record to the VPS. Since June 2026, the real masking endpoint should negotiate X25519MLKEM768 (`0x11ec`) in one round; classical-x25519-only domains can be a passive marker |
| `[censorship]` | `mask` | `true` | Forward unauthenticated connections to the configured masking target to defeat active probing |
| `[censorship]` | `mask_port` | `443` | Masking target port. `443` connects to `tls_domain:443`; non-443 values connect to a local address on that port (`127.0.0.1:<mask_port>`, or `10.200.200.1:<mask_port>` inside tunnel netns), so that port must be served by Caddy or another local backend. Use `8443` for self-domain Caddy so public `443` remains owned by `mtproto-proxy` |
| `[censorship]` | `mask_relay_max_secs` | `0` | Maximum lifetime for ordinary masking/probe connections to the configured backend. WEB-domain HTTPS/WebSocket carriers are exempt; `0` disables the cap for every masking relay |
| `[censorship]` | `desync` | `true` | Split fake `ServerHello` into `1 byte + short pause + rest` to desynchronize passive DPI |
| `[censorship]` | `desync_split_delay_ms` | `3` | Base delay between the first fake `ServerHello` byte and the remaining bytes |
| `[censorship]` | `desync_split_jitter_ms` | `2` | Random extra delay in milliseconds added to `desync_split_delay_ms` (`0..N` per connection) |
| `[censorship]` | `fake_cert_size` | `0` | Fake TLS encrypted-certificate AppData size in bytes. `0` keeps the built-in 2878-byte default; explicit values are clamped to `256..16384` |
| `[censorship]` | `drs` | `false` | Dynamic Record Sizing: ramp TLS records from 1369→16384 bytes after warmup (mimics Chrome/Firefox) |
| `[censorship]` | `fast_mode` | `false` | **Recommended** for direct-path traffic. Delegates S2C AES encryption to Telegram DC and reduces proxy CPU/RAM pressure |
| `[access.users]` | `<name>` | -- | 32 hex-char secret (16 bytes) per user |
| `[access.direct_users]` | `<name> = true` | _(none)_ | Optional per-user MiddleProxy bypass. `<name>` must match a user from `[access.users]`; the bypass covers regular and media paths with real direct endpoints, but CDN DC203 always uses its required MiddleProxy. Values `false`/`0`/`no` remove a previous duplicate entry. Alias section: `[access.admins]` |

</details>

`client_silence_fast_close_sec` and `client_silence_fast_after_idle_sec` were removed in favor of the single bounded `client_silence_close_sec` policy. Remove the legacy keys before upgrading; strict config parsing rejects unknown keys.

> **Operational note** &nbsp; High-churn mobile networks can produce many normal disconnects (`ConnectionResetByPeer`/`EndOfStream`). In release builds these are logged at debug level to keep production logs signal-focused.

> **Operational note** &nbsp; `deploy/mtproto-proxy.service` ships with `LimitNOFILE=131582` to allow higher custom caps when needed. Default `max_connections=512` is tuned for small VPS profiles; increase it only after capacity testing.

> **Shutdown note** &nbsp; The bundled systemd and Docker Compose definitions allow 25 seconds for the proxy's default 15-second graceful drain before the supervisor may force termination.

> **Operational note** &nbsp; The FakeTLS path uses one strict ClientHello parser for validation, SNI, cipher selection, and PQ key-share detection. It rejects inconsistent nested lengths and non-32-byte Session IDs; current Telegram MTProto-over-TLS clients use a 32-byte Session ID, which the proxy echoes in its TLS-like ServerHello template.

> **Operational note** &nbsp; The parser rejects unknown sections, unknown proxy keys, keys outside a section, and malformed non-comment lines. `[monitor].host` and `[monitor].port` remain accepted for the separate dashboard service. Socket ports must be in `1..65535`, and `backlog` must fit Linux's signed listen backlog range; invalid numeric values keep their safe defaults with a warning. Diagnostics identify the key or line number and reason but never echo raw config values or lines, which may contain credentials. Config load failures exit non-zero.

> **Operational note** &nbsp; If `accept()` hits `EMFILE`/`ENFILE`, the listener temporarily disables `EPOLLIN`, waits 500ms, and retries. In periodic `conn stats`, the first `paused=` flag reflects this fd-quota backoff.

> **Operational note** &nbsp; On startup, `max_connections` is automatically clamped to an effective-memory estimate derived from host RAM and the lowest readable limit in the process's cgroup hierarchy. After kernel/process headroom, half of the remaining allowance backs guaranteed connection baselines and half is reserved for dynamic relay/MiddleProxy buffers. Set `unsafe_override_limits = true` to disable only the connection-count clamp; the shared runtime buffer limit remains enforced. Admission control also pauses `accept()` at 90% capacity, resumes at 80%, and limits concurrent unauthenticated sockets per source subnet.

> **Operational note** &nbsp; MiddleProxy C2S/S2C buffers start at 16 KiB per direction and grow lazily. Relay pages, retained free-list pages, MiddleProxy stream buffers, shared scratch, and temporary replacement buffers during growth share one hard event-loop budget. A denied allocation is reported as `memory_pressure+=...`; an optional shrink keeps its existing buffer, while required growth closes the requesting path or uses direct fallback where available. This avoids reserving every connection's independent worst case simultaneously. Configured `middleproxy_buffer_kb` values above 3840 are accepted but the per-direction runtime cap remains 3840 KiB, leaving 256 KiB of framing headroom inside the 4 MiB relay queue.

> **Operational note** &nbsp; The proxy limits new connections to 30/sec per /24 subnet by default (`rate_limit_per_subnet`). Native IPv6 keys retain all 48 prefix bits, while IPv4-mapped IPv6 shares the native IPv4 `/24` key. This blocks ТСПУ scanners and DPI replay probes without affecting legitimate Telegram clients.

> **Operational note** &nbsp; Self-domain masking expects DNS `A proxy.example.com -> <VPS_IP>`, Cloudflare DNS-only mode if used, public TCP `80` for Let's Encrypt, public TCP `443` for `mtproto-proxy`, and local Caddy TLS on `127.0.0.1:8443` returning `404` for non-proxy requests. Docker Compose installs serve that local Caddy endpoint from the `mtproto-mask-caddy` container; source installs serve it from `mtproto-mask-caddy.service`. `setup_masking.sh` serves ACME HTTP-01 on `:80` and configures Caddy with `x25519mlkem768 x25519` curves. The `ee` link secret changes when `tls_domain` changes, so regenerate client links after changing the domain.

> **Tip** &nbsp; Generate a random secret: `openssl rand -hex 16`

> **Note** &nbsp; The documented sections and aliases are compatible with the Rust-based `telemt` proxy; unsupported keys are rejected instead of silently falling back to defaults.

> **Note** &nbsp; For compatibility, `fast_mode` is accepted in `[general]`, `[server]`, or `[censorship]`; all three set the same runtime flag.

> **Note** &nbsp; The parser supports inline `#` / `;` comments after values and treats duplicate owned string/user/direct-user entries as last-write-wins without leaking previous allocations.

> **Note** &nbsp; MiddleProxy settings (regular DC1..5 endpoints + media-path endpoints + shared secret), NAT discovery, and masking DNS resolution run after the listener is ready. Metadata and all masking candidates refresh hourly, with reactive early refresh after stalled MiddleProxy handshakes and bundled MiddleProxy defaults as fallback. Shutdown cancels active resolver, HTTPS, and curl tasks before joining the updater; an unsafe resolver configuration leaves the previous masking candidates intact and is retried on the next refresh.

## &nbsp; Troubleshooting ("Updating...")

Deployment firewall rules are restored by `netfilter-persistent`. The installers
and SYNFIX/NFQUEUE helpers preserve the previous saved rules if a new snapshot
fails, and report persistence errors instead of silently claiming success.
An error does not roll back live rules: resolve it and rerun setup before rebooting.
Standalone SYNFIX setup requires the `iptables-persistent` and
`netfilter-persistent` packages. TCPMSS remains opt-in; loopback traffic remains
excluded from SYNFIX, NFQUEUE, and TCPMSS.

If your Telegram app is stuck on "Updating...", your provider or network is dropping the connection.

### 0. Runtime expectations (important)

This proxy uses a Linux `epoll` event loop (single-thread relay path). Timeouts use a monotonic `timerfd` plus an indexed min-heap with one current deadline per active slot; there is no fixed polling cadence or full-slot timeout scan. If you see stale guidance mentioning `poll()`/`SO_RCVTIMEO`/fixed max-lifetime, treat it as outdated.

### 1. Check runtime health and fd pressure first

Before chasing client/network hypotheses, inspect the new low-noise runtime signals:

```bash
ssh root@<VPS_IP> 'journalctl -u mtproto-proxy --since "30 min ago" --no-pager | grep -E "conn stats|drops:|auto-clamping max_connections|baseline RAM ceiling|RAM admission clamp|max_connections clamped|fd quota reached|failed to resume accepts|connection saturation|saturation eased"'
ssh root@<VPS_IP> 'cat /proc/$(pgrep -f mtproto-proxy)/limits | grep "open files"'
```

Interpretation:

- `RAM ceiling` in the startup banner is the baseline admission ceiling derived from effective memory; `Configured` is the requested runtime cap before any later `RLIMIT_NOFILE` clamp. `auto-clamping max_connections ...` means startup reduced that configured cap to the RAM ceiling. `max_connections clamped ... due to RLIMIT_NOFILE` means runtime reduced it again to fit the process fd limit.
- `fd quota reached ... pausing accepts for 500ms` means the listener hit `EMFILE`/`ENFILE` and intentionally backed off instead of busy-looping.
- `conn stats ... paused=<fd_pause>/<saturation_pause> managed_buf=<used>/<limit>KiB peak=<peak>KiB` exposes both pause reasons and current/peak use of the shared dynamic-buffer budget. `managed_buf` is not whole-process RSS and excludes kernel socket memory and non-managed process allocations.
- `drops: ... rate+=...` means the per-subnet rate limiter rejected excess new connections.
- `drops: ... hs_budget+=...` means either the global handshake-inflight budget or the per-subnet unauthenticated-socket allowance rejected a new handshake.
- `drops: ... mp_fallback+=...` means the MiddleProxy path degraded and the proxy recovered by reconnecting directly to the same DC.
- `drops: ... memory_pressure+=...` means a relay page or MiddleProxy buffer allocation reached the shared hard limit; sustained increments call for a larger effective memory limit or a lower connection/traffic target.
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

On startup the proxy refreshes DC203 metadata from Telegram automatically, regardless of the optional DC1..5 MiddleProxy preferences. If your server cannot reach `core.telegram.org`, it uses bundled defaults. DC203 has no real direct endpoint, so its route never falls back to a raw direct stream; if no MiddleProxy candidate is available, the connection fails closed and requests a debounced metadata refresh.

## &nbsp; License

[MIT](LICENSE) &copy; 2026 Aleksandr Kalashnikov
