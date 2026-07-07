#!/usr/bin/env bash
#
# setup_masking.sh - Install self-domain Caddy 404 masking for mtproto-proxy.
#
# Public :443 stays owned by mtproto-proxy. Regular HTTPS browsers and active
# probers that do not present a valid MTProto secret are relayed by the proxy to
# this local Caddy backend on 127.0.0.1:8443. Use your own domain here: its DNS A
# record should point to the same VPS. The masking backend returns 404 for all
# non-ACME requests; valid MTProto clients never reach Caddy.
#
# Usage:
#   sudo env MASK_DOMAIN=proxy.example.com bash deploy/setup_masking.sh
#   sudo bash deploy/setup_masking.sh proxy.example.com
#
# Optional environment:
#   MASK_ACME_ROOT=/var/www/certbot            # ACME HTTP-01 webroot
#   MASK_SITE_ROOT=/var/www/certbot            # deprecated alias for MASK_ACME_ROOT
#   MASK_PORT=8443                            # local HTTPS backend port
#   LE_EMAIL=admin@example.com                # Let's Encrypt account email
#   MASK_ALLOW_SELF_SIGNED=1                  # dev/test fallback only
#   MASK_SET_PUBLIC_IP=0                      # do not set [server].public_ip
#   CHECK_PQ_DOMAIN=false                     # skip X25519MLKEM768 masking probe
#
# What it does:
#   1. Installs Caddy and certbot if needed. Docker installs run Caddy as a
#      Compose service; source installs run it as a host systemd service.
#   2. Creates/keeps an ACME webroot for the masking domain.
#   3. Serves HTTP-01 ACME on public :80, because public :443 is the proxy.
#   4. Obtains or reuses a Let's Encrypt certificate for the domain.
#   5. Configures Caddy on 127.0.0.1:8443 with X25519MLKEM768 first.
#   6. Updates config.toml with public_ip, tls_domain, mask=true, mask_port.
#   7. Installs the masking health monitor timer.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mtproto-proxy.service"
MASK_PORT="${MASK_PORT:-}"
MASK_SET_PUBLIC_IP="${MASK_SET_PUBLIC_IP:-1}"
MASK_ALLOW_SELF_SIGNED="${MASK_ALLOW_SELF_SIGNED:-0}"
CHECK_PQ_DOMAIN="${CHECK_PQ_DOMAIN:-true}"
ACME_ROOT="${MASK_ACME_ROOT:-${MASK_SITE_ROOT:-/var/www/certbot}}"
CADDY_SERVICE="mtproto-mask-caddy.service"
COMPOSE_FILE="${COMPOSE_FILE:-${INSTALL_DIR}/compose.yml}"
ENV_FILE="${ENV_FILE:-${INSTALL_DIR}/.env}"
case "${MTPROTO_DOCKER_INSTALL:-0}" in
    1|true|yes|on) CADDY_RUNTIME="docker" ;;
    *) CADDY_RUNTIME="host" ;;
esac
if [[ "$CADDY_RUNTIME" == "docker" ]]; then
    CADDYFILE="${MASK_CADDYFILE:-${INSTALL_DIR}/Caddyfile.mask}"
else
    CADDYFILE="${MASK_CADDYFILE:-/etc/caddy/mtproto-mask.Caddyfile}"
fi
TUNNEL_HOST_IP=""

read_config_value() {
    local section="$1"
    local key="$2"
    local default_value="${3:-}"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        printf '%s\n' "$default_value"
        return
    fi

    awk -v want_section="$section" -v want_key="$key" -v fallback="$default_value" '
        BEGIN { in_section = 0; value = "" }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            header = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", header)
            in_section = (header == want_section)
            next
        }
        in_section {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
                split(line, parts, "=")
                value = parts[2]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                gsub(/^"|"$/, "", value)
            }
        }
        END { print value == "" ? fallback : value }
    ' "$CONFIG_FILE"
}

TLS_DOMAIN="${1:-${MASK_DOMAIN:-}}"
if [[ -z "$TLS_DOMAIN" ]]; then
    TLS_DOMAIN="$(read_config_value "censorship" "tls_domain" "")"
fi
[[ -n "$TLS_DOMAIN" ]] || {
    echo "Set your masking domain: sudo env MASK_DOMAIN=proxy.example.com bash setup_masking.sh" >&2
    exit 1
}

if [[ ! "$TLS_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    echo "Invalid domain: ${TLS_DOMAIN}" >&2
    exit 1
fi

if [[ -z "$MASK_PORT" ]]; then
    MASK_PORT="$(read_config_value "censorship" "mask_port" "8443")"
fi

if [[ ! "$MASK_PORT" =~ ^[0-9]+$ ]] || (( MASK_PORT < 1 || MASK_PORT > 65535 )); then
    echo "Invalid MASK_PORT: ${MASK_PORT}" >&2
    exit 1
fi

if [[ "$CADDY_RUNTIME" == "docker" ]]; then
    CERT_DIR="${MASK_CERT_DIR:-${INSTALL_DIR}/caddy/ssl/mtproto-mask/${TLS_DOMAIN}}"
else
    CERT_DIR="${MASK_CERT_DIR:-/etc/caddy/ssl/mtproto-mask/${TLS_DOMAIN}}"
fi

if [[ "$ACME_ROOT" != /* || "$ACME_ROOT" =~ [[:space:]] ]]; then
    echo "MASK_ACME_ROOT/MASK_SITE_ROOT must be an absolute path without spaces: ${ACME_ROOT}" >&2
    exit 1
fi

is_tunnel_service_unit() {
    local unit_path="$1"
    [[ -f "$unit_path" ]] || return 1
    grep -Eq 'setup_netns\.sh|ip[[:space:]]+netns[[:space:]]+exec|AmneziaWG[[:space:]]+Tunnel' "$unit_path"
}

if ip -4 addr show 2>/dev/null | grep -q '10\.200\.200\.1/' || is_tunnel_service_unit "$SERVICE_FILE"; then
    TUNNEL_HOST_IP="10.200.200.1"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()  { echo -e "${CYAN}>${RESET} $*"; }
ok()    { echo -e "${GREEN}OK${RESET} $*"; }
warn()  { echo -e "${RED}WARN${RESET} $*"; }
fail()  { echo -e "${RED}FAIL${RESET} $*" >&2; exit 1; }

is_true() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

check_pq_fronting_backend() {
    local host="$1"
    local port="$2"
    local servername="$3"
    local out legacy_out

    is_true "$CHECK_PQ_DOMAIN" || return 0
    command -v openssl >/dev/null 2>&1 || {
        warn "openssl not found; skipping X25519MLKEM768 masking-domain check"
        return 0
    }

    info "Checking masking backend X25519MLKEM768 support..."
    out="$(echo | timeout 10 openssl s_client \
        -connect "${host}:${port}" \
        -servername "${servername}" \
        -groups X25519MLKEM768:X25519 \
        -tls1_3 2>&1 || true)"

    if grep -q "Server Temp Key" <<<"$out"; then
        if grep -Eqi "MLKEM|ML-KEM" <<<"$out"; then
            ok "Masking backend negotiates X25519MLKEM768 for ${servername}"
        else
            warn "Masking backend negotiates a classical TLS group, not X25519MLKEM768"
            warn "Since the June-2026 TSPU rollout this can mark iOS clients and everyone sharing their NAT egress IP"
        fi
        return 0
    fi

    if grep -q "CONNECTED" <<<"$out"; then
        warn "Masking backend connected but did not expose a single-round X25519MLKEM768/X25519 Server Temp Key"
        warn "Avoid HRR / non-x25519 masking targets; FakeTLS emits a single ServerHello"
        return 0
    fi

    legacy_out="$(echo | timeout 10 openssl s_client \
        -connect "${host}:${port}" \
        -servername "${servername}" \
        -groups X25519 \
        -tls1_3 2>&1 || true)"

    if grep -q "Server Temp Key" <<<"$legacy_out"; then
        warn "Couldn't test X25519MLKEM768, but x25519 works. This host may have OpenSSL older than 3.5"
        warn "Verify ${servername} with @Sni_checker_bot before sharing links"
    else
        warn "Could not verify TLS group support for masking backend ${host}:${port}"
    fi
}

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_masking.sh"

set_config_value() {
    local section="$1"
    local key="$2"
    local value="$3"
    local tmp

    [[ -f "$CONFIG_FILE" ]] || return 0
    tmp="$(mktemp)"
    if awk -v want_section="$section" -v want_key="$key" -v new_value="$value" '
        BEGIN { in_section = 0; saw_section = 0; wrote = 0; pending_blank = "" }
        function flush_pending_blank() {
            if (pending_blank != "") {
                printf "%s", pending_blank
                pending_blank = ""
            }
        }
        function emit_value() {
            if (!wrote) {
                print want_key " = " new_value
                wrote = 1
            }
        }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            if (in_section) {
                emit_value()
                flush_pending_blank()
            }
            header = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", header)
            in_section = (header == want_section)
            if (in_section) {
                saw_section = 1
                wrote = 0
            }
            print
            next
        }
        {
            if (in_section && $0 ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
                flush_pending_blank()
                emit_value()
                next
            }
            if (in_section && !wrote && $0 ~ /^[[:space:]]*$/) {
                pending_blank = pending_blank $0 "\n"
                next
            }
            if (in_section) {
                flush_pending_blank()
            }
            print
        }
        END {
            if (in_section) {
                emit_value()
                flush_pending_blank()
            }
            if (!saw_section) {
                print ""
                print "[" want_section "]"
                print want_key " = " new_value
            }
        }
    ' "$CONFIG_FILE" > "$tmp"; then
        mv "$tmp" "$CONFIG_FILE"
        chown mtproto:mtproto "$CONFIG_FILE" 2>/dev/null || true
    else
        rm -f "$tmp"
        fail "Failed to update ${CONFIG_FILE}"
    fi
}

install_caddy() {
    local caddy_needs_install=true
    local caddy_version caddy_minor

    if [[ "$CADDY_RUNTIME" == "docker" ]]; then
        info "Preparing Docker Caddy masking backend..."
        apt-get update -qq < /dev/null || true
        apt-get install -y ca-certificates curl certbot openssl < /dev/null >/dev/null 2>&1 || true
        command -v docker >/dev/null 2>&1 || fail "docker command not found"
        docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 plugin is not installed"
        command -v certbot >/dev/null 2>&1 || fail "certbot command not found after installation"
        [[ -f "$COMPOSE_FILE" ]] || fail "Compose file not found: ${COMPOSE_FILE}"
        ok "Docker Caddy backend is ready"
        return
    fi

    info "Installing Caddy and certbot..."
    apt-get update -qq < /dev/null || true
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https ca-certificates curl gnupg certbot openssl < /dev/null >/dev/null 2>&1 || true

    if command -v caddy >/dev/null 2>&1; then
        caddy_version="$(caddy version 2>/dev/null | awk '{print $1}' | head -1)"
        if [[ "$caddy_version" =~ ^v?2\.([0-9]+)\. ]]; then
            caddy_minor="${BASH_REMATCH[1]}"
            if (( caddy_minor >= 10 )); then
                caddy_needs_install=false
            fi
        fi
    fi

    if $caddy_needs_install; then
        mkdir -p /usr/share/keyrings /etc/apt/sources.list.d
        if curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
            | gpg --dearmor > /usr/share/keyrings/caddy-stable-archive-keyring.gpg; then
            curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
                -o /etc/apt/sources.list.d/caddy-stable.list || true
            apt-get update -qq < /dev/null || true
        else
            warn "Could not install Caddy apt repository key; trying distro package"
        fi
        apt-get install -y caddy < /dev/null >/dev/null 2>&1 || true
    fi

    command -v caddy >/dev/null 2>&1 || fail "caddy command not found after installation"
    command -v certbot >/dev/null 2>&1 || fail "certbot command not found after installation"
    caddy_version="$(caddy version 2>/dev/null | awk '{print $1}' | head -1)"
    if [[ "$caddy_version" =~ ^v?2\.([0-9]+)\. ]]; then
        caddy_minor="${BASH_REMATCH[1]}"
        if (( caddy_minor < 10 )); then
            fail "Caddy 2.10+ is required for x25519mlkem768, found ${caddy_version}"
        fi
    fi
    ok "Caddy is ready: $(caddy version 2>/dev/null | head -1)"
}

remove_legacy_caddy_container() {
    if command -v docker >/dev/null 2>&1; then
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'mtproto-mask-caddy'; then
            if [[ "$CADDY_RUNTIME" == "docker" ]]; then
                local existing_id managed_id
                existing_id="$(docker ps -aq --filter 'name=^/mtproto-mask-caddy$' | head -1)"
                managed_id="$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps -q mtproto-mask-caddy 2>/dev/null || true)"
                if [[ -n "$managed_id" && "$existing_id" == "$managed_id" ]]; then
                    return
                fi
            fi
            docker rm -f mtproto-mask-caddy >/dev/null 2>&1 || true
            ok "Removed legacy mtproto-mask-caddy container"
        fi
    fi
}

disable_legacy_host_caddy_service() {
    [[ "$CADDY_RUNTIME" == "docker" ]] || return 0
    command -v systemctl >/dev/null 2>&1 || return 0

    systemctl disable --now "$CADDY_SERVICE" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${CADDY_SERVICE}"
    rm -f /etc/systemd/system/mtproto-proxy.service.d/10-mask-caddy.conf
    systemctl daemon-reload >/dev/null 2>&1 || true
}

write_caddy_config() {
    local cert_ready="$1"
    local bind_line="    bind 127.0.0.1"

    if [[ -n "$TUNNEL_HOST_IP" && "$cert_ready" == "1" ]]; then
        bind_line="    bind 127.0.0.1 ${TUNNEL_HOST_IP}"
    fi

    mkdir -p "$(dirname "$CADDYFILE")"
    cat > "$CADDYFILE" << CADDYEOF
# mtproto-proxy self-domain 404 masking backend.
# Public :443 is owned by mtproto-proxy. Caddy is only the 404 masking backend.

{
    auto_https off
}

http://:80 {
    root * ${ACME_ROOT}
    handle /.well-known/acme-challenge/* {
        file_server
    }
    respond 404
}
CADDYEOF

    if [[ "$cert_ready" == "1" ]]; then
        cat >> "$CADDYFILE" << CADDYEOF

https://${TLS_DOMAIN}:${MASK_PORT} {
${bind_line}
    tls ${CERT_DIR}/cert.pem ${CERT_DIR}/key.pem {
        curves x25519mlkem768 x25519
    }
    respond 404
}
CADDYEOF
    fi

    chown root:root "$CADDYFILE"
    chmod 0644 "$CADDYFILE"
}

write_caddy_service() {
    if [[ "$CADDY_RUNTIME" == "docker" ]]; then
        return
    fi

    mkdir -p /var/lib/caddy /var/log/caddy /etc/caddy
    chown -R caddy:caddy /var/lib/caddy /var/log/caddy 2>/dev/null || true

    cat > "/etc/systemd/system/${CADDY_SERVICE}" << EOF
[Unit]
Description=MTProto Caddy masking backend
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config ${CADDYFILE} --adapter caddyfile
ExecReload=/usr/bin/caddy reload --config ${CADDYFILE} --adapter caddyfile --force
Restart=on-failure
RestartSec=2s
TimeoutStopSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/var/lib/caddy /var/log/caddy ${CERT_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl disable --now caddy >/dev/null 2>&1 || true
    systemctl enable "$CADDY_SERVICE" >/dev/null 2>&1 || true
}

reload_or_restart_caddy() {
    if [[ "$CADDY_RUNTIME" == "docker" ]]; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy >/dev/null
        sleep 1
        if docker inspect -f '{{.State.Running}}' mtproto-mask-caddy 2>/dev/null | grep -qx true; then
            return 0
        fi
        docker logs --tail=40 mtproto-mask-caddy 2>/dev/null || true
        return 1
    fi

    caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
    if systemctl is-active --quiet "$CADDY_SERVICE"; then
        systemctl reload "$CADDY_SERVICE" >/dev/null 2>&1 || systemctl restart "$CADDY_SERVICE"
    else
        systemctl restart "$CADDY_SERVICE"
    fi
}

install_certificate_files() {
    local src_cert="$1"
    local src_key="$2"

    mkdir -p "$CERT_DIR"
    install -m 0644 "$src_cert" "${CERT_DIR}/cert.pem"
    install -m 0600 "$src_key" "${CERT_DIR}/key.pem"
    if [[ "$CADDY_RUNTIME" == "host" ]]; then
        chown -R caddy:caddy "$CERT_DIR" 2>/dev/null || true
    fi
}

write_renewal_hook() {
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    if [[ "$CADDY_RUNTIME" == "docker" ]]; then
        cat > /etc/letsencrypt/renewal-hooks/deploy/mtproto-mask-caddy-reload.sh << HOOKEOF
#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${TLS_DOMAIN}"
CERT_DIR="${CERT_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
ENV_FILE="${ENV_FILE}"
LE_CERT="/etc/letsencrypt/live/\${DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/\${DOMAIN}/privkey.pem"

if [[ -f "\$LE_CERT" && -f "\$LE_KEY" ]]; then
    install -m 0644 "\$LE_CERT" "\${CERT_DIR}/cert.pem"
    install -m 0600 "\$LE_KEY" "\${CERT_DIR}/key.pem"
    docker compose --env-file "\$ENV_FILE" -f "\$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy >/dev/null 2>&1 || true
fi
HOOKEOF
    else
        cat > /etc/letsencrypt/renewal-hooks/deploy/mtproto-mask-caddy-reload.sh << HOOKEOF
#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${TLS_DOMAIN}"
CERT_DIR="${CERT_DIR}"
CADDY_SERVICE="${CADDY_SERVICE}"
LE_CERT="/etc/letsencrypt/live/\${DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/\${DOMAIN}/privkey.pem"

if [[ -f "\$LE_CERT" && -f "\$LE_KEY" ]]; then
    install -m 0644 "\$LE_CERT" "\${CERT_DIR}/cert.pem"
    install -m 0600 "\$LE_KEY" "\${CERT_DIR}/key.pem"
    chown -R caddy:caddy "\$CERT_DIR" 2>/dev/null || true
    systemctl reload "\$CADDY_SERVICE" >/dev/null 2>&1 || systemctl restart "\$CADDY_SERVICE" >/dev/null 2>&1 || true
fi
HOOKEOF
    fi
    chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mtproto-mask-caddy-reload.sh
}

install_caddy
mkdir -p "$ACME_ROOT/.well-known/acme-challenge" "$CERT_DIR"
if [[ "$CADDY_RUNTIME" == "host" ]]; then
    chown -R caddy:caddy "$ACME_ROOT" "$CERT_DIR" 2>/dev/null || true
fi
ok "Prepared masking/ACME roots"

remove_legacy_caddy_container
disable_legacy_host_caddy_service

info "Preparing Caddy HTTP-01 ACME challenge on :80 for ${TLS_DOMAIN}..."
write_caddy_config 0
write_caddy_service
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ok "Opened TCP/80 in ufw for Let's Encrypt HTTP-01"
fi
reload_or_restart_caddy || fail "Caddy HTTP config start failed. Check port 80 conflicts: ss -ltnp 'sport = :80'"

LE_CERT="/etc/letsencrypt/live/${TLS_DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/${TLS_DOMAIN}/privkey.pem"
CERT_OK=false

if [[ -f "$LE_CERT" && -f "$LE_KEY" ]]; then
    ok "Reusing existing Let's Encrypt certificate for ${TLS_DOMAIN}"
    CERT_OK=true
else
    info "Requesting Let's Encrypt certificate for ${TLS_DOMAIN} via HTTP-01..."
    CERTBOT_ARGS=(certonly --webroot -w "$ACME_ROOT" -d "$TLS_DOMAIN" --non-interactive --agree-tos --keep-until-expiring)
    if [[ -n "${LE_EMAIL:-}" ]]; then
        CERTBOT_ARGS+=(-m "$LE_EMAIL")
    else
        CERTBOT_ARGS+=(--register-unsafely-without-email)
    fi

    if certbot "${CERTBOT_ARGS[@]}"; then
        CERT_OK=true
        ok "Let's Encrypt certificate obtained for ${TLS_DOMAIN}"
    else
        warn "Let's Encrypt failed for ${TLS_DOMAIN}. Check DNS A record and port 80 reachability."
    fi
fi

if $CERT_OK; then
    install_certificate_files "$LE_CERT" "$LE_KEY"
    write_renewal_hook
elif [[ "$MASK_ALLOW_SELF_SIGNED" == "1" ]]; then
    warn "Using self-signed certificate because MASK_ALLOW_SELF_SIGNED=1"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -days 3650 -nodes \
        -subj "/CN=${TLS_DOMAIN}" \
        2>/dev/null
    if [[ "$CADDY_RUNTIME" == "host" ]]; then
        chown -R caddy:caddy "$CERT_DIR" 2>/dev/null || true
    fi
    chmod 0600 "${CERT_DIR}/key.pem"
else
    fail "No valid certificate for ${TLS_DOMAIN}. Point DNS to this VPS and open TCP/80, or use DNS-01/copy certs manually."
fi

info "Configuring local HTTPS masking backend on 127.0.0.1:${MASK_PORT}..."
write_caddy_config 1
reload_or_restart_caddy || fail "Caddy full config start failed"
ok "Caddy configured for ${TLS_DOMAIN}"
if [[ -n "$TUNNEL_HOST_IP" ]]; then
    ok "Caddy also listens on ${TUNNEL_HOST_IP}:${MASK_PORT} for tunnel netns"
fi

if curl -sk --max-time 5 --resolve "${TLS_DOMAIN}:${MASK_PORT}:127.0.0.1" "https://${TLS_DOMAIN}:${MASK_PORT}/" >/dev/null 2>&1; then
    ok "Masking backend responds with SNI ${TLS_DOMAIN} on 127.0.0.1:${MASK_PORT}"
    check_pq_fronting_backend "127.0.0.1" "$MASK_PORT" "$TLS_DOMAIN"
else
    warn "Masking backend probe failed. Check: curl -vk --resolve ${TLS_DOMAIN}:${MASK_PORT}:127.0.0.1 https://${TLS_DOMAIN}:${MASK_PORT}/"
fi

if [[ -f "$CONFIG_FILE" ]]; then
    set_config_value "censorship" "tls_domain" "\"${TLS_DOMAIN}\""
    set_config_value "censorship" "mask" "true"
    set_config_value "censorship" "mask_port" "${MASK_PORT}"
    if [[ "$MASK_SET_PUBLIC_IP" == "1" ]]; then
        set_config_value "server" "public_ip" "\"${TLS_DOMAIN}\""
    fi
    ok "Updated ${CONFIG_FILE} for self-domain 404 masking"
    info "Restart the proxy to apply: systemctl restart mtproto-proxy"
else
    warn "Config file not found at ${CONFIG_FILE}"
    info "Set [server].public_ip, [censorship].tls_domain, mask=true, and mask_port=${MASK_PORT} manually"
fi

MASK_MONITOR_SCRIPT="${INSTALL_DIR}/setup_mask_monitor.sh"
if [[ ! -x "$MASK_MONITOR_SCRIPT" ]]; then
    MASK_MONITOR_SCRIPT="$(dirname "$0")/setup_mask_monitor.sh"
fi

if [[ -x "$MASK_MONITOR_SCRIPT" ]]; then
    info "Installing masking health monitor..."
    bash "$MASK_MONITOR_SCRIPT" --quiet || warn "Masking monitor install failed"
else
    warn "setup_mask_monitor.sh not found; masking self-healing monitor not installed"
fi

echo ""
echo -e "${BOLD}${CYAN}Self-domain 404 masking configured${RESET}"
echo ""
echo -e "  ${DIM}Domain:${RESET}      ${TLS_DOMAIN}"
echo -e "  ${DIM}Public :443:${RESET} mtproto-proxy"
if [[ "$CADDY_RUNTIME" == "docker" ]]; then
echo -e "  ${DIM}Caddy TLS:${RESET}   Docker mtproto-mask-caddy on 127.0.0.1:${MASK_PORT}"
else
echo -e "  ${DIM}Caddy TLS:${RESET}   127.0.0.1:${MASK_PORT}"
fi
if [[ -n "$TUNNEL_HOST_IP" ]]; then
echo -e "  ${DIM}Tunnel TLS:${RESET}  ${TUNNEL_HOST_IP}:${MASK_PORT}"
fi
echo -e "  ${DIM}ACME root:${RESET}   ${ACME_ROOT}"
echo -e "  ${DIM}Cert:${RESET}        ${CERT_DIR}/cert.pem"
echo -e "  ${DIM}ACME HTTP:${RESET}   ${TLS_DOMAIN}:80"
echo ""
echo -e "Browsers and active probes for ${TLS_DOMAIN}:443 are relayed to Caddy and receive 404."
echo -e "Valid MTProto clients with the right secret stay on the proxy path."
