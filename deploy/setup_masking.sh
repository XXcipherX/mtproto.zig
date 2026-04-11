#!/usr/bin/env bash
#
# setup_masking.sh - Install self-domain Nginx 404 masking for mtproto-proxy.
#
# Public :443 stays owned by mtproto-proxy. Regular HTTPS browsers and active
# probers that do not present a valid MTProto secret are relayed by the proxy to
# this local Nginx backend on 127.0.0.1:8443. Use your own domain here: its DNS A
# record should point to the same VPS. The masking backend returns 404 for all
# non-ACME requests; valid MTProto clients never reach Nginx.
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
#
# What it does:
#   1. Installs Nginx and certbot if needed.
#   2. Creates/keeps an ACME webroot for the masking domain.
#   3. Serves HTTP-01 ACME on public :80, because public :443 is the proxy.
#   4. Obtains or reuses a Let's Encrypt certificate for the domain.
#   5. Configures Nginx on 127.0.0.1:8443 (and 10.200.200.1 in tunnel mode).
#   6. Updates config.toml with public_ip, tls_domain, mask=true, mask_port.
#   7. Installs the masking health monitor timer.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mtproto-proxy.service"
NGINX_PORT="${MASK_PORT:-8443}"
MASK_SET_PUBLIC_IP="${MASK_SET_PUBLIC_IP:-1}"
MASK_ALLOW_SELF_SIGNED="${MASK_ALLOW_SELF_SIGNED:-0}"
ACME_ROOT="${MASK_ACME_ROOT:-${MASK_SITE_ROOT:-/var/www/certbot}}"
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

if [[ ! "$NGINX_PORT" =~ ^[0-9]+$ ]] || (( NGINX_PORT < 1 || NGINX_PORT > 65535 )); then
    echo "Invalid MASK_PORT: ${NGINX_PORT}" >&2
    exit 1
fi

CERT_DIR="${MASK_CERT_DIR:-/etc/nginx/ssl/mtproto-mask/${TLS_DOMAIN}}"
MASKING_SITE="/etc/nginx/sites-available/mtproto-masking"

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

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_masking.sh"

set_config_value() {
    local section="$1"
    local key="$2"
    local value="$3"
    local tmp

    [[ -f "$CONFIG_FILE" ]] || return 0
    tmp="$(mktemp)"
    if awk -v want_section="$section" -v want_key="$key" -v new_value="$value" '
        BEGIN { in_section = 0; saw_section = 0; wrote = 0 }
        function emit_value() {
            if (!wrote) {
                print want_key " = " new_value
                wrote = 1
            }
        }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            if (in_section) {
                emit_value()
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
                emit_value()
                next
            }
            print
        }
        END {
            if (in_section) {
                emit_value()
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

write_nginx_config() {
    local cert_ready="$1"
    local extra_listen_line=""
    if [[ -n "$TUNNEL_HOST_IP" && "$cert_ready" == "1" ]]; then
        extra_listen_line="    listen ${TUNNEL_HOST_IP}:${NGINX_PORT} ssl;"
    fi

    cat > "$MASKING_SITE" << NGINXEOF
# mtproto-proxy self-domain 404 masking backend.
# Public :443 is owned by mtproto-proxy. Nginx is only the 404 masking backend.

server {
    listen 80;
    server_name ${TLS_DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_ROOT};
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        return 404;
    }
}
NGINXEOF

    if [[ "$cert_ready" == "1" ]]; then
        cat >> "$MASKING_SITE" << NGINXEOF

server {
    listen 127.0.0.1:${NGINX_PORT} ssl;
${extra_listen_line}

    server_name ${TLS_DOMAIN};

    ssl_certificate     ${CERT_DIR}/cert.pem;
    ssl_certificate_key ${CERT_DIR}/key.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        return 404;
    }

    access_log /var/log/nginx/mtproto-mask-access.log;
    error_log /var/log/nginx/mtproto-mask-error.log warn;
}
NGINXEOF
    fi
}

info "Installing Nginx and certbot..."
apt-get update -qq < /dev/null || true
apt-get install -y nginx certbot curl openssl < /dev/null >/dev/null 2>&1 || true

mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
mkdir -p "$ACME_ROOT/.well-known/acme-challenge" "$CERT_DIR"
ok "Prepared masking/ACME roots"

info "Preparing HTTP-01 ACME challenge on :80 for ${TLS_DOMAIN}..."
write_nginx_config 0
ln -sf "$MASKING_SITE" /etc/nginx/sites-enabled/mtproto-masking
nginx -t 2>/dev/null || fail "Nginx HTTP config test failed"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ok "Opened TCP/80 in ufw for Let's Encrypt HTTP-01"
fi
systemctl restart nginx || true
systemctl enable nginx >/dev/null 2>&1 || true

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
    ln -sf "$LE_CERT" "${CERT_DIR}/cert.pem"
    ln -sf "$LE_KEY" "${CERT_DIR}/key.pem"
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/mtproto-mask-nginx-reload.sh << 'HOOKEOF'
#!/usr/bin/env bash
systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
HOOKEOF
    chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mtproto-mask-nginx-reload.sh
elif [[ "$MASK_ALLOW_SELF_SIGNED" == "1" ]]; then
    warn "Using self-signed certificate because MASK_ALLOW_SELF_SIGNED=1"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -days 3650 -nodes \
        -subj "/CN=${TLS_DOMAIN}" \
        2>/dev/null
else
    fail "No valid certificate for ${TLS_DOMAIN}. Point DNS to this VPS and open TCP/80, or use DNS-01/copy certs manually."
fi

info "Configuring local HTTPS masking backend on 127.0.0.1:${NGINX_PORT}..."
write_nginx_config 1
nginx -t 2>/dev/null || fail "Nginx full config test failed"
systemctl restart nginx || true
ok "Nginx configured for ${TLS_DOMAIN}"
if [[ -n "$TUNNEL_HOST_IP" ]]; then
    ok "Nginx also listens on ${TUNNEL_HOST_IP}:${NGINX_PORT} for tunnel netns"
fi

if curl -sk --max-time 5 --resolve "${TLS_DOMAIN}:${NGINX_PORT}:127.0.0.1" "https://${TLS_DOMAIN}:${NGINX_PORT}/" >/dev/null 2>&1; then
    ok "Masking backend responds with SNI ${TLS_DOMAIN} on 127.0.0.1:${NGINX_PORT}"
else
    warn "Masking backend probe failed. Check: curl -vk --resolve ${TLS_DOMAIN}:${NGINX_PORT}:127.0.0.1 https://${TLS_DOMAIN}:${NGINX_PORT}/"
fi

if [[ -f "$CONFIG_FILE" ]]; then
    set_config_value "censorship" "tls_domain" "\"${TLS_DOMAIN}\""
    set_config_value "censorship" "mask" "true"
    set_config_value "censorship" "mask_port" "${NGINX_PORT}"
    if [[ "$MASK_SET_PUBLIC_IP" == "1" ]]; then
        set_config_value "server" "public_ip" "\"${TLS_DOMAIN}\""
    fi
    ok "Updated ${CONFIG_FILE} for self-domain 404 masking"
    info "Restart the proxy to apply: systemctl restart mtproto-proxy"
else
    warn "Config file not found at ${CONFIG_FILE}"
    info "Set [server].public_ip, [censorship].tls_domain, mask=true, and mask_port=${NGINX_PORT} manually"
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
echo -e "  ${DIM}Nginx TLS:${RESET}   127.0.0.1:${NGINX_PORT}"
if [[ -n "$TUNNEL_HOST_IP" ]]; then
echo -e "  ${DIM}Tunnel TLS:${RESET}  ${TUNNEL_HOST_IP}:${NGINX_PORT}"
fi
echo -e "  ${DIM}ACME root:${RESET}   ${ACME_ROOT}"
echo -e "  ${DIM}Cert:${RESET}        ${CERT_DIR}/cert.pem"
echo -e "  ${DIM}ACME HTTP:${RESET}   ${TLS_DOMAIN}:80"
echo ""
echo -e "Browsers and active probes for ${TLS_DOMAIN}:443 are relayed to Nginx and receive 404."
echo -e "Valid MTProto clients with the right secret stay on the proxy path."
