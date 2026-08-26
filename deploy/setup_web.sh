#!/usr/bin/env bash
# Configure Telegram Desktop WEB proxy alongside the existing Caddy-masked
# mtproto.zig service. Public :443 remains owned by mtproto-proxy.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
CONFIG_FILE="${CONFIG_FILE:-${INSTALL_DIR}/config.toml}"
COMPOSE_FILE="${COMPOSE_FILE:-${INSTALL_DIR}/compose.yml}"
ENV_FILE="${ENV_FILE:-${INSTALL_DIR}/.env}"
ACME_ROOT="${MASK_ACME_ROOT:-/var/www/certbot}"
CADDYFILE="${CADDYFILE:-/etc/caddy/mtproto-mask.Caddyfile}"
WEB_PORT="${WEB_PORT:-8081}"
WEB_TLS_PORT="${WEB_TLS_PORT:-8444}"
WEB_DOMAIN="${WEB_DOMAIN:-${1:-}}"
REMOVE=false

if [[ "${1:-}" == "--remove" ]]; then
    REMOVE=true
    WEB_DOMAIN=""
fi

info() { printf '> %s\n' "$*"; }
ok() { printf '+ %s\n' "$*"; }
fail() { printf 'x %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root"
[[ -f "$CONFIG_FILE" ]] || fail "Config not found: ${CONFIG_FILE}"
CONFIG_UID="$(stat -c '%u' "$CONFIG_FILE")"
CONFIG_GID="$(stat -c '%g' "$CONFIG_FILE")"
CONFIG_MODE="$(stat -c '%a' "$CONFIG_FILE")"

is_docker_install() {
    [[ -f "$COMPOSE_FILE" ]] && grep -Eq '^[[:space:]]+mtproto-proxy:[[:space:]]*$' "$COMPOSE_FILE"
}

if is_docker_install; then
    CADDYFILE="${INSTALL_DIR}/Caddyfile.mask"
    CADDY_WEB_DIR="${INSTALL_DIR}/caddy/web"
else
    CADDY_WEB_DIR="/etc/caddy/web"
fi

set_env_value() {
    local key="$1" value="$2" tmp
    touch "$ENV_FILE"
    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        $0 ~ "^" key "=" { print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }
    ' "$ENV_FILE" > "$tmp"
    install -m 0600 "$tmp" "$ENV_FILE"
    rm -f "$tmp"
}

set_config_value() {
    local section="$1" key="$2" value="$3" tmp
    tmp="$(mktemp)"
    awk -v want_section="$section" -v want_key="$key" -v new_value="$value" '
        BEGIN { in_section = 0; section_seen = 0; key_done = 0 }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            if (in_section && !key_done) { print want_key " = " new_value; key_done = 1 }
            header = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", header)
            in_section = (header == want_section)
            if (in_section) section_seen = 1
            print
            next
        }
        in_section && $0 ~ "^[[:space:]]*" want_key "[[:space:]]*=" {
            if (!key_done) print want_key " = " new_value
            key_done = 1
            next
        }
        { print }
        END {
            if (!section_seen) {
                print ""
                print "[" want_section "]"
                print want_key " = " new_value
            } else if (in_section && !key_done) print want_key " = " new_value
        }
    ' "$CONFIG_FILE" > "$tmp"
    install -o "$CONFIG_UID" -g "$CONFIG_GID" -m "$CONFIG_MODE" "$tmp" "$CONFIG_FILE"
    rm -f "$tmp"
}

ensure_caddy_imports() {
    [[ -f "$CADDYFILE" ]] || fail "Existing Caddy masking config not found: ${CADDYFILE}. Run setup_masking.sh first."
    grep -Fq 'import /etc/caddy/web/global.caddy' "$CADDYFILE" \
        || fail "Caddy config is from an older installer. Rerun the latest setup_masking.sh, then setup_web.sh."
    grep -Fq 'import /etc/caddy/web/site.caddy' "$CADDYFILE" \
        || fail "Caddy WEB site import is missing. Rerun the latest setup_masking.sh first."
}

reload_caddy() {
    if is_docker_install; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" run --rm --no-deps \
            mtproto-mask-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy
        sleep 1
        [[ "$(docker inspect -f '{{.State.Running}}' mtproto-mask-caddy 2>/dev/null || true)" == "true" ]] \
            || fail "Caddy did not stay running after the WEB configuration reload"
    else
        caddy validate --config "$CADDYFILE" --adapter caddyfile
        if systemctl is-active --quiet mtproto-mask-caddy.service; then
            systemctl reload mtproto-mask-caddy.service || systemctl restart mtproto-mask-caddy.service
        else
            systemctl restart mtproto-mask-caddy.service
        fi
    fi
}

mkdir -p "$CADDY_WEB_DIR/cert"
touch "$CADDY_WEB_DIR/global.caddy" "$CADDY_WEB_DIR/site.caddy"

if $REMOVE; then
    : > "$CADDY_WEB_DIR/global.caddy"
    : > "$CADDY_WEB_DIR/site.caddy"
    set_config_value web enabled false
    rm -f /etc/letsencrypt/renewal-hooks/deploy/mtproto-web-caddy-reload.sh
    if is_docker_install; then
        set_env_value COMPOSE_PROFILES ""
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop mtproto-web-relay >/dev/null 2>&1 || true
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" rm -f mtproto-web-relay >/dev/null 2>&1 || true
        if grep -Eq '^[[:space:]]+mtproto-mask-caddy:[[:space:]]*$' "$COMPOSE_FILE" &&
            [[ -f "$CADDYFILE" ]] &&
            grep -Fq 'import /etc/caddy/web/site.caddy' "$CADDYFILE"
        then
            reload_caddy
        else
            info "Caddy WEB import is absent; no Caddy reload is needed"
        fi
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate --no-deps mtproto-proxy
    else
        systemctl disable --now mtproto-web-relay.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/mtproto-web-relay.service
        systemctl daemon-reload
        if [[ -f "$CADDYFILE" ]] && grep -Fq 'import /etc/caddy/web/site.caddy' "$CADDYFILE"; then
            reload_caddy
        else
            info "Caddy WEB import is absent; no Caddy reload is needed"
        fi
        systemctl restart mtproto-proxy
    fi
    ok "WEB proxy disabled; ordinary MTProto and Caddy masking remain active"
    exit 0
fi

ensure_caddy_imports

[[ "$WEB_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || fail "Pass a valid WEB domain: setup_web.sh web.example.com"
[[ "$WEB_DOMAIN" == *.* ]] || fail "WEB domain must contain a dot"
[[ ${#WEB_DOMAIN} -le 253 && "$WEB_DOMAIN" != *..* ]] || fail "WEB domain is not a valid DNS hostname"
IFS='.' read -r -a WEB_LABELS <<< "$WEB_DOMAIN"
for label in "${WEB_LABELS[@]}"; do
    [[ ${#label} -le 63 && "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] \
        || fail "WEB domain contains an invalid DNS label: ${label}"
done
[[ ! "${WEB_LABELS[-1]}" =~ ^[0-9]+$ ]] || fail "WEB domain must not end in a numeric label"
[[ ! "${WEB_LABELS[-1]}" =~ ^0[xX][0-9A-Fa-f]+$ ]] || fail "WEB domain must not end in an IP-like hexadecimal label"
WEB_DOMAIN="${WEB_DOMAIN,,}"

for port_value in "$WEB_PORT" "$WEB_TLS_PORT"; do
    [[ "$port_value" =~ ^[0-9]+$ ]] && (( port_value >= 1 && port_value <= 65535 )) \
        || fail "WEB ports must be integers in 1..65535"
done

PROXY_PORT="$(awk '
    /^\[server\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /^[[:space:]]*port[[:space:]]*=/{line=$0; sub(/[;#].*/,"",line); sub(/^[^=]*=/,"",line); gsub(/[[:space:]]/,"",line); print line; exit}
' "$CONFIG_FILE")"
[[ "${PROXY_PORT:-443}" == "443" ]] || fail "Telegram WEB proxy requires [server].port = 443"

TLS_DOMAIN="$(awk '
    /^\[censorship\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /^[[:space:]]*tls_domain[[:space:]]*=/{line=$0; sub(/[;#].*/,"",line); sub(/^[^=]*=/,"",line); gsub(/^[[:space:]\"]+|[[:space:]\"]+$/,"",line); print tolower(line); exit}
' "$CONFIG_FILE")"
[[ "${WEB_DOMAIN,,}" != "${TLS_DOMAIN,,}" ]] \
    || fail "WEB_DOMAIN must differ from [censorship].tls_domain; use a separate DNS name on the same VPS"

MASK_PORT="$(awk '
    /^\[censorship\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /^[[:space:]]*mask_port[[:space:]]*=/{line=$0; sub(/[;#].*/,"",line); sub(/^[^=]*=/,"",line); gsub(/[[:space:]]/,"",line); print line; exit}
' "$CONFIG_FILE")"
MASK_PORT="${MASK_PORT:-443}"
MASK_ENABLED="$(awk '
    /^\[censorship\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /^[[:space:]]*mask[[:space:]]*=/{line=$0; sub(/[;#].*/,"",line); sub(/^[^=]*=/,"",line); gsub(/[[:space:]]/,"",line); print tolower(line); exit}
' "$CONFIG_FILE")"
[[ "${MASK_ENABLED:-true}" =~ ^(true|1|yes|on)$ ]] \
    || fail "WEB proxy requires censorship.mask=true and the existing Caddy masking service"
[[ "$WEB_PORT" != "$PROXY_PORT" && "$WEB_PORT" != "$MASK_PORT" && "$WEB_PORT" != "$WEB_TLS_PORT" ]] \
    || fail "WEB_PORT=${WEB_PORT} collides with an existing proxy/Caddy listener"
[[ "$WEB_TLS_PORT" != "$PROXY_PORT" && "$WEB_TLS_PORT" != "$MASK_PORT" ]] \
    || fail "WEB_TLS_PORT=${WEB_TLS_PORT} collides with an existing proxy/Caddy listener"

SECRET="$(awk '
    /^\[access.users\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /=/{line=$0; sub(/[;#].*$/,"",line); sub(/^[^=]*=/,"",line); gsub(/[ \t\r\"]/,"",line); if (length(line) == 32 && line !~ /[^0-9A-Fa-f]/) {print tolower(line); exit}}
' "$CONFIG_FILE")"
[[ -n "$SECRET" ]] \
    || fail "No valid 32-hex secret found in [access.users]; add a user before enabling WEB proxy"

command -v certbot >/dev/null 2>&1 || {
    apt-get update -qq < /dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot < /dev/null
}
mkdir -p "$ACME_ROOT/.well-known/acme-challenge"

LE_CERT="/etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/${WEB_DOMAIN}/privkey.pem"
if [[ ! -f "$LE_CERT" || ! -f "$LE_KEY" ]]; then
    info "Requesting Let's Encrypt certificate for ${WEB_DOMAIN} through the existing Caddy :80 ACME webroot"
    certbot certonly --webroot -w "$ACME_ROOT" -d "$WEB_DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email
else
    ok "Reusing Let's Encrypt certificate for ${WEB_DOMAIN}"
fi

TUNNEL_HOST_IP=""
BACKEND='127.0.0.1:443'
MASK_BACKEND="127.0.0.1:${WEB_TLS_PORT}"
RELAY_SOURCES='[]'
if command -v ip >/dev/null 2>&1 && ip netns list 2>/dev/null | awk '{print $1}' | grep -qx tg_proxy_ns; then
    TUNNEL_HOST_IP="10.200.200.1"
    BACKEND='10.200.200.2:443'
    MASK_BACKEND="10.200.200.1:${WEB_TLS_PORT}"
    RELAY_SOURCES='["10.200.200.1"]'
fi

set_config_value web enabled true
set_config_value web domain "\"${WEB_DOMAIN}\""
set_config_value web listen '"127.0.0.1"'
set_config_value web port "$WEB_PORT"
set_config_value web backend "\"${BACKEND}\""
set_config_value web mask_backend "\"${MASK_BACKEND}\""
set_config_value web ws_path '"/api/v1/socket"'
set_config_value web trust_forwarded_for true
set_config_value web client_ip_header '"x-forwarded-for"'
set_config_value web check_origin true
set_config_value web max_sessions "${WEB_MAX_SESSIONS:-8}"
set_config_value web max_streams "${WEB_MAX_STREAMS:-32}"
set_config_value web max_buffer_mb "${WEB_MAX_BUFFER_MB:-128}"
set_config_value web relay_sources "$RELAY_SOURCES"

install -m 0644 "$LE_CERT" "$CADDY_WEB_DIR/cert/fullchain.pem"
install -m 0600 "$LE_KEY" "$CADDY_WEB_DIR/cert/privkey.pem"
if ! is_docker_install; then chown -R caddy:caddy "$CADDY_WEB_DIR" 2>/dev/null || true; fi

cat > "$CADDY_WEB_DIR/global.caddy" <<EOF
servers 127.0.0.1:${WEB_TLS_PORT} {
    listener_wrappers {
        proxy_protocol {
            timeout 2s
            allow 127.0.0.0/8
            fallback_policy require
        }
        tls
    }
}
EOF

if [[ -n "$TUNNEL_HOST_IP" ]]; then
    cat >> "$CADDY_WEB_DIR/global.caddy" <<EOF

servers ${TUNNEL_HOST_IP}:${WEB_TLS_PORT} {
    listener_wrappers {
        proxy_protocol {
            timeout 2s
            allow 10.200.200.0/24
            fallback_policy require
        }
        tls
    }
}
EOF
fi

cat > "$CADDY_WEB_DIR/site.caddy" <<EOF
https://${WEB_DOMAIN}:${WEB_TLS_PORT} {
    bind 127.0.0.1
    tls /etc/caddy/web/cert/fullchain.pem /etc/caddy/web/cert/privkey.pem {
        curves x25519mlkem768 x25519
    }
    reverse_proxy 127.0.0.1:${WEB_PORT} {
        header_up X-Forwarded-For {remote_host}
        flush_interval -1
        stream_close_delay 5m
    }
}
EOF


if [[ -n "$TUNNEL_HOST_IP" ]]; then
    cat >> "$CADDY_WEB_DIR/site.caddy" <<EOF

https://${WEB_DOMAIN}:${WEB_TLS_PORT} {
    bind ${TUNNEL_HOST_IP}
    tls /etc/caddy/web/cert/fullchain.pem /etc/caddy/web/cert/privkey.pem {
        curves x25519mlkem768 x25519
    }
    reverse_proxy 127.0.0.1:${WEB_PORT} {
        header_up X-Forwarded-For {remote_host}
        flush_interval -1
        stream_close_delay 5m
    }
}
EOF
fi

if is_docker_install; then
    command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
    grep -Eq '^[[:space:]]+mtproto-web-relay:[[:space:]]*$' "$COMPOSE_FILE" \
        || fail "Compose file lacks WEB relay; rerun the latest install_docker_compose.sh, then setup_web.sh"
    set_env_value COMPOSE_PROFILES web
    set_env_value WEB_DOMAIN "$WEB_DOMAIN"
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull mtproto-proxy mtproto-web-relay mtproto-mask-caddy
    reload_caddy
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-proxy mtproto-web-relay
else
    cat > /etc/systemd/system/mtproto-web-relay.service <<EOF
[Unit]
Description=MTProto WEB proxy relay
After=network-online.target mtproto-proxy.service mtproto-mask-caddy.service
Wants=network-online.target mtproto-proxy.service mtproto-mask-caddy.service

[Service]
Type=simple
User=mtproto
Group=mtproto
ExecStart=${INSTALL_DIR}/mtproto-proxy web-relay ${CONFIG_FILE}
Restart=on-failure
RestartSec=2s
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    reload_caddy
    systemctl enable mtproto-web-relay.service >/dev/null
    systemctl restart mtproto-proxy mtproto-web-relay.service
fi

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/mtproto-web-caddy-reload.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
install -m 0644 /etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem ${CADDY_WEB_DIR}/cert/fullchain.pem
install -m 0600 /etc/letsencrypt/live/${WEB_DOMAIN}/privkey.pem ${CADDY_WEB_DIR}/cert/privkey.pem
if [[ -f ${COMPOSE_FILE} ]] && grep -q 'mtproto-mask-caddy:' ${COMPOSE_FILE}; then
  docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} up -d --force-recreate --no-deps mtproto-mask-caddy >/dev/null
else
  chown -R caddy:caddy ${CADDY_WEB_DIR} 2>/dev/null || true
  systemctl reload mtproto-mask-caddy.service
fi
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mtproto-web-caddy-reload.sh

sleep 1
PROBE_IP="${TUNNEL_HOST_IP:+10.200.200.2}"
PROBE_IP="${PROBE_IP:-127.0.0.1}"
curl -fsS --max-time 5 --resolve "${WEB_DOMAIN}:443:${PROBE_IP}" "https://${WEB_DOMAIN}/" >/dev/null \
    || info "End-to-end HTTPS probe is not ready yet; inspect the proxy, Caddy and relay logs"

ok "WEB proxy enabled alongside ordinary MTProto, using the existing Caddy instance"
printf '  WEB:      tg://webproxy?server=%s&secret=dd%s\n' "$WEB_DOMAIN" "$SECRET"
printf '  MTProto:  unchanged on the existing public endpoint\n'
if is_docker_install; then
    printf '  Logs:     docker compose --env-file %s -f %s logs -f mtproto-proxy mtproto-web-relay mtproto-mask-caddy\n' "$ENV_FILE" "$COMPOSE_FILE"
else
    printf '  Logs:     journalctl -u mtproto-proxy -u mtproto-web-relay -u mtproto-mask-caddy -f\n'
fi
