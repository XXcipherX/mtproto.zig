#!/usr/bin/env bash
#
# setup_mask_monitor.sh - install masking health self-healing for Caddy + mtproto-proxy.
#
# Idempotent helper used by install/setup_masking/setup_tunnel scripts.

set -euo pipefail

QUIET=0
if [[ "${1:-}" == "--quiet" ]]; then
    QUIET=1
fi

INSTALL_DIR="/opt/mtproto-proxy"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
MASK_CADDY_SERVICE="mtproto-mask-caddy.service"
COMPOSE_FILE="${INSTALL_DIR}/compose.yml"
ENV_FILE="${INSTALL_DIR}/.env"
MASK_HEALTH_SCRIPT="/usr/local/bin/mtproto-mask-health.sh"
MASK_HEALTH_SERVICE="/etc/systemd/system/mtproto-mask-health.service"
MASK_HEALTH_TIMER="/etc/systemd/system/mtproto-mask-health.timer"
PROXY_DROPIN_DIR="/etc/systemd/system/mtproto-proxy.service.d"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()  { [[ $QUIET -eq 1 ]] || echo -e "${CYAN}>${RESET} $*"; }
ok()    { [[ $QUIET -eq 1 ]] || echo -e "${GREEN}+${RESET} $*"; }
warn()  { echo -e "${RED}!${RESET} $*"; }
fail()  { echo -e "${RED}x${RESET} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_mask_monitor.sh"

docker_caddy_configured() {
    command -v docker >/dev/null 2>&1 || return 1
    [[ -f "$COMPOSE_FILE" ]] || return 1
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --services 2>/dev/null \
        | grep -qx 'mtproto-mask-caddy'
}

docker_caddy_running() {
    docker inspect -f '{{.State.Running}}' mtproto-mask-caddy 2>/dev/null | grep -qx true
}

wait_for_docker_caddy() {
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        docker_caddy_running && return 0
        sleep 1
    done
    return 1
}

DOCKER_CADDY=false
if docker_caddy_configured; then
    DOCKER_CADDY=true
fi

if $DOCKER_CADDY; then
    rm -f "${PROXY_DROPIN_DIR}/10-mask-caddy.conf"
else
    mkdir -p "$PROXY_DROPIN_DIR"
    cat > "${PROXY_DROPIN_DIR}/10-mask-caddy.conf" << 'EOF'
[Unit]
Wants=mtproto-mask-caddy.service
After=mtproto-mask-caddy.service
EOF
fi

cat > "$MASK_HEALTH_SCRIPT" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/opt/mtproto-proxy/config.toml"
MASK_CADDY_SERVICE="mtproto-mask-caddy.service"
COMPOSE_FILE="/opt/mtproto-proxy/compose.yml"
ENV_FILE="/opt/mtproto-proxy/.env"
CADDY_CONTAINER="mtproto-mask-caddy"
NS_NAME="tg_proxy_ns"
NS_HOST_IP="10.200.200.1"
LOCAL_HOST_IP="127.0.0.1"

read_censorship_value() {
    local key="$1"
    local default_value="$2"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        printf '%s\n' "$default_value"
        return
    fi

    awk -v want_key="$key" -v fallback="$default_value" '
        BEGIN {
            in_section = 0
            value = ""
        }
        /^[[:space:]]*\[censorship\][[:space:]]*$/ {
            in_section = 1
            next
        }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            in_section = 0
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
        END {
            if (value == "") {
                print fallback
            } else {
                print value
            }
        }
    ' "$CONFIG_FILE"
}

probe_local_endpoint() {
    local host="$1"
    local port="$2"
    local domain="$3"
    curl -sk --max-time 3 --resolve "${domain}:${port}:${host}" "https://${domain}:${port}/" >/dev/null 2>&1
}

probe_netns_endpoint() {
    local host="$1"
    local port="$2"
    local domain="$3"
    ip netns exec "$NS_NAME" curl -sk --max-time 3 --resolve "${domain}:${port}:${host}" "https://${domain}:${port}/" >/dev/null 2>&1
}

docker_caddy_available() {
    command -v docker >/dev/null 2>&1 || return 1
    [[ -f "$COMPOSE_FILE" ]] || return 1
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --services 2>/dev/null \
        | grep -qx 'mtproto-mask-caddy'
}

caddy_active() {
    if docker_caddy_available; then
        docker inspect -f '{{.State.Running}}' "$CADDY_CONTAINER" 2>/dev/null | grep -qx true
    else
        systemctl is-active --quiet "$MASK_CADDY_SERVICE"
    fi
}

restart_caddy() {
    if docker_caddy_available; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy >/dev/null 2>&1
    else
        systemctl restart "$MASK_CADDY_SERVICE"
    fi
}

if ! command -v systemctl >/dev/null 2>&1; then
    exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
    logger -t mtproto-mask-health "curl not found; cannot probe masking endpoint"
    exit 1
fi

if ! docker_caddy_available && ! systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -q "^${MASK_CADDY_SERVICE}[[:space:]]"; then
    exit 0
fi

mask_enabled_raw="$(read_censorship_value "mask" "true")"
mask_enabled_raw="$(printf '%s' "$mask_enabled_raw" | tr '[:upper:]' '[:lower:]')"
case "$mask_enabled_raw" in
    true|1|yes|on) mask_enabled=true ;;
    false|0|no|off) mask_enabled=false ;;
    *) mask_enabled=true ;;
esac

if [[ "$mask_enabled" != true ]]; then
    exit 0
fi

mask_port_raw="$(read_censorship_value "mask_port" "443")"
mask_port="${mask_port_raw//[^0-9]/}"
mask_port="${mask_port:-443}"
tls_domain="$(read_censorship_value "tls_domain" "localhost")"
tls_domain="${tls_domain:-localhost}"

if [[ "$mask_port" == "443" ]]; then
    exit 0
fi

use_netns=0
target_host="$LOCAL_HOST_IP"
if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
    if ip -4 addr show 2>/dev/null | grep -q "${NS_HOST_IP}/"; then
        use_netns=1
        target_host="$NS_HOST_IP"
    fi
fi

probe_endpoint() {
    if [[ "$use_netns" == "1" ]]; then
        probe_netns_endpoint "$target_host" "$mask_port" "$tls_domain"
    else
        probe_local_endpoint "$target_host" "$mask_port" "$tls_domain"
    fi
}

if ! caddy_active; then
    logger -t mtproto-mask-health "Caddy masking service inactive, restarting"
    restart_caddy || true
    sleep 1
fi

if probe_endpoint; then
    exit 0
fi

logger -t mtproto-mask-health "mask endpoint ${tls_domain} via ${target_host}:${mask_port} unreachable; restarting Caddy"
restart_caddy || true
sleep 1

if probe_endpoint; then
    logger -t mtproto-mask-health "mask endpoint ${tls_domain} via ${target_host}:${mask_port} recovered after Caddy restart"
    exit 0
fi

if systemctl is-active --quiet mtproto-proxy; then
    logger -t mtproto-mask-health "mask endpoint still unreachable; restarting mtproto-proxy"
    systemctl restart mtproto-proxy || true
    sleep 1
fi

if probe_endpoint; then
    logger -t mtproto-mask-health "mask endpoint ${tls_domain} via ${target_host}:${mask_port} recovered after mtproto-proxy restart"
    exit 0
fi

logger -t mtproto-mask-health "critical: mask endpoint ${tls_domain} via ${target_host}:${mask_port} still unreachable"
exit 1
EOF
chmod 0755 "$MASK_HEALTH_SCRIPT"

cat > "$MASK_HEALTH_SERVICE" << 'EOF'
[Unit]
Description=MTProto masking endpoint health check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mtproto-mask-health.sh
EOF

cat > "$MASK_HEALTH_TIMER" << 'EOF'
[Unit]
Description=Run MTProto masking health check every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
RandomizedDelaySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
if $DOCKER_CADDY; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d mtproto-mask-caddy >/dev/null 2>&1 || true
else
    systemctl enable "$MASK_CADDY_SERVICE" >/dev/null 2>&1 || true
fi
systemctl enable --now mtproto-mask-health.timer >/dev/null 2>&1 || true

if $DOCKER_CADDY; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy >/dev/null 2>&1 || true
elif systemctl is-active --quiet "$MASK_CADDY_SERVICE"; then
    systemctl try-reload-or-restart "$MASK_CADDY_SERVICE" >/dev/null 2>&1 || true
fi

systemctl start mtproto-mask-health.service >/dev/null 2>&1 || true

if systemctl is-active --quiet mtproto-mask-health.timer; then
    ok "Masking health timer is active"
else
    warn "Masking health timer is not active"
fi

if systemctl is-enabled --quiet mtproto-mask-health.timer; then
    ok "Masking health timer is enabled"
else
    warn "Masking health timer is not enabled"
fi

if $DOCKER_CADDY; then
    if wait_for_docker_caddy; then
        ok "Caddy masking container is active"
    else
        docker logs --tail=40 mtproto-mask-caddy 2>/dev/null || true
        warn "Caddy masking backend is not active"
    fi
elif systemctl is-active --quiet "$MASK_CADDY_SERVICE"; then
    ok "Caddy masking service is active"
else
    warn "Caddy masking backend is not active"
fi
