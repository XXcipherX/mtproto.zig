#!/usr/bin/env bash
#
# Docker Compose installer/updater for mtproto.zig.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install_docker_compose.sh \
#     | sudo env TLS_DOMAIN=proxy.example.com bash
#
# Optional environment:
#   IMAGE=ghcr.io/xxcipherx/mtproto.zig:latest
#   AUTO_IMAGE_CPU_VARIANT=true|false
#   INSTALL_DIR=/opt/mtproto-proxy
#   PORT=443
#   PUBLIC_IP=proxy.example.com
#   SECRET=<32 hex chars>
#   USE_MIDDLE_PROXY=true|false
#   ENABLE_MASKING=true|false
#   ENABLE_SYNFIX=true|false
#   MASK_PORT=8443
#   GHCR_USER=<user> GHCR_TOKEN=<token>   # for private GHCR packages

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
REPO_RAW_URL="${REPO_RAW_URL:-https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main}"
DEFAULT_IMAGE_REPO="${DEFAULT_IMAGE_REPO:-ghcr.io/xxcipherx/mtproto.zig}"
DEFAULT_IMAGE_TAG="${DEFAULT_IMAGE_TAG:-latest}"
IMAGE="${IMAGE:-}"
AUTO_IMAGE_CPU_VARIANT="${AUTO_IMAGE_CPU_VARIANT:-true}"
PORT="${PORT:-443}"
USE_MIDDLE_PROXY="${USE_MIDDLE_PROXY:-true}"
ENABLE_MASKING="${ENABLE_MASKING:-true}"
ENABLE_SYNFIX="${ENABLE_SYNFIX:-false}"
MASK_PORT="${MASK_PORT:-8443}"
COMPOSE_FILE="${INSTALL_DIR}/compose.yml"
ENV_FILE="${INSTALL_DIR}/.env"
CONFIG_FILE="${INSTALL_DIR}/config.toml"
SERVICE_NAME="mtproto-proxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
MASKING_OK=false
SYNFIX_OK=false
NFQWS_OK=false
AUTO_SELECTED_CPU_IMAGE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info() { echo -e "${CYAN}>${RESET} $*"; }
ok() { echo -e "${GREEN}+${RESET} $*"; }
warn() { echo -e "${RED}!${RESET} $*"; }
fail() { echo -e "${RED}x${RESET} $*" >&2; exit 1; }

is_true() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

bool_literal() {
    if is_true "$1"; then
        printf 'true'
    else
        printf 'false'
    fi
}

host_supports_amd64_v3() {
    local arch flags
    arch="$(uname -m 2>/dev/null || true)"
    case "$arch" in
        x86_64|amd64) ;;
        *) return 1 ;;
    esac

    [[ -r /proc/cpuinfo ]] || return 1
    flags="$(awk -F: '/flags/ { print " " tolower($2) " "; exit }' /proc/cpuinfo 2>/dev/null)"
    [[ -n "$flags" ]] || return 1

    local flag
    for flag in aes avx avx2 bmi1 bmi2 f16c fma movbe xsave sse4_1 sse4_2 ssse3 popcnt; do
        [[ "$flags" == *" ${flag} "* ]] || return 1
    done
}

select_default_image() {
    if [[ -n "$IMAGE" ]]; then
        return
    fi

    IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"
    if is_true "$AUTO_IMAGE_CPU_VARIANT" && host_supports_amd64_v3; then
        IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}-amd64-v3"
        AUTO_SELECTED_CPU_IMAGE=true
    fi
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

get_config_value() {
    local cfg="$1"
    local section="$2"
    local key="$3"
    local default_value="${4:-}"

    [[ -f "$cfg" ]] || { printf '%s\n' "$default_value"; return; }

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
            sub(/[;#].*/, "", line)
            if (line ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
                split(line, parts, "=")
                value = parts[2]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                gsub(/^"|"$/, "", value)
            }
        }
        END { print value == "" ? fallback : value }
    ' "$cfg" 2>/dev/null
}

get_first_user_secret() {
    local cfg="$1"
    [[ -f "$cfg" ]] || return 0

    awk '
        BEGIN { in_users = 0 }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            header = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", header)
            in_users = (header == "access.users")
            next
        }
        in_users {
            line = $0
            sub(/[;#].*/, "", line)
            if (line !~ /=/) next
            sub(/^[^=]*=/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            gsub(/^"|"$/, "", line)
            if (length(line) == 32 && line !~ /[^0-9A-Fa-f]/) {
                print tolower(line)
                exit
            }
        }
    ' "$cfg" 2>/dev/null
}

domain_to_hex() {
    printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

detect_compose() {
    if docker compose version >/dev/null 2>&1; then
        COMPOSE=(docker compose)
    else
        fail "Docker Compose v2 plugin is not installed"
    fi
}

docker_install() {
    local installer
    installer="$(mktemp)"
    if curl -fsSL https://get.docker.com -o "$installer" && sh "$installer"; then
        rm -f "$installer"
    else
        rm -f "$installer"
        return 1
    fi
}

install_packages() {
    info "Installing Docker and required tools..."
    apt-get update -qq < /dev/null || true
    apt-get install -y ca-certificates curl openssl iptables xxd jq git < /dev/null

    if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
        info "Installing Docker Engine and Compose plugin from get.docker.com..."
        docker_install || fail "Docker installation failed"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now docker >/dev/null 2>&1 || true
    fi
    command -v docker >/dev/null 2>&1 || fail "docker command not found after Docker install"
    detect_compose
    ok "Docker is ready"
}

fetch_helper_scripts() {
    info "Fetching deployment helper scripts..."
    local file
    for file in setup_masking.sh setup_nfqws.sh setup_synfix.sh setup_mask_monitor.sh ipv6-hop.sh update_dns.sh; do
        curl -fsSL "${REPO_RAW_URL}/deploy/${file}" -o "${INSTALL_DIR}/${file}" \
            || fail "Failed to download deploy/${file}"
        chmod 0755 "${INSTALL_DIR}/${file}"
    done
    curl -fsSL "${REPO_RAW_URL}/deploy/capture_template.py" -o "${INSTALL_DIR}/capture_template.py" \
        || true
    ok "Deployment helpers installed to ${INSTALL_DIR}"
}

write_compose_file() {
    cat > "$COMPOSE_FILE" <<'EOF'
services:
  mtproto-proxy:
    image: ${MTPROTO_IMAGE:-ghcr.io/xxcipherx/mtproto.zig:latest}
    container_name: mtproto-proxy
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config.toml:/etc/mtproto-proxy/config.toml:ro
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
EOF

    cat > "$ENV_FILE" <<EOF
MTPROTO_IMAGE=${IMAGE}
EOF
}

write_compose_service() {
    local docker_bin
    command -v systemctl >/dev/null 2>&1 || fail "systemd is required for Docker Compose install"
    docker_bin="$(command -v docker)"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MTProto Proxy (Docker Compose)
After=network-online.target docker.service nginx.service
Wants=network-online.target docker.service nginx.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=${docker_bin} compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} up -d
ExecStop=${docker_bin} compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    ok "Systemd wrapper ready: ${SERVICE_NAME}.service"
}

write_config_if_missing() {
    local mask_bool use_middle_proxy_bool

    if [[ -f "$CONFIG_FILE" ]]; then
        ok "Config already exists, keeping ${CONFIG_FILE}"
        SECRET="$(get_first_user_secret "$CONFIG_FILE")"
        TLS_DOMAIN="$(get_config_value "$CONFIG_FILE" "censorship" "tls_domain" "${TLS_DOMAIN:-}")"
        PORT="$(get_config_value "$CONFIG_FILE" "server" "port" "$PORT")"
        PUBLIC_IP="$(get_config_value "$CONFIG_FILE" "server" "public_ip" "${PUBLIC_IP:-$TLS_DOMAIN}")"
        return
    fi

    TLS_DOMAIN="${TLS_DOMAIN:-${MASK_DOMAIN:-${DNS_NAME:-}}}"
    if [[ -z "${TLS_DOMAIN:-}" ]]; then
        fail "Set TLS_DOMAIN=proxy.example.com (or MASK_DOMAIN/DNS_NAME) before running the installer"
    fi
    validate_domain "$TLS_DOMAIN" || fail "Invalid TLS_DOMAIN: ${TLS_DOMAIN}"

    SECRET="${SECRET:-$(openssl rand -hex 16)}"
    [[ "$SECRET" =~ ^[0-9A-Fa-f]{32}$ ]] || fail "SECRET must be 32 hex characters"
    SECRET="${SECRET,,}"

    PUBLIC_IP="${PUBLIC_IP:-$TLS_DOMAIN}"
    use_middle_proxy_bool="$(bool_literal "$USE_MIDDLE_PROXY")"
    mask_bool="$(bool_literal "$ENABLE_MASKING")"

    cat > "$CONFIG_FILE" <<EOF
[general]
use_middle_proxy = ${use_middle_proxy_bool}

[server]
port = ${PORT}
public_ip = "${PUBLIC_IP}"
max_connections = 512
idle_timeout_sec = 120
handshake_timeout_sec = 15

[censorship]
tls_domain = "${TLS_DOMAIN}"
mask = ${mask_bool}
fast_mode = true
EOF

    if is_true "$ENABLE_MASKING"; then
        cat >> "$CONFIG_FILE" <<EOF
mask_port = ${MASK_PORT}
EOF
    fi

    cat >> "$CONFIG_FILE" <<EOF

[access.users]
user = "${SECRET}"
EOF
    chmod 600 "$CONFIG_FILE"
    ok "Generated ${CONFIG_FILE}"
}

stop_legacy_service() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet mtproto-proxy; then
        warn "Stopping legacy systemd mtproto-proxy service to free port ${PORT}"
        systemctl stop mtproto-proxy || true
        systemctl disable mtproto-proxy >/dev/null 2>&1 || true
    fi
}

docker_login_if_needed() {
    if [[ -n "${GHCR_USER:-}" && -n "${GHCR_TOKEN:-}" ]]; then
        info "Logging in to ghcr.io as ${GHCR_USER}"
        printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin >/dev/null
    fi
}

refresh_config_vars() {
    TLS_DOMAIN="$(get_config_value "$CONFIG_FILE" "censorship" "tls_domain" "${TLS_DOMAIN:-}")"
    PUBLIC_IP="$(get_config_value "$CONFIG_FILE" "server" "public_ip" "${PUBLIC_IP:-$TLS_DOMAIN}")"
    PORT="$(get_config_value "$CONFIG_FILE" "server" "port" "$PORT")"
    MASK_PORT="$(get_config_value "$CONFIG_FILE" "censorship" "mask_port" "$MASK_PORT")"
    SECRET="$(get_first_user_secret "$CONFIG_FILE")"
}

apply_firewall_and_tcpmss() {
    refresh_config_vars
    PORT="${PORT:-443}"

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
        ok "Opened port ${PORT} in ufw"
    fi

    if command -v iptables >/dev/null 2>&1; then
        iptables -t mangle -D OUTPUT -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null || true
        iptables -t mangle -A OUTPUT -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ok "TCPMSS=88 clamping applied to IPv4"
    else
        warn "iptables not found; TCPMSS bypass was not applied"
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t mangle -D OUTPUT -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null || true
        if ip6tables -t mangle -A OUTPUT -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null; then
            mkdir -p /etc/iptables
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            ok "TCPMSS=88 clamping applied to IPv6"
        else
            info "IPv6 TCPMSS skipped"
        fi
    fi
}

setup_ipv6_hopping() {
    if [[ -n "${CF_TOKEN:-}" && -n "${CF_ZONE:-}" ]]; then
        DNS_NAME="${DNS_NAME:-$TLS_DOMAIN}"
        if [[ -z "${IPV6_PREFIX:-}" ]]; then
            warn "Skipping IPv6 hopping setup: set IPV6_PREFIX together with CF_TOKEN/CF_ZONE"
            return
        fi

        cat > "${INSTALL_DIR}/env.sh" <<EOF
export CF_TOKEN="${CF_TOKEN}"
export CF_ZONE="${CF_ZONE}"
export DNS_NAME="${DNS_NAME}"
export IPV6_PREFIX="${IPV6_PREFIX}"
export IPV6_INTERFACE="${IPV6_INTERFACE:-eth0}"
EOF
        chmod 600 "${INSTALL_DIR}/env.sh"

        cat > /etc/cron.d/mtproto-ipv6 <<EOF
*/5 * * * * root ${INSTALL_DIR}/ipv6-hop.sh >> /var/log/mtproto-ipv6-hop.log 2>&1
EOF
        chmod 644 /etc/cron.d/mtproto-ipv6
        "${INSTALL_DIR}/ipv6-hop.sh" >/dev/null 2>&1 || true
        ok "IPv6 auto-hopping configured for ${DNS_NAME}"
    else
        info "Skipping IPv6 hopping setup (CF_TOKEN and CF_ZONE not set)"
    fi
}

setup_masking_and_desync() {
    refresh_config_vars

    if is_true "$ENABLE_MASKING"; then
        [[ -n "$TLS_DOMAIN" ]] || fail "Masking requires TLS_DOMAIN or [censorship].tls_domain"
        info "Setting up Self-domain Nginx Masking..."
        if MASK_DOMAIN="$TLS_DOMAIN" MASK_PORT="$MASK_PORT" bash "${INSTALL_DIR}/setup_masking.sh" "$TLS_DOMAIN" < /dev/null; then
            MASKING_OK=true
            refresh_config_vars
        else
            warn "Masking setup failed. Check DNS A record and TCP/80 reachability."
        fi
    else
        warn "Self-domain Nginx Masking disabled by ENABLE_MASKING=false"
    fi

    if is_true "$ENABLE_SYNFIX"; then
        info "Setting up inbound SYN pacing..."
        if PORT="$PORT" bash "${INSTALL_DIR}/setup_synfix.sh" < /dev/null; then
            SYNFIX_OK=true
            ok "Inbound SYN pacing configured"
        else
            warn "Inbound SYN pacing setup failed"
        fi
    else
        info "Skipping inbound SYN pacing (set ENABLE_SYNFIX=true to install)"
    fi

    info "Setting up zapret nfqws TCP desync..."
    if bash "${INSTALL_DIR}/setup_nfqws.sh" < /dev/null; then
        NFQWS_OK=true
    else
        warn "nfqws setup failed"
    fi
}

validate_masking() {
    refresh_config_vars
    if ! is_true "$ENABLE_MASKING"; then
        return
    fi
    [[ -n "$TLS_DOMAIN" ]] || return
    [[ -n "$MASK_PORT" ]] || return

    if curl -sk --max-time 5 --resolve "${TLS_DOMAIN}:${MASK_PORT}:127.0.0.1" "https://${TLS_DOMAIN}:${MASK_PORT}/" >/dev/null 2>&1; then
        ok "Masking validation passed (${TLS_DOMAIN} via 127.0.0.1:${MASK_PORT})"
    else
        warn "Masking validation failed: ${TLS_DOMAIN} via 127.0.0.1:${MASK_PORT} is not responding"
    fi

    if systemctl is-active --quiet mtproto-mask-health.timer; then
        ok "Masking health monitor timer is active"
    else
        warn "Masking health monitor timer is not active"
    fi
}

print_summary() {
    local link_secret domain_hex
    TLS_DOMAIN="$(get_config_value "$CONFIG_FILE" "censorship" "tls_domain" "$TLS_DOMAIN")"
    PUBLIC_IP="$(get_config_value "$CONFIG_FILE" "server" "public_ip" "$PUBLIC_IP")"
    PORT="$(get_config_value "$CONFIG_FILE" "server" "port" "$PORT")"
    SECRET="$(get_first_user_secret "$CONFIG_FILE")"
    domain_hex="$(domain_to_hex "$TLS_DOMAIN")"

    echo ""
    echo -e "${BOLD}${CYAN}Docker Compose install complete${RESET}"
    echo ""
    echo -e "  ${DIM}Image:${RESET}   ${IMAGE}"
    echo -e "  ${DIM}Config:${RESET}  ${CONFIG_FILE}"
    echo -e "  ${DIM}Compose:${RESET} ${COMPOSE_FILE}"
    echo -e "  ${DIM}Status:${RESET}  systemctl status ${SERVICE_NAME}"
    echo -e "  ${DIM}Compose:${RESET} docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} ps"
    echo -e "  ${DIM}Logs:${RESET}    docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} logs -f"
    echo ""

    if [[ -n "$SECRET" ]]; then
        link_secret="ee${SECRET}${domain_hex}"
        echo -e "  ${BOLD}Connection link:${RESET}"
        echo -e "  ${CYAN}tg://proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${GREEN}${link_secret}${RESET}"
        echo ""
        echo -e "  ${DIM}t.me/proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${link_secret}${RESET}"
    else
        warn "Unable to build link: no valid 32-hex secret found in [access.users]"
    fi

    echo ""
    echo -e "  ${BOLD}DPI Bypass:${RESET}"
    echo -e "  ${GREEN}+${RESET} Anti-Replay Cache"
    echo -e "  ${GREEN}+${RESET} TCPMSS=88"
    if $SYNFIX_OK; then
        echo -e "  ${GREEN}+${RESET} Inbound SYN pacing"
    elif is_true "$ENABLE_SYNFIX"; then
        echo -e "  ${RED}!${RESET} Inbound SYN pacing"
    else
        echo -e "  ${DIM}o Inbound SYN pacing (optional; set ENABLE_SYNFIX=true)${RESET}"
    fi
    if $MASKING_OK; then
        echo -e "  ${GREEN}+${RESET} Self-domain Nginx Masking"
    else
        echo -e "  ${RED}!${RESET} Self-domain Nginx Masking"
    fi
    echo -e "  ${GREEN}+${RESET} Split-TLS"
    if $NFQWS_OK; then
        echo -e "  ${GREEN}+${RESET} TCP Desync nfqws"
    else
        echo -e "  ${RED}!${RESET} TCP Desync nfqws"
    fi
}

[[ $EUID -eq 0 ]] || fail "Run as root"

declare -a COMPOSE

select_default_image
mkdir -p "$INSTALL_DIR"
install_packages
fetch_helper_scripts
write_config_if_missing
write_compose_file
stop_legacy_service
write_compose_service
docker_login_if_needed

info "Pulling ${IMAGE}"
if ! "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull; then
    if $AUTO_SELECTED_CPU_IMAGE; then
        warn "Pull failed for auto-selected CPU image ${IMAGE}; falling back to ${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"
        IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"
        AUTO_SELECTED_CPU_IMAGE=false
        write_compose_file
        info "Pulling ${IMAGE}"
        "${COMPOSE[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull || fail "Docker image pull failed"
    else
        fail "Docker image pull failed"
    fi
fi

apply_firewall_and_tcpmss
setup_ipv6_hopping
setup_masking_and_desync

info "Starting mtproto-proxy Docker Compose service"
if systemctl restart "$SERVICE_NAME"; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Proxy service started"
    else
        fail "Proxy restart finished but service is not active. Check: journalctl -u ${SERVICE_NAME} --no-pager -n 50"
    fi
else
    fail "Proxy failed to restart. Check: journalctl -u ${SERVICE_NAME} --no-pager -n 50"
fi

validate_masking
print_summary
