#!/usr/bin/env bash
# Configure Telegram Desktop WEB proxy alongside the existing Caddy-masked
# mtproto.zig service. Public :443 remains owned by mtproto-proxy.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
CONFIG_FILE="${CONFIG_FILE:-${INSTALL_DIR}/config.toml}"
COMPOSE_FILE="${COMPOSE_FILE:-${INSTALL_DIR}/compose.yml}"
ENV_FILE="${ENV_FILE:-${INSTALL_DIR}/.env}"
CADDY_LOCK_FILE="/run/mtproto-mask-caddy.lock"
ACME_ROOT="${MASK_ACME_ROOT:-/var/www/certbot}"
CADDYFILE="${CADDYFILE:-/etc/caddy/mtproto-mask.Caddyfile}"
WEB_PORT="${WEB_PORT:-8081}"
WEB_TLS_PORT="${WEB_TLS_PORT:-8444}"
WEB_DOMAIN="${WEB_DOMAIN:-}"
if [[ -v WEB_BASE_PATH ]]; then WEB_BASE_PATH_EXPLICIT=true; else WEB_BASE_PATH_EXPLICIT=false; fi
WEB_BASE_PATH="${WEB_BASE_PATH:-}"
WEB_FORCE_DOMAIN_CHANGE="${WEB_FORCE_DOMAIN_CHANGE:-false}"
WEB_FORCE_BASE_PATH_CHANGE="${WEB_FORCE_BASE_PATH_CHANGE:-false}"
if [[ -v WEB_ONLY ]]; then WEB_ONLY_EXPLICIT=true; else WEB_ONLY_EXPLICIT=false; fi
WEB_ONLY="${WEB_ONLY:-false}"
REMOVE=false

info() { printf '> %s\n' "$*"; }
ok() { printf '+ %s\n' "$*"; }
fail() { printf 'x %s\n' "$*" >&2; exit 1; }

acquire_caddy_operation_lock() {
    command -v flock >/dev/null 2>&1 || fail "flock is required; install util-linux"
    exec 9>"$CADDY_LOCK_FILE"
    flock 9
}

MASK_HEALTH_TIMER_WAS_ACTIVE=false
pause_mask_health_monitor() {
    command -v systemctl >/dev/null 2>&1 || return 0
    if systemctl is-active --quiet mtproto-mask-health.timer; then
        MASK_HEALTH_TIMER_WAS_ACTIVE=true
    fi
    systemctl stop mtproto-mask-health.timer >/dev/null 2>&1 || true
    for _ in {1..30}; do
        if ! systemctl is-active --quiet mtproto-mask-health.service; then
            return 0
        fi
        sleep 1
    done
    fail "masking health check did not quiesce before Caddy maintenance"
}

resume_mask_health_monitor() {
    if $MASK_HEALTH_TIMER_WAS_ACTIVE && command -v systemctl >/dev/null 2>&1; then
        systemctl start mtproto-mask-health.timer >/dev/null 2>&1 || true
    fi
}

is_true() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

POSITIONAL_DOMAIN=""
while (($# > 0)); do
    case "$1" in
        --remove)
            REMOVE=true
            ;;
        --only)
            WEB_ONLY=true
            WEB_ONLY_EXPLICIT=true
            ;;
        --no-only)
            WEB_ONLY=false
            WEB_ONLY_EXPLICIT=true
            ;;
        --force)
            WEB_FORCE_DOMAIN_CHANGE=true
            WEB_FORCE_BASE_PATH_CHANGE=true
            ;;
        --base-path)
            shift
            (($# > 0)) || fail "--base-path requires a path or 'none'"
            WEB_BASE_PATH="$1"
            WEB_BASE_PATH_EXPLICIT=true
            ;;
        -h|--help)
            printf 'Usage: setup_web.sh [--only|--no-only] [--base-path PATH|none] [--force] web.example.com\n'
            printf '       setup_web.sh --remove\n'
            exit 0
            ;;
        -*)
            fail "Unknown option: $1"
            ;;
        *)
            [[ -z "$POSITIONAL_DOMAIN" ]] || fail "Only one WEB domain may be specified"
            POSITIONAL_DOMAIN="$1"
            ;;
    esac
    shift
done
WEB_DOMAIN="${WEB_DOMAIN:-$POSITIONAL_DOMAIN}"

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

trap resume_mask_health_monitor EXIT
pause_mask_health_monitor
acquire_caddy_operation_lock

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

remove_config_key() {
    local section="$1" key="$2" tmp
    tmp="$(mktemp)"
    awk -v want_section="$section" -v want_key="$key" '
        BEGIN { in_section = 0 }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            header = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", header)
            in_section = (header == want_section)
            print
            next
        }
        in_section && $0 ~ "^[[:space:]]*" want_key "[[:space:]]*=" { next }
        { print }
    ' "$CONFIG_FILE" > "$tmp"
    install -o "$CONFIG_UID" -g "$CONFIG_GID" -m "$CONFIG_MODE" "$tmp" "$CONFIG_FILE"
    rm -f "$tmp"
}

get_config_value() {
    local section="$1" key="$2" fallback="${3:-}"
    awk -v want_section="$section" -v want_key="$key" -v fallback="$fallback" '
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
                sub(/^[^=]*=/, "", line)
                gsub(/^[[:space:]\"]+|[[:space:]\"]+$/, "", line)
                value = line
            }
        }
        END { print value == "" ? fallback : value }
    ' "$CONFIG_FILE"
}

WEB_PREVIOUS_ONLY="$(get_config_value web only "")"
if [[ -z "$WEB_PREVIOUS_ONLY" ]]; then
    WEB_PREVIOUS_ONLY="$(get_config_value web web_only false)"
fi
if ! $WEB_ONLY_EXPLICIT; then
    WEB_ONLY="$WEB_PREVIOUS_ONLY"
fi
case "${WEB_ONLY,,}" in
    1|true|yes|on) WEB_ONLY=true ;;
    0|false|no|off|"") WEB_ONLY=false ;;
    *) fail "WEB_ONLY must be true or false" ;;
esac
if $REMOVE; then WEB_ONLY=false; fi

ensure_caddy_imports() {
    [[ -f "$CADDYFILE" ]] || fail "Existing Caddy masking config not found: ${CADDYFILE}. Run setup_masking.sh first."
    grep -Fq 'import /etc/caddy/web/global.caddy' "$CADDYFILE" \
        || fail "Caddy config is from an older installer. Rerun the latest setup_masking.sh, then setup_web.sh."
    grep -Fq 'import /etc/caddy/web/site.caddy' "$CADDYFILE" \
        || fail "Caddy WEB site import is missing. Rerun the latest setup_masking.sh first."
}

validate_caddy() {
    if is_docker_install; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" run --rm --no-deps \
            mtproto-mask-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    else
        caddy validate --config "$CADDYFILE" --adapter caddyfile
    fi
}

reload_caddy() {
    validate_caddy || return 1
    if is_docker_install; then
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-mask-caddy
        sleep 1
        [[ "$(docker inspect -f '{{.State.Running}}' mtproto-mask-caddy 2>/dev/null || true)" == "true" ]] \
            || fail "Caddy did not stay running after the WEB configuration reload"
    else
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
    remove_config_key web only
    remove_config_key web web_only
    rm -f /etc/letsencrypt/renewal-hooks/deploy/mtproto-web-caddy-reload.sh
    if is_docker_install; then
        set_env_value COMPOSE_PROFILES ""
        set_env_value WEB_ONLY false
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

WEB_LINK_HELPER="${INSTALL_DIR}/web_link.sh"
if [[ ! -r "$WEB_LINK_HELPER" ]]; then
    WEB_LINK_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/web_link.sh"
fi
[[ -r "$WEB_LINK_HELPER" ]] || fail "WEB link helper not found; update web_link.sh together with setup_web.sh"
# shellcheck source=deploy/web_link.sh
source "$WEB_LINK_HELPER"

WEB_PROBE_HELPER="${INSTALL_DIR}/web_probe.py"
if [[ ! -r "$WEB_PROBE_HELPER" ]]; then
    WEB_PROBE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/web_probe.py"
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
EXISTING_WEB_DOMAIN="$(get_config_value web domain "")"
EXISTING_WEB_BASE_PATH="$(get_config_value web base_path "")"
if [[ -n "$EXISTING_WEB_DOMAIN" && "${EXISTING_WEB_DOMAIN,,}" != "$WEB_DOMAIN" ]] &&
    ! is_true "$WEB_FORCE_DOMAIN_CHANGE"
then
    fail "Changing [web].domain invalidates existing WEB links. Use --force or WEB_FORCE_DOMAIN_CHANGE=true to change it explicitly."
fi

# A fresh WEB deployment follows the reference server and gets an 80-bit,
# 16-character lowercase RFC 4648 base32 prefix. Re-running an existing setup
# preserves its configured path; a pre-path config therefore remains at root.
if $WEB_BASE_PATH_EXPLICIT; then
    if [[ "$WEB_BASE_PATH" == "none" ]]; then WEB_BASE_PATH=""; fi
elif [[ -n "$EXISTING_WEB_DOMAIN" ]]; then
    WEB_BASE_PATH="$EXISTING_WEB_BASE_PATH"
else
    command -v base32 >/dev/null 2>&1 \
        || fail "base32 (coreutils) is required to generate WEB_BASE_PATH; set WEB_BASE_PATH explicitly"
    WEB_BASE_PATH="$(head -c 10 /dev/urandom | base32 | tr 'A-Z' 'a-z' | tr -d '\n')"
fi

if [[ -n "$WEB_BASE_PATH" ]]; then
    [[ ${#WEB_BASE_PATH} -le 128 ]] || fail "WEB base path must be at most 128 characters"
    [[ "$WEB_BASE_PATH" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)*$ ]] \
        || fail "WEB base path segments must match [A-Za-z0-9][A-Za-z0-9_-]* and be joined by /"
fi
if [[ -n "$EXISTING_WEB_DOMAIN" && "$EXISTING_WEB_BASE_PATH" != "$WEB_BASE_PATH" ]] &&
    ! is_true "$WEB_FORCE_BASE_PATH_CHANGE"
then
    fail "Changing [web].base_path invalidates existing WEB links. Use --force or WEB_FORCE_BASE_PATH_CHANGE=true to change it explicitly."
fi

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
chmod 0755 "$ACME_ROOT" "$ACME_ROOT/.well-known" "$ACME_ROOT/.well-known/acme-challenge"

LE_CERT="/etc/letsencrypt/live/${WEB_DOMAIN}/fullchain.pem"
LE_KEY="/etc/letsencrypt/live/${WEB_DOMAIN}/privkey.pem"
if [[ ! -f "$LE_CERT" || ! -f "$LE_KEY" ]] ||
    ! openssl x509 -checkend 86400 -noout -in "$LE_CERT" >/dev/null 2>&1
then
    info "Requesting Let's Encrypt certificate for ${WEB_DOMAIN} through the existing Caddy :80 ACME webroot"
    certbot certonly --webroot -w "$ACME_ROOT" -d "$WEB_DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email
else
    ok "Reusing Let's Encrypt certificate for ${WEB_DOMAIN}"
fi

# Validate the existing Caddy tree before replacing any live WEB files. If the
# candidate fails validation, restore the previous config and certificate pair.
validate_caddy || fail "Existing Caddy configuration is invalid; fix it before enabling WEB"
WEB_BACKUP="$(mktemp -d "${CADDY_WEB_DIR}/.backup.XXXXXX")"
cp -a "$CADDY_WEB_DIR/global.caddy" "$CADDY_WEB_DIR/site.caddy" "$CADDY_WEB_DIR/cert" "$WEB_BACKUP/"
cp -a "$CONFIG_FILE" "$WEB_BACKUP/config.toml"
WEB_CANDIDATE_VALID=false
cleanup_web_candidate() {
    local status=$?
    if ! $WEB_CANDIDATE_VALID; then
        cp -a "$WEB_BACKUP/global.caddy" "$WEB_BACKUP/site.caddy" "$CADDY_WEB_DIR/"
        rm -f "$CADDY_WEB_DIR/cert/fullchain.pem" "$CADDY_WEB_DIR/cert/privkey.pem"
        cp -a "$WEB_BACKUP/cert/." "$CADDY_WEB_DIR/cert/"
        cp -a "$WEB_BACKUP/config.toml" "$CONFIG_FILE"
        info "Restored the previous WEB configuration after setup failed"
    fi
    rm -rf -- "$WEB_BACKUP"
    resume_mask_health_monitor
    return "$status"
}
trap cleanup_web_candidate EXIT

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
# Keep an existing WEB-only gate intact during reinstall. A new gate is enabled
# only after Caddy and the relay have both passed the health checks below.
if is_true "$WEB_ONLY" && is_true "$WEB_PREVIOUS_ONLY"; then
    set_config_value web only true
else
    remove_config_key web only
fi
remove_config_key web web_only
set_config_value web domain "\"${WEB_DOMAIN}\""
set_config_value web base_path "\"${WEB_BASE_PATH}\""
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
	protocols h1 h2
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
	protocols h1 h2
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
	header {
		-Via
	}
	reverse_proxy 127.0.0.1:${WEB_PORT} {
		flush_interval -1
		stream_close_delay 5m
	}
	handle_errors {
		respond 404
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
	header {
		-Via
	}
	reverse_proxy 127.0.0.1:${WEB_PORT} {
		flush_interval -1
		stream_close_delay 5m
	}
	handle_errors {
		respond 404
	}
}
EOF
fi

verify_web_path() {
    local probe_ip="${TUNNEL_HOST_IP:+10.200.200.2}" probe_result attempt
    probe_ip="${probe_ip:-127.0.0.1}"
    command -v python3 >/dev/null 2>&1 || return 1
    [[ -r "$WEB_PROBE_HELPER" ]] || return 1
    for attempt in 1 2 3 4 5 6; do
        if is_docker_install; then
            probe_result="$(
                docker exec -i mtproto-proxy /usr/local/bin/mtproto-proxy \
                    web-probe-material /etc/mtproto-proxy/config.toml |
                    env WEB_PROBE_ADDRESS="$probe_ip" WEB_PROBE_PORT=443 \
                        python3 "$WEB_PROBE_HELPER" 2>/dev/null
            )" || probe_result=""
        else
            probe_result="$(
                "${INSTALL_DIR}/mtproto-proxy" web-probe-material "$CONFIG_FILE" |
                    env WEB_PROBE_ADDRESS="$probe_ip" WEB_PROBE_PORT=443 \
                        python3 "$WEB_PROBE_HELPER" 2>/dev/null
            )" || probe_result=""
        fi
        if [[ "$probe_result" == "WEB_PROBE_OK" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

WEB_PATH_VERIFIED=false
if is_docker_install; then
    command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
    grep -Eq '^[[:space:]]+mtproto-web-relay:[[:space:]]*$' "$COMPOSE_FILE" \
        || fail "Compose file lacks WEB relay; rerun the latest install_docker_compose.sh, then setup_web.sh"
    set_env_value COMPOSE_PROFILES web
    set_env_value WEB_DOMAIN "$WEB_DOMAIN"
    set_env_value WEB_BASE_PATH "${WEB_BASE_PATH:-none}"
    set_env_value WEB_ONLY "$WEB_ONLY"
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull mtproto-proxy mtproto-web-relay mtproto-mask-caddy
    reload_caddy
    WEB_CANDIDATE_VALID=true
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate mtproto-proxy mtproto-web-relay
    for _ in $(seq 1 10); do
        if [[ "$(docker inspect -f '{{.State.Running}}' mtproto-proxy 2>/dev/null || true)" == "true" ]] &&
            [[ "$(docker inspect -f '{{.State.Running}}' mtproto-web-relay 2>/dev/null || true)" == "true" ]]
        then
            break
        fi
        sleep 1
    done
    [[ "$(docker inspect -f '{{.State.Running}}' mtproto-proxy 2>/dev/null || true)" == "true" ]] \
        || fail "MTProto data plane did not stay running"
    [[ "$(docker inspect -f '{{.State.Running}}' mtproto-web-relay 2>/dev/null || true)" == "true" ]] \
        || fail "WEB relay did not stay running; WEB-only was not activated"

    if is_true "$WEB_ONLY"; then
        verify_web_path || fail "WEB TLS/WSS/MTProto req_pq probe failed; a new WEB-only gate was not activated"
        WEB_PATH_VERIFIED=true
        set_config_value web only true
        docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --force-recreate --no-deps mtproto-proxy
        sleep 1
        [[ "$(docker inspect -f '{{.State.Running}}' mtproto-proxy 2>/dev/null || true)" == "true" ]] \
            || fail "MTProto data plane failed after WEB-only activation"
    fi
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
    WEB_CANDIDATE_VALID=true
    systemctl enable mtproto-web-relay.service >/dev/null
    systemctl restart mtproto-proxy mtproto-web-relay.service
    systemctl is-active --quiet mtproto-proxy \
        || fail "MTProto data plane did not stay running"
    systemctl is-active --quiet mtproto-web-relay.service \
        || fail "WEB relay did not stay running; WEB-only was not activated"

    if is_true "$WEB_ONLY"; then
        verify_web_path || fail "WEB TLS/WSS/MTProto req_pq probe failed; a new WEB-only gate was not activated"
        WEB_PATH_VERIFIED=true
        set_config_value web only true
        systemctl restart mtproto-proxy
        sleep 1
        systemctl is-active --quiet mtproto-proxy \
            || fail "MTProto data plane failed after WEB-only activation"
    fi
fi

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/mtproto-web-caddy-reload.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
command -v flock >/dev/null 2>&1 || exit 1
exec 9>${CADDY_LOCK_FILE}
flock 9
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
if $WEB_PATH_VERIFIED || verify_web_path; then
    ok "Authenticated WEB path reached Telegram (req_pq/resPQ)"
else
    info "Full WEB TLS/WSS/MTProto probe failed; direct MTProto remains available, inspect the proxy and Caddy logs"
fi

WEB_LINK_ADDRESS="$(web_proxy_link_address "$WEB_DOMAIN" "$WEB_BASE_PATH")"
WEB_LINK_SECRET="$(web_proxy_link_secret "dd${SECRET}" "$WEB_BASE_PATH")" \
    || fail "Could not encode the WEB link secret"
if is_true "$WEB_ONLY"; then
    ok "WEB proxy enabled in WEB-only mode, using the existing Caddy instance"
else
    ok "WEB proxy enabled alongside ordinary MTProto, using the existing Caddy instance"
fi
printf '  WEB:      tg://webproxy?server=%s&secret=%s\n' "$WEB_LINK_ADDRESS" "$WEB_LINK_SECRET"
if is_true "$WEB_ONLY"; then
    printf '  MTProto:  direct links are masked; only the trusted WEB relay is served\n'
else
    printf '  MTProto:  unchanged on the existing public endpoint\n'
fi
if is_docker_install; then
    printf '  Logs:     docker compose --env-file %s -f %s logs -f mtproto-proxy mtproto-web-relay mtproto-mask-caddy\n' "$ENV_FILE" "$COMPOSE_FILE"
else
    printf '  Logs:     journalctl -u mtproto-proxy -u mtproto-web-relay -u mtproto-mask-caddy -f\n'
fi
