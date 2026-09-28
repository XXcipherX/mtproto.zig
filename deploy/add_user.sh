#!/usr/bin/env bash
# Host-side access-user management for the source and Docker Compose installers.
set -euo pipefail

dir="${INSTALL_DIR:-/opt/mtproto-proxy}"
config="$dir/config.toml"
compose="$dir/compose.yml"
env_file="$dir/.env"
die() { printf 'add-user: %s\n' "$*" >&2; exit 1; }
true_value() { case "$1" in true|1|yes|on) return 0 ;; *) return 1 ;; esac; }

[[ $# -eq 2 && "$1" == --add-user ]] || die "usage: $0 --add-user NAME"
name="$2"
[[ ${#name} -le 64 && "$name" =~ ^[[:alnum:]_][[:alnum:]_.-]*$ ]] \
    || die "name must be 1-64 letters/digits, dots, underscores or hyphens"
[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -f "$config" && ! -L "$config" && -f "$dir/web_link.sh" ]] || die "installation is incomplete: $dir"

# Shared with the WEB/masking setup scripts and health monitor.
exec 9>"${CADDY_LOCK_FILE:-/run/mtproto-mask-caddy.lock}"
flock 9

setting() {
    awk -v section="$1" -v key="$2" -v fallback="${3:-}" '
        /^[[:space:]]*\[[^]]+\]/ {
            s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
            inside = (s == section); next
        }
        inside && /^[[:space:]]*[^#;=]+[[:space:]]*=/ {
            line = $0; sub(/[;#].*$/, "", line)
            k = line; sub(/=.*/, "", k); gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
            if (k == key) {
                sub(/^[^=]*=/, "", line); gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                sub(/^"/, "", line); sub(/"$/, "", line); value = line
            }
        }
        END { print value == "" ? fallback : value }
    ' "$config"
}

mode=source
if [[ -f "$compose" && -f "$env_file" ]] &&
    systemctl cat mtproto-proxy.service 2>/dev/null |
        grep -Eq '^ExecStart=.*docker[[:space:]]+compose[[:space:]]'; then
    mode=docker
else
    [[ -x "$dir/mtproto-proxy" ]] || die "proxy binary not found: $dir/mtproto-proxy"
fi
web=false
if true_value "$(setting web enabled false)"; then
    web=true
    if [[ "$mode" == source ]]; then
        systemctl cat mtproto-web-relay.service >/dev/null 2>&1 || die "WEB relay service not found"
    fi
fi

apply() {
    if [[ "$mode" == docker ]]; then
        local -a services=(mtproto-proxy)
        $web && services+=(mtproto-web-relay)
        docker compose --env-file "$env_file" -f "$compose" \
            up -d --pull never --force-recreate --no-deps "${services[@]}" || return 1
        local service
        for service in "${services[@]}"; do
            [[ "$(docker inspect -f '{{.State.Running}}' "$service" 2>/dev/null)" == true ]] || return 1
        done
    else
        systemctl restart mtproto-proxy.service && systemctl is-active --quiet mtproto-proxy.service || return 1
        if $web; then
            systemctl restart mtproto-web-relay.service && systemctl is-active --quiet mtproto-web-relay.service || return 1
        fi
    fi
}

new="$(mktemp "$dir/.config.toml.add-user.XXXXXX")"
old=""
published=false
reloaded=false
cleanup() {
    local status=$?
    trap - EXIT
    if (( status != 0 )) && $published; then
        if mv -f -- "$old" "$config"; then
            old=""
            printf 'add-user: original config restored\n' >&2
            if $reloaded; then apply || printf 'add-user: service rollback failed; restart manually\n' >&2; fi
        else
            printf 'add-user: restore config manually from %s\n' "$old" >&2
            old=""
        fi
    fi
    [[ -z "$new" ]] || rm -f -- "$new"
    [[ -z "$old" ]] || rm -f -- "$old"
    exit "$status"
}
trap cleanup EXIT

secret="$(openssl rand -hex 16)" || die "secret generation failed"
[[ "$secret" =~ ^[0-9a-f]{32}$ ]] || die "invalid generated secret"
in_users=false
sections=0
duplicate=false
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*\[[^]]+\] ]]; then
        in_users=false
        if [[ "$line" =~ ^[[:space:]]*\[access\.users\][[:space:]]*([#\;].*)?$ ]]; then
            in_users=true
            ((sections += 1))
            printf '%s\n%s = "%s"\n' "$line" "$name" "$secret" >> "$new"
            continue
        fi
    elif $in_users && [[ "$line" == *'='* ]]; then
        key="${line%%=*}"
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        [[ "$key" != "$name" ]] || duplicate=true
    fi
    printf '%s\n' "$line" >> "$new"
done < "$config"
(( sections <= 1 )) || die "duplicate [access.users] sections"
if $duplicate; then die "user $name already exists"; fi
if (( sections == 0 )); then printf '\n[access.users]\n%s = "%s"\n' "$name" "$secret" >> "$new"; fi
chown --reference="$config" "$new"
chmod --reference="$config" "$new"
old="$(mktemp "$dir/.config.toml.rollback.XXXXXX")"
cp -a -- "$config" "$old"
mv -f -- "$new" "$config"
new=""
published=true

# The one-shot sees the new file-mounted config; running containers still have
# the old inode until Compose recreates them.
if [[ "$mode" == docker ]]; then
    docker compose --env-file "$env_file" -f "$compose" \
        run -T --rm --pull never --no-deps mtproto-proxy /etc/mtproto-proxy/config.toml --check-config \
        || die "new config failed validation"
else
    "$dir/mtproto-proxy" "$config" --check-config || die "new config failed validation"
fi
reloaded=true
apply || die "service reload failed"

# shellcheck source=deploy/web_link.sh
source "$dir/web_link.sh"
domain="$(setting censorship tls_domain google.com)"
address="$(setting server public_ip '<SERVER_IP>')"
port="$(setting server port 443)"
only="$(setting web only "$(setting web web_only false)")"
domain_hex="$(printf '%s' "$domain" | od -An -tx1 | tr -d ' \n')"
printf 'Added user %s; services reloaded. Keep the link(s) private:\n' "$name"
if ! $web || ! true_value "$only"; then
    printf 'tg://proxy?server=%s&port=%s&secret=ee%s%s\n' "$address" "$port" "$secret" "$domain_hex"
fi
if $web; then
    web_domain="$(setting web domain)"
    base_path="$(setting web base_path)"
    printf 'tg://webproxy?server=%s&secret=%s\n' \
        "$(web_proxy_link_address "$web_domain" "$base_path")" \
        "$(web_proxy_link_secret "dd${secret}" "$base_path")"
fi
