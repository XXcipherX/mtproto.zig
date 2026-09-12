#!/usr/bin/env bash
# Shared WEB-link encoding helpers. This file is sourced by deployment scripts.

web_proxy_link_address() {
    local domain="$1" base_path="${2:-}" escaped_path
    if [[ -z "$base_path" ]]; then
        printf '%s' "$domain"
        return
    fi
    escaped_path="${base_path//\//%2F}"
    printf '%s%%2F%s' "$domain" "$escaped_path"
}

# Print the client-facing MTProxy secret unchanged for a root deployment. For a
# base path, print unpadded base64url(0x70 || secret_bytes), as required by the
# Telegram WEB-proxy link format. Binary bytes go directly through the pipe so
# shell command substitution never has a chance to discard NUL bytes.
web_proxy_link_secret() {
    local secret_hex="$1" base_path="${2:-}" index
    if [[ -z "$base_path" ]]; then
        printf '%s' "$secret_hex"
        return
    fi
    [[ "$secret_hex" =~ ^[0-9A-Fa-f]+$ ]] || return 1
    (( ${#secret_hex} % 2 == 0 )) || return 1
    {
        printf '\x70'
        for ((index = 0; index < ${#secret_hex}; index += 2)); do
            printf '%b' "\\x${secret_hex:index:2}"
        done
    } | base64 | tr '+/' '-_' | tr -d '=\n'
}
