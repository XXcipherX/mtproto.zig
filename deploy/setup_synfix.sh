#!/usr/bin/env bash
#
# setup_synfix.sh — install inbound SYN pacing for MTProto clients.
#
# This protects the client->proxy leg before the proxy process accepts a
# connection. Android/Desktop clients can open multiple parallel TLS attempts;
# on filtered routes that pattern is enough for DPI to stall the following
# ClientHello/FakeTLS flow. The rule set lets iOS-like SYN fingerprints bypass
# the slow lane and paces all other clients per source IP. Loopback is excluded:
# the WEB relay opens one local TCP connection per logical stream, and those
# internal connections must never share an external-client pacing bucket.
# Excess attempts are dropped silently by default so Telegram does not amplify
# noisy retry bursts with immediate tcp-reset feedback.
#
# Usage:
#   sudo bash deploy/setup_synfix.sh
#   sudo bash deploy/setup_synfix.sh --remove
#
# Optional environment:
#   PORT=443
#   SYNFIX_RATE=30/minute
#   SYNFIX_BURST=1
#   SYNFIX_ACTION=drop|reject|icmp-host-unreachable

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mtproto-proxy}"
CONFIG_FILE="${CONFIG_FILE:-${INSTALL_DIR}/config.toml}"
CHAIN="MTPR_SYNFIX"
IOS_MARK="0x400"
SYNFIX_RATE="${SYNFIX_RATE:-30/minute}"
SYNFIX_BURST="${SYNFIX_BURST:-1}"
SYNFIX_ACTION="${SYNFIX_ACTION:-drop}"
SYNFIX_HTABLE_EXPIRE="${SYNFIX_HTABLE_EXPIRE:-60000}"
SYNFIX_HTABLE_SIZE="${SYNFIX_HTABLE_SIZE:-32768}"
IOS_U32='32 & 0x00FFFFFF = 0x0002FFFF && 40 & 0xFF000000 = 0x02000000 && 44 & 0xFFFF0000 = 0x01030000 && 48 & 0xFFFFFF00 = 0x01010800 && 60 & 0xFFFFFFFF = 0x04020000'

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

get_server_port() {
    local cfg="$1"
    awk '
        BEGIN { in_server = 0 }
        /^[[:space:]]*\[server\][[:space:]]*$/ { in_server = 1; next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_server = 0; next }
        in_server {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*port[[:space:]]*=/) {
                split(line, parts, "=")
                value = parts[2]
                gsub(/[^0-9]/, "", value)
                if (value != "") {
                    print value
                    exit
                }
            }
        }
    ' "$cfg" 2>/dev/null
}

PORT="${PORT:-$(get_server_port "$CONFIG_FILE")}"
PORT="${PORT:-443}"

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_synfix.sh"
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "Invalid PORT: ${PORT}"

REMOVE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --remove|--uninstall)
            REMOVE=true
            shift
            ;;
        --reject)
            SYNFIX_ACTION="reject"
            shift
            ;;
        --drop)
            SYNFIX_ACTION="drop"
            shift
            ;;
        --icmp-host-unreachable|--icmp)
            SYNFIX_ACTION="icmp-host-unreachable"
            shift
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

case "${SYNFIX_ACTION,,}" in
    reject|rst|reset|tcp-reset) SYNFIX_ACTION="reject" ;;
    icmp|host-unreachable|icmp-host-unreachable) SYNFIX_ACTION="icmp-host-unreachable" ;;
    drop) SYNFIX_ACTION="drop" ;;
    *) fail "Invalid SYNFIX_ACTION: ${SYNFIX_ACTION} (expected drop, reject, or icmp-host-unreachable)" ;;
esac

remove_rules() {
    if command -v iptables >/dev/null 2>&1; then
        while iptables -D INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null; do :; done
        while iptables -D INPUT ! -i lo -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null; do :; done
        while iptables -t mangle -D PREROUTING \
            -p tcp --dport "$PORT" --syn \
            -m u32 --u32 "$IOS_U32" \
            -j MARK --set-mark "$IOS_MARK" 2>/dev/null; do :; done
        while iptables -t mangle -D PREROUTING \
            ! -i lo -p tcp --dport "$PORT" --syn \
            -m u32 --u32 "$IOS_U32" \
            -j MARK --set-mark "$IOS_MARK" 2>/dev/null; do :; done
        iptables -F "$CHAIN" 2>/dev/null || true
        iptables -X "$CHAIN" 2>/dev/null || true
    fi
}

persist_rules() {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable netfilter-persistent.service >/dev/null 2>&1 || true
    fi
}

if $REMOVE; then
    info "Removing MTProto SYN fix rules for port ${PORT}..."
    remove_rules
    persist_rules
    ok "MTProto SYN fix removed"
    exit 0
fi

command -v iptables >/dev/null 2>&1 || fail "iptables not found"

info "Installing MTProto SYN fix for TCP/${PORT}..."
remove_rules

iptables -N "$CHAIN"

iptables -t mangle -A PREROUTING \
    ! -i lo -p tcp --dport "$PORT" --syn \
    -m u32 --u32 "$IOS_U32" \
    -j MARK --set-mark "$IOS_MARK"

iptables -A "$CHAIN" \
    -p tcp --dport "$PORT" --syn \
    -m mark --mark "$IOS_MARK" \
    -j ACCEPT

iptables -A "$CHAIN" \
    -p tcp --dport "$PORT" --syn \
    -m hashlimit \
    --hashlimit-name "mtproto_${PORT}" \
    --hashlimit-mode srcip \
    --hashlimit-upto "$SYNFIX_RATE" \
    --hashlimit-burst "$SYNFIX_BURST" \
    --hashlimit-htable-expire "$SYNFIX_HTABLE_EXPIRE" \
    --hashlimit-htable-size "$SYNFIX_HTABLE_SIZE" \
    -j ACCEPT

case "$SYNFIX_ACTION" in
    reject)
        iptables -A "$CHAIN" \
            -p tcp --dport "$PORT" --syn \
            -j REJECT --reject-with tcp-reset
        ;;
    icmp-host-unreachable)
        iptables -A "$CHAIN" \
            -p tcp --dport "$PORT" --syn \
            -j REJECT --reject-with icmp-host-unreachable
        ;;
    drop)
        iptables -A "$CHAIN" \
            -p tcp --dport "$PORT" --syn \
            -j DROP
        ;;
esac

iptables -A "$CHAIN" -j RETURN

iptables -I INPUT 1 ! -i lo -p tcp --dport "$PORT" --syn -j "$CHAIN"
persist_rules

ok "MTProto SYN fix applied"
echo ""
echo -e "${BOLD}${CYAN}MTProto SYN fix${RESET}"
echo -e "  ${DIM}Port:${RESET}       ${PORT}"
echo -e "  ${DIM}iOS mark:${RESET}   ${IOS_MARK}"
echo -e "  ${DIM}Other rate:${RESET} ${SYNFIX_RATE}, burst ${SYNFIX_BURST}"
echo -e "  ${DIM}Action:${RESET}     ${SYNFIX_ACTION}"
echo -e "  ${DIM}Loopback:${RESET}   excluded (WEB relay streams bypass pacing)"
echo ""
