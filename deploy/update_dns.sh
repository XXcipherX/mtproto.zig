#!/bin/bash
set -eo pipefail

NEW_IP="${1:-}"

if [ -z "$NEW_IP" ]; then
    echo "Usage: $0 <new_ip>"
    exit 1
fi

# Load variables if .env exists
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

DNS_NAME="${DNS_NAME:-}"

if [ -z "${CF_TOKEN:-}" ] || [ -z "${CF_ZONE:-}" ]; then
    echo "WARNING: CF_TOKEN or CF_ZONE not set in .env. Skipping DNS update."
    exit 0
fi

if [ -z "$DNS_NAME" ]; then
    echo "ERROR: DNS_NAME is not set. Add DNS_NAME=proxy.example.com to .env."
    exit 1
fi

if [[ ! "$DNS_NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    echo "ERROR: invalid DNS_NAME: $DNS_NAME"
    exit 1
fi

IFS=. read -r ip_a ip_b ip_c ip_d <<< "$NEW_IP"
for octet in "$ip_a" "$ip_b" "$ip_c" "$ip_d"; do
    if [[ ! "$octet" =~ ^[0-9]+$ ]] || (( octet > 255 )); then
        echo "ERROR: invalid IPv4 address: $NEW_IP"
        exit 1
    fi
done

echo "Updating $DNS_NAME A record to $NEW_IP..."

RECORD_ID=$(curl -s -X GET \
    "https://api.cloudflare.com/client/v4/zones/${CF_ZONE}/dns_records?type=A&name=${DNS_NAME}" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    | grep -oE '"id":"[^"]+"' | head -1 | cut -d'"' -f4)

if [ -z "$RECORD_ID" ]; then
    echo "Creating new A record..."
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE}/dns_records" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"A\",\"name\":\"${DNS_NAME}\",\"content\":\"${NEW_IP}\",\"ttl\":60,\"proxied\":false}" > /dev/null
else
    echo "Updating existing A record ($RECORD_ID)..."
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE}/dns_records/${RECORD_ID}" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"A\",\"name\":\"${DNS_NAME}\",\"content\":\"${NEW_IP}\",\"ttl\":60,\"proxied\":false}" > /dev/null
fi
echo "DNS A record updated successfully!"
