#!/bin/sh
# Keep the published example configuration out of the live data path. A container
# started without a mounted config gets a private, random access secret instead.
set -eu

binary=/usr/local/bin/mtproto-proxy
default_config=/etc/mtproto-proxy/config.toml

if [ "$#" -eq 0 ]; then
    set -- "$default_config"
fi

# `web-relay` is a real mtproto-proxy subcommand, not a config path. The WEB
# Compose service mounts the shared config explicitly, so pass every argument
# through unchanged and let the daemon report a missing/invalid config.
if [ "$1" = "web-relay" ]; then
    exec "$binary" "$@"
fi

# Options such as --check-config and --print-links must remain read-only: never
# create a config as a side effect of an inspection command.
case "$1" in
    --*) exec "$binary" "$@" ;;
esac

config=$1
if [ ! -e "$config" ]; then
    config_dir=$(dirname -- "$config")
    mkdir -p -- "$config_dir"

    old_umask=$(umask)
    umask 077
    tmp_config="${config}.tmp.$$"
    trap 'rm -f -- "$tmp_config"' EXIT HUP INT TERM

    secret=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if [ "${#secret}" -ne 32 ]; then
        echo "mtproto-proxy: failed to generate a 32-hex access secret" >&2
        exit 1
    fi

    cat >"$tmp_config" <<EOF
# Generated on first container start. Mount your own config.toml to override it.
[server]
port = 443

[censorship]
tls_domain = "google.com"
mask = true

[access.users]
user1 = "$secret"
EOF
    chmod 0600 "$tmp_config"
    mv -f -- "$tmp_config" "$config"
    trap - EXIT HUP INT TERM
    umask "$old_umask"

    echo "mtproto-proxy: generated $config with a random user1 secret" >&2
    echo "mtproto-proxy: inspect it inside the container; the secret is not written to logs" >&2
fi

exec "$binary" "$@"
