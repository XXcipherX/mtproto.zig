#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE="${MTPROTO_INSTALLER_E2E_IMAGE:-debian:12}"
LOG_DIR="${MTPROTO_INSTALLER_E2E_LOG_DIR:-$ROOT/test/installer-e2e/logs}"
SAFE_IMAGE="$(printf '%s' "$BASE_IMAGE" | tr '/:.' '---' | tr -cd 'A-Za-z0-9_-')"
TEST_IMAGE="mtproto-compose-installer-e2e:${SAFE_IMAGE}"
CONTAINER="mtproto-compose-installer-e2e-${SAFE_IMAGE}-$$"
INSTALL_DIR=/opt/mtproto-proxy
COMPOSE_FILE="$INSTALL_DIR/compose.yml"
ENV_FILE="$INSTALL_DIR/.env"
CONFIG_FILE="$INSTALL_DIR/config.toml"
TLS_DOMAIN=mask.example.test
WEB_DOMAIN=web.example.test
SECRET=00112233445566778899aabbccddeeff

mkdir -p "$LOG_DIR"

dump_debug() {
    docker logs "$CONTAINER" >"$LOG_DIR/${SAFE_IMAGE}.container.log" 2>&1 || true
    docker exec "$CONTAINER" journalctl --no-pager -n 400 >"$LOG_DIR/${SAFE_IMAGE}.journal.log" 2>&1 || true
    docker exec "$CONTAINER" bash -lc \
        'docker ps -a; docker logs --tail=200 mtproto-proxy; docker logs --tail=200 mtproto-web-relay; docker logs --tail=200 mtproto-mask-caddy' \
        >"$LOG_DIR/${SAFE_IMAGE}.services.log" 2>&1 || true
    docker exec "$CONTAINER" bash -lc \
        'iptables -S; iptables -t mangle -S; systemctl --failed --no-pager; systemctl status docker mtproto-proxy nfqws-mtproto mtproto-mask-health.timer --no-pager' \
        >"$LOG_DIR/${SAFE_IMAGE}.state.log" 2>&1 || true
}

cleanup() {
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        dump_debug
        docker exec "$CONTAINER" docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans \
            >/dev/null 2>&1 || true
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

wait_for_systemd() {
    local state=""
    for _ in $(seq 1 90); do
        state="$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
        case "$state" in
            running|degraded) return 0 ;;
        esac
        sleep 1
    done
    echo "systemd did not become ready (last state: ${state:-unknown})" >&2
    return 1
}

run_installer() {
    docker exec \
        -e DEBIAN_FRONTEND=noninteractive \
        -e REPO_RAW_URL=file:///workspace \
        -e INSTALL_DIR="$INSTALL_DIR" \
        -e IMAGE=ghcr.io/xxcipherx/mtproto.zig:latest \
        -e AUTO_IMAGE_CPU_VARIANT=false \
        -e TLS_DOMAIN="$TLS_DOMAIN" \
        -e PUBLIC_IP=127.0.0.1 \
        -e SECRET="$SECRET" \
        -e ENABLE_MASKING=true \
        -e MASK_SET_PUBLIC_IP=0 \
        -e CHECK_PQ_DOMAIN=false \
        -e ENABLE_WEB=true \
        -e WEB_DOMAIN="$WEB_DOMAIN" \
        -e ENABLE_SYNFIX=true \
        -e SYNFIX_RATE=30/minute \
        -e SYNFIX_BURST=1 \
        -e SYNFIX_ACTION=drop \
        "$CONTAINER" bash /workspace/deploy/install_docker_compose.sh
}

wait_for_status() {
    local domain="$1" port="$2" expected="$3" code=""
    for _ in $(seq 1 30); do
        code="$(docker exec "$CONTAINER" curl -sk --max-time 3 --resolve "${domain}:${port}:127.0.0.1" \
            -o /dev/null -w '%{http_code}' "https://${domain}:${port}/" 2>/dev/null || true)"
        [[ "$code" == "$expected" ]] && return 0
        sleep 1
    done
    echo "${domain}:${port} returned ${code:-no response}, expected HTTP ${expected}" >&2
    return 1
}

assert_no_alt_svc() {
    local domain="$1" port="$2" headers=""
    if ! headers="$(docker exec "$CONTAINER" curl -sk --max-time 3 \
        --resolve "${domain}:${port}:127.0.0.1" \
        -D - -o /dev/null "https://${domain}:${port}/" 2>/dev/null)"; then
        echo "${domain}:${port} failed while checking response headers" >&2
        return 1
    fi
    if grep -qi '^alt-svc:' <<<"$headers"; then
        echo "${domain}:${port} unexpectedly advertises an Alt-Svc endpoint" >&2
        return 1
    fi
}

verify_install() {
    docker exec \
        -e INSTALL_DIR="$INSTALL_DIR" \
        -e COMPOSE_FILE="$COMPOSE_FILE" \
        -e ENV_FILE="$ENV_FILE" \
        -e CONFIG_FILE="$CONFIG_FILE" \
        "$CONTAINER" bash -s <<'CONTAINER_TEST'
set -Eeuo pipefail

test -f "$CONFIG_FILE"
test -f "$COMPOSE_FILE"
test -f "$ENV_FILE"
test "$(stat -c '%a' "$CONFIG_FILE")" = 600
test "$(stat -c '%u:%g' "$CONFIG_FILE")" = 0:0

grep -F 'public_ip = "127.0.0.1"' "$CONFIG_FILE" >/dev/null
grep -F 'tls_domain = "mask.example.test"' "$CONFIG_FILE" >/dev/null
grep -F 'user = "00112233445566778899aabbccddeeff"' "$CONFIG_FILE" >/dev/null
grep -F '[web]' "$CONFIG_FILE" >/dev/null
grep -F 'enabled = true' "$CONFIG_FILE" >/dev/null
grep -F 'domain = "web.example.test"' "$CONFIG_FILE" >/dev/null
grep -F 'COMPOSE_PROFILES=web' "$ENV_FILE" >/dev/null
grep -F 'command: ["web-relay", "/etc/mtproto-proxy/config.toml"]' "$COMPOSE_FILE" >/dev/null
grep -F 'servers 127.0.0.1:8443 {' "$INSTALL_DIR/Caddyfile.mask" >/dev/null
grep -F 'protocols h1 h2' "$INSTALL_DIR/Caddyfile.mask" >/dev/null
! grep -Eq 'protocols .*h3' "$INSTALL_DIR/Caddyfile.mask"
grep -F 'protocols h1 h2' "$INSTALL_DIR/caddy/web/global.caddy" >/dev/null
! grep -Eq 'protocols .*h3' "$INSTALL_DIR/caddy/web/global.caddy"
! grep -R -F 'header_up X-Forwarded-For' "$INSTALL_DIR/caddy/web"
if grep -Rqi -- 'nginx' "$INSTALL_DIR"; then
    echo "installer unexpectedly generated an nginx artifact" >&2
    exit 1
fi

for helper in setup_masking.sh setup_web.sh setup_nfqws.sh setup_synfix.sh setup_mask_monitor.sh; do
    cmp "/workspace/deploy/$helper" "$INSTALL_DIR/$helper"
done

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config >/dev/null
for service in docker mtproto-proxy nfqws-mtproto mtproto-mask-health.timer; do
    systemctl is-active --quiet "$service"
done
for container in mtproto-proxy mtproto-web-relay mtproto-mask-caddy; do
    test "$(docker inspect -f '{{.State.Running}}' "$container")" = true
done
for caddy_file in /etc/caddy/Caddyfile /etc/caddy/web/global.caddy /etc/caddy/web/site.caddy; do
    docker exec mtproto-mask-caddy caddy fmt --diff "$caddy_file" >/dev/null
done

test "$(iptables -S INPUT | grep -c -- '-j MTPR_SYNFIX')" = 1
iptables -S INPUT | grep -F -- '-A INPUT ! -i lo -p tcp' | grep -F -- '--dport 443' | grep -F -- '-j MTPR_SYNFIX' >/dev/null
iptables -t mangle -S PREROUTING | grep -F -- '! -i lo' | grep -F -- '--set-xmark 0x400/' >/dev/null
test "$(iptables -t mangle -S OUTPUT | grep -c -- '--queue-num 200')" = 1
iptables -t mangle -S OUTPUT | grep -F -- '-A OUTPUT ! -o lo -p tcp' | grep -F -- '--sport 443' | grep -F -- '--queue-num 200' >/dev/null
if iptables -t mangle -S OUTPUT | grep -F -- '--sport 443' | grep -q -- '-j TCPMSS'; then
    echo "TCPMSS must stay disabled by default" >&2
    exit 1
fi
CONTAINER_TEST

    wait_for_status "$TLS_DOMAIN" 8443 404
    wait_for_status "$WEB_DOMAIN" 443 404
    assert_no_alt_svc "$TLS_DOMAIN" 8443
    assert_no_alt_svc "$WEB_DOMAIN" 443
}

echo "::group::Build isolated ${BASE_IMAGE} host"
docker build --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "$TEST_IMAGE" "$ROOT/test/installer-e2e"
echo "::endgroup::"

echo "::group::Boot isolated systemd + Docker host"
docker run -d \
    --name "$CONTAINER" \
    --privileged \
    --cgroupns=host \
    --tmpfs /run \
    --tmpfs /run/lock \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$ROOT:/workspace:ro" \
    "$TEST_IMAGE" >/dev/null
wait_for_systemd
echo "::endgroup::"

echo "::group::Fresh Docker Compose install"
run_installer 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.install.log"
grep -F 'WEB HTTPS probe returned expected HTTP 404' "$LOG_DIR/${SAFE_IMAGE}.install.log" >/dev/null
! grep -Eq 'Unnecessary header_up X-Forwarded-For|Caddyfile input is not formatted' \
    "$LOG_DIR/${SAFE_IMAGE}.install.log"
verify_install 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.verify.log"
echo "::endgroup::"

echo "::group::Idempotent reinstall"
before_hash="$(docker exec "$CONTAINER" sha256sum "$CONFIG_FILE" | awk '{print $1}')"
run_installer 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.reinstall.log"
grep -F 'WEB HTTPS probe returned expected HTTP 404' "$LOG_DIR/${SAFE_IMAGE}.reinstall.log" >/dev/null
! grep -Eq 'Unnecessary header_up X-Forwarded-For|Caddyfile input is not formatted' \
    "$LOG_DIR/${SAFE_IMAGE}.reinstall.log"
after_hash="$(docker exec "$CONTAINER" sha256sum "$CONFIG_FILE" | awk '{print $1}')"
if [[ "$before_hash" != "$after_hash" ]]; then
    echo "config.toml changed across identical installer rerun" >&2
    exit 1
fi
verify_install 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.verify-reinstall.log"
echo "::endgroup::"

echo "Installer E2E passed on ${BASE_IMAGE}"
