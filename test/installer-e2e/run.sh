#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE="${MTPROTO_INSTALLER_E2E_IMAGE:-debian:12}"
LOG_DIR="${MTPROTO_INSTALLER_E2E_LOG_DIR:-$ROOT/test/installer-e2e/logs}"
SAFE_IMAGE="$(printf '%s' "$BASE_IMAGE" | tr '/:.' '---' | tr -cd 'A-Za-z0-9_-')"
TEST_IMAGE="mtproto-compose-installer-e2e:${SAFE_IMAGE}"
CURRENT_IMAGE="mtproto-compose-current:${SAFE_IMAGE}"
INSTALL_IMAGE="127.0.0.1:5000/mtproto-proxy:current"
REGISTRY_CONTAINER=mtproto-installer-e2e-registry
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
        -e IMAGE="$INSTALL_IMAGE" \
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
    local expected_image_id
    expected_image_id="$(docker exec "$CONTAINER" docker image inspect -f '{{.Id}}' "$INSTALL_IMAGE")"
    docker exec \
        -e INSTALL_DIR="$INSTALL_DIR" \
        -e COMPOSE_FILE="$COMPOSE_FILE" \
        -e ENV_FILE="$ENV_FILE" \
        -e CONFIG_FILE="$CONFIG_FILE" \
        -e INSTALL_IMAGE="$INSTALL_IMAGE" \
        -e EXPECTED_IMAGE_ID="$expected_image_id" \
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
web_base_path="$(awk '
    /^\[web\]/{inside=1; next}
    /^\[/{inside=0}
    inside && /^[[:space:]]*base_path[[:space:]]*=/ {
        line=$0; sub(/^[^=]*=/,"",line); gsub(/^[[:space:]\"]+|[[:space:]\"]+$/,"",line); print line; exit
    }
' "$CONFIG_FILE")"
[[ "$web_base_path" =~ ^[a-z2-7]{16}$ ]]
grep -F 'COMPOSE_PROFILES=web' "$ENV_FILE" >/dev/null
grep -F "WEB_BASE_PATH=$web_base_path" "$ENV_FILE" >/dev/null
grep -F "MTPROTO_IMAGE=$INSTALL_IMAGE" "$ENV_FILE" >/dev/null
grep -F 'command: ["web-relay", "/etc/mtproto-proxy/config.toml"]' "$COMPOSE_FILE" >/dev/null
grep -F 'servers 127.0.0.1:8443 {' "$INSTALL_DIR/Caddyfile.mask" >/dev/null
grep -F 'protocols h1 h2' "$INSTALL_DIR/Caddyfile.mask" >/dev/null
! grep -Eq 'protocols .*h3' "$INSTALL_DIR/Caddyfile.mask"
grep -F 'protocols h1 h2' "$INSTALL_DIR/caddy/web/global.caddy" >/dev/null
! grep -Eq 'protocols .*h3' "$INSTALL_DIR/caddy/web/global.caddy"
! grep -R -F 'header_up X-Forwarded-For' "$INSTALL_DIR/caddy/web"
grep -F -- '-Via' "$INSTALL_DIR/caddy/web/site.caddy" >/dev/null
grep -F 'reverse_proxy 127.0.0.1:8081 {' "$INSTALL_DIR/caddy/web/site.caddy" >/dev/null
grep -F 'handle_errors {' "$INSTALL_DIR/caddy/web/site.caddy" >/dev/null
! grep -Eq '@web_bridge_(page|socket)|query (bridge|b)=\*' "$INSTALL_DIR/caddy/web/site.caddy"
if grep -Rqi -- 'nginx' "$INSTALL_DIR"; then
    echo "installer unexpectedly generated an nginx artifact" >&2
    exit 1
fi

for helper in setup_masking.sh setup_web.sh web_link.sh add_user.sh web_probe.py setup_nfqws.sh setup_synfix.sh setup_mask_monitor.sh; do
    cmp "/workspace/deploy/$helper" "$INSTALL_DIR/$helper"
done

# Root links stay hexadecimal. Base-path links percent-encode every slash and
# wrap the complete dd secret in the official 0x70 marker.
# shellcheck source=deploy/web_link.sh
source "$INSTALL_DIR/web_link.sh"
test "$(web_proxy_link_address web.example.test '')" = 'web.example.test'
test "$(web_proxy_link_secret dd00112233445566778899aabbccddeeff '')" = 'dd00112233445566778899aabbccddeeff'
test "$(web_proxy_link_address web.example.test 'one/two')" = 'web.example.test%2Fone%2Ftwo'
test "$(web_proxy_link_secret dd000102030405060708090a0b0c0d0e0f path)" = 'cN0AAQIDBAUGBwgJCgsMDQ4P'

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config >/dev/null
for service in docker mtproto-proxy nfqws-mtproto mtproto-mask-health.timer; do
    systemctl is-active --quiet "$service"
done
systemctl is-enabled --quiet netfilter-persistent.service
for container in mtproto-proxy mtproto-web-relay mtproto-mask-caddy; do
    test "$(docker inspect -f '{{.State.Running}}' "$container")" = true
done
for container in mtproto-proxy mtproto-web-relay; do
    test "$(docker inspect -f '{{.Image}}' "$container")" = "$EXPECTED_IMAGE_ID"
done
for caddy_file in /etc/caddy/Caddyfile /etc/caddy/web/global.caddy /etc/caddy/web/site.caddy; do
    docker exec mtproto-mask-caddy caddy fmt --diff "$caddy_file" >/dev/null
done

test "$(iptables -S INPUT | grep -c -- '-j MTPR_SYNFIX')" = 1
iptables -S INPUT | grep -F -- '-A INPUT ! -i lo -p tcp' | grep -F -- '--dport 443' | grep -F -- '-j MTPR_SYNFIX' >/dev/null
iptables -t mangle -S PREROUTING | grep -F -- '! -i lo' | grep -F -- '--set-xmark 0x400/' >/dev/null
test "$(iptables -t mangle -S OUTPUT | grep -c -- '--queue-num 200')" = 1
iptables -t mangle -S OUTPUT | grep -F -- '-A OUTPUT ! -o lo -p tcp' | grep -F -- '--sport 443' | grep -F -- '--queue-num 200' >/dev/null
grep -F -- '-j MTPR_SYNFIX' /etc/iptables/rules.v4 >/dev/null
grep -F -- '--queue-num 200' /etc/iptables/rules.v4 >/dev/null
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

verify_masking_maintenance_lock() {
    docker exec "$CONTAINER" bash -s <<'CONTAINER_TEST'
set -Eeuo pipefail

lock_file=/run/mtproto-mask-caddy.lock
container=mtproto-mask-caddy

exec 9>"$lock_file"
flock 9

restore_caddy() {
    flock -u 9 >/dev/null 2>&1 || true
    docker start "$container" >/dev/null 2>&1 || true
}
trap restore_caddy EXIT

before_id="$(docker inspect -f '{{.Id}}' "$container")"
docker stop "$container" >/dev/null

# A timer firing inside an installer/reload critical section must succeed
# without starting or recreating Caddy. The next timer tick will probe again.
/usr/local/bin/mtproto-mask-health.sh
test "$(docker inspect -f '{{.State.Running}}' "$container")" = false
test "$(docker inspect -f '{{.Id}}' "$container")" = "$before_id"

flock -u 9
docker start "$container" >/dev/null
trap - EXIT

for _ in $(seq 1 10); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$container")" == true ]]; then
        exit 0
    fi
    sleep 1
done
echo "Caddy did not recover after the maintenance-lock test" >&2
exit 1
CONTAINER_TEST
}

verify_add_user() {
    # Capture the command's links for assertions instead of echoing its output.
    docker exec -i \
        -e INSTALL_DIR="$INSTALL_DIR" \
        -e CONFIG_FILE="$CONFIG_FILE" \
        -e ENV_FILE="$ENV_FILE" \
        -e ORIGINAL_SECRET="$SECRET" \
        "$CONTAINER" bash -s <<'CONTAINER_TEST'
set -Eeuo pipefail

proxy_before="$(docker inspect -f '{{.Id}}' mtproto-proxy)"
relay_before="$(docker inspect -f '{{.Id}}' mtproto-web-relay)"
caddy_before="$(docker inspect -f '{{.Id}}' mtproto-mask-caddy)"
attributes_before="$(stat -c '%u:%g:%a' "$CONFIG_FILE")"
if ! output="$("$INSTALL_DIR/add_user.sh" --add-user tablet-2 2>&1)"; then
    echo 'add_user.sh failed to add a user' >&2
    exit 1
fi

new_secret="$(awk -F '"' '/^[[:space:]]*tablet-2[[:space:]]*=/{print $2; exit}' "$CONFIG_FILE")"
[[ "$new_secret" =~ ^[0-9a-f]{32}$ && "$new_secret" != "$ORIGINAL_SECRET" ]]
grep -Fq "user = \"$ORIGINAL_SECRET\"" "$CONFIG_FILE"
test "$(stat -c '%u:%g:%a' "$CONFIG_FILE")" = "$attributes_before"
mapfile -t links < <(printf '%s\n' "$output" | grep '^tg://')
test "${#links[@]}" -eq 2
domain_hex="$(printf '%s' mask.example.test | od -An -tx1 | tr -d ' \n')"
test "${links[0]}" = "tg://proxy?server=127.0.0.1&port=443&secret=ee${new_secret}${domain_hex}"
[[ "${links[1]}" == 'tg://webproxy?server='* ]]

# The binary is the independent link oracle; compare both new links without
# printing them to the runner log.
canonical="$(docker exec mtproto-proxy /usr/local/bin/mtproto-proxy \
    /etc/mtproto-proxy/config.toml --print-links | sed -E 's/\x1B\[[0-9;]*m//g')"
for link in "${links[@]}"; do [[ "$canonical" == *"$link"* ]]; done

test "$(docker inspect -f '{{.Id}}' mtproto-proxy)" != "$proxy_before"
test "$(docker inspect -f '{{.Id}}' mtproto-web-relay)" != "$relay_before"
test "$(docker inspect -f '{{.Id}}' mtproto-mask-caddy)" = "$caddy_before"
config_hash="$(sha256sum "$CONFIG_FILE" | awk '{print $1}')"
for service in mtproto-proxy mtproto-web-relay; do
    test "$(docker inspect -f '{{.State.Running}}' "$service")" = true
    test "$(docker exec "$service" sha256sum /etc/mtproto-proxy/config.toml | awk '{print $1}')" = "$config_hash"
    if docker logs "$service" 2>&1 | grep -Fq "$new_secret"; then
        echo 'new user secret leaked into service logs' >&2
        exit 1
    fi
done

proxy_after="$(docker inspect -f '{{.Id}}' mtproto-proxy)"
relay_after="$(docker inspect -f '{{.Id}}' mtproto-web-relay)"
for rejected in tablet-2 bad/name; do
    if "$INSTALL_DIR/add_user.sh" --add-user "$rejected" >/dev/null 2>&1; then
        echo "add_user.sh accepted rejected name: $rejected" >&2
        exit 1
    fi
done
test "$(sha256sum "$CONFIG_FILE" | awk '{print $1}')" = "$config_hash"
test "$(docker inspect -f '{{.Id}}' mtproto-proxy)" = "$proxy_after"
test "$(docker inspect -f '{{.Id}}' mtproto-web-relay)" = "$relay_after"
test "$(docker inspect -f '{{.Id}}' mtproto-mask-caddy)" = "$caddy_before"

# Force the pre-recreate validation to fail; the helper must restore the old
# config without touching any running container.
cp -a "$ENV_FILE" "${ENV_FILE}.add-user-ci-backup"
sed -i 's|^MTPROTO_IMAGE=.*|MTPROTO_IMAGE=mtproto-add-user-ci:missing|' "$ENV_FILE"
if "$INSTALL_DIR/add_user.sh" --add-user rollback-user >/dev/null 2>&1; then
    mv "${ENV_FILE}.add-user-ci-backup" "$ENV_FILE"
    echo 'add_user.sh accepted an unavailable image during validation' >&2
    exit 1
fi
mv "${ENV_FILE}.add-user-ci-backup" "$ENV_FILE"
test "$(sha256sum "$CONFIG_FILE" | awk '{print $1}')" = "$config_hash"
test "$(docker inspect -f '{{.Id}}' mtproto-proxy)" = "$proxy_after"
test "$(docker inspect -f '{{.Id}}' mtproto-web-relay)" = "$relay_after"
test "$(docker inspect -f '{{.Id}}' mtproto-mask-caddy)" = "$caddy_before"
echo 'add-user E2E passed'
CONTAINER_TEST
}

echo "::group::Build isolated ${BASE_IMAGE} host"
docker build --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "$TEST_IMAGE" "$ROOT/test/installer-e2e"
echo "::endgroup::"

echo "::group::Build proxy image from current checkout"
docker build --build-arg ZIG_VERSION=0.17.0 -t "$CURRENT_IMAGE" "$ROOT"
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
docker exec "$CONTAINER" systemctl start docker
docker_ready=false
for _ in $(seq 1 90); do
    if docker exec "$CONTAINER" docker info >/dev/null 2>&1; then
        docker_ready=true
        break
    fi
    sleep 0.2
done
if ! $docker_ready; then
    echo "isolated Docker daemon did not become ready" >&2
    exit 1
fi
echo "::endgroup::"

echo "::group::Publish current proxy image to isolated host"
docker save "$CURRENT_IMAGE" | docker exec -i "$CONTAINER" docker load >/dev/null
docker exec "$CONTAINER" docker run -d \
    --name "$REGISTRY_CONTAINER" \
    --restart unless-stopped \
    -p 127.0.0.1:5000:5000 \
    registry:2 >/dev/null
registry_ready=false
for _ in $(seq 1 30); do
    if docker exec "$CONTAINER" curl -fsS http://127.0.0.1:5000/v2/ >/dev/null; then
        registry_ready=true
        break
    fi
    sleep 0.2
done
if ! $registry_ready; then
    echo "isolated Docker registry did not become ready" >&2
    exit 1
fi
docker exec "$CONTAINER" docker tag "$CURRENT_IMAGE" "$INSTALL_IMAGE"
docker exec "$CONTAINER" docker push "$INSTALL_IMAGE" >/dev/null
echo "::endgroup::"

echo "::group::Fresh Docker Compose install"
run_installer 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.install.log"
grep -F 'Authenticated WEB path reached Telegram (req_pq/resPQ)' "$LOG_DIR/${SAFE_IMAGE}.install.log" >/dev/null
grep -F 'nfqws service started' "$LOG_DIR/${SAFE_IMAGE}.install.log" >/dev/null
! grep -Eq 'Cannot enable firewall restoration|nfqws setup failed' "$LOG_DIR/${SAFE_IMAGE}.install.log"
! grep -Eq 'Unnecessary header_up X-Forwarded-For|Caddyfile input is not formatted' \
    "$LOG_DIR/${SAFE_IMAGE}.install.log"
verify_install 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.verify.log"
verify_masking_maintenance_lock 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.maintenance-lock.log"
echo "::endgroup::"

echo "::group::Add access user"
verify_add_user
wait_for_status "$TLS_DOMAIN" 8443 404
wait_for_status "$WEB_DOMAIN" 443 404
echo "::endgroup::"

echo "::group::Idempotent reinstall"
before_hash="$(docker exec "$CONTAINER" sha256sum "$CONFIG_FILE" | awk '{print $1}')"
run_installer 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.reinstall.log"
grep -F 'Authenticated WEB path reached Telegram (req_pq/resPQ)' "$LOG_DIR/${SAFE_IMAGE}.reinstall.log" >/dev/null
grep -F 'nfqws service started' "$LOG_DIR/${SAFE_IMAGE}.reinstall.log" >/dev/null
! grep -Eq 'Cannot enable firewall restoration|nfqws setup failed' "$LOG_DIR/${SAFE_IMAGE}.reinstall.log"
! grep -Eq 'Unnecessary header_up X-Forwarded-For|Caddyfile input is not formatted' \
    "$LOG_DIR/${SAFE_IMAGE}.reinstall.log"
after_hash="$(docker exec "$CONTAINER" sha256sum "$CONFIG_FILE" | awk '{print $1}')"
if [[ "$before_hash" != "$after_hash" ]]; then
    echo "config.toml changed across identical installer rerun" >&2
    exit 1
fi
verify_install 2>&1 | tee "$LOG_DIR/${SAFE_IMAGE}.verify-reinstall.log"
docker exec "$CONTAINER" grep -Eq '^[[:space:]]*tablet-2[[:space:]]*=' "$CONFIG_FILE"
echo "::endgroup::"

echo "Installer E2E passed on ${BASE_IMAGE}"
