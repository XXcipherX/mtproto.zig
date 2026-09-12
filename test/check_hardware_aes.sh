#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/docker-image.yml"

mapfile -t cpu_profiles < <(
    sed -nE 's/^[[:space:]]*MTPROTO_CPU=([^[:space:]]+)[[:space:]]*$/\1/p' "$WORKFLOW"
)
if (( ${#cpu_profiles[@]} != 1 )); then
    echo "expected exactly one amd64 optimized MTPROTO_CPU profile in $WORKFLOW" >&2
    exit 1
fi

object_file="$(mktemp)"
trap 'rm -f "$object_file"' EXIT

zig build-obj \
    -target x86_64-linux \
    -mcpu="${cpu_profiles[0]}" \
    -femit-bin="$object_file" \
    "$ROOT/test/hardware_aes_probe.zig"

echo "hardware AES backend verified for MTPROTO_CPU=${cpu_profiles[0]}"
