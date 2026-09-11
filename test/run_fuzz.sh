#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <iterations> <artifact-dir> [time-limit]" >&2
    exit 2
}

if (( $# < 2 || $# > 3 )); then
    usage
fi

iterations="$1"
artifact_dir="$2"
time_limit="${3:-}"

if [[ ! "$iterations" =~ ^[1-9][0-9]*([KMG])?$ ]]; then
    echo "invalid fuzz iteration limit: $iterations" >&2
    usage
fi

if [[ -z "$artifact_dir" || "$artifact_dir" == "/" ]]; then
    echo "refusing unsafe fuzz artifact directory: $artifact_dir" >&2
    usage
fi

if [[ -n "$time_limit" && ! "$time_limit" =~ ^[1-9][0-9]*[smhd]$ ]]; then
    echo "invalid fuzz time limit: $time_limit" >&2
    usage
fi

mkdir -p -- "$artifact_dir"

run_log="$artifact_dir/fuzz-run.log"
crash_file=".zig-cache/f/crash"
saved_crash="$artifact_dir/crash-input"

# A stale finding must be triaged instead of silently attributed to a new run.
if [[ -L "$crash_file" ]]; then
    echo "refusing symbolic-link fuzz crash input at $crash_file" >&2
    exit 2
fi

if [[ -f "$crash_file" ]]; then
    cp -- "$crash_file" "$artifact_dir/preexisting-crash-input"
    echo "pre-existing Zig fuzz crash input found at $crash_file" >&2
    exit 2
fi

fuzz_command=(
    zig build
    -Doptimize=ReleaseSafe
    fuzz
    "--fuzz=$iterations"
)

if [[ -n "$time_limit" ]]; then
    fuzz_command=(
        timeout
        --signal=INT
        --kill-after=30s
        "$time_limit"
        "${fuzz_command[@]}"
    )
fi

set +e
"${fuzz_command[@]}" 2>&1 | tee "$run_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e

fuzz_status="${pipeline_status[0]}"
tee_status="${pipeline_status[1]}"
crash_reported=false

if [[ -L "$crash_file" ]]; then
    echo "refusing symbolic-link fuzz crash input at $crash_file" >&2
    exit 2
fi

if [[ -f "$crash_file" ]]; then
    cp -- "$crash_file" "$saved_crash"
    crash_reported=true
fi

# Zig 0.16 bounded fuzzing can report a finding without returning a failure.
if grep -Fq "crashed; input saved to" "$run_log"; then
    crash_reported=true
fi

if [[ -f .zig-cache/tmp/libfuzzer.log && ! -L .zig-cache/tmp/libfuzzer.log ]]; then
    cp -- .zig-cache/tmp/libfuzzer.log "$artifact_dir/zig-fuzzer.log"
fi

if (( tee_status != 0 )); then
    echo "failed to write fuzz output log (tee exit $tee_status)" >&2
    exit "$tee_status"
fi

if (( fuzz_status != 0 )); then
    echo "bounded fuzz command failed with exit $fuzz_status" >&2
    exit "$fuzz_status"
fi

if [[ "$crash_reported" == true ]]; then
    echo "bounded fuzzing found a crash; preserved evidence in $artifact_dir" >&2
    exit 1
fi
