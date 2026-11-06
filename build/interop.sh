#!/usr/bin/env bash
set -euo pipefail

go_bin=${GO:-go}
reports=$(mktemp -d)
trap 'rm -rf "$reports"' EXIT

run() {
    local log=$1
    shift
    if ! "$go_bin" test -json "$@" > "$log" 2>&1; then
        cat "$log"
        return 1
    fi
    if [[ ${XMLSEC_REQUIRE_INTEROP:-} == 1 ]]; then
        if ! "$go_bin" run ./tests/cmd/dev interop-check "$log"; then
            cat "$log"
            return 1
        fi
    else
        cat "$log"
    fi
}

shards=${XMLSEC_INTEROP_SHARDS:-1}
case "$shards" in [1-8]) ;; *) printf 'XMLSEC_INTEROP_SHARDS must be 1..8\n' >&2; exit 1 ;; esac
names=$("$go_bin" test -tags=interop ./transform -list '^TestCompare')
filters=()
for ((slot=0; slot<shards; slot++)); do filters[slot]=''; done
index=0
while IFS= read -r name; do
    [[ $name =~ ^TestCompare[[:alnum:]_]+$ ]] || continue
    slot=$((index % shards))
    filters[slot]+="${filters[slot]:+|}$name"
    index=$((index + 1))
done <<< "$names"
[[ $index -gt 0 ]] || { printf 'no transform comparisons discovered\n' >&2; exit 1; }
printf 'Running %d transform comparisons in %d isolated processes\n' "$index" "$shards"
pids=()
for ((slot=0; slot<shards; slot++)); do
    [[ -n ${filters[slot]} ]] || continue
    run "$reports/transform-$slot.jsonl" -tags=interop -count=1 -timeout=45m ./transform "-run=^(${filters[slot]})$" &
    pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
[[ $failed == 0 ]] || exit 1
# The parent test runs this helper in both subprocess roles; a direct invocation
# only skips and would fail the required zero-skip external-check gate.
run "$reports/interop.jsonl" -tags=interop -count=1 -timeout=25m ./tests/interop -skip='^TestLineProcessDiagnosticsProcess$' -args "$@"
