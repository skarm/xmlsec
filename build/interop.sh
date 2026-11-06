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
parallel=${XMLSEC_INTEROP_PARALLEL:-1}
case "$parallel" in [1-8]) ;; *) printf 'XMLSEC_INTEROP_PARALLEL must be 1..8\n' >&2; exit 1 ;; esac
names=$("$go_bin" test -tags=interop ./transform -list '^TestCompare')
index=0
while IFS= read -r name; do
    [[ $name =~ ^TestCompare[[:alnum:]_]+$ ]] || continue
    printf '%s\n' "$name" >> "$reports/transform-tests"
    index=$((index + 1))
done <<< "$names"
[[ $index -gt 0 ]] || { printf 'no transform comparisons discovered\n' >&2; exit 1; }
printf 'Running %d transform comparisons with %d workers and %d parallel subtests each\n' "$index" "$shards" "$parallel"

run_transform() {
    local name failed=0
    while IFS= read -r name; do
        # Claim the next test atomically. Workers take more work as they finish,
        # so large test tables cannot leave other workers idle for a whole shard.
        mkdir "$reports/claim-$name" 2>/dev/null || continue
        # Bound each comparison, rather than the accumulated time of unrelated
        # comparisons. Each invocation also has its own complete JSON stream.
        run "$reports/$name.jsonl" -tags=interop -count=1 -timeout=45m "-parallel=$parallel" ./transform "-run=^${name}$" || failed=1
    done < "$reports/transform-tests"
    return "$failed"
}

pids=()
for ((slot=0; slot<shards; slot++)); do
    run_transform &
    pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
[[ $failed == 0 ]] || exit 1
# The parent test runs this helper in both subprocess roles; a direct invocation
# only skips and would fail the required zero-skip external-check gate.
run "$reports/interop.jsonl" -tags=interop -count=1 -timeout=25m ./tests/interop -skip='^TestLineProcessDiagnosticsProcess$' -args "$@"
