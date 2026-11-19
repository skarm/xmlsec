#!/bin/sh
# Explicit build-time acquisition. Tests never download dependencies.
set -eu
destination=${1:?usage: prepare-interop.sh CACHE_DIRECTORY}
scope=${2:-all}
case "$scope" in all|transforms|native) ;; *) printf 'Invalid interop input scope: %s\n' "$scope" >&2; exit 1 ;; esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
mkdir -p "$destination"

temporary=
cleanup() {
    if [ -n "$temporary" ]; then rm -f -- "$temporary"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

prepare() {
    while read -r pin url name; do
        case "$pin" in ''|\#*) continue ;; esac
        case "$name" in ''|/*|*..*) printf 'invalid input path: %s\n' "$name" >&2; exit 1 ;; esac
        path="$destination/$name"
        if [ -f "$path" ] && [ "$(digest "$path")" = "$pin" ]; then
            continue
        fi
        mkdir -p "$(dirname -- "$path")"
        printf 'Fetching pinned input: %s\n' "$name"
        temporary=$(mktemp "$path.part.XXXXXXXX")
        curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 --max-time 600 "$url" -o "$temporary"
        [ "$(digest "$temporary")" = "$pin" ] || { printf 'SHA-256 mismatch: %s\n' "$name" >&2; exit 1; }
        mv "$temporary" "$path"
        temporary=
    done < "$root/build/$1"
}

if [ "$scope" != transforms ]; then
    prepare interop-inputs.txt
fi
if [ "$scope" != native ]; then
    prepare interop-transform-inputs.txt
fi
