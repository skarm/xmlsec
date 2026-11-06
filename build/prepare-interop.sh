#!/bin/sh
# Explicit build-time acquisition. Tests never download dependencies.
set -eu
destination=${1:?usage: prepare-interop.sh CACHE_DIRECTORY}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
mkdir -p "$destination"

digest() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

while read -r pin url name; do
    case "$pin" in ''|\#*) continue ;; esac
    case "$name" in ''|/*|*..*) printf 'invalid input path: %s\n' "$name" >&2; exit 1 ;; esac
    path="$destination/$name"
    if [ -f "$path" ] && [ "$(digest "$path")" = "$pin" ]; then
        continue
    fi
    mkdir -p "$(dirname -- "$path")"
    printf 'Fetching pinned input: %s\n' "$name"
    curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 --max-time 600 "$url" -o "$path.part"
    [ "$(digest "$path.part")" = "$pin" ] || { printf 'SHA-256 mismatch: %s\n' "$name" >&2; exit 1; }
    mv "$path.part" "$path"
done < "$root/build/interop-inputs.txt"
