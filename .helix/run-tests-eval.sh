#!/usr/bin/env bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

if [ -z "$1" ]; then
  go test -count=1 ./...
else
  IFS=',' read -ra FILES <<< "$1"
  declare -A PKG_TESTS
  for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    dir="$(dirname "$f")"
    tests=$(grep -oE '^func +Test[A-Za-z0-9_]+' "$f" | sed -E 's/^func +//' | tr '\n' '|' | sed 's/|$//')
    [ -z "$tests" ] && continue
    if [ -n "${PKG_TESTS[$dir]:-}" ]; then
      PKG_TESTS[$dir]="${PKG_TESTS[$dir]}|$tests"
    else
      PKG_TESTS[$dir]="$tests"
    fi
  done
  for dir in "${!PKG_TESTS[@]}"; do
    go test -count=1 "./$dir" -run "^(${PKG_TESTS[$dir]})$"
  done
fi
