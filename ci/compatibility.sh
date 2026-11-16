#!/usr/bin/env bash
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cc -std=c99 -Wall -Wextra /recipe/ci/compatibility.c -lcares -o "$work/consumer"
"$work/consumer"
