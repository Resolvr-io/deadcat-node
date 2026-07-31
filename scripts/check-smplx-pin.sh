#!/usr/bin/env bash
set -euo pipefail

expected="0.0.9"
expected_simplicityhl="0.6.0"
expected_simplicity_lang="0.8.0"
expected_simplicity_sys="0.7.0"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

simplex --version | grep -F "$expected" >/dev/null
grep -F "smplx-std = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "smplx-sdk = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "smplx-regtest = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "version = \"$expected\";" "$root/flake.nix" >/dev/null
grep -A1 -F 'name = "simplicityhl"' "$root/Cargo.lock" \
    | grep -F "version = \"$expected_simplicityhl\"" >/dev/null
grep -A1 -F 'name = "simplicity-lang"' "$root/Cargo.lock" \
    | grep -F "version = \"$expected_simplicity_lang\"" >/dev/null
grep -A1 -F 'name = "simplicity-sys"' "$root/Cargo.lock" \
    | grep -F "version = \"$expected_simplicity_sys\"" >/dev/null

echo "smplx $expected and compatible Simplicity $expected_simplicityhl/$expected_simplicity_lang/$expected_simplicity_sys are pinned"
