#!/usr/bin/env bash
set -euo pipefail

expected="0.0.6"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

simplex --version | grep -F "$expected" >/dev/null
grep -F "smplx-std = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "smplx-sdk = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "smplx-regtest = \"=$expected\"" "$root/Cargo.toml" >/dev/null
grep -F "version = \"$expected\";" "$root/flake.nix" >/dev/null

echo "smplx CLI, Rust crates, and Nix derivation are pinned to $expected"
