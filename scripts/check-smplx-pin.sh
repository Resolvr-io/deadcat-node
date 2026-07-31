#!/usr/bin/env bash
set -euo pipefail

expected="0.0.9"
expected_simplicityhl="0.6.0"
expected_simplicity_lang="0.8.0"
expected_simplicity_sys="0.7.0"
expected_registry_source="registry+https://github.com/rust-lang/crates.io-index"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "smplx pin check failed: $*" >&2
    exit 1
}

command -v jq >/dev/null || fail "jq is required; run inside nix develop .#default"
command -v python3 >/dev/null || fail "Python 3 is required; run inside nix develop .#default"
python3 -c 'import tomllib' 2>/dev/null \
    || fail "Python 3.11 or newer with tomllib is required; run inside nix develop .#default"

expected_cli_output="Simplex $expected"
actual_cli_output="$(simplex --version)" \
    || fail "could not run simplex --version"
[[ "$actual_cli_output" == "$expected_cli_output" ]] \
    || fail "expected CLI output '$expected_cli_output', got '$actual_cli_output'"

flake_version="$(nix eval --raw "$root#simplex.version")" \
    || fail "could not evaluate the flake's simplex version"
[[ "$flake_version" == "$expected" ]] \
    || fail "flake resolves simplex $flake_version, expected $expected"

metadata="$(cargo metadata --format-version 1 --locked --manifest-path "$root/Cargo.toml")" \
    || fail "cargo metadata could not resolve the locked workspace graph"

assert_workspace_requirement() {
    local package_name="$1"
    local expected_requirement="$2"
    local requirements

    requirements="$(
        jq -r --arg name "$package_name" '
            .workspace_members as $members
            | [
                .packages[]
                | select(.id as $id | $members | index($id))
                | .dependencies[]
                | select(.name == $name)
                | .req
              ]
            | unique
            | sort
            | join(", ")
        ' <<<"$metadata"
    )"

    [[ "$requirements" == "$expected_requirement" ]] \
        || fail "workspace requirement for $package_name is '${requirements:-<missing>}', expected '$expected_requirement'"
}

assert_resolved_crates_io_package() {
    local package_name="$1"
    local expected_version="$2"
    local identities
    local expected_identity="$expected_version @ $expected_registry_source"

    identities="$(
        jq -r --arg name "$package_name" '
            [
                .packages[]
                | select(.name == $name)
                | "\(.version) @ \(.source // "<path>")"
              ]
            | sort
            | join(", ")
        ' <<<"$metadata"
    )"

    [[ "$identities" == "$expected_identity" ]] \
        || fail "resolved $package_name identity '${identities:-<missing>}', expected only '$expected_identity'"
}

assert_cli_lock_stack() {
    local lockfile="$root/nix/smplx-Cargo.lock"

    if ! python3 - \
        "$lockfile" \
        "$expected_registry_source" \
        "simplicityhl=$expected_simplicityhl" \
        "simplicity-lang=$expected_simplicity_lang" \
        "simplicity-sys=$expected_simplicity_sys" <<'PYTHON'
import sys
import tomllib
from pathlib import Path

lock_path = Path(sys.argv[1])
expected_source = sys.argv[2]
expected_versions = dict(spec.split("=", 1) for spec in sys.argv[3:])

with lock_path.open("rb") as lock_file:
    packages = tomllib.load(lock_file).get("package", [])

errors = []
for name, expected_version in expected_versions.items():
    matches = [package for package in packages if package.get("name") == name]
    expected_identity = f"{expected_version} @ {expected_source}"
    actual_identities = sorted(
        f"{package.get('version', '<missing>')} @ {package.get('source', '<path>')}"
        for package in matches
    )
    if actual_identities != [expected_identity]:
        actual = ", ".join(actual_identities) if actual_identities else "<missing>"
        errors.append(f"{name}: found '{actual}', expected only '{expected_identity}'")

if errors:
    print(f"{lock_path} has an unexpected Simplicity stack:", file=sys.stderr)
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    raise SystemExit(1)
PYTHON
    then
        fail "CLI lockfile Simplicity stack does not match the workspace pin"
    fi
}

for package_name in smplx-std smplx-sdk smplx-regtest; do
    assert_workspace_requirement "$package_name" "=$expected"
done

required_smplx_packages=(
    smplx-build
    smplx-macros
    smplx-regtest
    smplx-sdk
    smplx-std
    smplx-test
)

for package_name in "${required_smplx_packages[@]}"; do
    assert_resolved_crates_io_package "$package_name" "$expected"
done

resolved_smplx_packages="$(
    jq -r '
        [.packages[] | select(.name | startswith("smplx-")) | .name]
        | unique
        | sort
        | .[]
    ' <<<"$metadata"
)"
[[ -n "$resolved_smplx_packages" ]] || fail "workspace graph contains no smplx-* packages"

while IFS= read -r package_name; do
    assert_resolved_crates_io_package "$package_name" "$expected"
done <<<"$resolved_smplx_packages"

assert_resolved_crates_io_package simplicityhl "$expected_simplicityhl"
assert_resolved_crates_io_package simplicity-lang "$expected_simplicity_lang"
assert_resolved_crates_io_package simplicity-sys "$expected_simplicity_sys"
assert_cli_lock_stack

echo "smplx $expected and compatible Simplicity $expected_simplicityhl/$expected_simplicity_lang/$expected_simplicity_sys are pinned"
