# Run these commands inside `nix develop .#default`.

default:
    @just --list

verify-smplx:
    @bash scripts/check-smplx-pin.sh

generate: verify-smplx
    cd crates/deadcat-contracts && simplex build

build: generate
    cargo build --locked --workspace

fmt: generate
    cargo fmt --all

fmt-check: generate
    cargo fmt --all -- --check

clippy: generate
    cargo clippy --locked --workspace --all-targets -- -D warnings

test: generate
    cargo test --locked --workspace

wasm-check:
    NIX_HARDENING_ENABLE=pic cargo check --locked -p deadcat-iroh --lib --target wasm32-unknown-unknown

ci: fmt-check clippy test wasm-check

node *ARGS:
    cargo run --locked -p deadcat-node -- {{ARGS}}

cli *ARGS:
    cargo run --locked -p deadcat-cli -- {{ARGS}}
