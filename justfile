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

# Run the production-shaped A/B binary-market lifecycle against an isolated
# liquidregtest elementsd + Electrs pair.
regtest-market-ab: generate
    cargo test --locked -p deadcat-client --test market_regtest \
        binary_market_ab_lifecycle_is_accepted_by_elementsd \
        -- --ignored --nocapture --test-threads=1

wasm-check:
    NIX_HARDENING_ENABLE=pic cargo check --locked -p deadcat-iroh --lib --target wasm32-unknown-unknown

ci: fmt-check clippy test wasm-check

node *ARGS:
    cargo run --locked -p deadcat-node -- {{ARGS}}

cli *ARGS:
    cargo run --locked -p deadcat-cli -- {{ARGS}}
