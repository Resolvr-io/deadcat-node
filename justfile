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

# Run the external-daemon RT blinding comparison. This is intentionally
# ignored by the normal workspace test suite: it starts one isolated
# liquidregtest elementsd + Electrs pair and drives both schedules serially.
regtest-rt-study: generate
    cargo test --locked -p deadcat-rt-study --lib \
        regtest::rolling_and_ab_chains_are_accepted_by_elementsd \
        -- --ignored --nocapture --test-threads=1

wasm-check:
    NIX_HARDENING_ENABLE=pic cargo check --locked -p deadcat-iroh --lib --target wasm32-unknown-unknown

ci: fmt-check clippy test wasm-check

node *ARGS:
    cargo run --locked -p deadcat-node -- {{ARGS}}

cli *ARGS:
    cargo run --locked -p deadcat-cli -- {{ARGS}}
