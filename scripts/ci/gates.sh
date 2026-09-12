#!/usr/bin/env bash
# Local gate entrypoint (Tier-0 parity with .github/workflows/ci.yml).
# Runs the same checks CI runs, fail-fast, so "green locally" means
# "green in CI". Run from the repo root: ./scripts/ci/gates.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

step() { printf '\n=== %s ===\n' "$1"; }

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo clippy -D warnings"
cargo clippy --all-targets --locked -- -D warnings

step "cargo build --locked"
cargo build --all-targets --locked

step "cargo test --locked"
cargo test --all --locked

step "cargo deny check"
cargo deny check

step "cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit --deny warnings
else
    printf 'cargo-audit not installed; skipping (CI runs it). Install: cargo install cargo-audit --locked\n'
fi

printf '\nAll gates passed.\n'
