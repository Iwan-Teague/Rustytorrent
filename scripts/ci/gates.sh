#!/usr/bin/env bash
# Local gate entrypoint (Tier-0 parity with .github/workflows/ci.yml).
# Runs every check CI runs, fail-fast, so "green locally" means "green
# in CI": build+test (ci.yml:43-46), cargo test --release (ci.yml:49-51),
# fmt+clippy+doc (ci.yml:65-71), cargo deny (ci.yml:77-81) and
# cargo audit (ci.yml:89-99). Run from the repo root: ./scripts/ci/gates.sh
#
# Two deltas from the YAML, named rather than skipped silently:
#   1. CI runs `cargo test --release` on ubuntu-latest only (ci.yml:50,
#      `if: matrix.os == 'ubuntu-latest'`, to bound CI time). This gate
#      runs it on every host: overflow-checks is a property of the
#      release profile, not of Linux.
#   2. CI pins cargo-audit at 0.22.2 (ci.yml:96-97); locally whatever
#      version is installed runs, and a MISSING cargo-audit fails the
#      gate -- it is never skipped into green.
set -euo pipefail
cd "$(dirname "$0")/../.."

step() { printf '\n=== %s ===\n' "$1"; }

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo clippy -D warnings"
cargo clippy --all-targets --locked -- -D warnings

step "cargo doc --no-deps --locked (ci.yml:70-71)"
cargo doc --no-deps --locked

step "cargo build --locked"
cargo build --all-targets --locked

step "cargo test --locked"
cargo test --all --locked

step "cargo test --release --locked (overflow-checks, ci.yml:49-51)"
cargo test --release --all --locked

step "cargo deny check"
cargo deny check

step "cargo audit (ci.yml:98-99)"
if ! command -v cargo-audit >/dev/null 2>&1; then
    printf 'GATE FAILED: cargo-audit not installed (CI runs it, pinned 0.22.2, ci.yml:96-97).\n'
    printf '  install: cargo install cargo-audit --locked --version 0.22.2\n'
    exit 1
fi
cargo audit --deny warnings

printf '\nAll gates passed.\n'
