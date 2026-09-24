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
#
# Toolchain (AQ-233): rust-toolchain.toml pins 1.88.0 — the floor this
# crate declares (Cargo.toml:10, rust-version = "1.88") — and the
# preamble below forces the gate onto that exact toolchain even when the
# ambient cargo is not a rustup proxy (Homebrew's on macOS ignores
# rust-toolchain.toml). CI deliberately floats `stable` (ci.yml:39-40,
# 59-62, 94-95): forward coverage that stays CI-only, mirroring
# rustydns's gate/CI split. Bump the pin deliberately, gate green on the
# new version, never passively.
set -euo pipefail
cd "$(dirname "$0")/../.."

# ── Toolchain pin preamble (AQ-233) ────────────────────────────────────
# The gate must run the exact toolchain rust-toolchain.toml pins — never
# the ambient one. An ambient cargo that is not a rustup proxy (Homebrew's
# on macOS) ignores rust-toolchain.toml entirely, so this preamble
# resolves the pinned toolchain's bin dir via `rustup which` and puts it
# FIRST on PATH, then refuses (exit 1) unless the rustc and clippy that
# PATH now finds match the pin's minor. A missing or malformed
# rust-toolchain.toml, a missing rustup, or an uninstalled pin are hard
# refusals — the gate never silently starts on the ambient toolchain.
# Parsing is grep + parameter expansion only (no sed/awk/read: BSD/GNU
# divergence).
toolchain_fail() {
  printf 'GATE REFUSED (toolchain pin): %s\n' "$1" >&2
  exit 1
}
[ -f rust-toolchain.toml ] \
  || toolchain_fail 'rust-toolchain.toml missing — refusing to gate on the ambient toolchain'
channel_count=$(grep -c '^channel[[:space:]]*=' rust-toolchain.toml) || channel_count=0
[ "$channel_count" -eq 1 ] \
  || toolchain_fail "expected exactly one 'channel =' line in rust-toolchain.toml, found $channel_count"
channel_line=$(grep '^channel[[:space:]]*=' rust-toolchain.toml)
channel_value=${channel_line#*=}
channel_value=${channel_value#"${channel_value%%[![:space:]]*}"}
channel_value=${channel_value%"${channel_value##*[![:space:]]}"}
case $channel_value in
  \"*\") channel=${channel_value#\"} ;;
  *) toolchain_fail "channel value is not a double-quoted string: $channel_value" ;;
esac
channel=${channel%\"}
case $channel in
  [0-9]*.[0-9]*|[0-9]*.[0-9]*.[0-9]*) ;;
  *) toolchain_fail "unsupported channel '$channel' — this gate requires a concrete X.Y or X.Y.Z pin so the clippy-minor assertion is well-defined" ;;
esac
command -v rustup >/dev/null 2>&1 \
  || toolchain_fail 'rustup not on PATH — cannot resolve the pinned toolchain (an ambient-only install refuses here by design)'
pinned_cargo=$(rustup which --toolchain "$channel" cargo 2>/dev/null) \
  || toolchain_fail "toolchain '$channel' is not installed — run: rustup toolchain install $channel"
[ -x "$pinned_cargo" ] || toolchain_fail "resolved cargo is not executable: $pinned_cargo"
PATH=${pinned_cargo%/*}:$PATH
export PATH
# Assert the toolchain PATH now resolves really is the pin: rustc minor
# must equal the pinned minor, and clippy (0.1.N) must track that rustc.
rustc_banner=$(rustc --version 2>/dev/null) \
  || toolchain_fail 'rustc --version failed under the pinned PATH'
rustc_ver=${rustc_banner#* }
rustc_ver=${rustc_ver%% *}
case $rustc_ver in
  [0-9]*.[0-9]*) ;;
  *) toolchain_fail "unparsable 'rustc --version' output: $rustc_banner" ;;
esac
rustc_minor=${rustc_ver#*.}
rustc_minor=${rustc_minor%%.*}
clippy_banner=$(cargo clippy --version 2>/dev/null) \
  || toolchain_fail 'cargo clippy --version failed under the pinned PATH'
clippy_ver=${clippy_banner#* }
clippy_ver=${clippy_ver%% *}
case $clippy_ver in
  0.*.*) ;;
  *) toolchain_fail "unparsable 'cargo clippy --version' output: $clippy_banner" ;;
esac
clippy_minor=${clippy_ver#*.}
clippy_minor=${clippy_minor#*.}
clippy_minor=${clippy_minor%%[!0-9]*}
pin_minor=${channel#*.}
pin_minor=${pin_minor%%.*}
if [ "$rustc_minor" -ne "$pin_minor" ] || [ "$clippy_minor" -ne "$rustc_minor" ]; then
  toolchain_fail "PATH resolves rustc $rustc_ver / clippy $clippy_ver, not the pinned $channel"
fi
printf 'gate toolchain: pin %s — rustc %s, clippy %s (pinned bin dir first on PATH)\n' \
  "$channel" "$rustc_ver" "$clippy_ver"

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
