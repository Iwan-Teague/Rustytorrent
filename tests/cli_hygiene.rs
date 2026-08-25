//! CLI hygiene: verify that all expected subcommands appear in --help
//! output, preventing accidental feature removal during refactors.

use std::process::Command;

#[test]
fn help_lists_all_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustytorrent"))
        .arg("--help")
        .output()
        .expect("binary runs");
    let text = String::from_utf8_lossy(&output.stdout);
    for cmd in [
        "info", "download", "magnet", "peers", "create", "decrypt", "daemon",
    ] {
        assert!(
            text.contains(cmd),
            "--help output missing subcommand '{cmd}'"
        );
    }
}

#[test]
fn version_flag_reports_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustytorrent"))
        .arg("--version")
        .output()
        .expect("binary runs");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("rustytorrent"),
        "--version should mention rustytorrent, got: {text}"
    );
    // The version must match Cargo.toml's package version.
    let expected = format!("rustytorrent {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(text.trim(), expected.trim());
}

#[test]
fn help_lists_key_flags_for_download() {
    // Verify important security/behavioral flags are documented.
    let output = Command::new(env!("CARGO_BIN_EXE_rustytorrent"))
        .args(["download", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--anonymous",
        "--encrypt",
        "--socks5",
        "--bind-iface",
        "--select",
        "--sequential",
        "--max-down",
        "--max-up",
        "--paranoid",
        "--sandbox",
        "--no-tracker",
    ] {
        assert!(text.contains(flag), "download --help missing {flag}");
    }
}
