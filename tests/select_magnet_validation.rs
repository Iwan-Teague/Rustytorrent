//! Pins that the magnet subcommand also routes through the
//! `validate_select_patterns` gate \u2014 not just the download command.
//! Without this, a regression that removes the validation from the magnet
//! path would pass all other tests.

#[test]
fn magnet_rejects_empty_select_pattern() {
    let bin = env!("CARGO_BIN_EXE_rustytorrent");
    let output = std::process::Command::new(bin)
        .args([
            "magnet",
            "magnet:?xt=urn:btih:0000000000000000000000000000000000000000",
            "--select",
            "",
        ])
        .output()
        .expect("binary runs");

    assert!(
        !output.status.success(),
        "magnet --select \"\" must be rejected"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("--select"),
        "expected the refusal to name --select, got: {text}"
    );
}
