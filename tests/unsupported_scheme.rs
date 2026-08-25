//! Pins that the CLI's `peers` subcommand rejects unsupported tracker
//! schemes cleanly rather than panicking or hanging.

use std::process::Command;

#[test]
fn peers_rejects_unsupported_tracker_scheme() {
    // Build a minimal .torrent with an ftp:// tracker.
    let tmp = std::env::temp_dir().join(format!("rt_ftp_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let payload = tmp.join("payload.bin");
    std::fs::write(&payload, b"test data").unwrap();

    // Use our own `create` subcommand to produce valid bencode.
    let bin = env!("CARGO_BIN_EXE_rustytorrent");
    let torrent_path = tmp.join("ftp.torrent");
    let status = Command::new(bin)
        .args([
            "create",
            payload.to_str().unwrap(),
            "--tracker",
            "ftp://127.0.0.1:9",
            "--output",
            torrent_path.to_str().unwrap(),
        ])
        .output()
        .expect("create runs");
    assert!(status.status.success(), "create failed");

    // Now run `peers` against the ftp:// tracker \u2014 must fail cleanly.
    let output = Command::new(bin)
        .args(["peers", torrent_path.to_str().unwrap()])
        .output()
        .expect("peers runs");
    assert!(
        !output.status.success(),
        "peers should fail for ftp:// tracker"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("unsupported tracker scheme"),
        "expected unsupported-scheme error, got: {text}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
