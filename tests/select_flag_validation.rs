//! Pins that the `--select` validation is actually WIRED into the
//! download command \u2014 not merely that the helper function works.
//!
//! Regression shape: someone deletes the
//! `validate_select_patterns(&select)?` call from `cmd_download`; the
//! unit test on the helper keeps passing, and `--select ""` silently
//! matches every file again. Here we run the real binary with an empty
//! pattern against a valid torrent and require a fast, clean refusal
//! naming the flag.

/// Minimal valid single-file metainfo (1 KiB piece, 512-byte payload).
fn minimal_torrent_bytes(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"d4:infod6:lengthi512e4:name");
    buf.extend_from_slice(format!("{}:{}", name.len(), name).as_bytes());
    buf.extend_from_slice(b"12:piece lengthi1024e6:pieces20:");
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(b"x");
    buf.extend_from_slice(&h.finalize());
    buf.extend_from_slice(b"ee");
    buf
}

#[test]
fn download_rejects_empty_select_pattern_before_doing_work() {
    let tmp = std::env::temp_dir().join(format!("rt_sel_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let torrent_path = tmp.join("sel.torrent");
    std::fs::write(&torrent_path, minimal_torrent_bytes("sel.bin")).unwrap();
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let bin = env!("CARGO_BIN_EXE_rustytorrent");
    let output = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            // The command must fail fast on its own \u2014 bound the whole run.
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                tokio::process::Command::new(bin)
                    .args([
                        "download",
                        torrent_path.to_str().unwrap(),
                        "--output",
                        out_dir.to_str().unwrap(),
                        "--port",
                        "0",
                        "--no-tracker",
                        "--select",
                        "",
                    ])
                    .output(),
            )
            .await
            .expect("binary finishes promptly")
        })
        .expect("spawn ok");

    assert!(
        !output.status.success(),
        "--select \"\" must be rejected; binary exited {:?}",
        output.status
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

    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_file(&torrent_path);
}
