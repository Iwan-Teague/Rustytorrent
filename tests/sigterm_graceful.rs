//! Proves that the binary handles SIGTERM gracefully (clean exit) instead
//! of dying from the default signal disposition. Process managers like
//! systemd and Docker send SIGTERM; without handling, in-progress writes,
//! tracker stopped-announces, and DHT state persistence are all lost.

#[cfg(unix)]
#[test]
fn sigterm_exits_cleanly_not_killed() {
    use std::process::Command;
    use std::time::Duration;

    let tmp = std::env::temp_dir().join(format!("rt_term_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    // Create a minimal .torrent file so the download subcommand parses.
    use sha1::{Digest, Sha1};
    let data = vec![0u8; 512];
    let mut h = Sha1::new();
    h.update(&data);
    let ih: [u8; 20] = h.finalize().into();
    let mut buf = Vec::new();
    buf.extend_from_slice(b"d4:infod6:lengthi512e4:name");
    buf.extend_from_slice(format!("{}:{}", "t.bin".len(), "t.bin").as_bytes());
    buf.extend_from_slice(b"12:piece lengthi16384e6:pieces20:");
    buf.extend_from_slice(&ih);
    buf.extend_from_slice(b"ee");
    let torrent_path = tmp.join("t.torrent");
    std::fs::write(&torrent_path, &buf).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustytorrent"))
        .args([
            "download",
            torrent_path.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--no-tracker",
            "--output",
            tmp.to_str().unwrap(),
        ])
        .spawn()
        .expect("binary spawns");

    // Give the engine time to start up.
    std::thread::sleep(Duration::from_millis(1500));

    // Send SIGTERM.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for clean exit (not killed by signal).
    let status = child.wait().expect("wait succeeds");
    #[cfg(unix)]
    eprintln!("DBG exit code={:?} signal={:?}", status.code(), {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    });
    assert!(
        status.code().is_some(),
        "process was killed by signal instead of exiting cleanly"
    );
    assert_eq!(status.code(), Some(0), "expected exit code 0");

    let _ = std::fs::remove_dir_all(&tmp);
}
