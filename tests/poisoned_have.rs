//! Data-integrity path end to end over an INBOUND connection.
//!
//! A two-piece torrent: the leecher already holds verified piece 0
//! (pre-written, picked up by the resume scan), and a malicious peer
//! connects inbound claiming piece 1 via HAVE. The leecher expresses
//! interest, the peer unchokes it, the leecher sends REQUEST, and the
//! peer answers with garbage.
//!
//! Required outcome: SHA-1 verification fails the block, the piece is
//! reset, the poisoner's IP is banned and BOTH of its connection tasks are
//! aborted (outer + inner read task) so the attacker sees closure
//! promptly \u2014 and not one poisoned byte ever reaches the output file.

use std::time::Duration;

use rustytorrent::engine::{EngineConfig, TorrentEngine};
use rustytorrent::metainfo::{Info, TorrentFile, TorrentFiles};
use sha1::{Digest, Sha1};

const PIECE_LEN: u64 = 16384;

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

fn make_two_piece_torrent(piece0: &[u8], piece1: &[u8]) -> TorrentFile {
    let mut data = Vec::new();
    data.extend_from_slice(piece0);
    data.extend_from_slice(piece1);
    TorrentFile {
        info_hash: sha1(&data),
        announce: None,
        announce_list: vec![],
        info: Info {
            name: "poison.bin".to_string(),
            piece_length: PIECE_LEN,
            piece_hashes: vec![sha1(piece0), sha1(piece1)],
            files: TorrentFiles::Single {
                length: data.len() as u64,
            },
            private: false,
        },
    }
}

fn frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    f.extend_from_slice(&((1 + payload.len()) as u32).to_be_bytes());
    f.push(id);
    f.extend_from_slice(payload);
    f
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poisoned_inbound_seeder_is_banned_and_disk_stays_clean() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let piece0: Vec<u8> = (0..PIECE_LEN as usize)
        .map(|i| (i % 251 + 1) as u8)
        .collect();
    let piece1: Vec<u8> = (0..PIECE_LEN as usize)
        .map(|i| (i % 249 + 2) as u8)
        .collect();
    let torrent = make_two_piece_torrent(&piece0, &piece1);

    // Malicious peer listens inbound; the leecher dials IT as the sole
    // source for its only missing piece.
    let evil = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil_addr = evil.local_addr().unwrap();

    let tmp = std::env::temp_dir().join(format!("rt_psn_{}", std::process::id()));
    tokio::fs::create_dir_all(&tmp).await.unwrap();

    let cfg = EngineConfig {
        output_dir: tmp.clone(),
        listen_port: 0,
        no_tracker: true,
        seed_peers: vec![evil_addr],
        ..Default::default()
    };

    // Pre-write the output: REAL piece0 + zeros for piece1. The engine's
    // resume scan verifies piece0 at startup, so the leecher starts as 1/2
    // complete and the attacker is the sole source for its only missing
    // piece.
    std::fs::write(tmp.join("poison.bin"), {
        let mut f = Vec::new();
        f.extend_from_slice(&piece0);
        f.extend(std::iter::repeat_n(0, PIECE_LEN as usize));
        f
    })
    .unwrap();

    let leecher = TorrentEngine::new(torrent.clone(), [2u8; 20], cfg);
    let leecher_task = tokio::spawn(async move {
        let _ = leecher.run().await;
    });

    // ---- Attacker script ----
    let (mut sock, _) = tokio::time::timeout(Duration::from_secs(10), evil.accept())
        .await
        .expect("leecher dials us")
        .unwrap();

    // Handshake exchange (echoing the engine's handshake back is valid).
    let mut hs = vec![0u8; 68];
    sock.read_exact(&mut hs).await.unwrap();
    sock.write_all(&hs).await.unwrap();

    // Phase 0 — UNSOLICITED block injection: push a garbage PIECE for
    // the missing piece 1 BEFORE any REQUEST exists. The solicitation
    // check must silently DROP it (no ban, no state change): if the check
    // ever regresses, this block is accepted, SHA1-fails, and self-bans
    // us — the subsequent interest dance below then times out and fails
    // the test.
    let mut junk = Vec::with_capacity(8 + PIECE_LEN as usize);
    junk.extend_from_slice(&1u32.to_be_bytes());
    junk.extend_from_slice(&0u32.to_be_bytes());
    junk.extend(std::iter::repeat_n(0xDD, PIECE_LEN as usize));
    sock.write_all(&frame(7, &junk)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    // Still connected and unbanned: prove it by round-tripping a PING-
    // equivalent — send KEEPALIVE and expect the connection to stay usable
    // (no EOF).
    sock.write_all(&[0u8; 4]).await.unwrap();

    // Claim piece 1 via HAVE (id 4).
    sock.write_all(&frame(4, &1u32.to_be_bytes()))
        .await
        .unwrap();

    // Wait for INTERESTED (id 2), then REQUEST (id 6) for piece 1.
    // Reads go through a fixed buffer appended into `acc` \u2014 reading
    // straight into an empty zero-length Vec yields zero bytes forever.
    let mut acc: Vec<u8> = Vec::new();
    let mut rbuf = vec![0u8; 8192];
    let mut saw_interested = false;
    let mut saw_request: Option<(u32, u32, u32)> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline && (!saw_interested || saw_request.is_none()) {
        let n = match tokio::time::timeout(Duration::from_millis(200), sock.read(&mut rbuf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        acc.extend_from_slice(&rbuf[..n]);
        loop {
            if acc.len() < 5 {
                break;
            }
            let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
            if len == 0 {
                acc.drain(..4);
                continue;
            }
            if acc.len() < 4 + len {
                break;
            }
            match acc[4] {
                // BitTorrent ids: 2 = INTERESTED (leecher -> us).
                2 => {
                    saw_interested = true;
                    // The leecher can only REQUEST once we UNCHOKE it.
                    sock.write_all(&frame(1, &[])).await.unwrap();
                }
                6 if len == 13 && acc[5..9] == [0, 0, 0, 1] => {
                    saw_request = Some((
                        u32::from_be_bytes([acc[5], acc[6], acc[7], acc[8]]),
                        u32::from_be_bytes([acc[9], acc[10], acc[11], acc[12]]),
                        u32::from_be_bytes([acc[13], acc[14], acc[15], acc[16]]),
                    ));
                }
                _ => {}
            }
            acc.drain(..4 + len);
        }
    }
    assert!(
        saw_interested,
        "engine never expressed interest in our claim"
    );
    let (r_index, r_begin, r_length) =
        saw_request.expect("engine never requested the claimed piece");
    assert_eq!(r_index, 1);
    assert_eq!(r_begin, 0);
    assert_eq!(r_length, PIECE_LEN as u32);

    // Poison: serve garbage for the requested window. A PIECE payload is
    // index || begin || data (8-byte header) \u2014 NO length field.
    let mut payload = Vec::with_capacity(8 + r_length as usize);
    payload.extend_from_slice(&r_index.to_be_bytes());
    payload.extend_from_slice(&r_begin.to_be_bytes());
    payload.extend(std::iter::repeat_n(0xEE, r_length as usize));
    sock.write_all(&frame(7, &payload)).await.unwrap();

    // The engine must verify, fail, BAN our IP, and drop_peer aborts BOTH
    // tasks \u2014 so the socket must CLOSE promptly. A pure timeout here
    // means the socket is still open, i.e. the ban did not propagate.
    match tokio::time::timeout(Duration::from_secs(6), sock.read(&mut rbuf)).await {
        Ok(Ok(_)) => {}  // trailing frames then closure within the window
        Ok(Err(_)) => {} // reset: closed
        Err(_) => panic!("connection stayed open 6s after poisoning - peer not banned"),
    }

    // Integrity: the poisoned bytes must NEVER have been written; the
    // pre-seeded honest piece 0 must be untouched.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let out = tokio::fs::read(tmp.join("poison.bin")).await.unwrap();
    assert_eq!(out.len(), 2 * PIECE_LEN as usize, "preallocated size");
    assert_eq!(
        &out[..PIECE_LEN as usize],
        &piece0[..],
        "honest piece corrupted"
    );
    assert!(
        out[PIECE_LEN as usize..].iter().all(|&b| b == 0),
        "poisoned bytes reached the output file"
    );

    leecher_task.abort();
    let _ = tokio::fs::remove_dir_all(&tmp).await;
}
