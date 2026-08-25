//! Wire-level proof that the MSE-only outgoing dial never sends the
//! plain BitTorrent handshake preamble (`\x13BitTorrent protocol`) on
//! the wire. A DPI middlebox that sees those bytes can identify the
//! traffic as BitTorrent regardless of any subsequent encryption.
//!
//! Under MSE-only mode, the first bytes on the wire are the DH public
//! key `Ya` — cryptographically random, not a recognizable marker.
//! This test drives `mse_handshake_outgoing` against a raw listener and
//! asserts the captured wire bytes don't match the plain preamble.

use std::time::Duration;

use rustytorrent::peer::connection::mse_handshake_outgoing;
use rustytorrent::peer::transport::Transport;

#[tokio::test]
async fn mse_wire_never_leaks_plain_bt_preamble() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let info_hash: [u8; 20] = sha1(b"wire-fingerprint-test");
    let peer_id: [u8; 20] = sha1(b"test-peer");

    // Drive the MSE handshake against the listener in a spawned task.
    let transport = Transport::Tcp(tokio::net::TcpStream::connect(addr).await.unwrap());
    let client = tokio::spawn(async move {
        let _ = mse_handshake_outgoing(transport, info_hash, peer_id).await;
    });

    // Accept and read the first bytes the initiator sends.
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = vec![0u8; 512];
    use tokio::io::AsyncReadExt;
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("read within 5s")
        .expect("read ok");

    // Assert: the first bytes are NOT the plain BT preamble.
    assert!(
        n < 20 || &buf[..19] != b"BitTorrent protocol",
        "wire begins with 'BitTorrent protocol' - DPI fingerprint leak"
    );

    // The MSE handshake sends Ya (96 bytes) as part of the key exchange,
    // so we should see at least that many bytes of cryptographically
    // random data before anything else.
    assert!(
        n >= 96,
        "MSE initiator must send at least Ya (96 bytes), got {n}"
    );

    drop(client);
}

fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut h = sha1::Sha1::new();
    use sha1::Digest;
    h.update(bytes);
    h.finalize().into()
}
