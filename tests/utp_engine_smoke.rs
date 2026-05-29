//! End-to-end smoke test for the µTP transport wired into the peer
//! connection layer: two peer tasks complete a real BitTorrent
//! handshake over a µTP `Transport` (UDP loopback), exercising the
//! whole new stack — UtpSocket connect/accept, the Transport enum, the
//! non-consuming peek the inbound dispatcher relies on, plain-handshake
//! dispatch, tokio::io::split, and the post-handshake loop startup.

use std::time::Duration;

use rustytorrent::peer::connection::{run_with_stream, PeerCommand, PeerEvent};
use rustytorrent::peer::transport::Transport;
use rustytorrent::peer::utp::UtpSocket;
use tokio::sync::mpsc;

#[tokio::test]
async fn two_peers_complete_bt_handshake_over_utp() {
    let info_hash = [0x42u8; 20];
    let server_id = [0x01u8; 20];
    let client_id = [0x02u8; 20];

    let server_sock = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let saddr = server_sock.local_addr();
    let client_sock = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Server side: accept a µTP stream, run the inbound dispatch path
    // (peek → plain BT handshake → post-handshake loop).
    let (s_ev_tx, mut s_ev_rx) = mpsc::channel::<PeerEvent>(16);
    let (_s_cmd_tx, s_cmd_rx) = mpsc::channel::<PeerCommand>(16);
    let server = tokio::spawn(async move {
        let (stream, addr) = server_sock.accept().await.unwrap();
        let _ = run_with_stream(
            Transport::Utp(stream),
            addr,
            info_hash,
            server_id,
            s_ev_tx,
            s_cmd_rx,
            false, // incoming
            false, // not anonymous
        )
        .await;
    });

    // Client side: dial µTP, run the outgoing plain-handshake path.
    let stream = client_sock.connect(saddr).await.unwrap();
    let caddr = stream.peer_addr();
    let (c_ev_tx, mut c_ev_rx) = mpsc::channel::<PeerEvent>(16);
    let (_c_cmd_tx, c_cmd_rx) = mpsc::channel::<PeerCommand>(16);
    let client = tokio::spawn(async move {
        let _ = run_with_stream(
            Transport::Utp(stream),
            caddr,
            info_hash,
            client_id,
            c_ev_tx,
            c_cmd_rx,
            true, // outgoing
            false,
        )
        .await;
    });

    // Both ends must report Connected carrying the *other* side's peer_id.
    let s_ev = tokio::time::timeout(Duration::from_secs(5), s_ev_rx.recv())
        .await
        .expect("server Connected timed out")
        .expect("server event channel closed");
    match s_ev {
        PeerEvent::Connected { peer_id, .. } => assert_eq!(peer_id, client_id),
        other => panic!("server expected Connected, got {other:?}"),
    }

    let c_ev = tokio::time::timeout(Duration::from_secs(5), c_ev_rx.recv())
        .await
        .expect("client Connected timed out")
        .expect("client event channel closed");
    match c_ev {
        PeerEvent::Connected { peer_id, .. } => assert_eq!(peer_id, server_id),
        other => panic!("client expected Connected, got {other:?}"),
    }

    server.abort();
    client.abort();
}
