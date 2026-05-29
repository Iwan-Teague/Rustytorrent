//! A peer connection's underlying byte transport — either a TCP
//! socket or a µTP (BEP 29) stream over UDP.
//!
//! The peer code above this layer (BT handshake, MSE, the wire-message
//! loop) only needs `AsyncRead + AsyncWrite`. Wrapping both transports
//! in one enum lets the dial path race TCP and µTP and hand the winner
//! to a single, transport-agnostic handshake/loop — no boxing, no
//! duplicated handshake code. `tokio::io::split` turns a `Transport`
//! into the read/write halves the post-handshake loop consumes.
//!
//! µTP is gated off whenever a SOCKS5 chain or `--bind-iface` is in
//! play: UDP can't ride a SOCKS5 CONNECT, and our µTP socket isn't
//! interface-bound, so allowing it there would leak outside the
//! tunnel / kill-switch. The engine simply doesn't hand a `UtpSocket`
//! to the dialer in those modes, so only `Tcp` is ever constructed.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::utp::UtpStream;

/// A connected peer byte-stream. Both variants are `Unpin`, so the
/// `AsyncRead`/`AsyncWrite` impls project through a plain `match`.
pub enum Transport {
    Tcp(TcpStream),
    Utp(UtpStream),
}

impl Transport {
    /// Disable Nagle on TCP; no-op for µTP (which paces itself).
    pub fn set_nodelay(&self) {
        if let Transport::Tcp(s) = self {
            let _ = s.set_nodelay(true);
        }
    }

    /// The remote peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.peer_addr(),
            Transport::Utp(s) => Ok(s.peer_addr()),
        }
    }

    /// Peek the first inbound byte without consuming it — the inbound
    /// dispatcher uses it to pick plain BT (`0x13`) vs MSE. `Ok(None)`
    /// is a clean EOF before any byte arrived. Non-consuming on both
    /// transports, so the handshake that follows still sees the byte.
    pub async fn peek_first_byte(&mut self) -> io::Result<Option<u8>> {
        match self {
            Transport::Tcp(s) => {
                let mut b = [0u8; 1];
                let n = s.peek(&mut b).await?;
                Ok((n > 0).then_some(b[0]))
            }
            Transport::Utp(s) => s.peek_first_byte().await,
        }
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Utp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Transport::Utp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
            Transport::Utp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Utp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::utp::UtpSocket;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn utp_transport_roundtrips_and_peeks() {
        let server = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let saddr = server.local_addr();
        let client = UtpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let srv = tokio::spawn(async move {
            let (s, _peer) = server.accept().await.unwrap();
            let mut t = Transport::Utp(s);
            // Peek must see the first byte without consuming it.
            let peeked = t.peek_first_byte().await.unwrap();
            assert_eq!(peeked, Some(0x13));
            let mut buf = [0u8; 3];
            t.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, &[0x13, 0xAA, 0xBB]);
            t.write_all(b"ok").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let mut t = Transport::Utp(client.connect(saddr).await.unwrap());
        t.set_nodelay(); // no-op for µTP, must not panic
        t.write_all(&[0x13, 0xAA, 0xBB]).await.unwrap();
        let mut buf = [0u8; 2];
        t.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
        srv.await.unwrap();
    }
}
