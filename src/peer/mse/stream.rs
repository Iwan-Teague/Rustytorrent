//! Stream wrapper that transparently encrypts/decrypts with RC4 in each direction.
//!
//! After the MSE handshake completes both peers run plain RC4 on the wire.
//! We expose this as an `AsyncRead + AsyncWrite` so the existing per-peer task
//! (which expects a single duplex stream) doesn't need to know it's encrypted.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::rc4::Rc4;

/// Inner stream wrapped with a separate RC4 keystream for each direction.
pub struct EncryptedStream<S> {
    inner: S,
    /// Decrypts bytes arriving on `inner`.
    read_cipher: Rc4,
    /// Encrypts bytes leaving on `inner`.
    write_cipher: Rc4,
}

impl<S> EncryptedStream<S> {
    pub fn new(inner: S, read_cipher: Rc4, write_cipher: Rc4) -> Self {
        Self {
            inner,
            read_cipher,
            write_cipher,
        }
    }

    /// Decompose into the raw stream and the two ciphers. Useful when the
    /// underlying stream supports splitting into independent owned halves
    /// (`tokio::net::TcpStream::into_split`): each half can then be wrapped
    /// with `Rc4Reader` / `Rc4Writer` and used from independent tasks
    /// without sharing state.
    pub fn into_parts(self) -> (S, Rc4, Rc4) {
        (self.inner, self.read_cipher, self.write_cipher)
    }
}

/// Wraps an async reader so every byte coming out of it has been XORed
/// with the supplied RC4 keystream. Owns its cipher; suitable for a
/// dedicated read task.
pub struct Rc4Reader<R> {
    inner: R,
    cipher: Rc4,
}

impl<R> Rc4Reader<R> {
    pub fn new(inner: R, cipher: Rc4) -> Self {
        Self { inner, cipher }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Rc4Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                this.cipher.process(&mut buf.filled_mut()[before..after]);
            }
        }
        result
    }
}

/// Wraps an async writer so every byte handed to `poll_write` is XORed
/// with the RC4 keystream before being passed to the inner writer. Owns
/// its cipher; suitable for a dedicated write task.
pub struct Rc4Writer<W> {
    inner: W,
    cipher: Rc4,
}

impl<W> Rc4Writer<W> {
    pub fn new(inner: W, cipher: Rc4) -> Self {
        Self { inner, cipher }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Rc4Writer<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // See `EncryptedStream::poll_write`: advance the keystream by exactly
        // the bytes the inner writer accepts so a `Pending` or short write
        // can't desync the peer. Encrypt with a clone; commit per the result.
        let mut cipher = this.cipher.clone();
        let mut encrypted = buf.to_vec();
        cipher.process(&mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) if n == encrypted.len() => {
                this.cipher = cipher;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Ok(n)) => {
                this.cipher.skip(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Capture how much was already filled so we only decrypt the bytes
        // that this poll actually deposits.
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let filled_after = buf.filled().len();
            if filled_after > before {
                let slice = &mut buf.filled_mut()[before..filled_after];
                this.read_cipher.process(slice);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // RC4 is forward-only, so the keystream must advance by exactly the
        // number of bytes the inner writer actually accepts. Encrypt with a
        // *clone* of the cipher and only commit the advance once the inner
        // write reports how much it took: adopt the advanced clone on a full
        // write, step the real cipher forward by `n` on a partial write, and
        // leave it untouched on `Pending`/`Err`. Advancing the real cipher up
        // front (the old behaviour) desynced the peer whenever the inner write
        // came back `Pending` under backpressure — `write_all` then re-encrypts
        // the same bytes from the already-advanced position.
        let mut cipher = this.write_cipher.clone();
        let mut encrypted = buf.to_vec();
        cipher.process(&mut encrypted);
        match Pin::new(&mut this.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) if n == encrypted.len() => {
                this.write_cipher = cipher;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Ok(n)) => {
                this.write_cipher.skip(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Two `EncryptedStream`s using mirrored keystreams roundtrip arbitrary
    /// payloads across a `tokio::io::duplex` connection.
    #[tokio::test]
    async fn roundtrip_through_duplex() {
        let (a, b) = tokio::io::duplex(4096);
        // Mirror: A writes encrypted with cipher K_out; B reads decrypted
        // with cipher K_in == K_out.
        let key = b"shared-handshake-derived-key";
        let mut alice = EncryptedStream::new(a, Rc4::new(key), Rc4::new(key));
        let mut bob = EncryptedStream::new(b, Rc4::new(key), Rc4::new(key));

        let payload: Vec<u8> = (0u8..200).collect();
        alice.write_all(&payload).await.unwrap();
        let mut out = vec![0u8; payload.len()];
        bob.read_exact(&mut out).await.unwrap();
        assert_eq!(out, payload);

        // Reverse direction too.
        let reply = b"BitTorrent protocol".to_vec();
        bob.write_all(&reply).await.unwrap();
        let mut got = vec![0u8; reply.len()];
        alice.read_exact(&mut got).await.unwrap();
        assert_eq!(got, reply);
    }

    /// An `AsyncWrite` that returns `Pending` (self-waking) on every other
    /// poll and never accepts more than one byte at a time — exactly the
    /// `Pending` / short-write conditions a real `TcpStream` produces under
    /// backpressure. Before the per-`n` keystream-advance fix, the writer
    /// advanced the cipher by the full buffer up front, so a `Pending` made
    /// `write_all` re-encrypt the same bytes from an advanced position and
    /// desync the peer.
    struct ChokeWriter<W> {
        inner: W,
        pend_next: bool,
    }

    impl<W: AsyncWrite + Unpin> AsyncWrite for ChokeWriter<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.pend_next {
                this.pend_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            this.pend_next = true;
            let n = buf.len().min(1);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..n])
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn keystream_survives_pending_and_partial_writes() {
        let (a, b) = tokio::io::duplex(8192);
        let key = b"shared-handshake-derived-key";
        let mut writer = EncryptedStream::new(
            ChokeWriter {
                inner: a,
                pend_next: true,
            },
            Rc4::new(key),
            Rc4::new(key),
        );
        let mut reader = EncryptedStream::new(b, Rc4::new(key), Rc4::new(key));

        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let to_send = payload.clone();
        let w = tokio::spawn(async move {
            writer.write_all(&to_send).await.unwrap();
            writer.flush().await.unwrap();
        });
        let mut got = vec![0u8; payload.len()];
        reader.read_exact(&mut got).await.unwrap();
        w.await.unwrap();
        assert_eq!(got, payload);
    }
}
