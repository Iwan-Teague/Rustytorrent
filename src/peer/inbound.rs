//! Inbound-connection plumbing shared between the single-torrent engine
//! (which binds its own listener) and the multi-torrent daemon (which
//! runs one shared acceptor that demuxes by info_hash).
//!
//! Both feed a session through the same channel of [`Inbound`] values:
//!
//! - [`Inbound::Raw`] — a freshly-accepted byte stream the *session*
//!   still has to handshake. This is what the single-torrent listener
//!   produces; the per-peer task does the plain/MSE dispatch and the BT
//!   handshake exactly as before, so that path is byte-for-byte unchanged.
//! - [`Inbound::Handshaken`] — a connection the *shared acceptor* has
//!   already taken all the way through MSE (if any) and the BT handshake,
//!   carrying the matched info_hash so the daemon can route it. The
//!   session just registers it and runs the post-handshake loop.
//!
//! The two-variant split is what lets the shared acceptor own the
//! handshake (it *must*, because an MSE peer's info_hash is only knowable
//! after the DH exchange) while the single-torrent path keeps doing the
//! handshake itself.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::peer::transport::Transport;
use crate::peer_id::PeerId;

/// Owned, type-erased read half of a peer stream (plain TCP/µTP split
/// half, or an MSE `Rc4Reader`). Boxed so the acceptor can hand off
/// either kind through one concrete channel type.
pub type BoxedReader = Box<dyn AsyncRead + Send + Unpin + 'static>;
/// Owned, type-erased write half — see [`BoxedReader`].
pub type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin + 'static>;

/// A connection the shared acceptor has already driven through the full
/// handshake. `reader`/`writer` are positioned at the first wire message
/// (immediately after the BT handshake), so the session runs only the
/// post-handshake loop.
pub struct HandshakenPeer {
    /// The torrent this connection belongs to (matched during the
    /// handshake — plain: read from the handshake; MSE: returned by
    /// `mse::perform_incoming`'s candidate match).
    pub info_hash: [u8; 20],
    /// Remote peer address.
    pub addr: SocketAddr,
    /// The peer's advertised peer_id from its handshake.
    pub peer_id: PeerId,
    /// Whether the peer set the BEP 10 extension-protocol reserved bit.
    pub supports_ext: bool,
    pub reader: BoxedReader,
    pub writer: BoxedWriter,
}

/// A connection arriving at a session's inbound channel.
pub enum Inbound {
    /// Not yet handshaken — the session handshakes it (single-torrent
    /// path, byte-identical to the pre-daemon behavior).
    Raw(Transport, SocketAddr),
    /// Already handshaken by the shared acceptor (daemon path).
    Handshaken(HandshakenPeer),
}
