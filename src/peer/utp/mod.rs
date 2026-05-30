//! µTP (Micro Transport Protocol) — BEP 29.
//!
//! BitTorrent's UDP-based reliable transport. Many real-world clients
//! speak µTP as a peer-discovery and data-exchange channel in
//! parallel with TCP; a TCP-only client like us misses the subset of
//! the swarm that's behind UDP-hole-punching NATs or that
//! deliberately prefers µTP for congestion-friendly background
//! transfer (LEDBAT).
//!
//! ## Scope of this implementation
//!
//! Layers, each a focused commit so a reviewer can audit them
//! independently: the packet codec (`packet`), the pure-logic
//! per-connection state machine (`connection`), the UDP socket runtime
//! + `AsyncRead`/`AsyncWrite` bridge (`socket`), and the engine
//! integration (`--utp`: parallel TCP+µTP dial; off under `--anonymous`
//! / SOCKS5 / `--bind-iface` since UDP can't ride a proxy or be
//! interface-bound here).
//!
//! ## Congestion control & loss recovery
//!
//! - **LEDBAT (BEP 29)**: a delay-based controller sizes the send
//!   window from one-way-delay samples (the peer's echoed
//!   `timestamp_diff`, which the driver also echoes back so the peer's
//!   controller works), yielding to other traffic as queuing delay
//!   builds. Falls back to a fixed window with a 2-packet floor until a
//!   usable sample arrives. Simplification vs libtorrent: a running-min
//!   base delay rather than the 13-slot per-minute history.
//! - **Selective Ack (BEP 29)** is acted on: the receiver emits a SACK
//!   bitmask, the sender prunes selectively-acked packets, and a SACK
//!   reporting >= 3 packets past the gap triggers an immediate fast
//!   retransmit of the gap (no RTO wait).

pub mod connection;
pub mod packet;
pub mod socket;

pub use connection::{Connection, State};
pub use packet::{Packet, PacketType};
pub use socket::{UtpSocket, UtpStream};
