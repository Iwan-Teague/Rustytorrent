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
//! Three layers, each a focused commit so a reviewer can audit them
//! independently: the packet codec (`packet`), the pure-logic
//! per-connection state machine (`connection`), and the UDP socket
//! runtime + `AsyncRead`/`AsyncWrite` bridge (`socket`). Engine
//! integration (parallel TCP+µTP dial; off under `--anonymous` since
//! UDP can't ride SOCKS5) is the remaining step.
//!
//! ## What we deliberately don't implement
//!
//! - Full LEDBAT congestion control. The spec describes a delay-based
//!   AIMD that targets a constant queuing delay; we use a much
//!   simpler fixed-window approach. Means we won't be as friendly to
//!   coexisting TCP flows under load, but data still moves.
//! - Selective Ack (BEP 29) IS acted on: the receiver emits a SACK
//!   bitmask, the sender prunes selectively-acked packets from its
//!   retransmit queue, and a SACK reporting >= 3 packets past the gap
//!   triggers an immediate fast retransmit of the gap (no RTO wait).
//!
//! Both gaps are noted on each call site so a future contributor can
//! tighten without first re-deriving the design.

pub mod connection;
pub mod packet;
pub mod socket;

pub use connection::{Connection, State};
pub use packet::{Packet, PacketType};
pub use socket::{UtpSocket, UtpStream};
