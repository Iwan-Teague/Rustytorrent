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
//! This module starts with the packet codec (`packet`). Subsequent
//! commits will add the connection state machine (`socket` /
//! `stream`) and the engine integration. Each is a focused commit so
//! a reviewer can audit the layers independently.
//!
//! ## What we deliberately don't implement
//!
//! - Full LEDBAT congestion control. The spec describes a delay-based
//!   AIMD that targets a constant queuing delay; we use a much
//!   simpler fixed-window approach. Means we won't be as friendly to
//!   coexisting TCP flows under load, but data still moves.
//! - The Selective Ack extension is parsed but not yet acted on.
//!   Lost-packet recovery is via the cumulative ack_nr only;
//!   re-sending the entire window starting at ack_nr+1.
//!
//! Both gaps are noted on each call site so a future contributor can
//! tighten without first re-deriving the design.

pub mod connection;
pub mod packet;

pub use connection::{Connection, State};
pub use packet::{Packet, PacketType};
