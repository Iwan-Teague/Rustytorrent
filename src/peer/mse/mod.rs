//! Message Stream Encryption (MSE/PE) — BitTorrent's opportunistic
//! transport-layer obfuscation. See
//! <https://wiki.vuze.com/w/Message_Stream_Encryption> and
//! <https://jwodder.github.io/kbits/posts/bt-encrypt/>.
//!
//! The protocol:
//! 1. Initiator → Receiver:  `Ya || PadA`       (96 + 0..512 bytes)
//! 2. Receiver → Initiator:  `Yb || PadB`       (96 + 0..512 bytes)
//! 3. Initiator → Receiver:  `HASH("req1",S) || HASH("req2",SKEY) XOR HASH("req3",S)
//!                            || ENCRYPT(VC || crypto_provide || len(PadC) || PadC
//!                                       || len(IA) || IA)`
//! 4. Receiver → Initiator:  `ENCRYPT(VC || crypto_select || len(PadD) || PadD)`
//!
//! After step 4, both ends switch to plain RC4 encryption keyed by:
//! - A→B direction: `HASH("keyA", S, SKEY)` (1024-byte discard)
//! - B→A direction: `HASH("keyB", S, SKEY)` (1024-byte discard)
//!
//! `SKEY` is the torrent's info_hash. `S` is the DH shared secret as 96 BE bytes.
//! `VC` is eight zero bytes — used by the receiver to recognise the start of the
//! encrypted region in step 4.

use sha1::{Digest, Sha1};

pub mod rc4;

mod dh;
mod handshake;
mod stream;

pub use handshake::{perform_incoming, perform_outgoing, MseError, MseResult};
pub use stream::{EncryptedStream, Rc4Reader, Rc4Writer};

/// crypto_provide / crypto_select bitfield values (BEP 8).
pub const CRYPTO_PLAINTEXT: u32 = 0x01;
pub const CRYPTO_RC4: u32 = 0x02;

/// Eight-byte verification constant. The receiver scans the incoming stream
/// for `ENCRYPT(VC)` to locate the start of the encrypted region.
pub const VC: [u8; 8] = [0u8; 8];

/// SHA-1 over the concatenation of arbitrary byte slices.
pub fn sha1_concat(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_concat_matches_single() {
        let a = sha1_concat(&[b"abc"]);
        let b = sha1_concat(&[b"a", b"b", b"c"]);
        assert_eq!(a, b);
    }
}
