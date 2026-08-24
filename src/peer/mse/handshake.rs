//! MSE/PE handshake — initiator (`perform_outgoing`) and receiver
//! (`perform_incoming`). On success both return an `EncryptedStream` whose
//! AsyncRead/AsyncWrite halves transparently RC4 the wire bytes; on top of
//! that the caller proceeds with the regular BitTorrent handshake plus
//! protocol traffic.
//!
//! Receiver-side note: `perform_incoming` takes a slice of already-buffered
//! bytes (the ones a "hint reader" peeked at to decide between plain BT and
//! MSE) and a list of `info_hash`es it's willing to accept. This lets the
//! caller make a peek-then-route decision without losing data — see
//! `perform_incoming_with_buffered`.

use rand::{Rng, RngCore};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::dh::{self, Keypair, KEY_LEN};
use super::rc4::Rc4;
use super::stream::EncryptedStream;
use super::{sha1_concat, CRYPTO_PLAINTEXT, CRYPTO_RC4, VC};

/// Maximum padding the spec allows for `PadA`, `PadB`, `PadC`, `PadD`.
const PAD_MAX: usize = 512;

/// Length of `Ya` / `Yb` (the DH public key).
const Y_LEN: usize = KEY_LEN;

/// Maximum bytes the receiver will read while searching for `HASH('req1', S)`.
/// Per BEP 8 the initiator's `PadA` is 0..512 bytes, so the hash starts no
/// later than 512 bytes into the post-Ya stream.
const SYNC_SEARCH_LIMIT: usize = PAD_MAX + 20;

#[derive(Debug, thiserror::Error)]
pub enum MseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mse handshake failed: {0}")]
    Handshake(String),
    #[error("no crypto algorithm in common with peer")]
    NoCommonCrypto,
    #[error("info_hash not recognised")]
    UnknownSkey,
}

pub type MseResult<T> = std::result::Result<T, MseError>;

/// Crypto selection between peers. We advertise both plaintext and RC4.
fn crypto_provide_bytes() -> [u8; 4] {
    (CRYPTO_PLAINTEXT | CRYPTO_RC4).to_be_bytes()
}

/// Drive the MSE handshake as the initiator (we opened the TCP connection).
/// Returns an `EncryptedStream` that the caller then runs the BT handshake on.
pub async fn perform_outgoing<S>(
    mut stream: S,
    info_hash: [u8; 20],
) -> MseResult<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1) Generate DH key, send Ya + random PadA.
    let kp = Keypair::generate();
    let ya = dh::to_bytes(&kp.public);
    let pad_a_len = rand::thread_rng().gen_range(0..=PAD_MAX);
    let mut pad_a = vec![0u8; pad_a_len];
    rand::thread_rng().fill_bytes(&mut pad_a);
    stream.write_all(&ya).await?;
    if !pad_a.is_empty() {
        stream.write_all(&pad_a).await?;
    }

    // 2) Read Yb (96 BE bytes), validate it's not a degenerate / malicious
    //    value (0, 1, p-1, p — any of which would force a predictable shared
    //    secret), then derive S.
    let mut yb = [0u8; Y_LEN];
    stream.read_exact(&mut yb).await?;
    let yb_big = dh::from_bytes(&yb);
    dh::validate_peer_public(&yb_big)
        .map_err(|why| MseError::Handshake(format!("bad peer DH key: {why}")))?;
    let s = dh::to_bytes(&kp.shared_secret(&yb_big));

    // 3) Send req1 || req2^req3 || ENCRYPT(VC || crypto_provide || len(PadC)
    //    || PadC || len(IA)=0 || IA="")
    let req1 = sha1_concat(&[b"req1", &s]);
    let req2 = sha1_concat(&[b"req2", &info_hash]);
    let req3 = sha1_concat(&[b"req3", &s]);
    let mut req23 = [0u8; 20];
    for i in 0..20 {
        req23[i] = req2[i] ^ req3[i];
    }

    let mut out_cipher = derive_rc4(b"keyA", &s, &info_hash);
    let mut in_cipher = derive_rc4(b"keyB", &s, &info_hash);

    let pad_c_len = rand::thread_rng().gen_range(0..=PAD_MAX);
    let mut pad_c = vec![0u8; pad_c_len];
    rand::thread_rng().fill_bytes(&mut pad_c);

    let mut encrypted_block: Vec<u8> = Vec::with_capacity(8 + 4 + 2 + pad_c_len + 2);
    encrypted_block.extend_from_slice(&VC);
    encrypted_block.extend_from_slice(&crypto_provide_bytes());
    encrypted_block.extend_from_slice(&(pad_c_len as u16).to_be_bytes());
    encrypted_block.extend_from_slice(&pad_c);
    encrypted_block.extend_from_slice(&0u16.to_be_bytes()); // len(IA) = 0 — we send the BT handshake unencrypted-of-MSE later
    out_cipher.process(&mut encrypted_block);

    stream.write_all(&req1).await?;
    stream.write_all(&req23).await?;
    stream.write_all(&encrypted_block).await?;

    // 4) Receive ENCRYPT(VC || crypto_select || len(PadD) || PadD).
    //    First we must sync on the encrypted VC. The receiver's `PadB` is
    //    0..512 random bytes preceding the encrypted block.
    sync_on_encrypted_vc(&mut stream, &mut in_cipher).await?;

    // Now `in_cipher` is aligned at the byte AFTER `ENCRYPT(VC)`. Read the
    // next 6 bytes: crypto_select (4) || len(PadD) (2).
    let mut tail = [0u8; 6];
    stream.read_exact(&mut tail).await?;
    in_cipher.process(&mut tail);
    let crypto_select = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
    let pad_d_len = u16::from_be_bytes([tail[4], tail[5]]) as usize;
    if pad_d_len > PAD_MAX {
        return Err(MseError::Handshake(format!(
            "PadD length {pad_d_len} > {PAD_MAX}"
        )));
    }
    if pad_d_len > 0 {
        let mut pad_d = vec![0u8; pad_d_len];
        stream.read_exact(&mut pad_d).await?;
        in_cipher.process(&mut pad_d);
    }

    // We only support full-encryption mode; per BEP 8, if RC4 is selected
    // by either party the rest of the stream is encrypted with the per-
    // direction RC4 keystreams already in `in_cipher`/`out_cipher`. If the
    // peer selected plaintext we'd have to expose a non-encrypting stream;
    // skip that complication and require RC4.
    if crypto_select & CRYPTO_RC4 == 0 {
        return Err(MseError::NoCommonCrypto);
    }

    Ok(EncryptedStream::new(stream, in_cipher, out_cipher))
}

/// Read bytes from `stream` and locate `ENCRYPT(VC)` within the first
/// `PAD_MAX + 8` bytes. On success, `in_cipher` is positioned at the byte
/// immediately AFTER the 8 VC bytes, and any bytes that were before VC are
/// discarded (they're `PadB`).
async fn sync_on_encrypted_vc<S>(stream: &mut S, in_cipher: &mut Rc4) -> MseResult<()>
where
    S: AsyncRead + Unpin,
{
    // Pre-compute what 8 bytes of zeroes look like once they pass through the
    // RC4 keystream we *expect* to be at position 0 — that pattern is the
    // 8-byte sequence we're searching for in the wire data.
    let mut needle = [0u8; 8];
    // We need a clone of `in_cipher` at its current state to derive the
    // expected encrypted VC, then keep the original to use post-sync.
    let mut probe = in_cipher.clone();
    probe.process(&mut needle);

    // Rolling search: read one byte at a time into a sliding window. After
    // each new byte, check if the last 8 bytes equal `needle`.
    let mut window: Vec<u8> = Vec::with_capacity(8);
    for _ in 0..(SYNC_SEARCH_LIMIT + 8) {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        window.push(byte[0]);
        if window.len() > 8 {
            window.remove(0);
        }
        if window.len() == 8 && window[..] == needle[..] {
            // Found. Replace `in_cipher` with the cipher positioned just
            // past these 8 VC bytes.
            *in_cipher = probe;
            return Ok(());
        }
    }
    Err(MseError::Handshake("could not sync on encrypted VC".into()))
}

/// RC4 with the standard MSE 1024-byte discard at the front.
fn derive_rc4(tag: &[u8; 4], s: &[u8], skey: &[u8; 20]) -> Rc4 {
    let key = sha1_concat(&[tag, s, skey]);
    let mut rc4 = Rc4::new(&key);
    rc4.skip(1024);
    rc4
}

/// Drive the MSE handshake as the receiver. `info_hashes` is the set of
/// torrents we know about; we use `HASH('req2', info_hash)` to identify which
/// one the initiator wants. Returns `(EncryptedStream, matched_info_hash)`.
///
/// `pre_read` is bytes the caller already consumed from the wire while
/// deciding this was MSE traffic (typically 0–20 bytes peeked to look at
/// the first byte). Those bytes are treated as the start of `Ya`.
pub async fn perform_incoming<S>(
    mut stream: S,
    info_hashes: &[[u8; 20]],
    pre_read: &[u8],
) -> MseResult<(EncryptedStream<S>, [u8; 20])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if pre_read.len() > Y_LEN {
        return Err(MseError::Handshake("pre_read longer than Ya".into()));
    }

    // 1) Receive Ya, validate it's not a degenerate / malicious value.
    let mut ya = [0u8; Y_LEN];
    ya[..pre_read.len()].copy_from_slice(pre_read);
    if pre_read.len() < Y_LEN {
        stream.read_exact(&mut ya[pre_read.len()..]).await?;
    }
    let peer_pub = dh::from_bytes(&ya);
    dh::validate_peer_public(&peer_pub)
        .map_err(|why| MseError::Handshake(format!("bad peer DH key: {why}")))?;

    // 2) Generate our DH key, send Yb + PadB.
    let kp = Keypair::generate();
    let yb = dh::to_bytes(&kp.public);
    let pad_b_len = rand::thread_rng().gen_range(0..=PAD_MAX);
    let mut pad_b = vec![0u8; pad_b_len];
    rand::thread_rng().fill_bytes(&mut pad_b);
    stream.write_all(&yb).await?;
    if !pad_b.is_empty() {
        stream.write_all(&pad_b).await?;
    }

    let s = dh::to_bytes(&kp.shared_secret(&peer_pub));

    // 3) Read past PadA and find HASH('req1', S) — exactly 20 bytes — within
    //    the first PAD_MAX+20 bytes of the post-Ya stream.
    let req1 = sha1_concat(&[b"req1", &s]);
    sync_on_pattern(&mut stream, &req1).await?;

    // 4) Read HASH('req2', SKEY) XOR HASH('req3', S). Try every known SKEY.
    let mut req23 = [0u8; 20];
    stream.read_exact(&mut req23).await?;
    let req3 = sha1_concat(&[b"req3", &s]);
    let mut req2_xor_req3 = [0u8; 20];
    for i in 0..20 {
        req2_xor_req3[i] = req23[i] ^ req3[i];
    }
    // Constant-time candidate evaluation: sweep EVERY hosted info-hash
    // with a data-independent comparison (subtle::ConstantTimeEq), no
    // early exit. A short-circuiting `find` over plain `==` would let an
    // active prober time the handshake to learn whether its SKEY guess
    // hit at all, and which hosted torrent it belongs to (candidate
    // index). Info-hashes are unique per torrent, so at most one
    // candidate satisfies the equation — last-match-wins is equivalent
    // to `find` while being timing-uniform in the candidate set.
    let mut matched: Option<[u8; 20]> = None;
    for ih in info_hashes {
        let cand = sha1_concat(&[b"req2", &ih[..]]);
        if bool::from(cand.ct_eq(&req2_xor_req3)) {
            matched = Some(*ih);
        }
    }
    let matched = matched.ok_or(MseError::UnknownSkey)?;

    // 5) Derive both ciphers.
    let mut in_cipher = derive_rc4(b"keyA", &s, &matched);
    let mut out_cipher = derive_rc4(b"keyB", &s, &matched);

    // 6) Read ENCRYPT(VC || crypto_provide || len(PadC) || PadC || len(IA) || IA).
    let mut vc_and_header = [0u8; 8 + 4 + 2];
    stream.read_exact(&mut vc_and_header).await?;
    in_cipher.process(&mut vc_and_header);
    if vc_and_header[..8] != VC {
        return Err(MseError::Handshake("VC mismatch after sync".into()));
    }
    let crypto_provide = u32::from_be_bytes([
        vc_and_header[8],
        vc_and_header[9],
        vc_and_header[10],
        vc_and_header[11],
    ]);
    let pad_c_len = u16::from_be_bytes([vc_and_header[12], vc_and_header[13]]) as usize;
    if pad_c_len > PAD_MAX {
        return Err(MseError::Handshake(format!(
            "PadC length {pad_c_len} > {PAD_MAX}"
        )));
    }
    if pad_c_len > 0 {
        let mut pad_c = vec![0u8; pad_c_len];
        stream.read_exact(&mut pad_c).await?;
        in_cipher.process(&mut pad_c);
    }
    let mut ia_len_buf = [0u8; 2];
    stream.read_exact(&mut ia_len_buf).await?;
    in_cipher.process(&mut ia_len_buf);
    let ia_len = u16::from_be_bytes(ia_len_buf) as usize;
    if ia_len > 0 {
        // We don't currently use the "initial payload" optimisation — drain it.
        let mut ia = vec![0u8; ia_len];
        stream.read_exact(&mut ia).await?;
        in_cipher.process(&mut ia);
    }

    // 7) Choose crypto algorithm. Prefer RC4 to keep the rest of the
    //    connection encrypted (matches what we wired into EncryptedStream).
    let crypto_select = if crypto_provide & CRYPTO_RC4 != 0 {
        CRYPTO_RC4
    } else {
        return Err(MseError::NoCommonCrypto);
    };

    // 8) Send ENCRYPT(VC || crypto_select || len(PadD) || PadD).
    let pad_d_len = rand::thread_rng().gen_range(0..=PAD_MAX);
    let mut pad_d = vec![0u8; pad_d_len];
    rand::thread_rng().fill_bytes(&mut pad_d);
    let mut packet = Vec::with_capacity(8 + 4 + 2 + pad_d_len);
    packet.extend_from_slice(&VC);
    packet.extend_from_slice(&crypto_select.to_be_bytes());
    packet.extend_from_slice(&(pad_d_len as u16).to_be_bytes());
    packet.extend_from_slice(&pad_d);
    out_cipher.process(&mut packet);
    stream.write_all(&packet).await?;

    Ok((EncryptedStream::new(stream, in_cipher, out_cipher), matched))
}

/// Read bytes until `needle` appears or we exceed `SYNC_SEARCH_LIMIT` bytes.
/// Used by the receiver to skip `PadA` and find `HASH('req1', S)`.
async fn sync_on_pattern<S>(stream: &mut S, needle: &[u8; 20]) -> MseResult<()>
where
    S: AsyncRead + Unpin,
{
    let mut window: Vec<u8> = Vec::with_capacity(needle.len());
    for _ in 0..SYNC_SEARCH_LIMIT {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        window.push(byte[0]);
        if window.len() > needle.len() {
            window.remove(0);
        }
        if window.len() == needle.len() && window[..] == needle[..] {
            return Ok(());
        }
    }
    Err(MseError::Handshake(
        "could not sync on HASH(req1, S) within search limit".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// End-to-end MSE handshake between two in-memory duplex streams.
    /// After both sides finish, the encrypted streams must roundtrip data
    /// in both directions byte-identical.
    #[tokio::test]
    async fn mse_full_handshake_roundtrip() {
        let info_hash = [0x42u8; 20];
        let (client_side, server_side) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let (mut enc, matched) = perform_incoming(server_side, &[info_hash], &[])
                .await
                .unwrap();
            assert_eq!(matched, info_hash);
            // Receiver reads "hello" from client, then sends "world".
            let mut buf = [0u8; 5];
            enc.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            enc.write_all(b"world").await.unwrap();
            enc
        });

        let mut client = perform_outgoing(client_side, info_hash).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn receiver_rejects_unknown_info_hash() {
        let known = [0x01u8; 20];
        let unknown = [0x02u8; 20];
        let (client_side, server_side) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let res = perform_incoming(server_side, &[known], &[]).await;
            assert!(matches!(res, Err(MseError::UnknownSkey)));
        });

        // The initiator side errors out when the receiver closes mid-handshake;
        // we don't care about the exact error, only that the receiver rejects.
        let _ = perform_outgoing(client_side, unknown).await;
        server.await.unwrap();
    }

    /// The receiver hosts SEVERAL torrents and the initiator speaks for a
    /// NON-FIRST candidate. Pins that the constant-time sweep still
    /// selects the correct SKEY — the sweep evaluates every candidate
    /// precisely so candidate order/index can't leak through timing, and
    /// this test makes sure that restructuring didn't break selection.
    #[tokio::test]
    async fn skey_selection_among_many_candidates_picks_right_one() {
        let candidates: [[u8; 20]; 4] = [[0xA1; 20], [0xB2; 20], [0xC3; 20], [0xD4; 20]];
        let wanted = candidates[2]; // third hosted torrent

        let (client_side, server_side) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let (mut enc, matched) = perform_incoming(server_side, &candidates, &[])
                .await
                .unwrap();
            assert_eq!(matched, wanted);
            let mut buf = [0u8; 5];
            enc.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });

        let mut client = perform_outgoing(client_side, wanted).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        server.await.unwrap();
    }
}
