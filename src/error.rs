#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A `.torrent` file, magnet URI, or any other bencoded blob (tracker
    /// response, DHT/extension payload) could not be parsed or failed a
    /// structural invariant. Returned from the bencode reader and the
    /// metainfo/magnet decoders. Almost always a malformed or truncated
    /// input rather than a transient condition.
    #[error("invalid torrent/magnet data ({0}); the file or link is malformed or truncated — re-download it or check the magnet URI")]
    Bencode(String),

    /// Announcing to a tracker failed: DNS/dial/timeout, a non-bencode or
    /// malformed response, or a `failure reason` the tracker sent back.
    /// Returned from the HTTP and UDP tracker clients. The client moves on
    /// to the next tracker in the tier; this surfaces only when every
    /// configured tracker has been exhausted.
    #[error("tracker announce failed ({0}); the tracker may be down or unreachable — check your network/proxy, or wait and retry. DHT/PEX can still find peers if enabled")]
    Tracker(String),

    /// The BitTorrent (or BT-over-MSE) handshake with a peer failed:
    /// timeout, connection reset, a bad protocol string, or an `info_hash`
    /// mismatch. Returned from the peer handshake and dial paths. Expected
    /// for individual flaky/incompatible peers — the engine just drops that
    /// peer and tries others, so a single occurrence is not fatal.
    #[error("peer handshake failed ({0}); this peer is unreachable, incompatible, or serving a different torrent — it will be skipped. If every peer fails, the swarm may be encryption-only (try without --no-mse)")]
    Handshake(String),

    /// A downloaded piece's SHA-1 did not match the hash in the metainfo.
    /// Returned by the piece verifier after a full piece is assembled. The
    /// piece is discarded and re-requested automatically; persistent
    /// failures for the same index point at a malicious or broken peer.
    #[error("piece {index} failed hash verification; the data was corrupt or from a bad peer — it will be re-downloaded automatically (no action needed unless this repeats)")]
    VerifyFailed { index: usize },

    /// A filesystem or socket I/O operation failed (open/read/write/seek,
    /// `set_len`, etc.). Converted automatically from `std::io::Error` via
    /// `?` anywhere in the crate, so the inner message is the OS-level
    /// cause.
    #[error("I/O error ({0}); check the path exists and is writable, that there is enough free disk space, and that file permissions allow access")]
    Io(#[from] std::io::Error),

    /// A networking or protocol-level failure outside the BT handshake:
    /// a dial/connect timeout, an unreachable SOCKS5 proxy or down
    /// `--bind-iface` interface, a malformed wire message or DHT/extension
    /// payload, or a refused-startup precondition (e.g. `--memory-only`
    /// with `--paranoid`, or anonymous mode without `--socks5`). Returned
    /// from the peer wire, DHT, uTP, and engine-startup paths. Read the
    /// inner detail: a startup precondition needs a flag change, whereas a
    /// dial/timeout is usually transient or a proxy/interface problem.
    #[error("network error ({0}); if this is a dial/timeout, check connectivity and any --socks5 proxy or --bind-iface interface; if it names a flag conflict or unsupported platform, adjust your command-line options")]
    Network(String),

    /// A cryptographic or encrypted-spool operation failed: Argon2 key
    /// derivation, AES-GCM encrypt/decrypt, a spool header/magic/version
    /// mismatch, or a missing `--passphrase` in `--paranoid` mode. Returned
    /// from the storage crypt and spool layers. A decrypt/verifier failure
    /// almost always means a wrong passphrase or a tampered/mismatched
    /// spool file rather than a code bug.
    #[error("crypto/encrypted-spool error ({0}); usually a wrong or missing --passphrase (set it or RUSTYTORRENT_PASSPHRASE), or a spool file that was tampered with or belongs to a different torrent")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
