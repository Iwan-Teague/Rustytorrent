//! Small shared helpers used across modules.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// Lowercase hex encoding of a byte slice (e.g. an info-hash → 40 chars).
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a 40-character hex string into a 20-byte info-hash. Returns
/// `None` on the wrong length or any non-hex character.
pub fn info_hash_from_hex(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Per-process pseudonymization key for log redaction. Regenerated every
/// run, so the same peer/info-hash never yields the same token across two
/// sessions (no long-term correlation from captured logs) while staying
/// stable WITHIN one process (log lines about the same peer still join up).
fn log_salt() -> &'static [u8; 16] {
    use std::sync::OnceLock;
    static SALT: OnceLock<[u8; 16]> = OnceLock::new();
    SALT.get_or_init(rand::random::<[u8; 16]>)
}

/// Keyed-digest pseudonym: first `bytes` of SHA-1(key || data), hex.
/// SHA-1 here is only a PRF over secret-salted input for log tokens —
/// no protocol/security property rests on it.
fn log_token(prefix: &str, data: &[u8], bytes: usize) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(log_salt());
    h.update(data);
    let out = h.finalize();
    format!("{prefix}:{}", hex(&out[..bytes]))
}

/// Normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4. The same
/// hazard [`is_dialable_ip`] guards against, on the log side: the kernel
/// surfaces one peer as v4-mapped through an AF_INET6 socket and as plain
/// v4 through another, and unnormalized tokens would split one peer into
/// two unrelated log identities.
fn log_canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Redact a peer address for logging: keyed per-run token, port dropped.
/// Raw IPs in logs are an anonymity leak — a seized or leaked logfile
/// reveals who we talked to; the token keeps intra-log correlation.
#[must_use]
pub fn redact_peer(addr: &SocketAddr) -> String {
    let ip = log_canonical_ip(addr.ip());
    log_token("peer", &ip.to_string().into_bytes(), 5)
}

/// Redact a bare IP for logging (same scheme as [`redact_peer`]).
#[must_use]
pub fn redact_ip(ip: &IpAddr) -> String {
    let ip = log_canonical_ip(*ip);
    log_token("ip", &ip.to_string().into_bytes(), 5)
}

/// Redact an info-hash for logging: keyed per-run token, full 160-bit
/// value never rendered. Identifies "the torrent" within one log without
/// revealing which torrent it actually is.
#[must_use]
pub fn redact_info_hash(ih: &[u8; 20]) -> String {
    log_token("ih", ih, 5)
}

/// Redact the DHT node ID for logging. The node ID is PERSISTED across
/// runs (`dht::persist`), so unlike a per-run peer_id it is a stable
/// long-term identity — rendering it raw would let any leaked logfile
/// fingerprint this node across sessions.
#[must_use]
pub fn redact_node_id(id: &[u8; 20]) -> String {
    log_token("nid", id, 5)
}
/// Strip control characters (CR/LF included) from remote-supplied free
/// text before embedding it in an error string: errors reach logs via
/// `error = %e`, and unfiltered controls let a remote party forge log
/// lines. Same treatment as tracker failure reasons.
///
/// Also strips Unicode bidi overrides/isolates and zero-width/format
/// characters. These are NOT `char::is_control()` (category Cc) — they
/// render as nothing or reorder surrounding text, so a hostile peer can
/// make a logged line *visually* say something it does not (Trojan-Source
/// style spoofing of log files opened in terminals/editors).
#[must_use]
pub fn sanitize_remote_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && !is_invisible_or_directional(*c))
        .collect()
}

/// Invisible or text-direction-altering code points that survive
/// `char::is_control()`: zero-width spaces/joiners/marks, bidi embedding
/// and override controls, bidi isolates, and the BOM.
fn is_invisible_or_directional(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'    // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}'  // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'  // LRI, RLI, FSI, PDI
        | '\u{FEFF}'               // BOM / zero-width no-break space
    )
}

/// Create `path` (and parents) as a private directory: mode 0700 on Unix,
/// so other local users cannot list our state (peer id, hosted torrents,
/// DHT routing table). Best-effort on other platforms.
///
/// Directories are CREATED with 0700 from the first instant (a
/// create-then-chmod sequence would leave a listable window). Only
/// directories CREATED by this call get that mode — an existing directory
/// keeps its mode, because the parent of a state file may be a shared
/// location (e.g. `$TMPDIR`/`/tmp` in tests) whose permissions we must
/// never touch.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let existed = path.is_dir();
        // Recursive DirBuilder applies 0700 to every component it creates;
        // existing components are untouched (EEXIST ignored).
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        if !existed {
            // Belt and braces: covers a racing creator between is_dir() and
            // create() (their dir keeps its own mode otherwise).
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Write `bytes` to `path` with owner-only permissions (0600 on Unix).
/// Used for every state file that identifies the user or what they seed.
///
/// The file is CREATED with 0600 from the first instant — a plain
/// `fs::write` followed by a chmod would leave a world-readable window
/// during which the peer id or stored state could be observed by other
/// local users. A pre-existing file keeps its old mode through `open()`,
/// so it is tightened unconditionally afterwards.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Decide whether `addr`, learned from an untrusted source (tracker
/// response, DHT value), is acceptable as a *dial target*.
///
/// Martians that can never be legitimate swarm peers are always refused:
/// loopback, unspecified, link-local (which includes the 169.254.169.254
/// cloud-metadata endpoint), broadcast/multicast, documentation,
/// benchmarking, CGNAT and IANA-reserved ranges. A hostile tracker or DHT
/// node handing out such addresses must not turn the client into an SSRF
/// pivot against the host or its network.
///
/// In `strict` mode — anonymous sessions, or any session riding a proxy
/// chain — site-local ranges (RFC1918 for IPv4, ULA fc00::/7 for IPv6)
/// are ALSO refused: there a dial does not even reach "the LAN we might
/// legitimately share", it just aims our proxy at its own localhost/
/// intranet. Clearnet users on a genuine LAN swarm keep working.
pub fn is_dialable_peer_addr(addr: &SocketAddr, strict: bool) -> bool {
    is_dialable_ip(&addr.ip(), strict)
}

/// Judge a URL host string by the martian policy for ANNOUNCE targets.
/// `host` comes from `Url::host_str()` — IPv6 arrives bracketed. Domain
/// names cannot be judged without DNS resolution and pass; whatever they
/// RESOLVE to is screened at connect time by the tracker HTTP client's
/// DNS resolver (`ScreenedResolver` in tracker/http.rs) through
/// [`is_dialable_resolved_ip`] — without that, a rebinding domain could
/// fetch 169.254.169.254 past this gate. This is the SSRF
/// gate for tracker URLs: a hostile magnet's `tr=` parameter pointing at
/// a cloud-metadata endpoint (`169.254.169.254`) must never turn our
/// announce (which carries info-hash + peer_id) into an intranet pivot.
///
/// One deliberate divergence from peer ingestion
/// ([`is_dialable_peer_addr`]): LOOPBACK hosts are allowed here. Tracker
/// URLs are explicit session configuration — the torrent the user chose —
/// the same trust class as engine `seed_peers`, whose dial-side screen
/// ([`is_safe_dial_target`]) makes the identical exception: a local
/// tracker (opentracker on 127.0.0.1) is a supported workflow and dialing
/// our own machine exposes nothing a remote actor doesn't already have.
/// Link-local, multicast, unspecified and — under `strict` — LAN/ULA
/// hosts remain refused. IPv4-mapped IPv6 wrappers are judged by the
/// IPv4 rules so `::ffff:127.0.0.1` gets the same treatment as `127.0.0.1`.
pub fn is_dialable_url_host(host: &str, strict: bool) -> bool {
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    let parsed = match bare.parse::<IpAddr>() {
        Ok(ip) => ip,
        // Domains cannot be judged without DNS; pass.
        Err(_) => return true,
    };
    let ip = match parsed {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    if ip.is_loopback() {
        return true;
    }
    is_dialable_ip(&ip, strict)
}

/// IP form of the [`is_dialable_url_host`] policy, for judging addresses
/// that DNS resolved from an otherwise-passing domain host: loopback is
/// allowed (explicit-configuration trust class, same as the URL gate),
/// everything else goes through [`is_dialable_ip`]. Used by the tracker
/// HTTP client's DNS-rebinding screen.
pub(crate) fn is_dialable_resolved_ip(ip: &IpAddr, strict: bool) -> bool {
    if ip.is_loopback() {
        return true;
    }
    is_dialable_ip(ip, strict)
}

/// Shared core of every DNS-resolution screen (HTTP tracker resolver,
/// UDP tracker target, DHT bootstrap): keep only addresses the martian
/// policy accepts and FAIL CLOSED when nothing survives — a host that
/// resolves exclusively to refused ranges must not fall back to "dial
/// something anyway".
pub(crate) fn filter_dialable_addrs(
    addrs: Vec<SocketAddr>,
    strict: bool,
) -> crate::error::Result<Vec<SocketAddr>> {
    let kept: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| is_dialable_resolved_ip(&a.ip(), strict))
        .collect();
    if kept.is_empty() {
        return Err(crate::error::Error::Tracker(
            "announce host resolved only to refused addresses".into(),
        ));
    }
    Ok(kept)
}

/// Last-line-of-defense screen applied AT THE DIAL SYSCALL, independent
/// of which source produced the address. Peer ingestion (tracker/DHT/PEX
/// responses) applies this policy per-source with session-derived
/// strictness; this re-check catches anything that ever reaches a dial
/// through a future unfiltered path.
///
/// One deliberate divergence from [`is_dialable_peer_addr`]: LOOPBACK is
/// allowed here. Multi-instance local peering (`--peer`, engine
/// `seed_peers`) dials 127.0.0.1 by design; ingested loopback contacts
/// are already refused upstream, and dialing our own machine exposes
/// nothing a remote actor doesn't already have.
///
/// Strictness mirrors ingestion: `strict = anonymous || proxied`,
/// derived by the caller (see `engine::dht_martian_strict`) so LAN/ULA
/// targets are additionally refused whenever the session runs behind an
/// anonymity tunnel.
#[must_use = "a dial target that fails this screen must not be dialed"]
pub fn is_safe_dial_target(addr: &SocketAddr, strict: bool) -> bool {
    if addr.ip().is_loopback() {
        return true;
    }
    is_dialable_peer_addr(addr, strict)
}

fn is_dialable_ip(ip: &IpAddr, strict: bool) -> bool {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) must be judged by the IPv4 rules:
    // the kernel dials such addresses as plain IPv4, while Ipv6Addr predicates
    // do NOT match them (::ffff:127.0.0.1 is not `is_loopback()`). Without
    // this normalization a hostile peer source could smuggle martian v4
    // targets — loopback, link-local metadata, LAN — past the filter in a
    // v6 wrapper.
    let ip = match ip {
        IpAddr::V4(_) => *ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        },
    };
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Ranges without a stable std predicate on our toolchain:
            // CGNAT 100.64/10, benchmarking 198.18/15, reserved 240/4.
            let cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
            let benchmarking = o[0] == 198 && (18..=19).contains(&o[1]);
            let reserved = o[0] & 0xF0 == 240 && !v4.is_broadcast();
            // RFC 1122 §3.2.1.3 "this network" (0.0.0.0/8): only the exact
            // unspecified address has a std predicate, but the kernel routes
            // ANY 0.x.y.z dial locally — a hostile peer source can smuggle a
            // loopback probe past `is_unspecified()` as 0.0.0.1.
            let this_network = o[0] == 0;
            // RFC 6890 "IETF protocol assignments" 192.0.0.0/24: PCP/NAT-PMP
            // anycast relays and similar protocol endpoints live here — a
            // dial reaches infrastructure gateways, never a swarm peer.
            let ietf_protocols = o[0] == 192 && o[1] == 0 && o[2] == 0;
            // Deprecated 6to4 relay anycast (RFC 7526): dialing it hands the
            // announcer-chosen v4-in-v6 translation to a gateway operator.
            let six_to_four_relay = o[0] == 192 && o[1] == 88 && o[2] == 99;
            !(v4.is_broadcast()
                || v4.is_link_local()
                || cgnat
                || benchmarking
                || v4.is_documentation()
                || reserved
                || this_network
                || ietf_protocols
                || six_to_four_relay
                || (strict && v4.is_private()))
        }
        IpAddr::V6(v6) => {
            // RFC 6052 NAT64 synthesis prefix 64:ff9b::/96: dialing such an
            // address targets the local network's NAT64 gateway, which
            // translates the embedded IPv4 host on ITS side — a hostile peer
            // source could use it to probe v4-only hosts behind that gateway.
            let segs = v6.segments();
            let nat64 = segs[0] == 0x64 && segs[1] == 0xff9b && segs[2] == 0 && segs[3] == 0;
            // RFC 8215 local-use NAT64 (64:ff9b:1::/48): same translation
            // trick as the well-known prefix, scoped to a site's own NAT64
            // translator — the embedded v4 host is dialed on ITS side, so it
            // is just as unusable as a swarm contact.
            let nat64_local_use = segs[0] == 0x64 && segs[1] == 0xff9b && segs[2] == 1;
            // Same class of transition-mechanism addresses: RFC 3056 6to4
            // (2002::/16, embedded v4 routed via a relay gateway) and RFC
            // 4380 Teredo (2001:0::/32, tunnel endpoints behind relays).
            // Dialing either sends our traffic through an operator we did not
            // choose; no legitimate swarm contact is announced under them.
            let six_to_four = segs[0] == 0x2002;
            let teredo = segs[0] == 0x2001 && segs[1] == 0x0000;
            // RFC 3849 documentation block 2001:db8::/32: reserved for
            // examples and never announced by a real swarm peer.
            let doc6 = segs[0] == 0x2001 && segs[1] == 0x0db8;
            // The IPv6 "unspecified prefix" block (::/128 minus :: itself,
            // RFC 4291): ::2 and friends are reserved, and Linux dials them
            // as local addresses just like 0.0.0.0/8 in v4.
            let zeronet6 = segs[..7].iter().all(|&s| s == 0);
            // RFC 6666 discard-only block (100::/64): packets sent here are
            // dropped by construction; it exists so networks can blackhole
            // traffic. Never a swarm peer.
            let discard_only = segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0;
            // Remaining IANA special-purpose assignments under 2001::/16:
            // RFC 6890 IETF protocol assignments (2001:1::/32), RFC 5180
            // benchmarking (2001:2::/48) and the deprecated RFC 4843 ORCHID
            // range (2001:10::/28). None of them is ever announced by a
            // real swarm peer.
            let ietf_protocols6 = segs[0] == 0x2001 && segs[1] == 1;
            // /48: the fourth hextet is inside the prefix, so only pin the
            // first three.
            let benchmarking6 = segs[0] == 0x2001 && segs[1] == 2 && segs[2] == 0;
            let orchid = segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0010;
            // The last special-purpose assignments under 2001::/23: RFC 7450
            // AMT relay namespace (2001:3::/32), RFC 7535 AS112-v6
            // (2001:4:112::/48), RFC 7343 ORCHIDv2 (2001:20::/28) and the
            // drone Remote-ID transport block (RFC 9415-style assignment,
            // 2001:30::/28). Infrastructure namespaces — an announcer can
            // only use them to steer our dials at gateways or blackholes.
            let amt = segs[0] == 0x2001 && segs[1] == 3;
            let as112v6 = segs[0] == 0x2001 && segs[1] == 4 && segs[2] == 0x112;
            let orchid_v2 = segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0020;
            let drone_rta = segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0030;
            !nat64
                && !nat64_local_use
                && !six_to_four
                && !teredo
                && !doc6
                && !ietf_protocols6
                && !benchmarking6
                && !orchid
                && !amt
                && !as112v6
                && !orchid_v2
                && !drone_rta
                && !zeronet6
                && !discard_only
                && !v6.is_unicast_link_local()
                && !(strict && v6.is_unique_local())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let bytes = [0x00, 0x0f, 0xa1, 0xff, 0x42];
        assert_eq!(hex(&bytes), "000fa1ff42");
    }

    #[test]
    fn info_hash_roundtrip() {
        let ih = [0xABu8; 20];
        let s = hex(&ih);
        assert_eq!(s.len(), 40);
        assert_eq!(info_hash_from_hex(&s), Some(ih));
    }

    #[test]
    fn info_hash_rejects_bad_input() {
        assert_eq!(info_hash_from_hex("short"), None);
        assert_eq!(info_hash_from_hex(&"zz".repeat(20)), None); // non-hex
        assert_eq!(info_hash_from_hex(&"00".repeat(19)), None); // 38 chars
    }

    #[test]
    fn martian_peer_addrs_are_never_dialable() {
        for addr in [
            "127.0.0.1:6881",       // loopback
            "[::1]:6881",           // loopback v6
            "0.0.0.0:6881",         // unspecified
            "169.254.169.254:80",   // link-local / cloud metadata
            "[fe80::1]:6881",       // link-local v6
            "224.0.0.1:6881",       // multicast
            "255.255.255.255:6881", // broadcast
            "192.0.2.1:6881",       // documentation (TEST-NET-1)
            "198.18.0.7:6881",      // benchmarking
            "100.64.0.1:6881",      // CGNAT shared range
            "240.0.0.3:6881",       // IANA reserved
        ] {
            let addr = addr.parse().unwrap();
            assert!(
                !is_dialable_peer_addr(&addr, false),
                "{addr} must be refused even non-strict"
            );
            assert!(
                !is_dialable_peer_addr(&addr, true),
                "{addr} must be refused strict"
            );
        }
    }

    #[test]
    fn site_local_peers_refused_only_in_strict_mode() {
        let lan = ["10.20.30.40:5555", "192.168.1.5:6881", "172.16.0.9:12345"];
        let ula = ["[fc00::1]:6881", "[fd12::abcd:9999]:6881"];
        for a in lan.iter().chain(ula.iter()) {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(is_dialable_peer_addr(&addr, false), "{a} allowed clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} refused strict");
        }
    }

    #[test]
    fn public_peer_addrs_pass_both_modes() {
        for a in [
            "1.2.3.4:6881",
            "93.184.215.14:51413",
            "[2606:4700::1111]:6881",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(is_dialable_peer_addr(&addr, false), "{a}");
            assert!(is_dialable_peer_addr(&addr, true), "{a}");
        }
    }

    #[test]
    fn ipv4_mapped_v6_addrs_are_judged_by_v4_rules() {
        // ::ffff:a.b.c.d is dialed as plain IPv4 by the kernel; the v6
        // predicates would wave it through.
        let always_bad = [
            "[::ffff:127.0.0.1]:6881",     // mapped loopback
            "[::ffff:169.254.169.254]:80", // mapped link-local metadata
        ];
        for a in always_bad {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        for a in ["[::ffff:10.20.30.40]:5555", "[::ffff:192.168.1.5]:6881"] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(is_dialable_peer_addr(&addr, false), "{a} clearnet LAN ok");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} refused strict");
        }
        // A mapped PUBLIC address stays dialable in both modes.
        let addr: SocketAddr = "[::ffff:93.184.215.14]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
        assert!(is_dialable_peer_addr(&addr, true));
    }

    #[test]
    fn nat64_synthesized_addrs_are_never_dialable() {
        // 64:ff9b::/96 (RFC 6052): dialing goes to the local network's NAT64
        // gateway, which translates the embedded v4 host on its side.
        let nat64 = [
            "[64:ff9b::127.0.0.1]:6881",
            "[64:ff9b::169.254.169.254]:80",
            "[64:ff9b::93.184.215.14]:51413",
        ];
        for a in nat64 {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Ordinary global v6 stays dialable.
        let addr: SocketAddr = "[2606:4700:4700::1111]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn transition_mechanism_v6_addrs_are_never_dialable() {
        // RFC 3056 6to4 (2002::/16) and RFC 4380 Teredo (2001:0::/32):
        // both route dials through relay/tunnel operators chosen by whoever
        // announced the contact — never legitimate swarm peers.
        for a in [
            "[2002:7f00:0001::]:6881",  // 6to4 wrapping 127.0.0.1
            "[2002:8ef8:d616::]:51413", // 6to4 wrapping a public v4
            "[2001:0:abcd::1]:51413",   // Teredo
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // 2001:x with a non-zero second group is NOT Teredo (real global v6).
        let addr: SocketAddr = "[2001:4860:4860::8888]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn this_network_addrs_are_never_dialable() {
        // RFC 1122 §3.2.1.3 (0.0.0.0/8) and the v6 unspecified prefix block
        // (::/128 minus ::): the kernel dials these locally, so a hostile
        // peer source can aim us at our own loopback with them.
        for a in [
            "0.0.0.1:6881",
            "0.127.0.1:51413",
            "[::2]:6881",
            "[::1234]:51413",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // 1.0.0.x is public APNIC space and must stay dialable.
        let addr: SocketAddr = "1.0.0.1:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn ietf_protocol_assignment_addrs_are_never_dialable() {
        // RFC 6890 IETF protocol assignments (192.0.0.0/24): PCP/NAT-PMP
        // anycast and friends — infrastructure gateways, not peers.
        for a in ["192.0.0.1:6881", "192.0.0.10:443"] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Public control: outside every special-purpose block.
        let addr: SocketAddr = "8.8.8.8:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn six_to_four_relay_anycast_addrs_are_never_dialable() {
        // Deprecated 6to4 relay anycast (192.88.99.0/24, RFC 7526): a dial
        // reaches an announcer-chosen translation gateway, never a peer.
        for a in ["192.88.99.1:6881", "192.88.99.9:51413"] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Public control.
        let addr: SocketAddr = "93.184.215.14:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn nat64_local_use_and_v6_documentation_addrs_are_never_dialable() {
        // RFC 8215 local-use NAT64 (64:ff9b:1::/48) translates the embedded
        // v4 host on the site's own NAT64 gateway — same SSRF class as the
        // well-known prefix. RFC 3849 documentation addresses are reserved
        // for examples and never a real swarm contact.
        for a in [
            "[64:ff9b:1::127.0.0.1]:6881",
            "[64:ff9b:1::169.254.169.254]:80",
            "[64:ff9b:1::93.184.215.14]:51413",
            "[2001:db8::dead]:51413",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Quad-9's real v6 anycast must stay dialable (2001:x but not db8).
        let addr: SocketAddr = "[2620:fe::fe]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn discard_only_v6_addrs_are_never_dialable() {
        // RFC 6666 discard-only block (100::/64): traffic sent there is
        // dropped by construction; a hostile peer source gains nothing but
        // we should not waste dials — and the range must never be treated
        // as a routable contact.
        for a in ["[100::1]:6881", "[100::abcd:ef12]:51413"] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Control: 200:: is NOT inside 100::/64 and stays dialable.
        let addr: SocketAddr = "[200::1]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn remaining_iana_v6_special_purpose_addrs_are_never_dialable() {
        // 2001:1::/32 (IETF protocol assignments), 2001:2::/48 (RFC 5180
        // benchmarking) and the deprecated ORCHID range (2001:10::/28):
        // registry-reserved, never announced by a real swarm peer.
        for a in [
            "[2001:1::1]:51413",
            "[2001:2:0:abcd::1]:51413",
            "[2001:10::dead]:51413",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Control: other 2001:x space is real-world address space and stays
        // dialable — none of the new predicates may match it.
        let addr: SocketAddr = "[2001:4860:4860::8888]:51413".parse().unwrap();
        assert!(is_dialable_peer_addr(&addr, false));
    }

    #[test]
    fn last_iana_v6_blocks_are_never_dialable() {
        // 2001:3::/32 (AMT relays), 2001:4:112::/48 (AS112-v6), the ORCHIDv2
        // range 2001:20::/28 and the drone Remote-ID transport block
        // 2001:30::/28: infrastructure namespaces an announcer can only use
        // to steer our dials at gateways or blackholes.
        for a in [
            "[2001:3::1]:51413",
            "[2001:4:112::1]:51413",
            "[2001:2a::dead]:51413",
            "[2001:33::1]:51413",
        ] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(!is_dialable_peer_addr(&addr, false), "{a} clearnet");
            assert!(!is_dialable_peer_addr(&addr, true), "{a} strict");
        }
        // Control: global space just outside every new prefix stays
        // dialable (2001:8:: is unassigned-but-global, and 2001:40:: is past
        // both /28 blocks).
        for a in ["[2001:8::1]:51413", "[2001:40::1]:51413"] {
            let addr: SocketAddr = a.parse().unwrap();
            assert!(is_dialable_peer_addr(&addr, false), "{a}");
        }
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode()
    }

    #[test]
    #[cfg(unix)]
    fn private_dir_is_owner_only() {
        let base = std::env::temp_dir().join(format!(
            "rt-util-dir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = base.join("rustytorrent").join("state");
        ensure_private_dir(&dir).unwrap();
        // Owner rwx, no group/other bits.
        assert_eq!(mode_of(&dir) & 0o777, 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    #[cfg(unix)]
    fn private_file_is_owner_only_even_when_preexisting_wide() {
        let path = std::env::temp_dir().join(format!(
            "rt-util-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Pre-create world-readable (what a plain fs::write yields).
        std::fs::write(&path, b"stale").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"secret").unwrap();
        assert_eq!(mode_of(&path) & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn safe_dial_target_refuses_invariant_martians_but_allows_loopback() {
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        // Loopback exemption: local multi-instance peering dials loopback
        // via --peer / seed_peers, in both modes.
        assert!(is_safe_dial_target(&p("127.0.0.1:6881"), false));
        assert!(is_safe_dial_target(&p("127.0.0.1:6881"), true));
        assert!(is_safe_dial_target(&p("[::1]:6881"), true));

        // Invariant martians — refused regardless of strictness.
        let refused_both = [
            "169.254.169.254:80",        // link-local metadata endpoint
            "0.0.0.1:6881",              // this-network smuggle
            "192.0.2.50:443",            // documentation range
            "100.64.1.1:6881",           // CGNAT
            "[fe80::1]:6881",            // link-local v6
            "[64:ff9b::5d38:d70e]:6881", // NAT64 synthesis
        ];
        for bad in refused_both {
            assert!(
                !is_safe_dial_target(&p(bad), false),
                "{bad} must be refused even non-strict"
            );
            assert!(
                !is_safe_dial_target(&p(bad), true),
                "{bad} must be refused strict"
            );
        }

        // Session-strict extras — LAN/ULA refused only when strict.
        let lan = ["192.168.1.50:51413", "10.0.0.7:6881", "[fd00::5]:6881"];
        for addr in lan {
            let a = p(addr);
            assert!(is_safe_dial_target(&a, false), "{addr} allowed on clearnet");
            assert!(
                !is_safe_dial_target(&a, true),
                "{addr} refused under anonymity"
            );
        }
    }

    #[test]
    fn redact_peer_hides_raw_ip_and_port() {
        let v4: SocketAddr = "203.0.113.7:51413".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:6881".parse().unwrap();
        for a in [v4, v6] {
            let out = redact_peer(&a);
            assert!(!out.contains("203.0.113"), "v4 leaked: {out}");
            assert!(!out.contains("51413"), "port leaked: {out}");
            assert!(!out.contains("2001:db8"), "v6 leaked: {out}");
            assert!(out.starts_with("peer:"), "unexpected shape: {out}");
        }
    }

    #[test]
    fn redact_peer_stable_within_run_and_distinct_across_peers() {
        let a: SocketAddr = "198.51.100.9:6881".parse().unwrap();
        let b: SocketAddr = "198.51.100.10:6881".parse().unwrap();
        // Same peer → same token, so one log's lines still join up.
        assert_eq!(redact_peer(&a), redact_peer(&a));
        // Different peers/ports → different tokens (no collisions here).
        assert_ne!(redact_peer(&a), redact_peer(&b));
    }

    #[test]
    fn redact_info_hash_hides_full_hex_but_is_deterministic() {
        let ih = [0xABu8; 20];
        let out = redact_info_hash(&ih);
        let full = hex(&ih);
        assert!(!out.contains(&full), "full hash leaked: {out}");
        // No run of the hash's repeated byte pattern survives either.
        assert!(!out.contains("ababab"), "partial hex leaked: {out}");
        assert_eq!(out, redact_info_hash(&ih));
        assert_ne!(out, redact_info_hash(&[0xCD; 20]));
    }

    #[test]
    fn redact_node_id_hides_full_hex_but_is_deterministic() {
        let id = [0x12u8; 20];
        let out = redact_node_id(&id);
        // NodeId's Display is lowercase hex; none of it may survive.
        let full = hex(&id);
        assert!(!out.contains(&full), "full node id leaked: {out}");
        assert!(!out.contains("121212"), "partial hex leaked: {out}");
        assert!(out.starts_with("nid:"), "{out}");
        // Stable within a run (log correlation), distinct across IDs.
        assert_eq!(out, redact_node_id(&id));
        assert_ne!(out, redact_node_id(&[0x34; 20]));
    }

    #[test]
    fn redact_ip_matches_redact_peer_scheme() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let addr = SocketAddr::new(ip, 1234);
        // Port is dropped, so bare-IP and SocketAddr tokens share a body
        // (prefixes differ: "ip:" vs "peer:").
        fn body(s: &str) -> &str {
            s.split_once(':').unwrap().1
        }
        assert_eq!(body(&redact_ip(&ip)), body(&redact_peer(&addr)));
        assert!(!redact_ip(&ip).contains("203.0.113"));
    }

    #[test]
    fn redact_peer_collapses_ipv4_mapped_ipv6_to_one_identity() {
        let v4: SocketAddr = "203.0.113.7:51413".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:51413".parse().unwrap();
        // One peer surfacing through an AF_INET6 socket and an AF_INET
        // socket must yield ONE token, or log correlation silently splits.
        assert_eq!(redact_peer(&v4), redact_peer(&mapped));
        // A genuinely different v6 address must NOT collapse onto it.
        let real_v6: SocketAddr = "[2001:db8::7]:51413".parse().unwrap();
        assert_ne!(redact_peer(&v4), redact_peer(&real_v6));
    }

    #[test]
    fn sanitize_remote_text_strips_controls_bidi_and_invisibles_keeps_normal_text() {
        // Line-forgery controls (Cc) must not survive.
        let crlf = sanitize_remote_text("ok\r\nEVIL log line");
        assert!(!crlf.contains('\r') && !crlf.contains('\n'), "{crlf}");
        assert!(!crlf.contains("EVIL\n"), "{crlf}");
        assert_eq!(crlf, "okEVIL log line");

        // Bidi overrides/isolates and zero-width/format chars survive
        // is_control() but let a hostile peer visually spoof a rendered
        // line (RLO can mirror/reorder the text a terminal shows).
        let hostile = "a\u{202E}evil\u{202C}b\u{200B}c\u{200F}d\u{2066}x\u{2069}e\u{FEFF}f";
        let clean = sanitize_remote_text(hostile);
        for bad in [
            '\u{202E}', '\u{202C}', '\u{200B}', '\u{200F}', '\u{2066}', '\u{2069}', '\u{FEFF}',
        ] {
            assert!(
                !clean.contains(bad),
                "U+{:04X} survived: {clean:?}",
                bad as u32
            );
        }
        assert!(clean.contains("evil"), "{clean}");

        // Ordinary non-ASCII text must pass through untouched — this
        // filter must never become an over-broad ASCII fold.
        let normal = "привет ✅ 中文 emoji 🌊 keep";
        assert_eq!(sanitize_remote_text(normal), normal);
    }
}
