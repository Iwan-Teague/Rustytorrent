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
            !(v4.is_broadcast()
                || v4.is_link_local()
                || cgnat
                || benchmarking
                || v4.is_documentation()
                || reserved
                || (strict && v4.is_private()))
        }
        IpAddr::V6(v6) => !v6.is_unicast_link_local() && !(strict && v6.is_unique_local()),
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
}
