//! Save/restore the DHT node ID + routing-table contents to disk.
//!
//! On-disk format (intentionally trivial — humans should be able to inspect
//! it with `xxd`):
//!
//! ```text
//! magic        4 bytes  "RTDH"
//! version      1 byte   0x01
//! node_id     20 bytes
//! n_contacts   4 bytes  big-endian u32
//! n_contacts × 26 bytes — compact (id || ipv4 || port)
//! ```
//!
//! Contacts with IPv6 addresses are skipped — DHT compact form is IPv4-only
//! per BEP 5.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use super::node_id::NodeId;
use super::routing::{Contact, RoutingTable};

const MAGIC: &[u8; 4] = b"RTDH";
const VERSION: u8 = 1;

/// Default location, resolved per-platform:
/// - `$XDG_CONFIG_HOME/rustytorrent/dht_state` if set
/// - Windows: `%APPDATA%\rustytorrent\dht_state`
/// - Unix-like: `$HOME/.config/rustytorrent/dht_state`
/// - Fallback: `.rustytorrent-dht-state` in the current directory
pub fn default_path() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return std::path::PathBuf::from(xdg)
                .join("rustytorrent")
                .join("dht_state");
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return std::path::PathBuf::from(appdata)
                    .join("rustytorrent")
                    .join("dht_state");
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return std::path::PathBuf::from(home)
                    .join(".config")
                    .join("rustytorrent")
                    .join("dht_state");
            }
        }
    }
    std::path::PathBuf::from(".rustytorrent-dht-state")
}

/// Try to load a previously-persisted (NodeId, contacts) from `path`. Any
/// parse error or missing file returns `None` (the caller mints a fresh
/// node id and starts with an empty table).
pub fn load(path: &Path) -> Option<(NodeId, Vec<Contact>)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < 4 + 1 + 20 + 4 {
        return None;
    }
    if &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return None;
    }
    let mut id = [0u8; 20];
    id.copy_from_slice(&bytes[5..25]);
    let n = u32::from_be_bytes([bytes[25], bytes[26], bytes[27], bytes[28]]) as usize;
    let expected = 4 + 1 + 20 + 4 + n * 26;
    if bytes.len() != expected {
        return None;
    }
    let mut contacts = Vec::with_capacity(n);
    for chunk in bytes[29..].chunks_exact(26) {
        let mut cid = [0u8; 20];
        cid.copy_from_slice(&chunk[..20]);
        let ip = Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
        let port = u16::from_be_bytes([chunk[24], chunk[25]]);
        contacts.push(Contact::new(
            NodeId(cid),
            SocketAddr::new(IpAddr::V4(ip), port),
        ));
    }
    Some((NodeId(id), contacts))
}

/// Persist the current node id + routing-table snapshot. Failures (missing
/// directory, EPERM, …) are reported via `Result` but generally treated as
/// non-fatal by callers.
pub fn save(path: &Path, node_id: NodeId, table: &RoutingTable) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        // 0700: routing table exposes which peers we talk to.
        crate::util::ensure_private_dir(parent)?;
    }
    // `RoutingTable` doesn't expose `iter` directly; `closest` against our
    // own id with `count == len()` returns every contact, sorted nearest-first.
    let count = table.len();
    let contacts: Vec<Contact> = table.closest(&node_id, count);
    let mut out = Vec::with_capacity(4 + 1 + 20 + 4 + contacts.len() * 26);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(node_id.as_bytes());
    let mut v4_contacts = 0u32;
    let mut payload = Vec::with_capacity(contacts.len() * 26);
    for c in &contacts {
        if let SocketAddr::V4(v4) = c.addr {
            payload.extend_from_slice(c.id.as_bytes());
            payload.extend_from_slice(&v4.ip().octets());
            payload.extend_from_slice(&v4.port().to_be_bytes());
            v4_contacts += 1;
        }
    }
    out.extend_from_slice(&v4_contacts.to_be_bytes());
    out.extend_from_slice(&payload);
    // Write to a temp file then rename, so an interrupted save doesn't
    // leave a half-written file at the canonical location. The temp file
    // is written owner-only (0600 on Unix) and the rename preserves that.
    let tmp = path.with_extension("tmp");
    crate::util::write_private_file(&tmp, &out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rt-dht-persist-{}-{}", std::process::id(), name));
        p
    }

    #[test]
    fn roundtrip_empty() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);
        let id = NodeId([0xAB; 20]);
        let table = RoutingTable::new(id);
        save(&path, id, &table).unwrap();
        let (id2, contacts) = load(&path).unwrap();
        assert_eq!(id, id2);
        assert!(contacts.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn roundtrip_with_contacts() {
        let path = temp_path("contacts");
        let _ = std::fs::remove_file(&path);
        let id = NodeId([0x11; 20]);
        let mut table = RoutingTable::new(id);
        table.insert(Contact::new(
            NodeId([0x22; 20]),
            "1.2.3.4:6881".parse().unwrap(),
        ));
        table.insert(Contact::new(
            NodeId([0x33; 20]),
            "5.6.7.8:51413".parse().unwrap(),
        ));
        save(&path, id, &table).unwrap();
        let (id2, contacts) = load(&path).unwrap();
        assert_eq!(id, id2);
        assert_eq!(contacts.len(), 2);
        // Contacts come back in nearest-first order (we serialized them
        // via `closest(self, len())` which produces nearest-first ordering).
        let ports: Vec<u16> = contacts.iter().map(|c| c.addr.port()).collect();
        assert!(ports.contains(&6881));
        assert!(ports.contains(&51413));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_bad_magic_returns_none() {
        let path = temp_path("badmagic");
        std::fs::write(&path, b"XXXX\x01rest").unwrap();
        assert!(load(&path).is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let path = temp_path("doesnotexist-zzz");
        let _ = std::fs::remove_file(&path);
        assert!(load(&path).is_none());
    }
}
