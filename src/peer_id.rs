use std::path::{Path, PathBuf};

use rand::Rng;

pub type PeerId = [u8; 20];

/// Azureus-style peer id: `-RT0100-` + 12 random ASCII bytes.
/// The eight-char prefix identifies client and version; the
/// remainder is random per session.
pub fn generate() -> PeerId {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(b"-RT0100-");
    let mut rng = rand::thread_rng();
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for slot in &mut id[8..] {
        *slot = ALPHABET[rng.gen_range(0..ALPHABET.len())];
    }
    id
}

/// Returns the configured persistence path. Resolution order:
/// - `$XDG_CONFIG_HOME/rustytorrent/peer_id` if set (any platform that honors it)
/// - Windows: `%APPDATA%\rustytorrent\peer_id`
/// - Unix-like (Linux, macOS, *BSD): `$HOME/.config/rustytorrent/peer_id`
/// - Fallback: `.rustytorrent-peer-id` in the current directory
pub fn default_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("rustytorrent").join("peer_id");
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                return PathBuf::from(appdata).join("rustytorrent").join("peer_id");
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home)
                    .join(".config")
                    .join("rustytorrent")
                    .join("peer_id");
            }
        }
    }
    PathBuf::from(".rustytorrent-peer-id")
}

/// Load the peer_id from `path` if it exists and is valid; otherwise
/// generate a new one and try to persist it. Failures to persist are
/// non-fatal — the session continues with the freshly generated id.
///
/// A stable peer_id reduces the chance some trackers / DHT nodes treat
/// us as a fresh client every run, which is generally considered better
/// network citizenship per the BitTorrent community's conventions.
pub fn load_or_generate(path: &Path) -> PeerId {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 20 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&bytes);
            tracing::debug!(
                target: "peer_id",
                path = %path.display(),
                "loaded persisted peer_id"
            );
            return id;
        }
        tracing::warn!(
            target: "peer_id",
            path = %path.display(),
            len = bytes.len(),
            "peer_id file has wrong length; regenerating"
        );
    }
    let id = generate();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::debug!(
                target: "peer_id",
                path = %parent.display(),
                error = %e,
                "could not create peer_id dir"
            );
            return id;
        }
    }
    if let Err(e) = std::fs::write(path, id) {
        tracing::debug!(
            target: "peer_id",
            path = %path.display(),
            error = %e,
            "could not persist peer_id"
        );
    } else {
        tracing::info!(
            target: "peer_id",
            path = %path.display(),
            "wrote new peer_id"
        );
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_azureus_style() {
        let id = generate();
        assert_eq!(&id[..8], b"-RT0100-");
    }

    #[test]
    fn unique_per_call() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
    }

    #[test]
    fn all_bytes_printable() {
        let id = generate();
        assert!(id.iter().all(|&c| c.is_ascii_graphic()));
    }

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rustytorrent-peerid-test-{}-{}",
            std::process::id(),
            suffix
        ));
        p
    }

    #[test]
    fn load_creates_and_persists() {
        let path = temp_path("create");
        let _ = std::fs::remove_file(&path);
        let id1 = load_or_generate(&path);
        let id2 = load_or_generate(&path);
        assert_eq!(id1, id2);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw.len(), 20);
        assert_eq!(&raw, &id1[..]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_regenerates_on_bad_length() {
        let path = temp_path("badlen");
        std::fs::write(&path, b"too short").unwrap();
        let id = load_or_generate(&path);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw.len(), 20);
        assert_eq!(&raw, &id[..]);
        let _ = std::fs::remove_file(&path);
    }
}
