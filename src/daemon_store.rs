//! Persistence for the daemon's hosted-torrent set, so a restart resumes
//! exactly what was running.
//!
//! Each hosted torrent is stored as two files under one directory, keyed
//! by info-hash hex:
//!
//! - `<ih>.torrent` — the original metainfo bytes (verbatim, so the
//!   info-hash is preserved exactly; we never re-encode the info dict).
//! - `<ih>.json` — a small sidecar with the output directory and whether
//!   the DHT was requested.
//!
//! Only an explicit *remove* deletes these; a daemon shutdown leaves them
//! so the next start restores the set.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A torrent recovered from disk on daemon startup.
pub struct PersistedTorrent {
    /// Original `.torrent` bytes (info-hash preserved verbatim).
    pub torrent_bytes: Vec<u8>,
    pub output: PathBuf,
    pub enable_dht: bool,
}

#[derive(Serialize, Deserialize)]
struct Sidecar {
    output: PathBuf,
    enable_dht: bool,
}

/// Handle to the daemon-state directory.
pub struct DaemonStore {
    dir: PathBuf,
}

impl DaemonStore {
    /// Open (creating if needed) the store at `dir`.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        // 0700: the store reveals what the user hosts and where it lands.
        crate::util::ensure_private_dir(&dir)?;
        Ok(Self { dir })
    }

    /// Default location: `$XDG_CONFIG_HOME`/`$HOME/.config` (Unix) or
    /// `%APPDATA%` (Windows) under `rustytorrent/daemon`, matching the DHT
    /// and peer-id state paths.
    pub fn default_dir() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("rustytorrent").join("daemon");
            }
        }
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                if !appdata.is_empty() {
                    return PathBuf::from(appdata).join("rustytorrent").join("daemon");
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
                        .join("daemon");
                }
            }
        }
        PathBuf::from(".rustytorrent-daemon")
    }

    fn torrent_path(&self, info_hash: &[u8; 20]) -> PathBuf {
        self.dir
            .join(format!("{}.torrent", crate::util::hex(info_hash)))
    }

    fn sidecar_path(&self, info_hash: &[u8; 20]) -> PathBuf {
        self.dir
            .join(format!("{}.json", crate::util::hex(info_hash)))
    }

    /// Record a hosted torrent. Idempotent — re-saving overwrites.
    pub fn save(
        &self,
        info_hash: &[u8; 20],
        torrent_bytes: &[u8],
        output: &Path,
        enable_dht: bool,
    ) -> io::Result<()> {
        // 0600: metainfo bytes + local output paths are private state.
        crate::util::write_private_file(self.torrent_path(info_hash).as_path(), torrent_bytes)?;
        let sidecar = Sidecar {
            output: output.to_path_buf(),
            enable_dht,
        };
        let json = serde_json::to_vec(&sidecar).map_err(io::Error::other)?;
        crate::util::write_private_file(self.sidecar_path(info_hash).as_path(), &json)?;
        Ok(())
    }

    /// Drop a torrent from the store (called on explicit remove). Missing
    /// files are not an error.
    pub fn forget(&self, info_hash: &[u8; 20]) {
        let _ = std::fs::remove_file(self.torrent_path(info_hash));
        let _ = std::fs::remove_file(self.sidecar_path(info_hash));
    }

    /// Load every persisted torrent. Entries that are malformed or missing
    /// their sidecar are skipped (logged), never fatal — one corrupt file
    /// must not stop the daemon from restoring the rest.
    pub fn load_all(&self) -> Vec<PersistedTorrent> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("torrent") {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let torrent_bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(target: "daemon", file = %path.display(), error = %e, "skip restore: read failed");
                    continue;
                }
            };
            let sidecar_path = self.dir.join(format!("{stem}.json"));
            let sidecar: Sidecar = match std::fs::read(&sidecar_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(s) => s,
                None => {
                    tracing::warn!(target: "daemon", file = %sidecar_path.display(), "skip restore: missing/invalid sidecar");
                    continue;
                }
            };
            out.push(PersistedTorrent {
                torrent_bytes,
                output: sidecar.output,
                enable_dht: sidecar.enable_dht,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        // A process-wide counter guarantees a distinct dir per call. pid+nanos
        // alone collided when two parallel test threads read an identical
        // `now()` (coarse clock resolution), so colliding tests saw each
        // other's files — e.g. `skips_entry_without_sidecar` would observe the
        // sidecar'd entry written by `save_load_forget_roundtrip` and fail.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "rt_dstore_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn save_load_forget_roundtrip() {
        let dir = scratch();
        let store = DaemonStore::open(dir.clone()).unwrap();
        let ih = [0xABu8; 20];
        let bytes = b"d4:infod...e".to_vec();
        store
            .save(&ih, &bytes, Path::new("/tmp/out"), true)
            .unwrap();

        let loaded = store.load_all();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].torrent_bytes, bytes);
        assert_eq!(loaded[0].output, PathBuf::from("/tmp/out"));
        assert!(loaded[0].enable_dht);

        store.forget(&ih);
        assert!(store.load_all().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_entry_without_sidecar() {
        let dir = scratch();
        let store = DaemonStore::open(dir.clone()).unwrap();
        // A bare .torrent with no .json sidecar must be skipped, not panic.
        std::fs::write(dir.join("deadbeef.torrent"), b"x").unwrap();
        assert!(store.load_all().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn saved_files_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode()
        }

        // Unique base we may remove afterwards; the store dir itself is
        // NOT pre-created, matching how open() meets it in production.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rt_dstore_perm_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = DaemonStore::open(dir.clone()).unwrap();
        let ih = [0x11u8; 20];
        store
            .save(&ih, b"torrent-bytes", Path::new("/tmp/out"), false)
            .unwrap();

        assert_eq!(mode(&dir) & 0o777, 0o700, "store dir must be 0700");
        let stem = crate::util::hex(&ih);
        let torrent = dir.join(format!("{stem}.torrent"));
        let sidecar = dir.join(format!("{stem}.json"));
        assert_eq!(mode(&torrent) & 0o777, 0o600, "metainfo must be 0600");
        assert_eq!(mode(&sidecar) & 0o777, 0o600, "sidecar must be 0600");

        std::fs::remove_dir_all(&dir).ok();
    }
}
