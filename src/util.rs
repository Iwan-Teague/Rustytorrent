//! Small shared helpers used across modules.

use std::io;
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
