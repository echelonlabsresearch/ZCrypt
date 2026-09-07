//! Private-file helpers: every wallet file (keystore, coin store, settings, chain pin)
//! is created with mode 0600 inside a 0700 data directory on Unix, so another local
//! user cannot copy the keystore for offline cracking or repoint the wallet by editing
//! settings. On other platforms the OS default ACLs apply.

use std::io::Write;
use std::path::Path;

/// Create `dir` (and parents) and restrict it to the current user.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write `bytes` to `path` as a 0600 file (created or truncated). The parent directory
/// is created and locked down first.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        // An existing file keeps its old mode on open; tighten it explicitly.
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(bytes)?;
    f.sync_all()
}

/// Write only if `path` does not exist yet (never silently overwrite an export).
pub fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
