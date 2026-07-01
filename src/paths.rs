//! Platform data directory layout (REQ: per-user application data directory).

use std::path::PathBuf;

use directories::ProjectDirs;

use crate::error::{Error, Result};

/// Resolve the agentmsg data directory, honouring `AGENTMSG_HOME` override.
pub fn data_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var("AGENTMSG_HOME") {
        return Ok(PathBuf::from(override_dir));
    }
    let pd = ProjectDirs::from("", "agentmsg", "agentmsg")
        .ok_or_else(|| Error::Config("cannot determine home directory".into()))?;
    Ok(pd.data_dir().to_path_buf())
}

/// Ensure the data directory exists and return it, restricting it to the owner
/// on Unix so the secrets and message history it holds are not group/world
/// readable on a multi-user host.
pub fn ensure_data_dir() -> Result<PathBuf> {
    let dir = data_dir()?;
    std::fs::create_dir_all(&dir)?;
    harden_dir(&dir)?;
    Ok(dir)
}

/// Restrict a file to owner read/write (0600) on Unix. No-op on Windows, where
/// the data dir lives under the ACL-protected user profile.
pub fn harden_file(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Restrict a directory to owner access (0700) on Unix. No-op on Windows.
pub fn harden_dir(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub fn config_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("config.toml"))
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("identity.json"))
}

pub fn trust_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("trust.json"))
}

pub fn store_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("messages.db"))
}

/// IPC endpoint name (Unix socket path / Windows named pipe).
pub fn ipc_name() -> Result<String> {
    #[cfg(windows)]
    {
        Ok(r"\\.\pipe\agentmsg".to_string())
    }
    #[cfg(not(windows))]
    {
        Ok(data_dir()?
            .join("daemon.sock")
            .to_string_lossy()
            .into_owned())
    }
}

/// Lock file ensuring a single daemon instance (REQ-0049).
pub fn lock_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("daemon.lock"))
}

/// Daemon log file (the background daemon writes tracing output here so
/// `daemon start --wait` can tail it on a readiness timeout).
pub fn log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("daemon.log"))
}
