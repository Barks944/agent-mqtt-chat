//! Local agent identity: the ML-DSA-65 keypair this daemon signs with.
//!
//! REQ-0007: generate + export identity. REQ-0022: one identity per daemon.
//! REQ-0027: private key stored owner-only. REQ-0028: never export private key.

use ml_dsa::{Generate, Keypair, MlDsa65, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths;
use crate::token::IdentityToken;
use crate::wire::{b64, make_kid, unb64};

/// 32-byte seed length used to persist the signing key.
const SEED_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    /// base64url of the 32-byte signing-key seed (PRIVATE).
    seed: String,
}

/// A loaded local identity.
pub struct Identity {
    pub name: String,
    signing_key: SigningKey<MlDsa65>,
    /// Encoded public key (1952 bytes).
    public_key: Vec<u8>,
}

impl Identity {
    /// Generate a fresh identity for `name` using the OS RNG.
    pub fn generate(name: impl Into<String>) -> Identity {
        let signing_key = SigningKey::<MlDsa65>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        Identity {
            name: name.into(),
            signing_key,
            public_key,
        }
    }

    /// The encoded public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Signer key id `<name>#<fingerprint>` for the wrapper.
    pub fn kid(&self) -> String {
        make_kid(&self.name, &self.public_key)
    }

    /// Shareable public identity token (REQ-0007/0043).
    pub fn token(&self) -> IdentityToken {
        IdentityToken::new(self.name.clone(), self.public_key.clone())
    }

    /// Sign a message, returning the encoded signature bytes (REQ-0005).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(msg);
        sig.encode().to_vec()
    }

    /// True if an identity file already exists.
    pub fn exists() -> bool {
        paths::identity_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Persist this identity, restricting the file to the owner (REQ-0027).
    pub fn save(&self) -> Result<()> {
        paths::ensure_data_dir()?;
        let path = paths::identity_path()?;
        let seed = self.signing_key.to_seed();
        let file = IdentityFile {
            name: self.name.clone(),
            seed: b64(seed.as_slice()),
        };
        let text = serde_json::to_string_pretty(&file)?;
        std::fs::write(&path, text)?;
        restrict_permissions(&path)?;
        Ok(())
    }

    /// Load the local identity from disk.
    pub fn load() -> Result<Identity> {
        let path = paths::identity_path()?;
        if !path.exists() {
            return Err(Error::NoIdentity);
        }
        let text = std::fs::read_to_string(&path)?;
        let file: IdentityFile =
            serde_json::from_str(&text).map_err(|e| Error::Crypto(format!("identity: {e}")))?;
        let seed_bytes = unb64(&file.seed).map_err(|_| Error::Crypto("bad seed".into()))?;
        let seed: [u8; SEED_LEN] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("seed must be 32 bytes".into()))?;
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let public_key = signing_key.verifying_key().encode().to_vec();
        Ok(Identity {
            name: file.name,
            signing_key,
            public_key,
        })
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    // On Windows the data dir lives under the user profile (ACL-protected by
    // default). Mark the file read-only is not desired; rely on the per-user
    // profile ACL. Touch the path to keep the signature uniform.
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::generate("alice");
        let msg = b"instruction: report disk usage";
        let sig = id.sign(msg);
        assert!(crypto::verify(id.public_key(), msg, &sig));
        // Tampered message fails (REQ-0005 acceptance).
        assert!(!crypto::verify(id.public_key(), b"tampered", &sig));
    }

    #[test]
    fn public_key_len_is_ml_dsa_65() {
        let id = Identity::generate("bob");
        assert_eq!(id.public_key().len(), crypto::PUBLIC_KEY_LEN);
    }
}
