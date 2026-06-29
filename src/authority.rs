//! Human-authority signing key (REQ: human-authorization grants). Mirrors
//! [`crate::identity`] but holds an ML-DSA-65 keypair only and lives in its own
//! `authority.json`. The authority key signs grants that authorize an agent to
//! take a privileged action; agents trust authorities via their trust store.

use ml_dsa::{Generate, Keypair, MlDsa65, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::crypto::PUBLIC_KEY_LEN;
use crate::error::{Error, Result};
use crate::paths;
use crate::wire::{b64, fingerprint, make_kid, unb64};

/// 32-byte seed length used to persist the signing key.
const SEED_LEN: usize = 32;

/// Token prefix for an authority public key. Layout mirrors the v2 identity
/// token: `agentmsg-auth-v2.<b64 json body>.<b64 crc32(body bytes)>`.
const AUTH_TOKEN_PREFIX: &str = "agentmsg-auth-v2.";

#[derive(Serialize, Deserialize)]
struct AuthorityFile {
    name: String,
    /// base64url of the 32-byte signing-key seed (PRIVATE).
    seed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthTokenBody {
    name: String,
    /// base64url ML-DSA-65 public key.
    pk: String,
}

/// A shareable authority public identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityToken {
    pub name: String,
    pub public_key: Vec<u8>,
}

impl AuthorityToken {
    /// Short public-key fingerprint (matches the `kid` fingerprint).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }

    /// Encode to a single paste-friendly token string with a CRC-32 tail.
    pub fn encode(&self) -> String {
        let body = AuthTokenBody {
            name: self.name.clone(),
            pk: b64(&self.public_key),
        };
        let json = serde_json::to_vec(&body).expect("auth token body serializes");
        let b64body = b64(&json);
        let crc = crc32fast::hash(b64body.as_bytes());
        format!("{AUTH_TOKEN_PREFIX}{b64body}.{}", b64(&crc.to_be_bytes()))
    }

    /// Decode an authority token. Returns [`Error::NotAnAuthorityToken`] if the
    /// prefix does not match (e.g. an identity token was supplied by mistake).
    pub fn decode(s: &str) -> Result<AuthorityToken> {
        let s = s.trim();
        let rest = s
            .strip_prefix(AUTH_TOKEN_PREFIX)
            .ok_or(Error::NotAnAuthorityToken)?;
        let (b64body, b64crc) = rest
            .rsplit_once('.')
            .ok_or_else(|| Error::TokenCorrupt("missing checksum".into()))?;
        let crc_bytes = unb64(b64crc).map_err(|_| Error::TokenCorrupt("bad checksum".into()))?;
        let crc_arr: [u8; 4] = crc_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::TokenCorrupt("bad checksum length".into()))?;
        if crc32fast::hash(b64body.as_bytes()) != u32::from_be_bytes(crc_arr) {
            return Err(Error::TokenCorrupt(
                "checksum mismatch — token truncated/corrupted".into(),
            ));
        }
        let json = unb64(b64body).map_err(|_| Error::TokenCorrupt("bad base64".into()))?;
        let body: AuthTokenBody =
            serde_json::from_slice(&json).map_err(|_| Error::TokenCorrupt("bad json".into()))?;
        if body.name.is_empty() {
            return Err(Error::InvalidToken("empty name".into()));
        }
        let public_key = unb64(&body.pk).map_err(|_| Error::InvalidToken("bad key".into()))?;
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(Error::TokenCorrupt(format!(
                "public key is {} bytes, expected {PUBLIC_KEY_LEN} — token truncated/corrupted",
                public_key.len()
            )));
        }
        Ok(AuthorityToken {
            name: body.name,
            public_key,
        })
    }
}

/// A loaded human authority signing key.
pub struct Authority {
    pub name: String,
    signing_key: SigningKey<MlDsa65>,
    /// Encoded public key (1952 bytes).
    public_key: Vec<u8>,
}

impl Authority {
    /// Generate a fresh authority key for `name` using the OS RNG.
    pub fn generate(name: impl Into<String>) -> Authority {
        let signing_key = SigningKey::<MlDsa65>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        Authority {
            name: name.into(),
            signing_key,
            public_key,
        }
    }

    /// The encoded public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Authority key id `<name>#<fingerprint>` used in [`crate::wire::SignedGrant`].
    pub fn kid(&self) -> String {
        make_kid(&self.name, &self.public_key)
    }

    /// Shareable public authority token.
    pub fn token(&self) -> AuthorityToken {
        AuthorityToken {
            name: self.name.clone(),
            public_key: self.public_key.clone(),
        }
    }

    /// Sign grant claim bytes, returning the encoded signature.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg).encode().to_vec()
    }

    /// Path to the authority key file.
    fn path() -> Result<std::path::PathBuf> {
        Ok(paths::data_dir()?.join("authority.json"))
    }

    /// True if an authority file already exists.
    pub fn exists() -> bool {
        Self::path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Persist this authority key, restricting the file to the owner.
    pub fn save(&self) -> Result<()> {
        paths::ensure_data_dir()?;
        let path = Self::path()?;
        let seed = self.signing_key.to_seed();
        let file = AuthorityFile {
            name: self.name.clone(),
            seed: b64(seed.as_slice()),
        };
        let text = serde_json::to_string_pretty(&file)?;
        std::fs::write(&path, text)?;
        restrict_permissions(&path)?;
        Ok(())
    }

    /// Load the authority key from disk.
    pub fn load() -> Result<Authority> {
        let path = Self::path()?;
        if !path.exists() {
            return Err(Error::NoAuthority);
        }
        let text = std::fs::read_to_string(&path)?;
        let file: AuthorityFile =
            serde_json::from_str(&text).map_err(|e| Error::Crypto(format!("authority: {e}")))?;
        let seed_bytes = unb64(&file.seed).map_err(|_| Error::Crypto("bad seed".into()))?;
        let seed: [u8; SEED_LEN] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("seed must be 32 bytes".into()))?;
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let public_key = signing_key.verifying_key().encode().to_vec();
        Ok(Authority {
            name: file.name,
            signing_key,
            public_key,
        })
    }

    /// Back up an existing authority file to `authority.json.bak-<fp>` before it
    /// is overwritten. Returns the backed-up key's fingerprint, or `None`.
    pub fn backup_existing() -> Result<Option<String>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let fp = match Self::load() {
            Ok(a) => fingerprint(&a.public_key),
            Err(_) => "unknown".to_string(),
        };
        let bak = paths::data_dir()?.join(format!("authority.json.bak-{fp}"));
        std::fs::copy(&path, &bak)?;
        restrict_permissions(&bak)?;
        Ok(Some(fp))
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let a = Authority::generate("ops-lead");
        let tok = a.token();
        let encoded = tok.encode();
        assert!(encoded.starts_with(AUTH_TOKEN_PREFIX));
        assert_eq!(AuthorityToken::decode(&encoded).unwrap(), tok);
    }

    #[test]
    fn rejects_identity_token() {
        assert!(matches!(
            AuthorityToken::decode("agentmsg-id-v2.abc.def"),
            Err(Error::NotAnAuthorityToken)
        ));
    }
}
