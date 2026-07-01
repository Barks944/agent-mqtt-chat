//! Local agent identity: the ML-DSA-65 signing keypair this daemon signs with,
//! plus an ML-KEM-768 keypair for receiving encrypted payloads.
//!
//! REQ-0007: generate + export identity. REQ-0022: one identity per daemon.
//! REQ-0027: private key stored owner-only. REQ-0028: never export private key.
//! REQ: ML-KEM payload encryption (recipient KEM keypair).

use ml_dsa::{Generate, Keypair, MlDsa65, Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::kem;
use crate::paths;
use crate::token::IdentityToken;
use crate::wire::{b64, fingerprint, make_kid, unb64};

/// 32-byte seed length used to persist the signing key.
const SEED_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    /// base64url of the 32-byte signing-key seed (PRIVATE). The ML-KEM-768
    /// keypair is derived deterministically from this same seed (see
    /// [`kem::derive_from_seed`]), so nothing else needs to be persisted and a
    /// migrated v0.1 file (which has only `name` + `seed`) yields a stable KEM
    /// key. A legacy `kem_seed` field, if present, is ignored.
    seed: String,
}

/// A loaded local identity.
pub struct Identity {
    pub name: String,
    signing_key: SigningKey<MlDsa65>,
    /// Encoded public key (1952 bytes).
    public_key: Vec<u8>,
    /// Encoded ML-KEM-768 decapsulation key (PRIVATE).
    kem_dk: Vec<u8>,
    /// Encoded ML-KEM-768 encapsulation key (public).
    kem_ek: Vec<u8>,
}

impl Identity {
    /// Generate a fresh identity for `name` using the OS RNG (both keypairs).
    pub fn generate(name: impl Into<String>) -> Identity {
        let signing_key = SigningKey::<MlDsa65>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        // Derive the KEM keypair from the signing seed so it is stable across
        // loads/processes (REQ: ML-KEM payload encryption).
        let (kem_dk, kem_ek) = kem::derive_from_seed(signing_key.to_seed().as_slice());
        Identity {
            name: name.into(),
            signing_key,
            public_key,
            kem_dk,
            kem_ek,
        }
    }

    /// The encoded ML-DSA-65 public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The encoded ML-KEM-768 encapsulation (public) key bytes.
    pub fn kem_ek(&self) -> &[u8] {
        &self.kem_ek
    }

    /// The encoded ML-KEM-768 decapsulation (private) key bytes.
    pub fn kem_dk(&self) -> &[u8] {
        &self.kem_dk
    }

    /// Fingerprint of the KEM encapsulation key (matches `recipient_kid`).
    pub fn kem_fingerprint(&self) -> String {
        kem::kem_fingerprint(&self.kem_ek)
    }

    /// Signer key id `<name>#<fingerprint>` for the wrapper.
    pub fn kid(&self) -> String {
        make_kid(&self.name, &self.public_key)
    }

    /// Shareable public identity token (REQ-0007/0043), carrying both keys.
    pub fn token(&self) -> IdentityToken {
        IdentityToken::with_kem(
            self.name.clone(),
            self.public_key.clone(),
            Some(self.kem_ek.clone()),
        )
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
        // Derive the KEM keypair deterministically from the signing seed. This
        // is what makes the advertised KEM key stable across every load and
        // process, and gives migrated v0.1 identities (seed only, no stored KEM
        // material) a working, stable KEM key (REQ: ML-KEM payload encryption).
        let (kem_dk, kem_ek) = kem::derive_from_seed(&seed);
        Ok(Identity {
            name: file.name,
            signing_key,
            public_key,
            kem_dk,
            kem_ek,
        })
    }

    /// Back up an existing identity file to `identity.json.bak-<fp>` (owner-only)
    /// before it is overwritten. Returns the backed-up identity's fingerprint, or
    /// `None` if there was nothing to back up.
    pub fn backup_existing() -> Result<Option<String>> {
        let path = paths::identity_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let fp = load_name_fp()?
            .map(|(_, fp)| fp)
            .unwrap_or_else(|| "unknown".to_string());
        let bak = paths::data_dir()?.join(format!("identity.json.bak-{fp}"));
        std::fs::copy(&path, &bak)?;
        restrict_permissions(&bak)?;
        Ok(Some(fp))
    }
}

/// Read the existing identity's `(name, fingerprint)` without a hard failure on
/// a malformed file (returns `None` when absent/unreadable). Used by the
/// `id generate` cross-name guard and by [`Identity::backup_existing`].
pub fn load_name_fp() -> Result<Option<(String, String)>> {
    let path = paths::identity_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let file: IdentityFile = match serde_json::from_str(&text) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let Ok(seed_bytes) = unb64(&file.seed) else {
        return Ok(None);
    };
    let Ok(seed) = <[u8; SEED_LEN]>::try_from(seed_bytes.as_slice()) else {
        return Ok(None);
    };
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed.into());
    let public_key = signing_key.verifying_key().encode().to_vec();
    Ok(Some((file.name, fingerprint(&public_key))))
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

    /// Serializes the `AGENTMSG_HOME`-mutating tests so they cannot race on the
    /// process-global environment variable.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn load_name_fp_backs_the_generate_guard() {
        // The `id generate` cross-name guard refuses to overwrite an existing
        // identity with a different name; it reads the current (name, fp) via
        // `load_name_fp`. Here we verify that data source end-to-end on disk.
        let _g = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AGENTMSG_HOME", dir.path());

        // Nothing on disk yet -> no existing identity to guard against.
        assert!(load_name_fp().unwrap().is_none());

        let id = Identity::generate("orchestrator");
        id.save().unwrap();

        let (name, fp) = load_name_fp().unwrap().expect("identity present");
        assert_eq!(name, "orchestrator");
        assert_eq!(fp, fingerprint(id.public_key()));
        // The guard compares the requested name against this one: a mismatch
        // (e.g. requesting "worker") is what triggers the refuse-without-force.
        assert_ne!(name, "worker");

        std::env::remove_var("AGENTMSG_HOME");
    }

    #[test]
    fn migrated_v1_identity_has_stable_kem_key_that_round_trips() {
        // Regression for issue #13: a v0.1 identity file carries only {name, seed}
        // (no KEM material). Loading it must derive a STABLE KEM key — identical
        // across separate loads (i.e. across the `id token` process and the daemon
        // process) — and a message encrypted to the token's advertised KEM key
        // must decrypt with the loaded identity's private key.
        let _g = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AGENTMSG_HOME", dir.path());

        // Hand-write a legacy v0.1 identity.json: name + seed ONLY.
        let seed = [42u8; SEED_LEN];
        let legacy = format!(
            "{{\n  \"name\": \"worker\",\n  \"seed\": \"{}\"\n}}",
            b64(&seed)
        );
        std::fs::write(paths::identity_path().unwrap(), legacy).unwrap();

        // Two independent loads (simulating two processes) must agree on the KEM
        // public key — the bug was that each load generated a fresh ephemeral one.
        let load1 = Identity::load().unwrap();
        let load2 = Identity::load().unwrap();
        assert_eq!(load1.kem_ek(), load2.kem_ek(), "KEM key must be stable");
        assert_eq!(
            load1.token().kem_public_key.as_deref(),
            Some(load1.kem_ek())
        );

        // Cross-load encryption round-trip: encapsulate to load1's *advertised
        // token* key, decapsulate with load2's private key.
        let advertised = load1.token().kem_public_key.unwrap();
        let (ct, ss_send) = crate::kem::encapsulate(&advertised).expect("encapsulate");
        let ss_recv = crate::kem::decapsulate(load2.kem_dk(), &ct).expect("decapsulate");
        assert_eq!(ss_send, ss_recv, "shared secret must match across loads");

        std::env::remove_var("AGENTMSG_HOME");
    }

    #[test]
    fn backup_existing_copies_identity_file() {
        let _g = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AGENTMSG_HOME", dir.path());

        // Nothing to back up initially.
        assert!(Identity::backup_existing().unwrap().is_none());

        let id = Identity::generate("agent-a");
        id.save().unwrap();
        let fp = Identity::backup_existing().unwrap().expect("backed up");
        assert_eq!(fp, fingerprint(id.public_key()));
        assert!(dir.path().join(format!("identity.json.bak-{fp}")).exists());

        std::env::remove_var("AGENTMSG_HOME");
    }
}
