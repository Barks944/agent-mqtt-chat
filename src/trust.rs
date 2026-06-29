//! Trust store of known agents and authorities (REQ-0006, REQ-0008, REQ-0040,
//! REQ-0041, REQ: human-authorization grants, ML-KEM payload encryption).
//!
//! The trust store is the sole authority for which signers an agent will act
//! on (REQ: authenticity independent of broker auth).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::authority::AuthorityToken;
use crate::error::{Error, Result};
use crate::paths;
use crate::token::IdentityToken;
use crate::wire::{b64, fingerprint, unb64};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KnownAgentRecord {
    /// base64url ML-DSA-65 public key.
    pk: String,
    /// base64url ML-KEM-768 encapsulation key, if the agent advertised one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kem_pk: Option<String>,
}

/// A trusted agent entry (decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownAgent {
    pub name: String,
    pub public_key: Vec<u8>,
    /// ML-KEM-768 encapsulation key, when known.
    pub kem_public_key: Option<Vec<u8>>,
}

impl KnownAgent {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }
}

/// On-disk trust store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    #[serde(default)]
    agents: BTreeMap<String, KnownAgentRecord>,
    /// Known human authorities whose signed grants are accepted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    authorities: BTreeMap<String, KnownAgentRecord>,
}

impl TrustStore {
    pub fn load() -> Result<TrustStore> {
        let path = paths::trust_path()?;
        if !path.exists() {
            return Ok(TrustStore::default());
        }
        let text = std::fs::read_to_string(&path)?;
        serde_json::from_str(&text).map_err(|e| Error::Store(format!("trust store: {e}")))
    }

    pub fn save(&self) -> Result<()> {
        paths::ensure_data_dir()?;
        let path = paths::trust_path()?;
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Add or replace a known agent from a parsed identity token (REQ-0044),
    /// storing its KEM key too when present.
    pub fn add_from_token(&mut self, token: &IdentityToken) {
        self.agents.insert(
            token.name.clone(),
            KnownAgentRecord {
                pk: b64(&token.public_key),
                kem_pk: token.kem_public_key.as_deref().map(b64),
            },
        );
    }

    /// Add or replace by explicit name + key.
    pub fn add(&mut self, name: &str, public_key: &[u8]) {
        self.agents.insert(
            name.to_string(),
            KnownAgentRecord {
                pk: b64(public_key),
                kem_pk: None,
            },
        );
    }

    /// Add or replace by explicit name + signing key + optional KEM key. Used by
    /// the pairing flow, which captures both keys from a verified hello
    /// (REQ: bootstrap/pairing mode).
    pub fn add_with_kem(&mut self, name: &str, public_key: &[u8], kem_public_key: Option<&[u8]>) {
        self.agents.insert(
            name.to_string(),
            KnownAgentRecord {
                pk: b64(public_key),
                kem_pk: kem_public_key.map(b64),
            },
        );
    }

    /// Remove a known agent; returns true if it existed (REQ-0041).
    pub fn remove(&mut self, name: &str) -> bool {
        self.agents.remove(name).is_some()
    }

    /// Look up a trusted agent's public key by name.
    pub fn public_key(&self, name: &str) -> Result<Vec<u8>> {
        let rec = self
            .agents
            .get(name)
            .ok_or_else(|| Error::UnknownAgent(name.to_string()))?;
        unb64(&rec.pk).map_err(|_| Error::Store("corrupt trust key".into()))
    }

    /// The currently stored signing key for `name`, if any (for rotation diff).
    pub fn current_key(&self, name: &str) -> Option<Vec<u8>> {
        self.agents.get(name).and_then(|rec| unb64(&rec.pk).ok())
    }

    /// The stored KEM encapsulation key for `name`, if known.
    pub fn kem_public_key(&self, name: &str) -> Option<Vec<u8>> {
        self.agents
            .get(name)
            .and_then(|rec| rec.kem_pk.as_deref())
            .and_then(|k| unb64(k).ok())
    }

    /// True if the named agent is trusted.
    pub fn contains(&self, name: &str) -> bool {
        self.agents.contains_key(name)
    }

    /// List trusted agents (REQ-0040).
    pub fn list(&self) -> Vec<KnownAgent> {
        self.agents
            .iter()
            .filter_map(|(name, rec)| {
                unb64(&rec.pk).ok().map(|public_key| KnownAgent {
                    name: name.clone(),
                    public_key,
                    kem_public_key: rec.kem_pk.as_deref().and_then(|k| unb64(k).ok()),
                })
            })
            .collect()
    }

    /// Add or replace a trusted human authority from its token.
    pub fn add_authority_from_token(&mut self, token: &AuthorityToken) {
        self.authorities.insert(
            token.name.clone(),
            KnownAgentRecord {
                pk: b64(&token.public_key),
                kem_pk: None,
            },
        );
    }

    /// Look up a trusted authority's public key by name.
    pub fn authority_public_key(&self, name: &str) -> Result<Vec<u8>> {
        let rec = self
            .authorities
            .get(name)
            .ok_or_else(|| Error::UnknownAgent(name.to_string()))?;
        unb64(&rec.pk).map_err(|_| Error::Store("corrupt authority key".into()))
    }

    /// Remove a trusted authority; returns true if it existed.
    pub fn remove_authority(&mut self, name: &str) -> bool {
        self.authorities.remove(name).is_some()
    }

    /// List trusted authorities.
    pub fn list_authorities(&self) -> Vec<KnownAgent> {
        self.authorities
            .iter()
            .filter_map(|(name, rec)| {
                unb64(&rec.pk).ok().map(|public_key| KnownAgent {
                    name: name.clone(),
                    public_key,
                    kem_public_key: None,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_remove() {
        let mut ts = TrustStore::default();
        let tok = IdentityToken::new("bob", b"bob-key".to_vec());
        ts.add_from_token(&tok);
        assert!(ts.contains("bob"));
        assert_eq!(ts.public_key("bob").unwrap(), b"bob-key");
        assert_eq!(ts.list().len(), 1);
        assert!(ts.remove("bob"));
        assert!(!ts.contains("bob"));
        assert!(ts.public_key("bob").is_err());
    }

    #[test]
    fn rotation_replaces_key_and_current_key_reports_old() {
        // Agent rotation (REQ: agent rotation): re-adding under the same name
        // replaces the key; `current_key` lets the CLI diff old vs new fp.
        let mut ts = TrustStore::default();
        ts.add("bob", b"old-key");
        assert_eq!(ts.current_key("bob").as_deref(), Some(&b"old-key"[..]));
        // No record yet for an unknown agent.
        assert!(ts.current_key("carol").is_none());

        // Rotate to a new key under the same name.
        ts.add("bob", b"new-key");
        assert_eq!(ts.current_key("bob").as_deref(), Some(&b"new-key"[..]));
        assert_eq!(ts.public_key("bob").unwrap(), b"new-key");
        assert_eq!(ts.list().len(), 1); // still a single record
    }

    #[test]
    fn stores_and_returns_kem_key() {
        let mut ts = TrustStore::default();
        ts.add_from_token(&IdentityToken::with_kem(
            "dave",
            vec![1, 2, 3],
            Some(vec![9, 8, 7]),
        ));
        assert_eq!(ts.kem_public_key("dave").as_deref(), Some(&[9u8, 8, 7][..]));
        // An agent added without a KEM key returns None.
        ts.add("eve", b"k");
        assert!(ts.kem_public_key("eve").is_none());
    }
}
