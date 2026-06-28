//! Trust store of known agents (REQ-0006, REQ-0008, REQ-0040, REQ-0041).
//!
//! The trust store is the sole authority for which signers an agent will act
//! on (REQ: authenticity independent of broker auth).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths;
use crate::token::IdentityToken;
use crate::wire::{b64, fingerprint, unb64};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KnownAgentRecord {
    /// base64url public key.
    pk: String,
}

/// A trusted agent entry (decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownAgent {
    pub name: String,
    pub public_key: Vec<u8>,
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

    /// Add or replace a known agent from a parsed identity token (REQ-0044).
    pub fn add_from_token(&mut self, token: &IdentityToken) {
        self.agents.insert(
            token.name.clone(),
            KnownAgentRecord {
                pk: b64(&token.public_key),
            },
        );
    }

    /// Add or replace by explicit name + key.
    pub fn add(&mut self, name: &str, public_key: &[u8]) {
        self.agents.insert(
            name.to_string(),
            KnownAgentRecord {
                pk: b64(public_key),
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
}
