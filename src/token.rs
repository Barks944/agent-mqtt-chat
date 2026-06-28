//! Paste-friendly identity token (REQ-0043): a single self-contained block
//! carrying an agent name and its public key, with no private material.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::wire::{b64, fingerprint, unb64};

/// Prefix marking an agentmsg identity token. The body after the dot is
/// base64url(JSON) so the whole thing is one contiguous, copy-pasteable token.
const TOKEN_PREFIX: &str = "agentmsg-id-v1.";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBody {
    name: String,
    /// base64url public key.
    pk: String,
}

/// A shareable public identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityToken {
    pub name: String,
    pub public_key: Vec<u8>,
}

impl IdentityToken {
    pub fn new(name: impl Into<String>, public_key: Vec<u8>) -> Self {
        IdentityToken {
            name: name.into(),
            public_key,
        }
    }

    /// Short public-key fingerprint (matches the `kid` fingerprint).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }

    /// Encode to a single paste-friendly token string.
    pub fn encode(&self) -> String {
        let body = TokenBody {
            name: self.name.clone(),
            pk: b64(&self.public_key),
        };
        // Compact JSON; infallible for this shape.
        let json = serde_json::to_vec(&body).expect("token body serializes");
        format!("{TOKEN_PREFIX}{}", b64(&json))
    }

    /// Decode a token string (tolerates surrounding whitespace from pasting).
    pub fn decode(s: &str) -> Result<IdentityToken> {
        let s = s.trim();
        let rest = s
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| Error::InvalidToken("missing agentmsg-id-v1 prefix".into()))?;
        let json = unb64(rest).map_err(|_| Error::InvalidToken("bad base64".into()))?;
        let body: TokenBody =
            serde_json::from_slice(&json).map_err(|_| Error::InvalidToken("bad json".into()))?;
        if body.name.is_empty() {
            return Err(Error::InvalidToken("empty name".into()));
        }
        let public_key = unb64(&body.pk).map_err(|_| Error::InvalidToken("bad key".into()))?;
        Ok(IdentityToken {
            name: body.name,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let t = IdentityToken::new("orchestrator-home", b"public-key-material".to_vec());
        let encoded = t.encode();
        assert!(encoded.starts_with(TOKEN_PREFIX));
        assert!(!encoded.contains(' '));
        // Tolerates pasted whitespace.
        let decoded = IdentityToken::decode(&format!("  {encoded}\n")).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn rejects_garbage() {
        assert!(IdentityToken::decode("not-a-token").is_err());
        assert!(IdentityToken::decode("agentmsg-id-v1.!!!").is_err());
    }
}
