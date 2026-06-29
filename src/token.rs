//! Paste-friendly identity token (REQ-0043): a single self-contained block
//! carrying an agent name and its public key(s), with no private material.
//!
//! v2 (REQ: token integrity/length) adds an ML-KEM encapsulation key and a
//! CRC-32 integrity tail so a truncated/garbled paste is rejected loudly rather
//! than silently importing a broken key. v1 tokens are still accepted on decode
//! for backward compatibility (REQ: protocol v2 + compat).

use serde::{Deserialize, Serialize};

use crate::crypto::PUBLIC_KEY_LEN;
use crate::error::{Error, Result};
use crate::wire::{b64, fingerprint, unb64};

/// v1 prefix (legacy, decode-only). Body after the dot is base64url(JSON).
const TOKEN_PREFIX_V1: &str = "agentmsg-id-v1.";
/// v2 prefix. Layout: `agentmsg-id-v2.<b64 json body>.<b64 crc32(body bytes)>`.
const TOKEN_PREFIX_V2: &str = "agentmsg-id-v2.";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBodyV1 {
    name: String,
    /// base64url public key.
    pk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBodyV2 {
    name: String,
    /// base64url ML-DSA-65 public key.
    pk: String,
    /// base64url ML-KEM-768 encapsulation key (optional for older peers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kem_pk: Option<String>,
}

/// A shareable public identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityToken {
    pub name: String,
    pub public_key: Vec<u8>,
    /// ML-KEM-768 encapsulation key, when the peer advertises payload encryption.
    pub kem_public_key: Option<Vec<u8>>,
}

impl IdentityToken {
    /// Construct a signing-only token (no KEM key).
    pub fn new(name: impl Into<String>, public_key: Vec<u8>) -> Self {
        IdentityToken {
            name: name.into(),
            public_key,
            kem_public_key: None,
        }
    }

    /// Construct a token carrying both the signing and KEM public keys.
    pub fn with_kem(
        name: impl Into<String>,
        public_key: Vec<u8>,
        kem_public_key: Option<Vec<u8>>,
    ) -> Self {
        IdentityToken {
            name: name.into(),
            public_key,
            kem_public_key,
        }
    }

    /// Short public-key fingerprint (matches the `kid` fingerprint).
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }

    /// Encode to a single paste-friendly v2 token string with a CRC-32 tail.
    pub fn encode(&self) -> String {
        let body = TokenBodyV2 {
            name: self.name.clone(),
            pk: b64(&self.public_key),
            kem_pk: self.kem_public_key.as_deref().map(b64),
        };
        // Compact JSON; infallible for this shape.
        let json = serde_json::to_vec(&body).expect("token body serializes");
        let b64body = b64(&json);
        let crc = crc32fast::hash(b64body.as_bytes());
        format!("{TOKEN_PREFIX_V2}{b64body}.{}", b64(&crc.to_be_bytes()))
    }

    /// Decode a token string (tolerates surrounding whitespace from pasting).
    /// Accepts v1 (no CRC) and v2 (CRC-verified). Both enforce the ML-DSA-65
    /// public-key length so truncated/corrupted tokens are rejected.
    pub fn decode(s: &str) -> Result<IdentityToken> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix(TOKEN_PREFIX_V2) {
            Self::decode_v2(rest)
        } else if let Some(rest) = s.strip_prefix(TOKEN_PREFIX_V1) {
            Self::decode_v1(rest)
        } else {
            Err(Error::InvalidToken(
                "missing agentmsg-id-v2/v1 prefix".into(),
            ))
        }
    }

    fn decode_v1(rest: &str) -> Result<IdentityToken> {
        let json = unb64(rest).map_err(|_| Error::InvalidToken("bad base64".into()))?;
        let body: TokenBodyV1 =
            serde_json::from_slice(&json).map_err(|_| Error::InvalidToken("bad json".into()))?;
        if body.name.is_empty() {
            return Err(Error::InvalidToken("empty name".into()));
        }
        let public_key = unb64(&body.pk).map_err(|_| Error::InvalidToken("bad key".into()))?;
        check_pk_len(&public_key)?;
        Ok(IdentityToken {
            name: body.name,
            public_key,
            kem_public_key: None,
        })
    }

    fn decode_v2(rest: &str) -> Result<IdentityToken> {
        let (b64body, b64crc) = rest
            .rsplit_once('.')
            .ok_or_else(|| Error::TokenCorrupt("missing checksum".into()))?;
        let crc_bytes = unb64(b64crc).map_err(|_| Error::TokenCorrupt("bad checksum".into()))?;
        let crc_arr: [u8; 4] = crc_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::TokenCorrupt("bad checksum length".into()))?;
        let expected = u32::from_be_bytes(crc_arr);
        if crc32fast::hash(b64body.as_bytes()) != expected {
            return Err(Error::TokenCorrupt(
                "checksum mismatch — token truncated/corrupted".into(),
            ));
        }
        let json = unb64(b64body).map_err(|_| Error::TokenCorrupt("bad base64".into()))?;
        let body: TokenBodyV2 =
            serde_json::from_slice(&json).map_err(|_| Error::TokenCorrupt("bad json".into()))?;
        if body.name.is_empty() {
            return Err(Error::InvalidToken("empty name".into()));
        }
        let public_key = unb64(&body.pk).map_err(|_| Error::InvalidToken("bad key".into()))?;
        check_pk_len(&public_key)?;
        let kem_public_key = match body.kem_pk {
            Some(k) => Some(unb64(&k).map_err(|_| Error::InvalidToken("bad kem key".into()))?),
            None => None,
        };
        Ok(IdentityToken {
            name: body.name,
            public_key,
            kem_public_key,
        })
    }
}

/// Enforce the ML-DSA-65 public-key length (REQ: token integrity/length).
fn check_pk_len(public_key: &[u8]) -> Result<()> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(Error::TokenCorrupt(format!(
            "public key is {} bytes, expected {PUBLIC_KEY_LEN} — token truncated/corrupted",
            public_key.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn token_roundtrip() {
        let id = Identity::generate("orchestrator-home");
        let t = id.token();
        let encoded = t.encode();
        assert!(encoded.starts_with(TOKEN_PREFIX_V2));
        assert!(!encoded.contains(' '));
        // Tolerates pasted whitespace.
        let decoded = IdentityToken::decode(&format!("  {encoded}\n")).unwrap();
        assert_eq!(decoded, t);
    }

    #[test]
    fn rejects_garbage() {
        assert!(IdentityToken::decode("not-a-token").is_err());
        assert!(IdentityToken::decode("agentmsg-id-v2.!!!").is_err());
    }

    #[test]
    fn rejects_truncated_crc() {
        let id = Identity::generate("alice");
        let mut encoded = id.token().encode();
        encoded.pop();
        encoded.pop();
        assert!(matches!(
            IdentityToken::decode(&encoded),
            Err(Error::TokenCorrupt(_))
        ));
    }

    #[test]
    fn rejects_wrong_public_key_length() {
        // A CRC-valid v2 token whose public key is the wrong length must be
        // rejected as corrupt (REQ: token integrity/length).
        let body = TokenBodyV2 {
            name: "alice".into(),
            pk: b64(&[0u8; 100]), // far short of the 1952-byte ML-DSA-65 key
            kem_pk: None,
        };
        let json = serde_json::to_vec(&body).unwrap();
        let b64body = b64(&json);
        let crc = crc32fast::hash(b64body.as_bytes());
        let token = format!("{TOKEN_PREFIX_V2}{b64body}.{}", b64(&crc.to_be_bytes()));
        match IdentityToken::decode(&token) {
            Err(Error::TokenCorrupt(msg)) => {
                assert!(msg.contains("expected 1952"), "unexpected message: {msg}");
            }
            other => panic!("expected TokenCorrupt, got {other:?}"),
        }
    }
}
