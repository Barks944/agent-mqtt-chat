//! Human-authorization grants (REQ: human-authorization grants). An authority
//! key signs a [`GrantClaims`] document; an agent attaches the resulting
//! [`SignedGrant`] to a message to prove it was authorized to take a privileged
//! action. Verification resolves the authority in the trust store, checks the
//! signature over the exact claim bytes, and rejects expired grants. Subject and
//! replay checks happen in the message pipeline (it has the sender + store).

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::authority::Authority;
use crate::crypto;
use crate::error::{Error, RejectReason, Result};
use crate::trust::TrustStore;
use crate::wire::{b64, fingerprint, split_kid, unb64, SignedGrant, ALG_ML_DSA_65};

/// Token prefix for a paste-friendly signed grant.
const GRANT_TOKEN_PREFIX: &str = "agentmsg-grant-v1.";

/// The claims an authority asserts in a grant. Serialized to canonical JSON and
/// signed; the bytes are carried base64url in [`SignedGrant::grant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClaims {
    /// Unique grant id (also the replay-dedupe key).
    pub id: String,
    /// Authorized action (free-form, e.g. "deploy").
    pub action: String,
    /// Scope the action is limited to (e.g. a resource or topic).
    pub scope: String,
    /// Agent name the grant authorizes (must equal the message sender).
    pub subject: String,
    /// RFC3339 expiry timestamp; the grant is invalid once past.
    pub expiry: String,
    /// Random nonce for uniqueness.
    pub nonce: String,
}

/// Mint a signed grant: sign the canonical claim bytes with the authority key.
pub fn mint(authority: &Authority, claims: &GrantClaims) -> SignedGrant {
    let json = serde_json::to_vec(claims).expect("grant claims serialize");
    let sig = authority.sign(&json);
    SignedGrant {
        alg: ALG_ML_DSA_65.to_string(),
        authority_kid: authority.kid(),
        grant: b64(&json),
        sig: b64(&sig),
    }
}

/// Verify a signed grant against the known `authorities`. On success returns the
/// decoded claims (expiry already checked). Subject/replay checks are the
/// caller's responsibility (see [`crate::message::verify_incoming`]).
pub fn verify(
    sg: &SignedGrant,
    authorities: &TrustStore,
) -> std::result::Result<GrantClaims, RejectReason> {
    let (name, fp) = split_kid(&sg.authority_kid).ok_or(RejectReason::InvalidGrant)?;

    // Resolve the authority in the trust store (REQ: unknown authority).
    let public_key = authorities
        .authority_public_key(name)
        .map_err(|_| RejectReason::UnknownAuthority)?;
    if fp != fingerprint(&public_key) {
        return Err(RejectReason::UnknownAuthority);
    }

    let grant_bytes = unb64(&sg.grant).map_err(|_| RejectReason::InvalidGrant)?;
    let sig_bytes = unb64(&sg.sig).map_err(|_| RejectReason::InvalidGrant)?;

    // Verify the signature over the EXACT claim bytes (REQ-0055 invariant).
    if !crypto::verify(&public_key, &grant_bytes, &sig_bytes) {
        return Err(RejectReason::InvalidGrant);
    }

    let claims: GrantClaims =
        serde_json::from_slice(&grant_bytes).map_err(|_| RejectReason::InvalidGrant)?;

    if is_expired(&claims.expiry) {
        return Err(RejectReason::GrantExpired);
    }

    Ok(claims)
}

/// True if `expiry` (RFC3339) is in the past (or unparseable).
fn is_expired(expiry: &str) -> bool {
    match OffsetDateTime::parse(expiry, &Rfc3339) {
        Ok(t) => OffsetDateTime::now_utc() > t,
        Err(_) => true,
    }
}

/// Encode a signed grant to a single paste-friendly token string.
pub fn encode_token(sg: &SignedGrant) -> String {
    let json = serde_json::to_vec(sg).expect("signed grant serializes");
    format!("{GRANT_TOKEN_PREFIX}{}", b64(&json))
}

/// Decode a signed-grant token string (tolerates pasted whitespace).
pub fn decode_token(s: &str) -> Result<SignedGrant> {
    let s = s.trim();
    let rest = s
        .strip_prefix(GRANT_TOKEN_PREFIX)
        .ok_or_else(|| Error::InvalidToken("missing agentmsg-grant-v1 prefix".into()))?;
    let json = unb64(rest).map_err(|_| Error::InvalidToken("bad base64".into()))?;
    serde_json::from_slice(&json).map_err(|_| Error::InvalidToken("bad grant json".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn claims(subject: &str, expiry: &str) -> GrantClaims {
        GrantClaims {
            id: Ulid::new().to_string(),
            action: "deploy".into(),
            scope: "prod".into(),
            subject: subject.into(),
            expiry: expiry.into(),
            nonce: "n".into(),
        }
    }

    #[test]
    fn mint_verify_roundtrip() {
        let auth = Authority::generate("ops");
        let mut trust = TrustStore::default();
        trust.add_authority_from_token(&auth.token());
        let c = claims("agent-a", "2999-01-01T00:00:00Z");
        let sg = mint(&auth, &c);
        let got = verify(&sg, &trust).unwrap();
        assert_eq!(got, c);
    }

    #[test]
    fn expired_rejected() {
        let auth = Authority::generate("ops");
        let mut trust = TrustStore::default();
        trust.add_authority_from_token(&auth.token());
        let sg = mint(&auth, &claims("agent-a", "2000-01-01T00:00:00Z"));
        assert_eq!(verify(&sg, &trust).unwrap_err(), RejectReason::GrantExpired);
    }

    #[test]
    fn unknown_authority_rejected() {
        let auth = Authority::generate("ops");
        let trust = TrustStore::default();
        let sg = mint(&auth, &claims("agent-a", "2999-01-01T00:00:00Z"));
        assert_eq!(
            verify(&sg, &trust).unwrap_err(),
            RejectReason::UnknownAuthority
        );
    }

    #[test]
    fn token_roundtrip() {
        let auth = Authority::generate("ops");
        let sg = mint(&auth, &claims("agent-a", "2999-01-01T00:00:00Z"));
        let tok = encode_token(&sg);
        let back = decode_token(&tok).unwrap();
        assert_eq!(back.authority_kid, sg.authority_kid);
        assert_eq!(back.grant, sg.grant);
    }
}
