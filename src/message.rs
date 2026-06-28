//! Build outbound signed messages and verify inbound ones.
//!
//! REQ-0056 (verify-on-ingest pipeline): parse wrapper -> check version/alg ->
//! resolve signer in trust store -> confirm kid fingerprint -> verify signature
//! over exact inner bytes -> parse inner -> confirm sender -> size & freshness.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::crypto;
use crate::error::RejectReason;
use crate::identity::Identity;
use crate::trust::TrustStore;
use crate::wire::{
    b64, fingerprint, make_kid, split_kid, Inner, Wrapper, ALG_ML_DSA_65, PROTOCOL_VERSION,
};

/// Build a signed wrapper from the local identity.
pub fn build(
    id: &Identity,
    to: &str,
    ctype: &str,
    body: &str,
    in_reply_to: Option<String>,
) -> (Inner, Wrapper) {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("OS RNG");
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());

    let inner = Inner {
        id: Ulid::new().to_string(),
        v: PROTOCOL_VERSION,
        from: id.name.clone(),
        to: to.to_string(),
        ts,
        nonce: b64(&nonce),
        ctype: ctype.to_string(),
        in_reply_to,
        body: body.to_string(),
    };

    // Serialize once; THESE exact bytes are what we sign and transmit (REQ-0055).
    let inner_bytes = serde_json::to_vec(&inner).expect("inner serializes");
    let sig = id.sign(&inner_bytes);

    let wrapper = Wrapper {
        v: PROTOCOL_VERSION,
        alg: ALG_ML_DSA_65.to_string(),
        kid: make_kid(&id.name, id.public_key()),
        msg: b64(&inner_bytes),
        sig: b64(&sig),
    };
    (inner, wrapper)
}

/// Verify a wrapper received on the wire. On success returns the decoded inner
/// message; on failure returns the reason it was rejected (REQ-0046).
///
/// Duplicate detection (REQ-0013 id dedupe) is handled by the store after this.
pub fn verify_incoming(
    raw: &[u8],
    trust: &TrustStore,
    freshness_secs: i64,
    max_payload: usize,
) -> Result<Inner, RejectReason> {
    let wrapper = Wrapper::from_bytes(raw)?;

    if wrapper.v != PROTOCOL_VERSION {
        return Err(RejectReason::UnsupportedVersion(wrapper.v));
    }
    if wrapper.alg != ALG_ML_DSA_65 {
        return Err(RejectReason::UnsupportedAlg(wrapper.alg));
    }

    let (kid_name, kid_fp) = split_kid(&wrapper.kid).ok_or(RejectReason::MalformedWrapper)?;

    // Signer must be in the trust store (REQ-0006).
    let public_key = trust
        .public_key(kid_name)
        .map_err(|_| RejectReason::UnknownSigner)?;

    // kid fingerprint must match the trusted key (REQ-0056).
    if kid_fp != fingerprint(&public_key) {
        return Err(RejectReason::KidMismatch);
    }

    let inner_bytes = wrapper.inner_bytes()?;
    let sig_bytes = wrapper.sig_bytes()?;

    // Verify the signature over the EXACT transmitted bytes (REQ-0055).
    if !crypto::verify(&public_key, &inner_bytes, &sig_bytes) {
        return Err(RejectReason::InvalidSignature);
    }

    let inner = Wrapper::parse_inner(&inner_bytes)?;

    // Sender field must match the signer (no impersonation across the kid).
    if inner.from != kid_name {
        return Err(RejectReason::KidMismatch);
    }

    if inner.body.len() > max_payload {
        return Err(RejectReason::TooLarge);
    }

    if !fresh_enough(&inner.ts, freshness_secs) {
        return Err(RejectReason::Stale);
    }

    Ok(inner)
}

/// True if `ts` (RFC3339) is within `freshness_secs` of now (REQ-0013).
fn fresh_enough(ts: &str, freshness_secs: i64) -> bool {
    if freshness_secs <= 0 {
        return true;
    }
    match OffsetDateTime::parse(ts, &Rfc3339) {
        Ok(t) => {
            let now = OffsetDateTime::now_utc();
            let delta = (now - t).whole_seconds().abs();
            delta <= freshness_secs
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::IdentityToken;
    use crate::wire::CTYPE_TEXT;

    fn trusted(id: &Identity) -> TrustStore {
        let mut ts = TrustStore::default();
        ts.add_from_token(&IdentityToken::new(
            id.name.clone(),
            id.public_key().to_vec(),
        ));
        ts
    }

    #[test]
    fn build_then_verify_ok() {
        let alice = Identity::generate("alice");
        let trust = trusted(&alice);
        let (_inner, w) = build(&alice, "bob", CTYPE_TEXT, "hello", None);
        let raw = w.to_bytes().unwrap();
        let got = verify_incoming(&raw, &trust, 300, 65536).unwrap();
        assert_eq!(got.from, "alice");
        assert_eq!(got.body, "hello");
    }

    #[test]
    fn unknown_signer_rejected() {
        let alice = Identity::generate("alice");
        let empty = TrustStore::default();
        let (_i, w) = build(&alice, "bob", CTYPE_TEXT, "hi", None);
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &empty, 300, 65536).unwrap_err(),
            RejectReason::UnknownSigner
        );
    }

    #[test]
    fn tampered_body_rejected() {
        let alice = Identity::generate("alice");
        let trust = trusted(&alice);
        let (_i, mut w) = build(&alice, "bob", CTYPE_TEXT, "hi", None);
        // Re-encode a different inner under the same signature.
        let mut inner = Wrapper::parse_inner(&w.inner_bytes().unwrap()).unwrap();
        inner.body = "EVIL".into();
        w.msg = b64(&serde_json::to_vec(&inner).unwrap());
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &trust, 300, 65536).unwrap_err(),
            RejectReason::InvalidSignature
        );
    }

    #[test]
    fn stale_rejected() {
        let alice = Identity::generate("alice");
        let trust = trusted(&alice);
        let (_i, mut w) = build(&alice, "bob", CTYPE_TEXT, "hi", None);
        let mut inner = Wrapper::parse_inner(&w.inner_bytes().unwrap()).unwrap();
        inner.ts = "2000-01-01T00:00:00Z".into();
        let bytes = serde_json::to_vec(&inner).unwrap();
        w.msg = b64(&bytes);
        w.sig = b64(&alice.sign(&bytes)); // re-sign so only freshness fails
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &trust, 300, 65536).unwrap_err(),
            RejectReason::Stale
        );
    }
}
