//! Build outbound messages and verify inbound ones.
//!
//! REQ-0056 (verify-on-ingest pipeline): parse wrapper -> check version/alg ->
//! resolve signer in trust store -> confirm kid fingerprint -> verify signature
//! over exact inner bytes -> parse inner -> confirm sender -> size & freshness ->
//! decrypt payload -> verify any attached grant.
//!
//! v0.2 additions (DESIGN_V2 Layer 3): typed [`BuildOpts`], optional ML-KEM
//! payload encryption, unsigned (insecure) messages with downgrade protection,
//! v1 backward compatibility, and human-authorization grant verification. The
//! replay (`seen_grant`) and store interactions stay in the daemon (Layer 5);
//! this module performs only crypto / grant signature+expiry+subject checks.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::crypto;
use crate::error::{RejectInfo, RejectReason};
use crate::grant;
use crate::identity::Identity;
use crate::kem;
use crate::trust::TrustStore;
use crate::wire::{
    b64, fingerprint, make_kid, split_kid, unb64, EncInfo, Inner, MsgKind, Receipt, SignedGrant,
    Wrapper, ALG_KEM_AEAD, ALG_ML_DSA_65, ALG_NONE, BROADCAST, PROTOCOL_VERSION,
};

/// Options describing the message to build (REQ: typed schema, encryption,
/// grants, unsigned mode). Borrows the small string fields; owned `Option`s are
/// moved into the resulting [`Inner`].
pub struct BuildOpts<'a> {
    /// Recipient agent name, or [`BROADCAST`] (`"*"`).
    pub to: &'a str,
    /// Content type of `body` (the plaintext content type when encrypting).
    pub ctype: &'a str,
    /// Plaintext payload.
    pub body: &'a str,
    /// Typed message kind.
    pub kind: MsgKind,
    /// Optional id of a message this one replies to.
    pub in_reply_to: Option<String>,
    /// Optional correlation id linking related messages.
    pub correlation_id: Option<String>,
    /// Optional id of a message this one supersedes.
    pub supersedes: Option<String>,
    /// Optional human-authorization grant to attach.
    pub grant: Option<SignedGrant>,
    /// Optional delivery/read receipt to carry.
    pub receipt: Option<Receipt>,
    /// Recipient ML-KEM encapsulation key to encrypt to; `None` = cleartext.
    pub encrypt_to: Option<Vec<u8>>,
    /// Send unsigned (`alg=none`, insecure) rather than ML-DSA-65 signed.
    pub unsigned: bool,
}

impl<'a> BuildOpts<'a> {
    /// A minimal cleartext, signed message to `to` carrying `body`/`ctype`.
    pub fn new(to: &'a str, ctype: &'a str, body: &'a str) -> Self {
        BuildOpts {
            to,
            ctype,
            body,
            kind: MsgKind::default(),
            in_reply_to: None,
            correlation_id: None,
            supersedes: None,
            grant: None,
            receipt: None,
            encrypt_to: None,
            unsigned: false,
        }
    }
}

/// Build an outbound message from the local identity per `opts`.
///
/// - Cleartext signed: signs the exact inner bytes; `kid`/`sig` are `Some`.
/// - Encrypted: ML-KEM encapsulates a shared secret to `encrypt_to`, AES-256-GCM
///   seals the body (routing fields bound as AAD), stores [`EncInfo`], and sets
///   `body` to the base64url ciphertext. Encrypted broadcast is rejected.
/// - Unsigned: `alg=none`, `kid`/`sig` are `None`.
pub fn build(
    id: &Identity,
    opts: &BuildOpts,
) -> std::result::Result<(Inner, Wrapper), RejectReason> {
    // Encrypted broadcast is unsupported: a single KEM ciphertext binds to one
    // recipient key (REQ: ML-KEM payload encryption).
    if opts.encrypt_to.is_some() && opts.to == BROADCAST {
        return Err(RejectReason::EncBroadcastUnsupported);
    }

    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("OS RNG");
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());

    let mut inner = Inner {
        id: Ulid::new().to_string(),
        v: PROTOCOL_VERSION,
        from: id.name.clone(),
        to: opts.to.to_string(),
        ts,
        nonce: b64(&nonce),
        ctype: opts.ctype.to_string(),
        in_reply_to: opts.in_reply_to.clone(),
        body: opts.body.to_string(),
        kind: opts.kind,
        correlation_id: opts.correlation_id.clone(),
        supersedes: opts.supersedes.clone(),
        enc: None,
        grant: opts.grant.clone(),
        receipt: opts.receipt.clone(),
    };

    // Optional payload encryption (REQ: ML-KEM payload encryption).
    if let Some(ek) = opts.encrypt_to.as_deref() {
        // Encapsulate a fresh shared secret to the recipient KEM key.
        let (kem_ct, ss) = kem::encapsulate(ek).ok_or(RejectReason::UnknownRecipientKey)?;
        let mut aead_nonce = [0u8; 12];
        getrandom::getrandom(&mut aead_nonce).expect("OS RNG");
        // AAD binds the ciphertext to this exact envelope's routing fields.
        let aad = aad(&inner);
        let ct = kem::seal(&ss, &aead_nonce, aad.as_bytes(), opts.body.as_bytes());
        inner.enc = Some(EncInfo {
            alg: ALG_KEM_AEAD.to_string(),
            kem_ct: b64(&kem_ct),
            recipient_kid: kem::kem_fingerprint(ek),
            nonce: b64(&aead_nonce),
            ptype: opts.ctype.to_string(),
        });
        // On the wire the content type advertises encryption; the real content
        // type is restored from `enc.ptype` after decryption.
        inner.ctype = ALG_KEM_AEAD.to_string();
        inner.body = b64(&ct);
    }

    // Serialize once; THESE exact bytes are what we sign and transmit (REQ-0055).
    let inner_bytes = serde_json::to_vec(&inner).expect("inner serializes");

    let wrapper = if opts.unsigned {
        // Insecure mode: no signature, no key id (REQ: unsigned/insecure mode).
        Wrapper {
            v: PROTOCOL_VERSION,
            alg: ALG_NONE.to_string(),
            kid: None,
            msg: b64(&inner_bytes),
            sig: None,
        }
    } else {
        let sig = id.sign(&inner_bytes);
        Wrapper {
            v: PROTOCOL_VERSION,
            alg: ALG_ML_DSA_65.to_string(),
            kid: Some(make_kid(&id.name, id.public_key())),
            msg: b64(&inner_bytes),
            sig: Some(b64(&sig)),
        }
    };

    Ok((inner, wrapper))
}

/// Canonical AEAD associated-data binding the ciphertext to its envelope
/// (REQ: ML-KEM payload encryption). Must match on build and verify.
fn aad(inner: &Inner) -> String {
    format!("{}|{}|{}|{}", inner.id, inner.from, inner.to, inner.ts)
}

/// Verify a wrapper received on the wire. On success returns the decoded (and,
/// if encrypted, decrypted) inner message; on failure returns the reason it was
/// rejected together with the claimed sender (from the wrapper `kid`) when known
/// (REQ-0046).
///
/// Duplicate detection (REQ-0013 id dedupe) and grant replay (`seen_grant`) are
/// handled by the store/daemon after this returns.
#[allow(clippy::too_many_arguments)]
pub fn verify_incoming(
    raw: &[u8],
    me: &Identity,
    trust: &TrustStore,
    cfg_freshness: i64,
    max_payload: usize,
    allow_unsigned: bool,
    accept_v1: bool,
) -> std::result::Result<Inner, RejectInfo> {
    let wrapper = Wrapper::from_bytes(raw).map_err(RejectInfo::from)?;

    // claimed_sender derives from the wrapper kid (step 1); carried in every
    // RejectInfo where known.
    let claimed_sender = wrapper
        .kid
        .as_deref()
        .and_then(split_kid)
        .map(|(name, _)| name.to_string());
    let ri = |reason: RejectReason| RejectInfo {
        reason,
        claimed_sender: claimed_sender.clone(),
    };

    // Version gate (step 2). v1 takes the legacy signed path (no enc/grant/
    // unsigned); v>2 is unsupported.
    match wrapper.v {
        1 => {
            if !accept_v1 {
                return Err(ri(RejectReason::UnsupportedVersion(1)));
            }
        }
        v if v == PROTOCOL_VERSION => {}
        other => return Err(ri(RejectReason::UnsupportedVersion(other))),
    }

    // Algorithm gate (step 3).
    let inner = if wrapper.alg == ALG_NONE {
        // Unsigned path: only when explicitly allowed (REQ: insecure mode).
        if !allow_unsigned {
            return Err(ri(RejectReason::UnsignedNotAllowed));
        }
        let inner_bytes = wrapper.inner_bytes().map_err(&ri)?;
        let inner = Wrapper::parse_inner(&inner_bytes).map_err(&ri)?;
        // Downgrade protection: refuse an unsigned message that claims to be from
        // a known signing agent (REQ: downgrade rejected).
        if trust.public_key(&inner.from).is_ok() {
            return Err(ri(RejectReason::DowngradeRejected));
        }
        inner
    } else if wrapper.alg == ALG_ML_DSA_65 {
        // Signed path (steps 4-5).
        let kid = wrapper
            .kid
            .as_deref()
            .ok_or_else(|| ri(RejectReason::MalformedWrapper))?;
        let (kid_name, kid_fp) =
            split_kid(kid).ok_or_else(|| ri(RejectReason::MalformedWrapper))?;

        // Signer must be in the trust store (REQ-0006).
        let public_key = trust
            .public_key(kid_name)
            .map_err(|_| ri(RejectReason::UnknownSigner))?;
        // kid fingerprint must match the trusted key (REQ-0056).
        if kid_fp != fingerprint(&public_key) {
            return Err(ri(RejectReason::KidMismatch));
        }

        let inner_bytes = wrapper.inner_bytes().map_err(&ri)?;
        let sig_bytes = wrapper.sig_bytes().map_err(&ri)?;
        // Verify the signature over the EXACT transmitted bytes (REQ-0055).
        if !crypto::verify(&public_key, &inner_bytes, &sig_bytes) {
            return Err(ri(RejectReason::InvalidSignature));
        }

        let inner = Wrapper::parse_inner(&inner_bytes).map_err(&ri)?;
        // Sender field must match the signer (no impersonation across the kid).
        if inner.from != kid_name {
            return Err(ri(RejectReason::KidMismatch));
        }
        inner
    } else {
        return Err(ri(RejectReason::UnsupportedAlg(wrapper.alg.clone())));
    };

    finalize(inner, me, trust, cfg_freshness, max_payload, &ri)
}

/// Common post-verification pipeline (steps 5-7): size & freshness, payload
/// decryption, and grant signature/expiry/subject checks.
fn finalize(
    mut inner: Inner,
    me: &Identity,
    trust: &TrustStore,
    freshness_secs: i64,
    max_payload: usize,
    ri: &impl Fn(RejectReason) -> RejectInfo,
) -> std::result::Result<Inner, RejectInfo> {
    // Size & freshness (step 5) over the transmitted body (ciphertext if any).
    if inner.body.len() > max_payload {
        return Err(ri(RejectReason::TooLarge));
    }
    if !fresh_enough(&inner.ts, freshness_secs) {
        return Err(ri(RejectReason::Stale));
    }

    // Payload decryption (step 6). `enc` is retained (now describing a decrypted
    // body) so the daemon can flag the message as having been encrypted.
    if let Some(enc) = inner.enc.clone() {
        if enc.recipient_kid != me.kem_fingerprint() {
            return Err(ri(RejectReason::UnknownRecipientKey));
        }
        let kem_ct = unb64(&enc.kem_ct).map_err(|_| ri(RejectReason::DecryptFailed))?;
        let ss = kem::decapsulate(me.kem_dk(), &kem_ct)
            .ok_or_else(|| ri(RejectReason::DecryptFailed))?;
        let nonce_bytes = unb64(&enc.nonce).map_err(|_| ri(RejectReason::DecryptFailed))?;
        let nonce: [u8; 12] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ri(RejectReason::DecryptFailed))?;
        let ct = unb64(&inner.body).map_err(|_| ri(RejectReason::DecryptFailed))?;
        let aad = aad(&inner);
        let pt = kem::open(&ss, &nonce, aad.as_bytes(), &ct)
            .ok_or_else(|| ri(RejectReason::DecryptFailed))?;
        inner.body = String::from_utf8(pt).map_err(|_| ri(RejectReason::DecryptFailed))?;
        // Restore the original (plaintext) content type.
        inner.ctype = enc.ptype.clone();
    }

    // Grant verification (step 7): signature + expiry in grant::verify; subject
    // must equal the sender. Replay (seen_grant) is the daemon's job.
    if let Some(sg) = inner.grant.clone() {
        let claims = grant::verify(&sg, trust).map_err(ri)?;
        if claims.subject != inner.from {
            return Err(ri(RejectReason::GrantSubjectMismatch));
        }
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
        let bob = Identity::generate("bob");
        let trust = trusted(&alice);
        let (_inner, w) = build(&alice, &BuildOpts::new("bob", CTYPE_TEXT, "hello")).unwrap();
        let raw = w.to_bytes().unwrap();
        let got = verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap();
        assert_eq!(got.from, "alice");
        assert_eq!(got.body, "hello");
    }

    #[test]
    fn unknown_signer_rejected() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let empty = TrustStore::default();
        let (_i, w) = build(&alice, &BuildOpts::new("bob", CTYPE_TEXT, "hi")).unwrap();
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &bob, &empty, 300, 65536, false, true)
                .unwrap_err()
                .reason,
            RejectReason::UnknownSigner
        );
    }

    #[test]
    fn encrypt_roundtrip() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let trust = trusted(&alice);
        let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "secret");
        opts.encrypt_to = Some(bob.kem_ek().to_vec());
        let (_i, w) = build(&alice, &opts).unwrap();
        let raw = w.to_bytes().unwrap();
        let got = verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap();
        assert_eq!(got.body, "secret");
        assert_eq!(got.ctype, CTYPE_TEXT);
    }

    #[test]
    fn encrypt_broadcast_rejected() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let mut opts = BuildOpts::new("*", CTYPE_TEXT, "secret");
        opts.encrypt_to = Some(bob.kem_ek().to_vec());
        assert_eq!(
            build(&alice, &opts).unwrap_err(),
            RejectReason::EncBroadcastUnsupported
        );
    }

    #[test]
    fn unsigned_requires_opt_in() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let empty = TrustStore::default();
        let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "hi");
        opts.unsigned = true;
        let (_i, w) = build(&alice, &opts).unwrap();
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &bob, &empty, 300, 65536, false, true)
                .unwrap_err()
                .reason,
            RejectReason::UnsignedNotAllowed
        );
        // Allowed when configured and the sender is not a known signer.
        let got = verify_incoming(&raw, &bob, &empty, 300, 65536, true, true).unwrap();
        assert_eq!(got.body, "hi");
    }

    #[test]
    fn unsigned_downgrade_rejected() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let trust = trusted(&alice); // alice is a known signing agent
        let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "hi");
        opts.unsigned = true;
        let (_i, w) = build(&alice, &opts).unwrap();
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &bob, &trust, 300, 65536, true, true)
                .unwrap_err()
                .reason,
            RejectReason::DowngradeRejected
        );
    }

    #[test]
    fn tampered_body_rejected() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let trust = trusted(&alice);
        let (_i, mut w) = build(&alice, &BuildOpts::new("bob", CTYPE_TEXT, "hi")).unwrap();
        let mut inner = Wrapper::parse_inner(&w.inner_bytes().unwrap()).unwrap();
        inner.body = "EVIL".into();
        w.msg = b64(&serde_json::to_vec(&inner).unwrap());
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &bob, &trust, 300, 65536, false, true)
                .unwrap_err()
                .reason,
            RejectReason::InvalidSignature
        );
    }

    #[test]
    fn stale_rejected() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let trust = trusted(&alice);
        let (_i, mut w) = build(&alice, &BuildOpts::new("bob", CTYPE_TEXT, "hi")).unwrap();
        let mut inner = Wrapper::parse_inner(&w.inner_bytes().unwrap()).unwrap();
        inner.ts = "2000-01-01T00:00:00Z".into();
        let bytes = serde_json::to_vec(&inner).unwrap();
        w.msg = b64(&bytes);
        w.sig = Some(b64(&alice.sign(&bytes))); // re-sign so only freshness fails
        let raw = w.to_bytes().unwrap();
        assert_eq!(
            verify_incoming(&raw, &bob, &trust, 300, 65536, false, true)
                .unwrap_err()
                .reason,
            RejectReason::Stale
        );
    }
}
