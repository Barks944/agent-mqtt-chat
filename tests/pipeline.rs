//! End-to-end receive pipeline (REQ-0056): a signed wrapper from a trusted peer
//! is verified, stored (with dedupe), and drained; an untrusted signer is
//! rejected. This composes the real crypto, wire, trust, and store layers.
//!
//! v0.2 (DESIGN_V2 Layer 7) extends the integration coverage to the typed
//! [`message::BuildOpts`] builder, ML-KEM payload encryption, and the
//! human-authorization grant path (verify + subject + store-backed replay).

use agentmsg::authority::Authority;
use agentmsg::grant::{self, GrantClaims};
use agentmsg::identity::Identity;
use agentmsg::message::{self, BuildOpts};
use agentmsg::store::Store;
use agentmsg::token::IdentityToken;
use agentmsg::trust::TrustStore;
use agentmsg::wire::CTYPE_TEXT;

/// Bob's view of the world: he trusts Alice's signing key.
fn bob_trusts(alice: &Identity) -> TrustStore {
    let mut trust = TrustStore::default();
    trust.add_from_token(&IdentityToken::with_kem(
        "alice",
        alice.public_key().to_vec(),
        Some(alice.kem_ek().to_vec()),
    ));
    trust
}

#[test]
fn trusted_message_flows_end_to_end() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let (_inner, wrapper) =
        message::build(&alice, &BuildOpts::new("bob", CTYPE_TEXT, "do the thing")).unwrap();
    let raw = wrapper.to_bytes().unwrap();

    let trust = bob_trusts(&alice);

    // Verify on ingest, store, dedupe, drain.
    let inner = message::verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("m.db")).unwrap();
    assert!(store
        .insert_inbound(&inner, "agentmsg/chat")
        .unwrap()
        .is_some());
    // REQ-0013 dedupe: a second insert of the same id is ignored.
    assert!(store
        .insert_inbound(&inner, "agentmsg/chat")
        .unwrap()
        .is_none());

    let batch = store.read_after_cursor("bob", 10).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].from, "alice");
    assert_eq!(batch[0].body, "do the thing");

    // Browsing is non-destructive (REQ-0037).
    assert_eq!(store.browse(10, None, None, "in").unwrap().len(), 1);
    assert_eq!(store.read_after_cursor("bob", 10).unwrap().len(), 1);

    // Acknowledge advances the cursor (REQ-0012).
    store.ack("bob", batch[0].seq).unwrap();
    assert!(store.read_after_cursor("bob", 10).unwrap().is_empty());
}

#[test]
fn untrusted_signer_is_rejected() {
    let mallory = Identity::generate("mallory");
    let bob = Identity::generate("bob");
    let (_i, wrapper) = message::build(
        &mallory,
        &BuildOpts::new("bob", CTYPE_TEXT, "evil instruction"),
    )
    .unwrap();
    let raw = wrapper.to_bytes().unwrap();

    // Bob's trust store is empty -> rejected (REQ-0006, authenticity rests on
    // signatures + trust store, not the broker).
    let trust = TrustStore::default();
    assert!(message::verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).is_err());
}

#[test]
fn encrypted_payload_round_trips_end_to_end() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let trust = bob_trusts(&alice);

    // Alice encrypts to Bob's KEM key; only Bob can recover the plaintext.
    let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "top secret");
    opts.encrypt_to = Some(bob.kem_ek().to_vec());
    let (inner_built, wrapper) = message::build(&alice, &opts).unwrap();
    // On the wire the body is ciphertext, not the plaintext.
    assert!(inner_built.enc.is_some());
    assert_ne!(inner_built.body, "top secret");

    let raw = wrapper.to_bytes().unwrap();
    let inner = message::verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap();
    assert_eq!(inner.body, "top secret");
    assert_eq!(inner.ctype, CTYPE_TEXT);

    // A third party with the wrong KEM key cannot decrypt.
    let carol = Identity::generate("carol");
    assert!(message::verify_incoming(&raw, &carol, &trust, 300, 65536, false, true).is_err());
}

#[test]
fn authorized_grant_verifies_and_replay_is_caught() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let ops = Authority::generate("ops");

    // Bob trusts Alice as a signer and ops as an authority.
    let mut trust = bob_trusts(&alice);
    trust.add_authority_from_token(&ops.token());

    let claims = GrantClaims {
        id: ulid_like(),
        action: "deploy".into(),
        scope: "prod".into(),
        subject: "alice".into(),
        expiry: "2999-01-01T00:00:00Z".into(),
        nonce: "n".into(),
    };
    let sg = grant::mint(&ops, &claims);

    let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "deploying now");
    opts.grant = Some(sg);
    let (inner, wrapper) = message::build(&alice, &opts).unwrap();
    let raw = wrapper.to_bytes().unwrap();

    // verify_incoming checks the grant signature, expiry, and subject==sender.
    let got = message::verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap();
    let attached = got.grant.as_ref().unwrap();
    let verified = grant::verify(attached, &trust).unwrap();
    assert_eq!(verified.subject, "alice");

    // Store-backed replay guard: first use is fresh, the second is a replay.
    let _ = inner; // built inner carries the same grant; id checked via claims
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("g.db")).unwrap();
    let gid = &verified.id;
    assert!(!store.seen_grant(gid).unwrap()); // first time: not seen
    assert!(store.seen_grant(gid).unwrap()); // replay: already seen
}

#[test]
fn grant_subject_mismatch_is_rejected() {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let ops = Authority::generate("ops");
    let mut trust = bob_trusts(&alice);
    trust.add_authority_from_token(&ops.token());

    // Grant is for "carol" but the message is signed/sent by "alice".
    let claims = GrantClaims {
        id: ulid_like(),
        action: "deploy".into(),
        scope: "prod".into(),
        subject: "carol".into(),
        expiry: "2999-01-01T00:00:00Z".into(),
        nonce: "n".into(),
    };
    let mut opts = BuildOpts::new("bob", CTYPE_TEXT, "deploying now");
    opts.grant = Some(grant::mint(&ops, &claims));
    let (_i, wrapper) = message::build(&alice, &opts).unwrap();
    let raw = wrapper.to_bytes().unwrap();

    let err = message::verify_incoming(&raw, &bob, &trust, 300, 65536, false, true).unwrap_err();
    assert_eq!(err.reason.code(), "grant_subject_mismatch");
}

/// A unique-ish grant id (integration tests only see `agentmsg` + dev-deps, so
/// no `ulid`/`getrandom` here — a monotonic counter plus the clock suffices).
fn ulid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("grant-{nanos}-{n}")
}
