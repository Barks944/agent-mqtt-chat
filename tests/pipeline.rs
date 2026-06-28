//! End-to-end receive pipeline (REQ-0056): a signed wrapper from a trusted peer
//! is verified, stored (with dedupe), and drained; an untrusted signer is
//! rejected. This composes the real crypto, wire, trust, and store layers.

use agentmsg::identity::Identity;
use agentmsg::message;
use agentmsg::store::Store;
use agentmsg::token::IdentityToken;
use agentmsg::trust::TrustStore;
use agentmsg::wire::CTYPE_TEXT;

#[test]
fn trusted_message_flows_end_to_end() {
    let alice = Identity::generate("alice");
    let (_inner, wrapper) = message::build(&alice, "bob", CTYPE_TEXT, "do the thing", None);
    let raw = wrapper.to_bytes().unwrap();

    // Bob trusts Alice.
    let mut trust = TrustStore::default();
    trust.add_from_token(&IdentityToken::new("alice", alice.public_key().to_vec()));

    // Verify on ingest, store, dedupe, drain.
    let inner = message::verify_incoming(&raw, &trust, 300, 65536).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("m.db")).unwrap();
    assert!(store.insert_inbound(&inner, "agentmsg/chat").unwrap());
    assert!(!store.insert_inbound(&inner, "agentmsg/chat").unwrap()); // REQ-0013 dedupe

    let batch = store.read_after_cursor("bob", 10).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].from, "alice");
    assert_eq!(batch[0].body, "do the thing");

    // Browsing is non-destructive (REQ-0037).
    assert_eq!(store.browse(10, None, None).unwrap().len(), 1);
    assert_eq!(store.read_after_cursor("bob", 10).unwrap().len(), 1);

    // Acknowledge advances the cursor (REQ-0012).
    store.ack("bob", batch[0].seq).unwrap();
    assert!(store.read_after_cursor("bob", 10).unwrap().is_empty());
}

#[test]
fn untrusted_signer_is_rejected() {
    let mallory = Identity::generate("mallory");
    let (_i, wrapper) = message::build(&mallory, "bob", CTYPE_TEXT, "evil instruction", None);
    let raw = wrapper.to_bytes().unwrap();

    // Bob's trust store is empty -> rejected (REQ-0006, authenticity rests on
    // signatures + trust store, not the broker).
    let trust = TrustStore::default();
    assert!(message::verify_incoming(&raw, &trust, 300, 65536).is_err());
}
