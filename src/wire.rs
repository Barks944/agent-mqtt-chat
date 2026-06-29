//! Self-contained JSON wire format.
//!
//! REQ-0023: each message is a single self-contained JSON document.
//! REQ-0053: wrapper carries version, algorithm, signer key id, base64 inner
//!           bytes, and base64 signature.
//! REQ-0054: inner message field set (id, v, from, to, ts, nonce, ctype, body,
//!           optional in_reply_to).
//! REQ-0055: the signature is computed/verified over the EXACT transmitted
//!           inner bytes (the base64-decoded `msg`), never a re-serialized form.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, RejectReason, Result};

/// Wire protocol version (REQ-0025).
pub const PROTOCOL_VERSION: u8 = 2;
/// Signature algorithm identifier (REQ-0026).
pub const ALG_ML_DSA_65: &str = "ML-DSA-65";
/// Algorithm identifier for an unsigned (insecure) message.
pub const ALG_NONE: &str = "none";
/// Algorithm identifier for ML-KEM-768 + AES-256-GCM payload encryption.
pub const ALG_KEM_AEAD: &str = "ML-KEM-768.AES-256-GCM";
/// Recipient marker for broadcast messages (REQ-0031).
pub const BROADCAST: &str = "*";
/// Baseline recognised content types (REQ + recognised content types).
pub const CTYPE_TEXT: &str = "text/plain";
pub const CTYPE_JSON: &str = "application/json";
/// Content type for application presence beacons.
pub const CTYPE_PRESENCE: &str = "application/agentmsg-presence";
/// Content type for delivery/read receipts.
pub const CTYPE_RECEIPT: &str = "application/agentmsg-receipt";
/// Content type for a TOFU/SAS pairing "hello" (REQ: bootstrap/pairing mode).
pub const CTYPE_PAIR: &str = "application/agentmsg-pair";

/// Typed message kind (REQ: typed schema). Defaults to `Message`.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum MsgKind {
    #[default]
    Message,
    Command,
    Query,
    Result,
    Ack,
    Error,
    Grant,
    Receipt,
}

/// The signed wrapper — this is exactly what is published on the MQTT topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wrapper {
    /// Protocol version.
    pub v: u8,
    /// Signature algorithm.
    pub alg: String,
    /// Signer key id: "<sender-name>#<public-key-fingerprint>". Absent for
    /// unsigned (alg=none) messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// base64url(no-pad) of the exact inner-message bytes that were signed.
    pub msg: String,
    /// base64url(no-pad) of the signature over the decoded `msg` bytes. Absent
    /// for unsigned (alg=none) messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// The inner message (decoded from `Wrapper::msg`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inner {
    /// Unique message id (ULID); also the replay-dedupe key.
    pub id: String,
    /// Protocol version (mirrors the wrapper).
    pub v: u8,
    /// Sender agent name.
    pub from: String,
    /// Recipient agent name, or [`BROADCAST`].
    pub to: String,
    /// RFC3339 UTC timestamp.
    pub ts: String,
    /// Random nonce (base64url) for replay resistance.
    pub nonce: String,
    /// Content type of `body`.
    pub ctype: String,
    /// Optional correlation id referencing a prior message id (REQ: reply id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Opaque payload (REQ: body is opaque, identified by ctype). Binary
    /// payloads are carried base64-encoded under an octet-stream ctype.
    pub body: String,
    /// Typed message kind (REQ: typed schema).
    #[serde(default)]
    pub kind: MsgKind,
    /// Correlation id linking related messages (REQ: typed schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Id of a message this one supersedes (REQ: typed schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Payload encryption metadata; present when `body` is ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<EncInfo>,
    /// A signed human-authorization grant carried with the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SignedGrant>,
    /// A delivery/read receipt referencing a prior message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
}

/// Payload encryption metadata (REQ: ML-KEM payload encryption). When present,
/// `Inner::body` holds the base64url AES-256-GCM ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncInfo {
    /// AEAD/KEM algorithm identifier ([`ALG_KEM_AEAD`]).
    pub alg: String,
    /// base64url ML-KEM-768 ciphertext (encapsulated shared secret).
    pub kem_ct: String,
    /// Recipient KEM key fingerprint the ciphertext is bound to.
    pub recipient_kid: String,
    /// base64url AES-256-GCM nonce (12 bytes).
    pub nonce: String,
    /// Original (plaintext) content type, restored after decryption.
    pub ptype: String,
}

/// A human-authorization grant signed by an authority key (REQ: grants).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    /// Signature algorithm ([`ALG_ML_DSA_65`]).
    pub alg: String,
    /// Authority key id: "<authority-name>#<fingerprint>".
    pub authority_kid: String,
    /// base64url of the canonical [`crate::grant::GrantClaims`] JSON bytes.
    pub grant: String,
    /// base64url signature over the decoded grant bytes.
    pub sig: String,
}

/// A delivery/read receipt (REQ: delivery/read receipts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Id of the message this receipt refers to.
    pub ref_id: String,
    /// Receipt status.
    pub status: ReceiptStatus,
}

/// Delivery state advertised by a [`Receipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

impl Inner {
    /// True if this message targets everyone.
    pub fn is_broadcast(&self) -> bool {
        self.to == BROADCAST
    }

    /// True if this message is addressed to `me` or is a broadcast.
    pub fn addressed_to(&self, me: &str) -> bool {
        self.is_broadcast() || self.to == me
    }
}

/// Compute a short, stable fingerprint of a public key for use in `kid`.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..8])
}

/// Build the `kid` field from a sender name and public key.
pub fn make_kid(sender: &str, public_key: &[u8]) -> String {
    format!("{sender}#{}", fingerprint(public_key))
}

/// Parse a `kid` into (sender, fingerprint).
pub fn split_kid(kid: &str) -> Option<(&str, &str)> {
    kid.split_once('#')
}

/// Encode bytes as base64url without padding.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url-without-padding bytes.
pub fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| Error::Serde(format!("base64: {e}")))
}

impl Wrapper {
    /// Serialize the wrapper to the bytes published on the topic.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse a wrapper received from the stream.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Wrapper, RejectReason> {
        serde_json::from_slice(bytes).map_err(|_| RejectReason::MalformedWrapper)
    }

    /// Decode and return the exact inner-message bytes that were signed
    /// (REQ-0055: verification operates on these bytes verbatim).
    pub fn inner_bytes(&self) -> std::result::Result<Vec<u8>, RejectReason> {
        URL_SAFE_NO_PAD
            .decode(self.msg.as_bytes())
            .map_err(|_| RejectReason::MalformedWrapper)
    }

    /// Decode the signature bytes. Errors if the wrapper carries no signature
    /// (an unsigned `alg=none` message).
    pub fn sig_bytes(&self) -> std::result::Result<Vec<u8>, RejectReason> {
        let sig = self.sig.as_deref().ok_or(RejectReason::MalformedWrapper)?;
        URL_SAFE_NO_PAD
            .decode(sig.as_bytes())
            .map_err(|_| RejectReason::MalformedWrapper)
    }

    /// Parse the inner message from already-decoded inner bytes.
    pub fn parse_inner(inner_bytes: &[u8]) -> std::result::Result<Inner, RejectReason> {
        serde_json::from_slice(inner_bytes).map_err(|_| RejectReason::MalformedWrapper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal cleartext, signed `Inner` for wire tests (v2 field set).
    fn test_inner(id: &str, from: &str, to: &str, body: &str) -> Inner {
        Inner {
            id: id.into(),
            v: PROTOCOL_VERSION,
            from: from.into(),
            to: to.into(),
            ts: "2026-06-28T00:00:00Z".into(),
            nonce: "abc".into(),
            ctype: CTYPE_TEXT.into(),
            in_reply_to: None,
            body: body.into(),
            kind: MsgKind::default(),
            correlation_id: None,
            supersedes: None,
            enc: None,
            grant: None,
            receipt: None,
        }
    }

    #[test]
    fn roundtrip_inner_bytes_are_stable() {
        // REQ-0055: signing over transmitted bytes — re-decoding `msg` yields
        // the identical bytes that were base64-encoded.
        let inner = test_inner("01J0", "alice", "bob", "hello");
        let bytes = serde_json::to_vec(&inner).unwrap();
        let w = Wrapper {
            v: PROTOCOL_VERSION,
            alg: ALG_ML_DSA_65.into(),
            kid: Some("alice#deadbeef".into()),
            msg: b64(&bytes),
            sig: Some(b64(b"sig")),
        };
        let wire = w.to_bytes().unwrap();
        let parsed = Wrapper::from_bytes(&wire).unwrap();
        assert_eq!(parsed.inner_bytes().unwrap(), bytes);
        let inner2 = Wrapper::parse_inner(&parsed.inner_bytes().unwrap()).unwrap();
        assert_eq!(inner2.from, "alice");
        assert!(inner2.addressed_to("bob"));
        assert!(!inner2.addressed_to("carol"));
    }

    #[test]
    fn unsigned_wrapper_omits_kid_and_sig() {
        // alg=none messages carry neither a key id nor a signature.
        let inner = test_inner("1", "alice", "bob", "hi");
        let w = Wrapper {
            v: PROTOCOL_VERSION,
            alg: ALG_NONE.into(),
            kid: None,
            msg: b64(&serde_json::to_vec(&inner).unwrap()),
            sig: None,
        };
        let wire = w.to_bytes().unwrap();
        // Optional fields are skipped when serializing.
        let text = String::from_utf8(wire.clone()).unwrap();
        assert!(!text.contains("\"kid\""));
        assert!(!text.contains("\"sig\""));
        let parsed = Wrapper::from_bytes(&wire).unwrap();
        assert!(parsed.kid.is_none());
        assert!(parsed.sig_bytes().is_err());
    }

    #[test]
    fn broadcast_addressing() {
        let inner = test_inner("1", "a", BROADCAST, "hi");
        assert!(inner.is_broadcast());
        assert!(inner.addressed_to("anyone"));
    }

    #[test]
    fn kid_roundtrip() {
        let pk = b"some-public-key-bytes";
        let kid = make_kid("alice", pk);
        let (name, fp) = split_kid(&kid).unwrap();
        assert_eq!(name, "alice");
        assert_eq!(fp, fingerprint(pk));
    }
}
