//! REQ-0048: distinct, machine-distinguishable error categories so agents can
//! react (e.g. tell "daemon not running" apart from other failures).

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type for agentmsg.
#[derive(Debug, Error)]
pub enum Error {
    #[error("daemon is not running (no IPC endpoint at {0})")]
    DaemonNotRunning(String),

    #[error("a daemon is already running for this identity")]
    DaemonAlreadyRunning,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("no identity configured; run `agentmsg id generate` first")]
    NoIdentity,

    #[error("identity already exists at {0}")]
    IdentityExists(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("invalid identity token: {0}")]
    InvalidToken(String),

    #[error("unknown agent: {0}")]
    UnknownAgent(String),

    #[error("message rejected: {0}")]
    Rejected(#[from] RejectReason),

    #[error("storage error: {0}")]
    Store(String),

    #[error("mqtt error: {0}")]
    Mqtt(String),

    #[error("ipc error: {0}")]
    Ipc(String),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("identity name mismatch: {0}")]
    // exit 4
    IdentityNameMismatch(String),

    #[error("no authority key configured; run `agentmsg authority generate` first")]
    // exit 4
    NoAuthority,

    #[error("token corrupt: {0}")]
    // exit 5  (checksum/length failure)
    TokenCorrupt(String),

    #[error("key rotation required: {0}")]
    // exit 5
    RotationRequired(String),

    #[error("not an authority token")]
    // exit 5
    NotAnAuthorityToken,

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reasons an inbound message is refused on ingest (REQ-0046: recorded with a
/// reason rather than silently dropped).
#[derive(Debug, Clone, Error, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum RejectReason {
    #[error("malformed wrapper")]
    MalformedWrapper,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported signature algorithm {0}")]
    UnsupportedAlg(String),
    #[error("unknown signer")]
    UnknownSigner,
    #[error("signer key id does not match sender")]
    KidMismatch,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("duplicate message id")]
    Duplicate,
    #[error("timestamp outside freshness window")]
    Stale,
    #[error("payload too large")]
    TooLarge,
    #[error("unsigned messages are not allowed")]
    UnsignedNotAllowed,
    #[error("protocol downgrade rejected for a known signing agent")]
    DowngradeRejected,
    #[error("unknown authority")]
    UnknownAuthority,
    #[error("invalid grant")]
    InvalidGrant,
    #[error("grant expired")]
    GrantExpired,
    #[error("grant subject does not match sender")]
    GrantSubjectMismatch,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("unknown recipient key")]
    UnknownRecipientKey,
    #[error("encrypted broadcast is not supported")]
    EncBroadcastUnsupported,
    #[error("replayed grant")]
    ReplayedGrant,
}

impl RejectReason {
    /// Stable snake_case code for logs and JSON output.
    pub fn code(&self) -> &'static str {
        match self {
            RejectReason::MalformedWrapper => "malformed_wrapper",
            RejectReason::UnsupportedVersion(_) => "unsupported_version",
            RejectReason::UnsupportedAlg(_) => "unsupported_alg",
            RejectReason::UnknownSigner => "unknown_signer",
            RejectReason::KidMismatch => "kid_mismatch",
            RejectReason::InvalidSignature => "invalid_signature",
            RejectReason::Duplicate => "duplicate",
            RejectReason::Stale => "stale",
            RejectReason::TooLarge => "too_large",
            RejectReason::UnsignedNotAllowed => "unsigned_not_allowed",
            RejectReason::DowngradeRejected => "downgrade_rejected",
            RejectReason::UnknownAuthority => "unknown_authority",
            RejectReason::InvalidGrant => "invalid_grant",
            RejectReason::GrantExpired => "grant_expired",
            RejectReason::GrantSubjectMismatch => "grant_subject_mismatch",
            RejectReason::DecryptFailed => "decrypt_failed",
            RejectReason::UnknownRecipientKey => "unknown_recipient_key",
            RejectReason::EncBroadcastUnsupported => "enc_broadcast_unsupported",
            RejectReason::ReplayedGrant => "replayed_grant",
        }
    }
}

/// Rejection metadata recorded alongside the reason (REQ-0046). The claimed
/// sender (from the wrapper `kid`) is captured when known so diagnostics can
/// attribute a rejection even when verification failed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RejectInfo {
    pub reason: RejectReason,
    pub claimed_sender: Option<String>,
}

impl From<RejectReason> for RejectInfo {
    fn from(reason: RejectReason) -> Self {
        RejectInfo {
            reason,
            claimed_sender: None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}
