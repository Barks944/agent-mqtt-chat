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
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}
