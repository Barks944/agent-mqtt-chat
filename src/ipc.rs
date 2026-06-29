//! Local IPC between the short-lived CLI and the resident daemon (REQ-0014).
//!
//! The CLI never holds the signing key or the broker connection; it asks the
//! daemon to act over a length-prefixed JSON protocol on a local socket
//! (abstract namespace on Linux / named pipe on Windows).
//!
//! v0.2 (DESIGN_V2 Layer 5) adds an IPC protocol version + `Hello` handshake,
//! the v2 message attributes on `Send` (topic/kind/correlation/supersedes/
//! encrypt/grant/unsigned), a streaming `Subscribe` channel of [`StreamFrame`]s,
//! and the diagnostic requests (rejections/transcript/consumers/receipts/
//! presence). All new request fields are `#[serde(default)]` so an older CLI
//! still interoperates.

use std::io::{self, BufReader, Read, Write};

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericNamespaced, Name, Stream};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::{ConsumerRow, PresenceRow, RejectionRow, StoredMsg};

/// IPC protocol version exchanged in the [`Request::Hello`] handshake.
pub const IPC_PROTO_VERSION: u32 = 2;

/// Requests the CLI sends to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Daemon + connection status (REQ-0017 part / status command).
    Status,
    /// Protocol handshake: the CLI announces its IPC protocol version and the
    /// daemon replies with [`Response::Hello`] (REQ: protocol v2 + compat).
    Hello { ipc_proto: u32 },
    /// Publish a message (REQ-0011), optionally typed/encrypted/grant-bearing.
    Send {
        to: String,
        ctype: String,
        body: String,
        in_reply_to: Option<String>,
        /// Override the publish topic (must be a configured chat topic).
        #[serde(default)]
        topic: Option<String>,
        /// Typed message kind (snake_case; empty = `message`).
        #[serde(default)]
        kind: String,
        /// Correlation id linking related messages.
        #[serde(default)]
        correlation_id: Option<String>,
        /// Id of a message this one supersedes.
        #[serde(default)]
        supersedes: Option<String>,
        /// Encrypt the payload to the recipient's KEM key.
        #[serde(default)]
        encrypt: bool,
        /// A signed-grant token to attach.
        #[serde(default)]
        grant: Option<String>,
        /// Send unsigned (`alg=none`, insecure).
        #[serde(default)]
        unsigned: bool,
    },
    /// Drain the queue since the consumer cursor (REQ-0012).
    Read { consumer: String, limit: i64 },
    /// Acknowledge up to a seq (REQ-0012).
    Ack { consumer: String, seq: i64 },
    /// Open a streaming subscription that forwards new inbound messages as
    /// length-prefixed [`StreamFrame`]s (REQ: read --follow + IPC stream).
    Subscribe { consumer: String, ack: bool },
    /// Non-destructive browse (REQ-0037/0038).
    Browse {
        limit: i64,
        from: Option<String>,
        to: Option<String>,
    },
    /// Chronological transcript across both directions (REQ-0038).
    Transcript {
        limit: i64,
        from: Option<String>,
        to: Option<String>,
        peer: Option<String>,
    },
    /// Recent rejections diagnostic (REQ-0046).
    Rejections {
        limit: i64,
        reason: Option<String>,
        since: Option<String>,
    },
    /// Per-consumer cursor summaries (REQ: consumers diagnostic).
    Consumers,
    /// Outbound delivery/read receipt state (REQ: delivery/read receipts).
    Receipts {
        id: Option<String>,
        limit: i64,
        state: Option<String>,
    },
    /// Reply to a stored message by id (REQ: reply diagnostic).
    Reply {
        msg_id: String,
        ctype: String,
        body: String,
    },
    /// Emit an application presence beacon (REQ: application presence).
    Presence {
        state: String,
        ttl_secs: Option<i64>,
        detail: Option<String>,
    },
    /// List known presence records (REQ: application presence).
    PresenceList,
    /// Connect the broker session (REQ-0018).
    Connect,
    /// Disconnect the broker session (REQ-0018).
    Disconnect,
    /// Stop the daemon (REQ-0017).
    Shutdown,
}

/// Daemon status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub identity: Option<String>,
    pub fingerprint: Option<String>,
    pub broker: String,
    pub connected: bool,
    pub topics: Vec<String>,
    pub stored: i64,
    pub rejected: i64,
    pub pending_out: i64,
    pub known_agents: usize,
    /// IPC protocol version this daemon speaks (REQ: protocol v2 + compat).
    #[serde(default)]
    pub ipc_proto: u32,
    /// Known application presence records (REQ: application presence).
    #[serde(default)]
    pub presence: Vec<PresenceRow>,
    /// Accept unsigned inbound messages (REQ: unsigned/insecure mode).
    #[serde(default)]
    pub allow_unsigned: bool,
    /// Accept v1 protocol messages (REQ: protocol v2 + compat).
    #[serde(default)]
    pub accept_v1: bool,
    /// Require payload encryption (REQ: ML-KEM payload encryption).
    #[serde(default)]
    pub require_encryption: bool,
    /// Emit automatic delivery/read receipts (REQ: delivery/read receipts).
    #[serde(default)]
    pub auto_receipts: bool,
}

/// Responses the daemon returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Ok,
    Status(StatusInfo),
    /// Handshake reply: daemon IPC protocol version, build version, capabilities.
    Hello {
        ipc_proto: u32,
        version: String,
        caps: Vec<String>,
    },
    Sent {
        id: String,
        /// Delivery lifecycle state at send time (pending|sent).
        delivery_state: String,
    },
    /// A batch of messages with an optional advisory about the consumer cursor.
    Messages {
        msgs: Vec<StoredMsg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consumer_warning: Option<String>,
    },
    Rejections(Vec<RejectionRow>),
    Consumers(Vec<ConsumerRow>),
    Presence(Vec<PresenceRow>),
    Error {
        message: String,
    },
}

/// A frame written on a [`Request::Subscribe`] connection (REQ: IPC stream).
///
/// The `Message` variant intentionally carries a full [`StoredMsg`] inline
/// (rather than boxed): a stream of messages is exactly the hot path, so the
/// allocation per frame would be pure overhead.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamFrame {
    /// A newly stored inbound message.
    Message(StoredMsg),
    /// The subscriber fell behind and `dropped` frames were skipped.
    Lagged { dropped: u64 },
}

/// Cross-platform IPC endpoint name, scoped to one agent identity so multiple
/// daemons can coexist on a host (REQ-0014, REQ-0049 "per host for a given
/// agent identity").
pub fn endpoint_name(agent: &str) -> io::Result<Name<'static>> {
    let s: &'static str = Box::leak(format!("agentmsg-{agent}.sock").into_boxed_str());
    s.to_ns_name::<GenericNamespaced>()
}

/// Write a length-prefixed frame.
pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// Read a length-prefixed frame.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Send a single request to the named agent's daemon and read its response.
///
/// Returns [`Error::DaemonNotRunning`] when nothing is listening (REQ-0048).
pub fn call(agent: &str, req: &Request) -> Result<Response> {
    let name = endpoint_name(agent).map_err(|e| Error::Ipc(e.to_string()))?;
    let stream = Stream::connect(name)
        .map_err(|e| Error::DaemonNotRunning(format!("agentmsg-{agent}.sock ({e})")))?;
    let mut conn = BufReader::new(stream);

    let bytes = serde_json::to_vec(req)?;
    write_frame(conn.get_mut(), &bytes).map_err(|e| Error::Ipc(e.to_string()))?;

    let resp_bytes = read_frame(&mut conn).map_err(|e| Error::Ipc(e.to_string()))?;
    let resp: Response = serde_json::from_slice(&resp_bytes)?;
    Ok(resp)
}

/// Connect a streaming subscription and return the open reader so the caller can
/// pull [`StreamFrame`]s with [`read_frame`] until the daemon closes the socket
/// (REQ: read --follow + IPC stream).
pub fn subscribe(agent: &str, consumer: &str, ack: bool) -> Result<BufReader<Stream>> {
    let name = endpoint_name(agent).map_err(|e| Error::Ipc(e.to_string()))?;
    let stream = Stream::connect(name)
        .map_err(|e| Error::DaemonNotRunning(format!("agentmsg-{agent}.sock ({e})")))?;
    let mut conn = BufReader::new(stream);
    let req = Request::Subscribe {
        consumer: consumer.to_string(),
        ack,
    };
    let bytes = serde_json::to_vec(&req)?;
    write_frame(conn.get_mut(), &bytes).map_err(|e| Error::Ipc(e.to_string()))?;
    Ok(conn)
}

/// Is the named agent's daemon currently listening?
pub fn daemon_running(agent: &str) -> bool {
    matches!(call(agent, &Request::Ping), Ok(Response::Pong))
}
