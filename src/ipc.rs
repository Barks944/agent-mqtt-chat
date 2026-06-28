//! Local IPC between the short-lived CLI and the resident daemon (REQ-0014).
//!
//! The CLI never holds the signing key or the broker connection; it asks the
//! daemon to act over a length-prefixed JSON protocol on a local socket
//! (abstract namespace on Linux / named pipe on Windows).

use std::io::{self, BufReader, Read, Write};

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericNamespaced, Name, Stream};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::StoredMsg;

/// Requests the CLI sends to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Daemon + connection status (REQ-0017 part / status command).
    Status,
    /// Publish a signed message (REQ-0011).
    Send {
        to: String,
        ctype: String,
        body: String,
        in_reply_to: Option<String>,
    },
    /// Drain the queue since the consumer cursor (REQ-0012).
    Read { consumer: String, limit: i64 },
    /// Acknowledge up to a seq (REQ-0012).
    Ack { consumer: String, seq: i64 },
    /// Non-destructive browse (REQ-0037/0038).
    Browse {
        limit: i64,
        from: Option<String>,
        to: Option<String>,
    },
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
}

/// Responses the daemon returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Ok,
    Status(StatusInfo),
    Sent { id: String },
    Messages(Vec<StoredMsg>),
    Error { message: String },
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

/// Is the named agent's daemon currently listening?
pub fn daemon_running(agent: &str) -> bool {
    matches!(call(agent, &Request::Ping), Ok(Response::Pong))
}
