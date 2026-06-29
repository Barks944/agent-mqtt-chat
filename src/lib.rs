//! agentmsg — cross-host agent-to-agent messaging over MQTT with post-quantum
//! signatures and a local trust store.
//!
//! REQ-0001: single cross-platform Rust binary/library.

pub mod authority;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod daemon;
pub mod error;
pub mod grant;
pub mod identity;
pub mod ipc;
pub mod kem;
pub mod message;
pub mod mqtt;
pub mod paths;
pub mod store;
pub mod token;
pub mod trust;
pub mod wire;

pub use error::{Error, RejectReason, Result};
