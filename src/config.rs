//! Persistent configuration: broker endpoint, shared credentials, chat topic(s).
//!
//! REQ-0020/0021: set broker endpoint + auth credentials.
//! REQ: configurable shared chat topic(s).
//! REQ: single shared broker credential.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths;

fn default_port() -> u16 {
    8883
}
fn default_tls() -> bool {
    true
}
fn default_freshness_secs() -> i64 {
    300
}
fn default_max_messages() -> u64 {
    50_000
}
fn default_max_bytes() -> u64 {
    500 * 1024 * 1024
}
fn default_max_payload() -> usize {
    256 * 1024
}

/// On-disk configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Broker hostname.
    #[serde(default)]
    pub broker_host: String,
    /// Broker port (default 8883, MQTT-over-TLS).
    #[serde(default = "default_port")]
    pub broker_port: u16,
    /// Require TLS to the broker (REQ-0015: TLS-only).
    #[serde(default = "default_tls")]
    pub tls: bool,
    /// Shared broker username.
    #[serde(default)]
    pub username: String,
    /// Shared broker password.
    #[serde(default)]
    pub password: String,
    /// Chat topic(s) the daemon publishes/subscribes on. First is the default
    /// publish topic; all are subscribed (REQ: multiple chat topics).
    #[serde(default)]
    pub topics: Vec<String>,
    /// Reject inbound messages with a timestamp older than this (seconds).
    #[serde(default = "default_freshness_secs")]
    pub freshness_secs: i64,
    /// Store cap: maximum retained messages (REQ-0050).
    #[serde(default = "default_max_messages")]
    pub max_messages: u64,
    /// Store cap: maximum retained bytes (REQ-0050).
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Maximum accepted payload size in bytes (REQ: message size limit).
    #[serde(default = "default_max_payload")]
    pub max_payload: usize,
    /// Optional periodic presence heartbeat interval in seconds (REQ: optional
    /// signed presence heartbeat). 0 disables.
    #[serde(default)]
    pub heartbeat_secs: u64,
    /// Accept unsigned (alg=none) inbound messages (REQ: unsigned/insecure mode).
    #[serde(default)]
    pub allow_unsigned: bool,
    /// Accept v1 protocol messages for backward compatibility (REQ: protocol
    /// v2 + compat).
    #[serde(default = "default_accept_v1")]
    pub accept_v1: bool,
    /// Require payload encryption on inbound/outbound messages (REQ: ML-KEM
    /// payload encryption).
    #[serde(default)]
    pub require_encryption: bool,
    /// Emit automatic delivery/read receipts (REQ: delivery/read receipts).
    #[serde(default = "default_auto_receipts")]
    pub auto_receipts: bool,
}

fn default_accept_v1() -> bool {
    true
}
fn default_auto_receipts() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            broker_host: String::new(),
            broker_port: default_port(),
            tls: default_tls(),
            username: String::new(),
            password: String::new(),
            topics: Vec::new(),
            freshness_secs: default_freshness_secs(),
            max_messages: default_max_messages(),
            max_bytes: default_max_bytes(),
            max_payload: default_max_payload(),
            heartbeat_secs: 0,
            allow_unsigned: false,
            accept_v1: default_accept_v1(),
            require_encryption: false,
            auto_receipts: default_auto_receipts(),
        }
    }
}

impl Config {
    /// Load config, returning defaults if none exists yet.
    pub fn load() -> Result<Config> {
        let path = paths::config_path()?;
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))
    }

    /// Persist config to disk.
    pub fn save(&self) -> Result<()> {
        paths::ensure_data_dir()?;
        let path = paths::config_path()?;
        let text = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Primary topic used for publishing.
    pub fn primary_topic(&self) -> Option<&str> {
        self.topics.first().map(|s| s.as_str())
    }

    /// Validate that an MQTT chat topic contains no wildcards (REQ: valid topic).
    pub fn validate_topic(topic: &str) -> Result<()> {
        if topic.is_empty() {
            return Err(Error::Config("topic must not be empty".into()));
        }
        if topic.contains('+') || topic.contains('#') {
            return Err(Error::Config(
                "chat topic must not contain MQTT wildcards (+ or #)".into(),
            ));
        }
        Ok(())
    }

    /// True if enough config is present for the daemon to connect.
    pub fn is_connectable(&self) -> bool {
        !self.broker_host.is_empty() && !self.username.is_empty() && !self.topics.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_validation() {
        assert!(Config::validate_topic("agentmsg/chat").is_ok());
        assert!(Config::validate_topic("a/+/b").is_err());
        assert!(Config::validate_topic("a/#").is_err());
        assert!(Config::validate_topic("").is_err());
    }

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.broker_port, 8883);
        assert!(c.tls);
        assert_eq!(c.max_messages, 50_000);
        assert!(!c.is_connectable());
    }
}
