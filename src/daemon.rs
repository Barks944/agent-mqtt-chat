//! Resident daemon (REQ-0002): owns the MQTT connection and the local store,
//! verifies inbound messages on ingest, and serves the CLI over local IPC.

use std::io::{BufReader, ErrorKind};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, Stream};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::ipc::{self, Request, Response, StatusInfo};
use crate::message;
use crate::mqtt::{Mqtt, OnMessage};
use crate::store::{Outbound, Store};
use crate::trust::TrustStore;
use crate::wire::{fingerprint, split_kid, Wrapper};

/// Shared daemon state.
pub struct Daemon {
    identity: Arc<Identity>,
    store: Arc<Store>,
    mqtt: Arc<Mutex<Option<Mqtt>>>,
}

impl Daemon {
    /// Start the daemon: bind the IPC endpoint (single instance, REQ-0049),
    /// connect the broker if configured, and serve requests until shutdown.
    pub fn run() -> Result<()> {
        let identity = Arc::new(Identity::load()?);
        let store = Arc::new(Store::open_default()?);
        let daemon = Arc::new(Daemon {
            identity,
            store,
            mqtt: Arc::new(Mutex::new(None)),
        });

        // Single-instance guard: binding the endpoint fails if one is running.
        let name =
            ipc::endpoint_name(&daemon.identity.name).map_err(|e| Error::Ipc(e.to_string()))?;
        let listener = ListenerOptions::new()
            .name(name)
            .create_sync()
            .map_err(|e| {
                if e.kind() == ErrorKind::AddrInUse {
                    Error::DaemonAlreadyRunning
                } else {
                    Error::Ipc(e.to_string())
                }
            })?;

        // Connect now if the config is complete.
        if Config::load().map(|c| c.is_connectable()).unwrap_or(false) {
            if let Err(e) = daemon.connect() {
                tracing::warn!("initial connect failed: {e}");
            }
        }

        daemon.spawn_outbox_pump();
        daemon.spawn_heartbeat();

        tracing::info!("agentmsg daemon listening as '{}'", daemon.identity.name);
        for conn in listener.incoming().filter_map(std::result::Result::ok) {
            let d = daemon.clone();
            thread::spawn(move || d.handle_conn(conn));
        }
        Ok(())
    }

    /// (Re)connect the broker session (REQ-0018).
    fn connect(&self) -> Result<()> {
        let mut guard = self.mqtt.lock().unwrap();
        if guard.is_some() {
            return Ok(());
        }
        let cfg = Config::load()?;
        if !cfg.is_connectable() {
            return Err(Error::Config(
                "broker host, credentials and at least one topic must be set".into(),
            ));
        }

        let store = self.store.clone();
        let me = self.identity.name.clone();
        let client_id = format!("{}-{}", me, std::process::id());
        let on_msg: OnMessage = Arc::new(move |topic: String, payload: Vec<u8>| {
            // Ignore our own echoes from the shared topic before any work.
            if let Ok(w) = Wrapper::from_bytes(&payload) {
                if let Some((name, _)) = split_kid(&w.kid) {
                    if name == me {
                        return;
                    }
                }
            }
            // Reload config + trust each message so CLI edits take effect live.
            let cfg = Config::load().unwrap_or_default();
            let trust = TrustStore::load().unwrap_or_default();
            match message::verify_incoming(&payload, &trust, cfg.freshness_secs, cfg.max_payload) {
                Ok(inner) => {
                    if let Ok(true) = store.insert_inbound(&inner, &topic) {
                        let _ = store.enforce_bounds(cfg.max_messages, cfg.max_bytes);
                    }
                }
                Err(reason) => {
                    let _ = store.record_rejection(&reason, &topic);
                }
            }
        });

        let mqtt = Mqtt::start(&cfg, &client_id, on_msg)?;
        *guard = Some(mqtt);
        Ok(())
    }

    /// Disconnect the broker session (REQ-0018).
    fn disconnect(&self) {
        let mut guard = self.mqtt.lock().unwrap();
        if let Some(mut m) = guard.take() {
            m.stop();
        }
    }

    fn is_connected(&self) -> bool {
        self.mqtt
            .lock()
            .unwrap()
            .as_ref()
            .map(|m| m.is_connected())
            .unwrap_or(false)
    }

    /// Periodically flush the durable outbox while connected (REQ-0016).
    fn spawn_outbox_pump(self: &Arc<Self>) {
        let store = self.store.clone();
        let mqtt = self.mqtt.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            let connected = mqtt
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.is_connected())
                .unwrap_or(false);
            if !connected {
                continue;
            }
            let pending = store.pending_outbound().unwrap_or_default();
            for ob in pending {
                let ok = mqtt
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|m| m.publish(&ob.topic, ob.payload.clone(), ob.retain).is_ok())
                    .unwrap_or(false);
                if ok {
                    let _ = store.mark_delivered(&ob.id);
                }
            }
        });
    }

    /// Optional signed presence heartbeat (REQ: optional presence heartbeat).
    fn spawn_heartbeat(self: &Arc<Self>) {
        let identity = self.identity.clone();
        let store = self.store.clone();
        thread::spawn(move || loop {
            let cfg = Config::load().unwrap_or_default();
            let secs = cfg.heartbeat_secs;
            if secs == 0 {
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            thread::sleep(Duration::from_secs(secs));
            if let Some(topic) = cfg.primary_topic() {
                let (inner, wrapper) = message::build(
                    &identity,
                    "*",
                    "application/agentmsg-presence",
                    "online",
                    None,
                );
                if let Ok(payload) = wrapper.to_bytes() {
                    let _ = store.enqueue_outbound(&Outbound {
                        id: inner.id.clone(),
                        topic: topic.to_string(),
                        payload,
                        qos: 1,
                        retain: false,
                    });
                }
            }
        });
    }

    fn handle_conn(self: Arc<Self>, conn: Stream) {
        let mut br = BufReader::new(conn);
        let bytes = match ipc::read_frame(&mut br) {
            Ok(b) => b,
            Err(_) => return,
        };
        let req: Request = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => return,
        };
        let is_shutdown = matches!(req, Request::Shutdown);
        let resp = self.handle(req);
        let out = serde_json::to_vec(&resp).unwrap_or_default();
        let _ = ipc::write_frame(br.get_mut(), &out);
        if is_shutdown {
            std::process::exit(0);
        }
    }

    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong,
            Request::Status => self.status(),
            Request::Connect => match self.connect() {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            },
            Request::Disconnect => {
                self.disconnect();
                Response::Ok
            }
            Request::Shutdown => Response::Ok,
            Request::Send {
                to,
                ctype,
                body,
                in_reply_to,
            } => self.send(to, ctype, body, in_reply_to),
            Request::Read { consumer, limit } => {
                match self.store.read_after_cursor(&consumer, limit) {
                    Ok(msgs) => Response::Messages(msgs),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::Ack { consumer, seq } => match self.store.ack(&consumer, seq) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            },
            Request::Browse { limit, from, to } => {
                match self.store.browse(limit, from.as_deref(), to.as_deref()) {
                    Ok(msgs) => Response::Messages(msgs),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
        }
    }

    fn status(&self) -> Response {
        let cfg = Config::load().unwrap_or_default();
        let trust = TrustStore::load().unwrap_or_default();
        let info = StatusInfo {
            identity: Some(self.identity.name.clone()),
            fingerprint: Some(fingerprint(self.identity.public_key())),
            broker: if cfg.broker_host.is_empty() {
                String::new()
            } else {
                format!("{}:{}", cfg.broker_host, cfg.broker_port)
            },
            connected: self.is_connected(),
            topics: cfg.topics.clone(),
            stored: self.store.message_count().unwrap_or(0),
            rejected: self.store.rejection_count().unwrap_or(0),
            pending_out: self
                .store
                .pending_outbound()
                .map(|p| p.len() as i64)
                .unwrap_or(0),
            known_agents: trust.list().len(),
        };
        Response::Status(info)
    }

    fn send(
        &self,
        to: String,
        ctype: String,
        body: String,
        in_reply_to: Option<String>,
    ) -> Response {
        let cfg = Config::load().unwrap_or_default();
        let topic = match cfg.primary_topic() {
            Some(t) => t.to_string(),
            None => {
                return Response::Error {
                    message: "no chat topic configured".into(),
                }
            }
        };
        if body.len() > cfg.max_payload {
            return Response::Error {
                message: "payload exceeds configured maximum".into(),
            };
        }

        let (inner, wrapper) = message::build(&self.identity, &to, &ctype, &body, in_reply_to);
        let payload = match wrapper.to_bytes() {
            Ok(p) => p,
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        };

        // Log + enqueue durably (REQ-0016), then publish immediately if up.
        let _ = self.store.insert_outbound_log(&inner, &topic);
        if let Err(e) = self.store.enqueue_outbound(&Outbound {
            id: inner.id.clone(),
            topic: topic.clone(),
            payload: payload.clone(),
            qos: 1,
            retain: false,
        }) {
            return Response::Error {
                message: e.to_string(),
            };
        }

        if self.is_connected() {
            let published = self
                .mqtt
                .lock()
                .unwrap()
                .as_ref()
                .map(|m| m.publish(&topic, payload, false).is_ok())
                .unwrap_or(false);
            if published {
                let _ = self.store.mark_delivered(&inner.id);
            }
        }

        Response::Sent { id: inner.id }
    }
}
