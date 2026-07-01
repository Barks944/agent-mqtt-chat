//! Resident daemon (REQ-0002): owns the MQTT connection and the local store,
//! verifies inbound messages on ingest, and serves the CLI over local IPC.
//!
//! v0.2 (DESIGN_V2 Layer 5): the ingest path intercepts presence beacons and
//! delivery/read receipts before storing, applies a grant replay guard, emits
//! automatic delivery receipts, and pushes newly stored inbound messages to any
//! streaming [`Request::Subscribe`] consumers. `send` honours the v2 message
//! attributes (topic/kind/correlation/supersedes/encrypt/grant/unsigned).

use std::collections::BTreeMap;
use std::io::{BufReader, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{ListenerOptions, Stream};
use rumqttc::Client;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, RejectReason, Result};
use crate::grant;
use crate::identity::Identity;
use crate::ipc::{
    self, PendingPairView, Request, Response, StatusInfo, StreamFrame, IPC_PROTO_VERSION,
};
use crate::message::{self, BuildOpts};
use crate::mqtt::{self, Mqtt, OnMessage};
use crate::pair::sas;
use crate::store::{Outbound, Store, StoredMsg};
use crate::trust::TrustStore;
use crate::wire::{
    fingerprint, split_kid, MsgKind, Receipt, ReceiptStatus, Wrapper, CTYPE_PAIR, CTYPE_PRESENCE,
    CTYPE_RECEIPT,
};

/// A live streaming subscriber fed by the ingest path (REQ: IPC stream).
struct Subscriber {
    /// Unique registry id (used for deregistration).
    id: u64,
    /// Consumer name this stream serves. Not yet used for routing (all inbound
    /// is fanned out to every subscriber today); reserved for the per-name
    /// mailbox routing the local-hub mode will need.
    #[allow(dead_code)]
    consumer: String,
    /// Channel to the serving thread.
    tx: SyncSender<StreamFrame>,
    /// Messages dropped since the last successfully-delivered lag notice. Kept
    /// per subscriber so the reported count is accurate across a burst and the
    /// `Lagged` signal is never silently lost.
    dropped: u64,
}

/// Registry of live streaming subscribers.
type Subscribers = Arc<Mutex<Vec<Subscriber>>>;

/// A peer seen on the pairing topic, awaiting an out-of-band SAS confirmation
/// before it is added to the trust store (REQ: bootstrap/pairing mode).
#[derive(Debug, Clone)]
struct PendingPair {
    name: String,
    public_key: Vec<u8>,
    kem_public_key: Option<Vec<u8>>,
    sas: String,
    first_seen: String,
}

/// In-memory map of pending pairings keyed by peer name.
type Pending = Arc<Mutex<BTreeMap<String, PendingPair>>>;

/// JSON body of an application presence beacon (REQ: application presence).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresenceBeacon {
    state: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    ttl_secs: i64,
    #[serde(default)]
    seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Shared daemon state.
pub struct Daemon {
    identity: Arc<Identity>,
    store: Arc<Store>,
    mqtt: Arc<Mutex<Option<Mqtt>>>,
    /// Live streaming subscribers fed by the ingest path (REQ: IPC stream).
    subscribers: Subscribers,
    /// Monotonic id source for subscriber registry entries.
    next_sub_id: AtomicU64,
    /// Peers seen on the pairing topic, awaiting SAS confirmation.
    pending: Pending,
}

impl Daemon {
    /// Start the daemon: bind the IPC endpoint (single instance, REQ-0049),
    /// connect the broker if configured, and serve requests until shutdown.
    pub fn run() -> Result<()> {
        // The background daemon has its stdio nulled (see `cli::spawn_detached`),
        // so route tracing output to `daemon.log` where `daemon start --wait` can
        // tail it on a readiness timeout (DESIGN_V2 Layer 7). `try_init` is used
        // so the foreground case (a global stderr subscriber already installed by
        // `main`) does not panic.
        init_file_tracing();

        let identity = Arc::new(Identity::load()?);
        let store = Arc::new(Store::open_default()?);
        let daemon = Arc::new(Daemon {
            identity,
            store,
            mqtt: Arc::new(Mutex::new(None)),
            subscribers: Arc::new(Mutex::new(Vec::new())),
            next_sub_id: AtomicU64::new(1),
            pending: Arc::new(Mutex::new(BTreeMap::new())),
        });

        // Single-instance guard: binding the endpoint fails if one is running.
        let name =
            ipc::endpoint_name(&daemon.identity.name).map_err(|e| Error::Ipc(e.to_string()))?;
        let agent = daemon.identity.name.clone();
        let listener = ListenerOptions::new()
            .name(name)
            .create_sync()
            .map_err(|e| {
                if e.kind() == ErrorKind::AddrInUse {
                    tracing::error!(
                        "another agentmsg daemon is already listening for identity '{agent}' \
                         (endpoint agentmsg-{agent}.sock); stop it with `agentmsg daemon stop` \
                         or use a distinct AGENTMSG_HOME per identity"
                    );
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
        let identity = self.identity.clone();
        let subscribers = self.subscribers.clone();
        let pending = self.pending.clone();
        let me = self.identity.name.clone();
        let client_id = format!("{}-{}", me, std::process::id());
        let on_msg: OnMessage = Arc::new(move |topic: String, payload: Vec<u8>| {
            // Ignore our own echoes from the shared topic before any work.
            if let Ok(w) = Wrapper::from_bytes(&payload) {
                if let Some((name, _)) = w.kid.as_deref().and_then(split_kid) {
                    if name == me {
                        return;
                    }
                }
                // Pairing intercept (REQ: bootstrap/pairing mode): a CTYPE_PAIR
                // hello is self-signed and must NOT go through the trust-store
                // verify path. Peek the inner ctype, then verify_pair separately.
                if let Ok(peek) = w.inner_bytes().and_then(|b| Wrapper::parse_inner(&b)) {
                    if peek.ctype == CTYPE_PAIR {
                        match message::verify_pair(&payload) {
                            Ok(hello) => {
                                let sas_code = sas(identity.public_key(), &hello.public_key);
                                let entry = PendingPair {
                                    name: hello.name.clone(),
                                    public_key: hello.public_key,
                                    kem_public_key: hello.kem_public_key,
                                    sas: sas_code,
                                    first_seen: peek.ts.clone(),
                                };
                                pending.lock().unwrap().entry(hello.name).or_insert(entry);
                            }
                            Err(reason) => {
                                let _ = store.record_rejection(
                                    &reason,
                                    Some(&peek.from),
                                    &topic,
                                    "pairing hello",
                                );
                            }
                        }
                        return;
                    }
                }
            }
            // Reload config + trust each message so CLI edits take effect live.
            let cfg = Config::load().unwrap_or_default();
            let trust = TrustStore::load().unwrap_or_default();
            match message::verify_incoming(
                &payload,
                &identity,
                &trust,
                cfg.freshness_secs,
                cfg.max_payload,
                cfg.allow_unsigned,
                cfg.accept_v1,
            ) {
                Ok(inner) => {
                    // Presence beacon: update the presence table, never stored as
                    // a message and never receipted.
                    if inner.ctype == CTYPE_PRESENCE {
                        if let Ok(pb) = serde_json::from_str::<PresenceBeacon>(&inner.body) {
                            let _ = store.upsert_presence(
                                &inner.from,
                                &pb.state,
                                &pb.source,
                                pb.ttl_secs,
                                pb.seq,
                                pb.detail.as_deref(),
                                &inner.ts,
                            );
                        }
                        return;
                    }

                    // Delivery/read receipt: apply to the referenced outbound
                    // message's delivery state; not stored as a visible message.
                    if inner.kind == MsgKind::Receipt || inner.ctype == CTYPE_RECEIPT {
                        if let Some(rcpt) = inner.receipt.as_ref() {
                            match rcpt.status {
                                ReceiptStatus::Delivered => {
                                    let _ = store.apply_delivery_receipt(&rcpt.ref_id, &inner.ts);
                                }
                                ReceiptStatus::Read => {
                                    let _ = store.apply_read_receipt(&rcpt.ref_id, &inner.ts);
                                }
                            }
                        }
                        return;
                    }

                    // Grant replay guard: an authorization grant id may only be
                    // used once (REQ: grant replay).
                    if let Some(sg) = inner.grant.as_ref() {
                        if let Ok(claims) = grant::verify(sg, &trust) {
                            if store.seen_grant(&claims.id).unwrap_or(false) {
                                let _ = store.record_rejection(
                                    &RejectReason::ReplayedGrant,
                                    Some(&inner.from),
                                    &topic,
                                    "",
                                );
                                return;
                            }
                        }
                    }

                    // Store the inbound message; push to streaming subscribers and
                    // emit an automatic delivery receipt for direct messages.
                    match store.insert_inbound(&inner, &topic) {
                        Ok(Some(seq)) => {
                            let _ = store.enforce_bounds(cfg.max_messages, cfg.max_bytes);
                            if let Ok(Some(msg)) = store.message_by_seq(seq) {
                                push_to_subscribers(&subscribers, &msg);
                            }
                            if cfg.auto_receipts && inner.to == me && !inner.is_broadcast() {
                                enqueue_receipt(
                                    &identity,
                                    &store,
                                    &inner.from,
                                    &inner.id,
                                    ReceiptStatus::Delivered,
                                    &topic,
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!("store inbound failed: {e}"),
                    }
                }
                Err(info) => {
                    let _ = store.record_rejection(
                        &info.reason,
                        info.claimed_sender.as_deref(),
                        &topic,
                        "",
                    );
                }
            }
        });

        let mqtt = Mqtt::start(&cfg, &client_id, on_msg)?;
        *guard = Some(mqtt);
        Ok(())
    }

    /// Disconnect the broker session (REQ-0018).
    ///
    /// The `Mqtt` is taken out of the mutex *before* `stop()` is called, so the
    /// blocking join on the eventloop thread happens with the lock released.
    /// Otherwise a `disconnect` while the broker is unreachable would hold the
    /// daemon-wide mqtt lock for the whole reconnect backoff, freezing every
    /// other IPC request that touches it.
    fn disconnect(&self) {
        let taken = self.mqtt.lock().unwrap().take();
        if let Some(mut m) = taken {
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

    /// Clone the broker client handle iff currently connected, holding the mqtt
    /// mutex only for the clone. Publishing through the returned handle never
    /// blocks under the lock (fixes daemon-wide stalls when the broker applies
    /// backpressure and `rumqttc`'s bounded request channel fills up).
    fn connected_client(&self) -> Option<Client> {
        let guard = self.mqtt.lock().unwrap();
        match guard.as_ref() {
            Some(m) if m.is_connected() => Some(m.client()),
            _ => None,
        }
    }

    /// Periodically flush the durable outbox while connected (REQ-0016).
    fn spawn_outbox_pump(self: &Arc<Self>) {
        let this = self.clone();
        let store = self.store.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            // Grab a client handle only if connected, then publish with the lock
            // released so a slow/backpressured broker cannot stall other IPC.
            let Some(client) = this.connected_client() else {
                continue;
            };
            let pending = store.pending_outbound().unwrap_or_default();
            for ob in pending {
                if mqtt::publish_on(&client, &ob.topic, ob.payload.clone(), ob.retain).is_ok() {
                    let _ = store.mark_delivered(&ob.id);
                }
            }
        });
    }

    /// Optional presence heartbeat (REQ: optional presence heartbeat). Emits a
    /// signed [`CTYPE_PRESENCE`] beacon with a JSON body the peers ingest into
    /// their presence tables.
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
                let beacon = PresenceBeacon {
                    state: "online".into(),
                    source: "daemon".into(),
                    ttl_secs: (secs * 3) as i64,
                    seq: now_seq(),
                    detail: None,
                };
                enqueue_presence(&identity, &store, topic, &beacon);
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
        // A subscription is a long-lived stream rather than a single response.
        if let Request::Subscribe { consumer, ack } = req {
            self.serve_subscribe(br, consumer, ack);
            return;
        }
        let is_shutdown = matches!(req, Request::Shutdown);
        let resp = self.handle(req);
        let out = serde_json::to_vec(&resp).unwrap_or_default();
        let _ = ipc::write_frame(br.get_mut(), &out);
        if is_shutdown {
            std::process::exit(0);
        }
    }

    /// Register a streaming subscriber and forward frames until the peer
    /// disconnects (detected on the next failed write). When `ack` is set, each
    /// message frame that is successfully delivered advances the consumer cursor
    /// (and emits a read receipt), so `read --follow --ack` does not redeliver
    /// streamed messages on a later plain `read`.
    fn serve_subscribe(self: Arc<Self>, mut br: BufReader<Stream>, consumer: String, ack: bool) {
        let id = self.next_sub_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = sync_channel::<StreamFrame>(256);
        self.subscribers.lock().unwrap().push(Subscriber {
            id,
            consumer: consumer.clone(),
            tx,
            dropped: 0,
        });
        // Forward frames; a write error means the CLI hung up.
        while let Ok(frame) = rx.recv() {
            let seq = match &frame {
                StreamFrame::Message(m) => Some(m.seq),
                StreamFrame::Lagged { .. } => None,
            };
            let bytes = match serde_json::to_vec(&frame) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if ipc::write_frame(br.get_mut(), &bytes).is_err() {
                break;
            }
            // Only advance the cursor once the frame is actually delivered.
            if ack {
                if let Some(seq) = seq {
                    let _ = self.store.ack(&consumer, seq);
                    self.maybe_read_receipt(seq);
                }
            }
        }
        // Deregister this subscriber by its unique id.
        self.subscribers.lock().unwrap().retain(|s| s.id != id);
    }

    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong,
            Request::Status => self.status(),
            Request::Hello { .. } => Response::Hello {
                ipc_proto: IPC_PROTO_VERSION,
                version: env!("CARGO_PKG_VERSION").to_string(),
                caps: caps(),
            },
            Request::Connect => match self.connect() {
                Ok(()) => Response::Ok,
                Err(e) => err(e),
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
                topic,
                kind,
                correlation_id,
                supersedes,
                encrypt,
                grant,
                unsigned,
            } => self.send(SendParams {
                to,
                ctype,
                body,
                in_reply_to,
                topic,
                kind,
                correlation_id,
                supersedes,
                encrypt,
                grant,
                unsigned,
            }),
            Request::Read { consumer, limit } => {
                match self.store.read_after_cursor(&consumer, limit) {
                    Ok(msgs) => Response::Messages {
                        msgs,
                        consumer_warning: None,
                    },
                    Err(e) => err(e),
                }
            }
            Request::Ack { consumer, seq } => match self.store.ack(&consumer, seq) {
                Ok(()) => {
                    self.maybe_read_receipt(seq);
                    Response::Ok
                }
                Err(e) => err(e),
            },
            Request::Browse { limit, from, to } => {
                match self
                    .store
                    .browse(limit, from.as_deref(), to.as_deref(), "in")
                {
                    Ok(msgs) => Response::Messages {
                        msgs,
                        consumer_warning: None,
                    },
                    Err(e) => err(e),
                }
            }
            Request::Transcript {
                limit,
                from,
                to,
                peer,
            } => match self
                .store
                .transcript(limit, from.as_deref(), to.as_deref(), peer.as_deref())
            {
                Ok(msgs) => Response::Messages {
                    msgs,
                    consumer_warning: None,
                },
                Err(e) => err(e),
            },
            Request::Rejections {
                limit,
                reason,
                since,
            } => match self
                .store
                .rejections(limit, reason.as_deref(), since.as_deref())
            {
                Ok(rows) => Response::Rejections(rows),
                Err(e) => err(e),
            },
            Request::Consumers => match self.store.consumers() {
                Ok(rows) => Response::Consumers(rows),
                Err(e) => err(e),
            },
            Request::Receipts { id, limit, state } => self.receipts(id, limit, state),
            Request::Reply {
                msg_id,
                ctype,
                body,
            } => self.reply(msg_id, ctype, body),
            Request::Presence {
                state,
                ttl_secs,
                detail,
            } => self.presence(state, ttl_secs, detail),
            Request::PresenceList => match self.store.list_presence() {
                Ok(rows) => Response::Presence(rows),
                Err(e) => err(e),
            },
            Request::PairStart { topic } => self.pair_start(topic),
            Request::PairList => self.pair_list(),
            Request::PairConfirm { name } => self.pair_confirm(name),
            // Subscribe is handled in handle_conn; reaching here is a protocol bug.
            Request::Subscribe { .. } => Response::Error {
                message: "subscribe must be served as a stream".into(),
            },
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
            ipc_proto: IPC_PROTO_VERSION,
            presence: self.store.list_presence().unwrap_or_default(),
            allow_unsigned: cfg.allow_unsigned,
            accept_v1: cfg.accept_v1,
            require_encryption: cfg.require_encryption,
            auto_receipts: cfg.auto_receipts,
        };
        Response::Status(info)
    }

    /// Outbound delivery/read state, optionally for one id (REQ: receipts).
    fn receipts(&self, id: Option<String>, limit: i64, state: Option<String>) -> Response {
        if let Some(id) = id {
            match self.store.get_message(&id) {
                Ok(Some(m)) => Response::Messages {
                    msgs: vec![m],
                    consumer_warning: None,
                },
                Ok(None) => Response::Messages {
                    msgs: Vec::new(),
                    consumer_warning: None,
                },
                Err(e) => err(e),
            }
        } else {
            match self.store.outbound_receipts(limit, state.as_deref()) {
                Ok(msgs) => Response::Messages {
                    msgs,
                    consumer_warning: None,
                },
                Err(e) => err(e),
            }
        }
    }

    /// Reply to a stored message by id, addressing its original sender.
    fn reply(&self, msg_id: String, ctype: String, body: String) -> Response {
        let original = match self.store.get_message(&msg_id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return Response::Error {
                    message: format!("no message with id {msg_id}"),
                }
            }
            Err(e) => return err(e),
        };
        self.send(SendParams {
            to: original.from,
            ctype,
            body,
            in_reply_to: Some(msg_id),
            topic: None,
            kind: String::new(),
            correlation_id: None,
            supersedes: None,
            encrypt: false,
            grant: None,
            unsigned: false,
        })
    }

    /// Emit an application presence beacon with source `agent` (REQ: presence).
    fn presence(&self, state: String, ttl_secs: Option<i64>, detail: Option<String>) -> Response {
        let cfg = Config::load().unwrap_or_default();
        let topic = match cfg.primary_topic() {
            Some(t) => t.to_string(),
            None => {
                return Response::Error {
                    message: "no chat topic configured".into(),
                }
            }
        };
        let beacon = PresenceBeacon {
            state,
            source: "agent".into(),
            ttl_secs: ttl_secs.unwrap_or(0),
            seq: now_seq(),
            detail,
        };
        enqueue_presence(&self.identity, &self.store, &topic, &beacon);
        Response::Ok
    }

    /// Broadcast a self-signed pairing hello on the chosen (or primary) topic
    /// (REQ: bootstrap/pairing mode). The operator can re-run to re-broadcast.
    fn pair_start(&self, topic: Option<String>) -> Response {
        let cfg = Config::load().unwrap_or_default();
        let topic = match topic {
            Some(t) => {
                if !cfg.topics.iter().any(|c| c == &t) {
                    return Response::Error {
                        message: format!("topic '{t}' is not a configured chat topic"),
                    };
                }
                t
            }
            None => match cfg.primary_topic() {
                Some(t) => t.to_string(),
                None => {
                    return Response::Error {
                        message: "no chat topic configured".into(),
                    }
                }
            },
        };
        let (inner, wrapper) = match message::build_pair(&self.identity) {
            Ok(v) => v,
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        };
        let payload = match wrapper.to_bytes() {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        if let Err(e) = self.store.enqueue_outbound(&Outbound {
            id: inner.id,
            topic: topic.clone(),
            payload: payload.clone(),
            qos: 1,
            retain: false,
        }) {
            return err(e);
        }
        // Publish immediately when connected (the outbox pump covers the rest).
        if let Some(client) = self.connected_client() {
            let _ = mqtt::publish_on(&client, &topic, payload, false);
        }
        Response::Ok
    }

    /// The peers seen on the pairing topic awaiting confirmation.
    fn pair_list(&self) -> Response {
        let views: Vec<PendingPairView> = self
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|p| PendingPairView {
                name: p.name.clone(),
                fingerprint: fingerprint(&p.public_key),
                sas: p.sas.clone(),
                kem: p.kem_public_key.is_some(),
            })
            .collect();
        Response::Pairs(views)
    }

    /// Confirm a pending peer into the trust store after a SAS match, capturing
    /// both its signing and KEM keys, then drop it from the pending map.
    fn pair_confirm(&self, name: String) -> Response {
        let entry = self.pending.lock().unwrap().get(&name).cloned();
        let entry = match entry {
            Some(e) => e,
            None => {
                return Response::Error {
                    message: format!("no pending pairing for '{name}'"),
                }
            }
        };
        let mut ts = match TrustStore::load() {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        ts.add_with_kem(
            &entry.name,
            &entry.public_key,
            entry.kem_public_key.as_deref(),
        );
        if let Err(e) = ts.save() {
            return err(e);
        }
        self.pending.lock().unwrap().remove(&name);
        tracing::info!(
            "paired with '{}' ({}) first seen {}",
            entry.name,
            fingerprint(&entry.public_key),
            entry.first_seen
        );
        Response::Ok
    }

    /// Best-effort read receipt when a consumer acks a direct inbound message.
    fn maybe_read_receipt(&self, seq: i64) {
        let cfg = Config::load().unwrap_or_default();
        if !cfg.auto_receipts {
            return;
        }
        if let Ok(Some(m)) = self.store.message_by_seq(seq) {
            if m.direction == "in" && m.to == self.identity.name && m.to != "*" {
                enqueue_receipt(
                    &self.identity,
                    &self.store,
                    &m.from,
                    &m.id,
                    ReceiptStatus::Read,
                    &m.topic,
                );
            }
        }
    }

    fn send(&self, p: SendParams) -> Response {
        let cfg = Config::load().unwrap_or_default();
        // Choose the publish topic: an explicit topic must be configured.
        let topic = match &p.topic {
            Some(t) => {
                if !cfg.topics.iter().any(|c| c == t) {
                    return Response::Error {
                        message: format!("topic '{t}' is not a configured chat topic"),
                    };
                }
                t.clone()
            }
            None => match cfg.primary_topic() {
                Some(t) => t.to_string(),
                None => {
                    return Response::Error {
                        message: "no chat topic configured".into(),
                    }
                }
            },
        };
        if p.body.len() > cfg.max_payload {
            return Response::Error {
                message: "payload exceeds configured maximum".into(),
            };
        }

        // Resolve an optional grant token and recipient KEM key up front.
        let grant = match &p.grant {
            Some(tok) => match grant::decode_token(tok) {
                Ok(sg) => Some(sg),
                Err(e) => return err(e),
            },
            None => None,
        };
        let encrypt_to = if p.encrypt {
            let trust = TrustStore::load().unwrap_or_default();
            match trust.kem_public_key(&p.to) {
                Some(ek) => Some(ek),
                None => {
                    return Response::Error {
                        message: RejectReason::UnknownRecipientKey.to_string(),
                    }
                }
            }
        } else {
            None
        };

        let mut opts = BuildOpts::new(&p.to, &p.ctype, &p.body);
        opts.in_reply_to = p.in_reply_to;
        opts.kind = parse_kind(&p.kind);
        opts.correlation_id = p.correlation_id;
        opts.supersedes = p.supersedes;
        opts.grant = grant;
        opts.encrypt_to = encrypt_to;
        opts.unsigned = p.unsigned;

        let (inner, wrapper) = match message::build(&self.identity, &opts) {
            Ok(v) => v,
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        };
        let payload = match wrapper.to_bytes() {
            Ok(p) => p,
            Err(e) => return err(e),
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
            return err(e);
        }

        let mut delivery_state = "pending".to_string();
        if let Some(client) = self.connected_client() {
            if mqtt::publish_on(&client, &topic, payload, false).is_ok() {
                let _ = self.store.mark_delivered(&inner.id);
                delivery_state = "sent".to_string();
            }
        }

        Response::Sent {
            id: inner.id,
            delivery_state,
        }
    }
}

/// Parameters for [`Daemon::send`] (avoids a too-many-arguments signature).
struct SendParams {
    to: String,
    ctype: String,
    body: String,
    in_reply_to: Option<String>,
    topic: Option<String>,
    kind: String,
    correlation_id: Option<String>,
    supersedes: Option<String>,
    encrypt: bool,
    grant: Option<String>,
    unsigned: bool,
}

/// Map a snake_case kind string (empty = `message`) to a [`MsgKind`].
fn parse_kind(s: &str) -> MsgKind {
    match s {
        "command" => MsgKind::Command,
        "query" => MsgKind::Query,
        "result" => MsgKind::Result,
        "ack" => MsgKind::Ack,
        "error" => MsgKind::Error,
        "grant" => MsgKind::Grant,
        "receipt" => MsgKind::Receipt,
        _ => MsgKind::Message,
    }
}

/// Capabilities advertised in the [`Response::Hello`] handshake.
fn caps() -> Vec<String> {
    [
        "send",
        "subscribe",
        "transcript",
        "rejections",
        "consumers",
        "receipts",
        "reply",
        "presence",
        "grants",
        "encryption",
        "unsigned",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Monotonic-ish presence sequence (wall-clock seconds; ties accepted by
/// `upsert_presence`'s `>=` guard).
fn now_seq() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn err(e: Error) -> Response {
    Response::Error {
        message: e.to_string(),
    }
}

/// Install a tracing subscriber that appends to `daemon.log` (REQ: Windows
/// service hardening / daemon readiness diagnostics). Best-effort: if the data
/// directory or file cannot be opened, or a global subscriber is already
/// installed (foreground run), this is a no-op.
fn init_file_tracing() {
    use std::fs::OpenOptions;
    let Ok(path) = crate::paths::log_path() else {
        return;
    };
    let _ = crate::paths::ensure_data_dir();
    let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("AGENTMSG_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(move || file.try_clone().expect("clone daemon.log handle"))
        .try_init();
}

/// Push a newly stored inbound message to every live subscriber, dropping any
/// that have disconnected. If a subscriber's channel is full the message is
/// counted against that subscriber's running `dropped` total; the accurate lag
/// count is delivered as a single `Lagged` frame as soon as the channel drains,
/// so the signal is never silently lost or understated.
fn push_to_subscribers(subs: &Subscribers, msg: &StoredMsg) {
    let mut guard = subs.lock().unwrap();
    guard.retain_mut(|s| {
        // First flush any outstanding lag notice so the consumer learns exactly
        // how many messages it missed before receiving the next live one.
        if s.dropped > 0 {
            match s.tx.try_send(StreamFrame::Lagged { dropped: s.dropped }) {
                Ok(()) => s.dropped = 0,
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        match s.tx.try_send(StreamFrame::Message(msg.clone())) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                s.dropped += 1;
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    });
}

/// Build + durably enqueue an automatic delivery/read receipt to `to`.
fn enqueue_receipt(
    identity: &Identity,
    store: &Store,
    to: &str,
    ref_id: &str,
    status: ReceiptStatus,
    topic: &str,
) {
    let mut opts = BuildOpts::new(to, CTYPE_RECEIPT, "");
    opts.kind = MsgKind::Receipt;
    opts.receipt = Some(Receipt {
        ref_id: ref_id.to_string(),
        status,
    });
    if let Ok((inner, wrapper)) = message::build(identity, &opts) {
        if let Ok(payload) = wrapper.to_bytes() {
            let _ = store.insert_outbound_log(&inner, topic);
            let _ = store.enqueue_outbound(&Outbound {
                id: inner.id.clone(),
                topic: topic.to_string(),
                payload,
                qos: 1,
                retain: false,
            });
        }
    }
}

/// Build + durably enqueue a presence beacon with the given body.
fn enqueue_presence(identity: &Identity, store: &Store, topic: &str, beacon: &PresenceBeacon) {
    let body = match serde_json::to_string(beacon) {
        Ok(b) => b,
        Err(_) => return,
    };
    let mut opts = BuildOpts::new("*", CTYPE_PRESENCE, &body);
    opts.kind = MsgKind::Message;
    if let Ok((inner, wrapper)) = message::build(identity, &opts) {
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
}
