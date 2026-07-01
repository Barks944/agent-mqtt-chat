//! MQTT transport (REQ-0002 connection, REQ-0015 TLS, REQ-0032 subscribe,
//! REQ-0033 persistent session, REQ-0034 reconnect with backoff).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rumqttc::{Client, Event, MqttOptions, Packet, QoS, Transport};

use crate::config::Config;
use crate::error::{Error, Result};

/// Callback invoked for each inbound publish: (topic, payload).
pub type OnMessage = Arc<dyn Fn(String, Vec<u8>) + Send + Sync + 'static>;

/// A running MQTT session.
pub struct Mqtt {
    client: Client,
    connected: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Mqtt {
    /// Establish a session and start the event loop in a background thread.
    pub fn start(cfg: &Config, client_id: &str, on_message: OnMessage) -> Result<Mqtt> {
        if cfg.broker_host.is_empty() {
            return Err(Error::Config("broker host not set".into()));
        }
        if !cfg.tls {
            // REQ-0015: TLS-only transport.
            return Err(Error::Config("TLS is required (set tls = true)".into()));
        }

        let mut opts = MqttOptions::new(client_id, &cfg.broker_host, cfg.broker_port);
        opts.set_keep_alive(Duration::from_secs(20));
        // rumqttc defaults the max incoming/outgoing packet size to 10 KiB, which
        // is SMALLER than a post-quantum envelope: a single ML-DSA-65 signature is
        // 3309 bytes and a TOFU pairing hello embeds the full ML-DSA-65 (1952 B)
        // and ML-KEM-768 (1184 B) public keys, pushing the wrapper past 10 KiB.
        // Without raising this cap rumqttc refuses to (de)serialise such packets,
        // poll() returns an error, the connection drops, and the queued publish is
        // retried on every reconnect — an endless reconnect storm. Size the limit
        // from the configured payload cap plus envelope overhead (double base64 of
        // the body inside the inner, the signature, and JSON framing).
        let max_pkt = cfg
            .max_payload
            .saturating_mul(2)
            .saturating_add(64 * 1024)
            .max(256 * 1024);
        opts.set_max_packet_size(max_pkt, max_pkt);
        opts.set_clean_session(false); // persistent session (REQ-0033)
        if !cfg.username.is_empty() {
            opts.set_credentials(&cfg.username, &cfg.password);
        }
        opts.set_transport(Transport::tls_with_default_config());

        let (client, mut connection) = Client::new(opts, 64);
        let connected = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        let topics = cfg.topics.clone();
        let sub_client = client.clone();
        let conn_flag = connected.clone();
        let stop_flag = stop.clone();

        let handle = thread::spawn(move || {
            // Whatever exits this thread (a clean stop, a panic escaping the loop,
            // or the iterator ending) MUST leave `connected` false, so callers of
            // `is_connected()` never observe a stale `true` after the eventloop is
            // gone (fixes a silent-death hang where the daemon believed it was
            // connected forever). A Drop guard guarantees it on every exit path.
            let _conn_guard = ConnGuard(conn_flag.clone());
            let mut backoff = Duration::from_millis(250);
            for event in connection.iter() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                match event {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        conn_flag.store(true, Ordering::Relaxed);
                        backoff = Duration::from_millis(250);
                        // Subscriptions are not auto-restored; (re)subscribe here.
                        for t in &topics {
                            let _ = sub_client.subscribe(t, QoS::AtLeastOnce);
                        }
                    }
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        // Isolate the user callback: a panic inside `on_message`
                        // (e.g. a poisoned mutex on the ingest path) must NOT kill
                        // the eventloop thread. Catch it, drop the one message, and
                        // keep the connection alive.
                        let topic = p.topic.clone();
                        let payload = p.payload.to_vec();
                        let cb = &on_message;
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            cb(topic, payload);
                        }))
                        .is_err()
                        {
                            tracing::error!(
                                "on_message panicked; dropping message, eventloop continues"
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("eventloop poll error: {e}");
                        conn_flag.store(false, Ordering::Relaxed);
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // Bounded exponential backoff (REQ-0034); the iterator
                        // reconnects on the next poll. Sleep in short slices so a
                        // concurrent `stop()` is honoured promptly instead of
                        // blocking a `disconnect()`/shutdown for up to 30s.
                        if sleep_interruptible(backoff, &stop_flag) {
                            break;
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });

        Ok(Mqtt {
            client,
            connected,
            stop,
            handle: Some(handle),
        })
    }

    /// Publish a payload at QoS1 (REQ-0016 delivery semantics).
    pub fn publish(&self, topic: &str, payload: Vec<u8>, retain: bool) -> Result<()> {
        publish_on(&self.client, topic, payload, retain)
    }

    /// A cheap clone of the broker client handle. Callers use this to publish
    /// WITHOUT holding the daemon's `Mutex<Option<Mqtt>>` across the (potentially
    /// blocking) publish — `rumqttc::Client` is a thin handle over the request
    /// channel, so cloning is cheap and the clone stays valid for the session.
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Stop the session and join the event thread.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.client.disconnect();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.connected.store(false, Ordering::Relaxed);
    }
}

impl Drop for Mqtt {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.stop();
        }
    }
}

/// Publish `payload` at QoS1 on a bare client handle (see [`Mqtt::client`]).
/// Kept as a free function so the daemon can publish from a cloned handle
/// without holding any lock across the call.
pub fn publish_on(client: &Client, topic: &str, payload: Vec<u8>, retain: bool) -> Result<()> {
    client
        .publish(topic, QoS::AtLeastOnce, retain, payload)
        .map_err(|e| Error::Mqtt(e.to_string()))
}

/// Clears the `connected` flag when the eventloop thread exits by any path,
/// including a panic that unwinds out of the loop.
struct ConnGuard(Arc<AtomicBool>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Sleep for `dur`, waking early if `stop` is set. Returns `true` if a stop was
/// observed (so the caller should break out of the eventloop).
fn sleep_interruptible(dur: Duration, stop: &AtomicBool) -> bool {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < dur {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        let this = step.min(dur - slept);
        thread::sleep(this);
        slept += this;
    }
    stop.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn sleep_interruptible_returns_early_when_stop_already_set() {
        // The disconnect-responsiveness fix: a long backoff must not be served
        // in full once stop is signalled.
        let stop = AtomicBool::new(true);
        let start = Instant::now();
        assert!(sleep_interruptible(Duration::from_secs(30), &stop));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn sleep_interruptible_sleeps_full_duration_when_not_stopped() {
        let stop = AtomicBool::new(false);
        assert!(!sleep_interruptible(Duration::from_millis(150), &stop));
    }
}
