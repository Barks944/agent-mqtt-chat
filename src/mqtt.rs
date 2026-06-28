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
                        on_message(p.topic.clone(), p.payload.to_vec());
                    }
                    Ok(_) => {}
                    Err(_) => {
                        conn_flag.store(false, Ordering::Relaxed);
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // Bounded exponential backoff (REQ-0034); the iterator
                        // reconnects on the next poll.
                        thread::sleep(backoff);
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                }
            }
            conn_flag.store(false, Ordering::Relaxed);
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
        self.client
            .publish(topic, QoS::AtLeastOnce, retain, payload)
            .map_err(|e| Error::Mqtt(e.to_string()))
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
