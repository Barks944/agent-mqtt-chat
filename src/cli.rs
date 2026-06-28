//! Command-line interface (REQ-0047: every subcommand supports --json).

use clap::{Parser, Subcommand};
use serde::Serialize;

use crate::config::Config;
use crate::daemon::Daemon;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::ipc::{self, Request, Response};
use crate::token::IdentityToken;
use crate::trust::TrustStore;
use crate::wire::{fingerprint, BROADCAST, CTYPE_TEXT};

#[derive(Parser)]
#[command(
    name = "agentmsg",
    version,
    about = "Cross-host agent-to-agent messaging over MQTT with post-quantum signatures"
)]
pub struct Cli {
    /// Emit machine-readable JSON instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage this agent's identity.
    Id {
        #[command(subcommand)]
        cmd: IdCmd,
    },
    /// Manage trusted (known) agents.
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Configure the broker connection and chat topic.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Control the resident daemon.
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
    /// Show daemon + connection status.
    Status,
    /// Publish a message.
    Send {
        /// Message body.
        body: String,
        /// Recipient agent name (omit with --broadcast).
        #[arg(long)]
        to: Option<String>,
        /// Address to all agents on the topic.
        #[arg(long)]
        broadcast: bool,
        /// Content type.
        #[arg(long, default_value = CTYPE_TEXT)]
        ctype: String,
        /// Correlation id this message replies to.
        #[arg(long)]
        reply_to: Option<String>,
    },
    /// Drain unread messages (queue, advances cursor only with --ack).
    Read {
        /// Consumer name (defaults to local identity).
        #[arg(long)]
        consumer: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Block until at least one message is available.
        #[arg(long)]
        wait: bool,
        /// Acknowledge the returned batch (advance the cursor).
        #[arg(long)]
        ack: bool,
    },
    /// Browse recent messages without consuming them.
    Browse {
        #[arg(long, default_value_t = 20)]
        limit: i64,
        /// Only messages from this sender.
        #[arg(long)]
        from: Option<String>,
        /// Only messages addressed to this agent (or broadcast).
        #[arg(long)]
        to: Option<String>,
        /// Shortcut for --to <local identity>.
        #[arg(long)]
        mine: bool,
    },
    /// Acknowledge messages up to a sequence number.
    Ack {
        seq: i64,
        #[arg(long)]
        consumer: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IdCmd {
    /// Generate a new identity (post-quantum keypair).
    Generate {
        name: String,
        /// Overwrite an existing identity.
        #[arg(long)]
        force: bool,
    },
    /// Show the local identity.
    Show,
    /// Print the shareable identity token (paste into peers).
    Token,
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Add a known agent from a pasted identity token.
    Add { token: String },
    /// List known agents.
    List,
    /// Remove a known agent.
    Remove { name: String },
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Set the broker host (and port).
    SetBroker {
        host: String,
        #[arg(long, default_value_t = 8883)]
        port: u16,
        /// Disable TLS (NOT recommended; the daemon refuses non-TLS anyway).
        #[arg(long)]
        no_tls: bool,
    },
    /// Set the shared broker credentials.
    SetCreds { username: String, password: String },
    /// Set the chat topic (replaces existing topics).
    SetTopic { topic: String },
    /// Add an additional chat topic.
    AddTopic { topic: String },
    /// Show the current configuration.
    Show,
}

#[derive(Subcommand)]
pub enum DaemonCmd {
    /// Run the daemon in the foreground (used by service managers).
    Run,
    /// Start the daemon as a background process.
    Start,
    /// Stop the running daemon.
    Stop,
    /// Connect the broker session.
    Connect,
    /// Disconnect the broker session.
    Disconnect,
}

/// JSON envelope for `--json` output.
#[derive(Serialize)]
struct JsonOut<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok_json<T: Serialize>(json: bool, data: T, human: impl FnOnce()) {
    if json {
        let out = JsonOut {
            ok: true,
            data: Some(data),
            error: None,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        human();
    }
}

fn fail(json: bool, e: &Error) -> ! {
    if json {
        let out = JsonOut::<()> {
            ok: false,
            data: None,
            error: Some(e.to_string()),
        };
        eprintln!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        eprintln!("error: {e}");
    }
    std::process::exit(exit_code(e));
}

/// Distinct exit codes so agents can branch (REQ-0048).
fn exit_code(e: &Error) -> i32 {
    match e {
        Error::DaemonNotRunning(_) => 3,
        Error::NoIdentity => 4,
        Error::UnknownAgent(_) | Error::InvalidToken(_) => 5,
        _ => 1,
    }
}

/// Entry point used by `main`.
pub fn run(cli: Cli) {
    let json = cli.json;
    let result = dispatch(&cli);
    if let Err(e) = result {
        fail(json, &e);
    }
}

/// Local agent name (the daemon is addressed by identity).
fn local_agent() -> Result<String> {
    Ok(Identity::load()?.name)
}

/// Call the local agent's daemon over IPC.
fn call(req: Request) -> Result<Response> {
    let agent = local_agent()?;
    ipc::call(&agent, &req)
}

fn dispatch(cli: &Cli) -> Result<()> {
    let json = cli.json;
    match &cli.command {
        Command::Id { cmd } => id_cmd(json, cmd),
        Command::Agent { cmd } => agent_cmd(json, cmd),
        Command::Config { cmd } => config_cmd(json, cmd),
        Command::Daemon { cmd } => daemon_cmd(json, cmd),
        Command::Status => status_cmd(json),
        Command::Send {
            body,
            to,
            broadcast,
            ctype,
            reply_to,
        } => send_cmd(json, to, body, *broadcast, ctype, reply_to),
        Command::Read {
            consumer,
            limit,
            wait,
            ack,
        } => read_cmd(json, consumer, *limit, *wait, *ack),
        Command::Browse {
            limit,
            from,
            to,
            mine,
        } => browse_cmd(json, *limit, from, to, *mine),
        Command::Ack { seq, consumer } => ack_cmd(json, *seq, consumer),
    }
}

// --- identity -------------------------------------------------------------

fn id_cmd(json: bool, cmd: &IdCmd) -> Result<()> {
    match cmd {
        IdCmd::Generate { name, force } => {
            if Identity::exists() && !force {
                return Err(Error::IdentityExists("use --force to overwrite".into()));
            }
            let id = Identity::generate(name);
            id.save()?;
            let token = id.token().encode();
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
                token: String,
            }
            let data = Out {
                name: id.name.clone(),
                fingerprint: fingerprint(id.public_key()),
                token: token.clone(),
            };
            ok_json(json, data, || {
                println!(
                    "Generated identity '{}' ({})",
                    id.name,
                    fingerprint(id.public_key())
                );
                println!("\nShare this token with other agents:\n{token}");
            });
            Ok(())
        }
        IdCmd::Show => {
            let id = Identity::load()?;
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
                token: String,
            }
            let data = Out {
                name: id.name.clone(),
                fingerprint: fingerprint(id.public_key()),
                token: id.token().encode(),
            };
            ok_json(json, data, || {
                println!("name:        {}", id.name);
                println!("fingerprint: {}", fingerprint(id.public_key()));
                println!("token:       {}", id.token().encode());
            });
            Ok(())
        }
        IdCmd::Token => {
            let id = Identity::load()?;
            let token = id.token().encode();
            ok_json(json, &token, || println!("{token}"));
            Ok(())
        }
    }
}

// --- trusted agents -------------------------------------------------------

fn agent_cmd(json: bool, cmd: &AgentCmd) -> Result<()> {
    match cmd {
        AgentCmd::Add { token } => {
            let parsed = IdentityToken::decode(token)?;
            let mut ts = TrustStore::load()?;
            ts.add_from_token(&parsed);
            ts.save()?;
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
            }
            let data = Out {
                name: parsed.name.clone(),
                fingerprint: parsed.fingerprint(),
            };
            ok_json(json, data, || {
                println!("Added '{}' ({})", parsed.name, parsed.fingerprint());
            });
            Ok(())
        }
        AgentCmd::List => {
            let ts = TrustStore::load()?;
            #[derive(Serialize)]
            struct Entry {
                name: String,
                fingerprint: String,
            }
            let list: Vec<Entry> = ts
                .list()
                .into_iter()
                .map(|a| Entry {
                    name: a.name.clone(),
                    fingerprint: a.fingerprint(),
                })
                .collect();
            ok_json(json, &list, || {
                if list.is_empty() {
                    println!("(no known agents)");
                } else {
                    for e in &list {
                        println!("{}  {}", e.fingerprint, e.name);
                    }
                }
            });
            Ok(())
        }
        AgentCmd::Remove { name } => {
            let mut ts = TrustStore::load()?;
            let removed = ts.remove(name);
            ts.save()?;
            ok_json(json, removed, || {
                if removed {
                    println!("Removed '{name}'");
                } else {
                    println!("'{name}' was not in the trust store");
                }
            });
            Ok(())
        }
    }
}

// --- config ---------------------------------------------------------------

fn config_cmd(json: bool, cmd: &ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::SetBroker { host, port, no_tls } => {
            let mut c = Config::load()?;
            c.broker_host = host.clone();
            c.broker_port = *port;
            c.tls = !no_tls;
            c.save()?;
            ok_json(json, &c, || {
                println!(
                    "broker set to {}:{} (tls={})",
                    c.broker_host, c.broker_port, c.tls
                )
            });
            Ok(())
        }
        ConfigCmd::SetCreds { username, password } => {
            let mut c = Config::load()?;
            c.username = username.clone();
            c.password = password.clone();
            c.save()?;
            ok_json(json, true, || {
                println!("credentials set for user '{}'", username)
            });
            Ok(())
        }
        ConfigCmd::SetTopic { topic } => {
            Config::validate_topic(topic)?;
            let mut c = Config::load()?;
            c.topics = vec![topic.clone()];
            c.save()?;
            ok_json(json, &c.topics, || println!("topic set to '{topic}'"));
            Ok(())
        }
        ConfigCmd::AddTopic { topic } => {
            Config::validate_topic(topic)?;
            let mut c = Config::load()?;
            if !c.topics.contains(topic) {
                c.topics.push(topic.clone());
            }
            c.save()?;
            ok_json(json, &c.topics, || println!("topics: {:?}", c.topics));
            Ok(())
        }
        ConfigCmd::Show => {
            let c = Config::load()?;
            #[derive(Serialize)]
            struct Redacted {
                broker_host: String,
                broker_port: u16,
                tls: bool,
                username: String,
                password_set: bool,
                topics: Vec<String>,
                max_messages: u64,
                max_bytes: u64,
                heartbeat_secs: u64,
            }
            let r = Redacted {
                broker_host: c.broker_host.clone(),
                broker_port: c.broker_port,
                tls: c.tls,
                username: c.username.clone(),
                password_set: !c.password.is_empty(),
                topics: c.topics.clone(),
                max_messages: c.max_messages,
                max_bytes: c.max_bytes,
                heartbeat_secs: c.heartbeat_secs,
            };
            ok_json(json, &r, || {
                println!(
                    "broker:   {}:{} (tls={})",
                    r.broker_host, r.broker_port, r.tls
                );
                println!(
                    "user:     {} (password {})",
                    r.username,
                    if r.password_set { "set" } else { "unset" }
                );
                println!("topics:   {:?}", r.topics);
                println!(
                    "store:    max {} msgs / {} bytes",
                    r.max_messages, r.max_bytes
                );
            });
            Ok(())
        }
    }
}

// --- daemon ---------------------------------------------------------------

fn daemon_cmd(json: bool, cmd: &DaemonCmd) -> Result<()> {
    match cmd {
        DaemonCmd::Run => {
            // Foreground; blocks until shutdown.
            Daemon::run()
        }
        DaemonCmd::Start => {
            if ipc::daemon_running(&local_agent()?) {
                return Err(Error::DaemonAlreadyRunning);
            }
            let exe = std::env::current_exe().map_err(Error::Io)?;
            spawn_detached(&exe)?;
            ok_json(json, true, || println!("daemon started"));
            Ok(())
        }
        DaemonCmd::Stop => {
            let resp = call(Request::Shutdown)?;
            render_simple(json, resp, "daemon stopped")
        }
        DaemonCmd::Connect => {
            let resp = call(Request::Connect)?;
            render_simple(json, resp, "connect requested")
        }
        DaemonCmd::Disconnect => {
            let resp = call(Request::Disconnect)?;
            render_simple(json, resp, "disconnected")
        }
    }
}

#[cfg(windows)]
fn spawn_detached(exe: &std::path::Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(exe)
        .args(["daemon", "run"])
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()
        .map_err(Error::Io)?;
    Ok(())
}

#[cfg(not(windows))]
fn spawn_detached(exe: &std::path::Path) -> Result<()> {
    std::process::Command::new(exe)
        .args(["daemon", "run"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(Error::Io)?;
    Ok(())
}

// --- status ---------------------------------------------------------------

fn status_cmd(json: bool) -> Result<()> {
    match call(Request::Status) {
        Ok(Response::Status(info)) => {
            ok_json(json, &info, || {
                println!("identity:  {}", info.identity.clone().unwrap_or_default());
                println!("broker:    {}", info.broker);
                println!("connected: {}", info.connected);
                println!("topics:    {:?}", info.topics);
                println!("stored:    {}", info.stored);
                println!("rejected:  {}", info.rejected);
                println!("pending:   {}", info.pending_out);
                println!("known:     {} agent(s)", info.known_agents);
            });
            Ok(())
        }
        Ok(other) => render_simple(json, other, "status"),
        Err(Error::DaemonNotRunning(_)) | Err(Error::NoIdentity) => {
            // Report a local, daemon-down status rather than erroring out.
            let id = Identity::load().ok();
            let cfg = Config::load().unwrap_or_default();
            #[derive(Serialize)]
            struct Down {
                daemon_running: bool,
                identity: Option<String>,
                broker: String,
                topics: Vec<String>,
            }
            let d = Down {
                daemon_running: false,
                identity: id.map(|i| i.name),
                broker: if cfg.broker_host.is_empty() {
                    String::new()
                } else {
                    format!("{}:{}", cfg.broker_host, cfg.broker_port)
                },
                topics: cfg.topics,
            };
            ok_json(json, &d, || {
                println!("daemon:    not running");
                println!("identity:  {}", d.identity.clone().unwrap_or_default());
                println!("broker:    {}", d.broker);
            });
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// --- messaging ------------------------------------------------------------

fn send_cmd(
    json: bool,
    to: &Option<String>,
    body: &str,
    broadcast: bool,
    ctype: &str,
    reply_to: &Option<String>,
) -> Result<()> {
    let recipient = if broadcast {
        BROADCAST.to_string()
    } else {
        to.clone()
            .ok_or_else(|| Error::Config("specify a recipient or --broadcast".into()))?
    };
    let resp = call(Request::Send {
        to: recipient,
        ctype: ctype.to_string(),
        body: body.to_string(),
        in_reply_to: reply_to.clone(),
    })?;
    match resp {
        Response::Sent { id } => {
            ok_json(json, &id, || println!("sent {id}"));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "sent"),
    }
}

fn default_consumer(consumer: &Option<String>) -> Result<String> {
    match consumer {
        Some(c) => Ok(c.clone()),
        None => Ok(Identity::load()?.name),
    }
}

fn read_cmd(
    json: bool,
    consumer: &Option<String>,
    limit: i64,
    wait: bool,
    ack: bool,
) -> Result<()> {
    let consumer = default_consumer(consumer)?;
    loop {
        let resp = call(Request::Read {
            consumer: consumer.clone(),
            limit,
        })?;
        let msgs = match resp {
            Response::Messages(m) => m,
            Response::Error { message } => return Err(Error::Ipc(message)),
            other => return render_simple(json, other, "read"),
        };
        if msgs.is_empty() && wait {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        if ack {
            if let Some(last) = msgs.last() {
                let _ = call(Request::Ack {
                    consumer: consumer.clone(),
                    seq: last.seq,
                })?;
            }
        }
        ok_json(json, &msgs, || print_messages(&msgs));
        return Ok(());
    }
}

fn browse_cmd(
    json: bool,
    limit: i64,
    from: &Option<String>,
    to: &Option<String>,
    mine: bool,
) -> Result<()> {
    let to = if mine {
        Some(Identity::load()?.name)
    } else {
        to.clone()
    };
    let resp = call(Request::Browse {
        limit,
        from: from.clone(),
        to,
    })?;
    match resp {
        Response::Messages(m) => {
            ok_json(json, &m, || print_messages(&m));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "browse"),
    }
}

fn ack_cmd(json: bool, seq: i64, consumer: &Option<String>) -> Result<()> {
    let consumer = default_consumer(consumer)?;
    let resp = call(Request::Ack { consumer, seq })?;
    render_simple(json, resp, "acknowledged")
}

// --- helpers --------------------------------------------------------------

fn print_messages(msgs: &[crate::store::StoredMsg]) {
    if msgs.is_empty() {
        println!("(no messages)");
        return;
    }
    for m in msgs {
        let reply = m
            .in_reply_to
            .as_ref()
            .map(|r| format!(" reply-to={r}"))
            .unwrap_or_default();
        println!(
            "#{seq} [{ts}] {from} -> {to} ({ctype}){reply}\n    {body}",
            seq = m.seq,
            ts = m.ts,
            from = m.from,
            to = m.to,
            ctype = m.ctype,
            body = m.body,
        );
    }
}

fn render_simple(json: bool, resp: Response, human: &str) -> Result<()> {
    match resp {
        Response::Ok | Response::Pong => {
            ok_json(json, true, || println!("{human}"));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => {
            ok_json(json, format!("{other:?}"), || println!("{other:?}"));
            Ok(())
        }
    }
}
