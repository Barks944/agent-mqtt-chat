//! Command-line interface (REQ-0047: every subcommand supports --json).
//!
//! v0.2 (DESIGN_V2 Layer 6) wires the v2 surface to the daemon over IPC: the
//! expanded `send` flags, `read --follow` streaming, `browse --all`, the new
//! diagnostic subcommands (log/reply/rejections/consumers/receipts), human
//! authorities + grants, application presence, the security config, the
//! id-generate cross-name guard, agent rotation, and a `daemon start` readiness
//! poll. New-feature IPC calls are preceded by a [`Request::Hello`] handshake.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde::Serialize;
use ulid::Ulid;

use crate::authority::{Authority, AuthorityToken};
use crate::config::Config;
use crate::daemon::Daemon;
use crate::error::{Error, Result};
use crate::grant::{self, GrantClaims};
use crate::identity::{self, Identity};
use crate::ipc::{self, PendingPairView, Request, Response, StreamFrame, IPC_PROTO_VERSION};
use crate::store::{ConsumerRow, PresenceRow, RejectionRow};
use crate::token::IdentityToken;
use crate::trust::TrustStore;
use crate::wire::{fingerprint, validate_name, BROADCAST, CTYPE_TEXT};

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
    /// Manage the human authority key and trusted authorities.
    Authority {
        #[command(subcommand)]
        cmd: AuthorityCmd,
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
    /// Application presence beacons.
    Presence {
        #[command(subcommand)]
        cmd: PresenceCmd,
    },
    /// Bootstrap trust with a peer via TOFU + a compared SAS code.
    Pair {
        #[command(subcommand)]
        cmd: PairCmd,
    },
    /// Show daemon + connection status.
    Status,
    /// Publish a message.
    Send {
        /// Message body (omit when using --file).
        body: Option<String>,
        /// Recipient agent name (omit with --broadcast).
        #[arg(long, conflicts_with = "broadcast")]
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
        /// Override the publish topic (must be a configured chat topic).
        #[arg(long)]
        topic: Option<String>,
        /// Typed message kind (message|command|query|result|ack|error|grant|receipt).
        #[arg(long, default_value = "message")]
        kind: String,
        /// Correlation id linking related messages.
        #[arg(long)]
        correlation_id: Option<String>,
        /// Id of a message this one supersedes.
        #[arg(long)]
        supersedes: Option<String>,
        /// Encrypt the payload to the recipient's KEM key.
        #[arg(long)]
        encrypt: bool,
        /// Attach a signed-grant token (`<token>` or `@<file>`).
        #[arg(long)]
        grant: Option<String>,
        /// Send unsigned (alg=none, insecure).
        #[arg(long)]
        unsigned: bool,
        /// Read the body from a file, or `-` for stdin.
        #[arg(long)]
        file: Option<String>,
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
        /// Cap how long `--wait` blocks, in seconds (0 or unset = wait forever).
        #[arg(long)]
        wait_timeout: Option<u64>,
        /// Acknowledge the returned batch (advance the cursor).
        #[arg(long)]
        ack: bool,
        /// After draining, stream new messages as they arrive.
        #[arg(long, short = 'f')]
        follow: bool,
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
        /// Include outbound messages too (both directions, chronological).
        #[arg(long)]
        all: bool,
    },
    /// Chronological transcript across both directions.
    Log {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        /// Restrict to a conversation with one peer (either direction).
        #[arg(long)]
        peer: Option<String>,
    },
    /// Reply to a stored message by id.
    Reply {
        msg_id: String,
        body: String,
        #[arg(long, default_value = CTYPE_TEXT)]
        ctype: String,
    },
    /// Show recent rejections (diagnostics).
    Rejections {
        #[arg(long, default_value_t = 20)]
        limit: i64,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        since: Option<String>,
    },
    /// Show per-consumer cursor summaries.
    Consumers,
    /// Show outbound delivery/read receipt state.
    Receipts {
        /// A single message id to inspect.
        id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: i64,
        /// Filter by delivery state (pending|sent|delivered|read|failed).
        #[arg(long)]
        state: Option<String>,
    },
    /// Mint a human-authorization grant token (signs with the authority key).
    Grant {
        /// Agent the grant authorizes.
        #[arg(long, visible_alias = "to")]
        subject: String,
        /// Authorized action.
        #[arg(long, visible_alias = "capability")]
        action: String,
        /// Scope the action is limited to.
        #[arg(long, default_value = "")]
        scope: String,
        /// RFC3339 expiry timestamp (the grant is invalid once past).
        #[arg(long)]
        expiry: String,
        /// Write the grant token to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
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
        /// Overwrite an existing identity (backs it up first).
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
    /// Add a known agent from an identity token (positional, --file, or '-').
    Add {
        /// Identity token, or `-` to read it from stdin.
        token: Option<String>,
        /// Read the token from a file.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Allow replacing an existing agent's key (rotation).
        #[arg(long)]
        rotate: bool,
    },
    /// List known agents.
    List,
    /// Remove a known agent.
    Remove { name: String },
}

#[derive(Subcommand)]
pub enum AuthorityCmd {
    /// Generate a new local authority key.
    Generate {
        name: String,
        /// Overwrite an existing authority key (backs it up first).
        #[arg(long)]
        force: bool,
    },
    /// Show the local authority key.
    Show,
    /// Print the shareable authority token.
    Token,
    /// Trust an authority from its token (positional, --file, or '-').
    Add {
        token: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// List trusted authorities.
    List,
    /// Remove a trusted authority.
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
    /// Set the security posture flags.
    SetSecurity {
        /// Accept unsigned (alg=none) inbound messages.
        #[arg(long)]
        allow_unsigned: Option<bool>,
        /// Accept v1 protocol messages.
        #[arg(long)]
        accept_v1: Option<bool>,
        /// Require payload encryption.
        #[arg(long)]
        require_encryption: Option<bool>,
        /// Emit automatic delivery/read receipts.
        #[arg(long)]
        auto_receipts: Option<bool>,
    },
    /// Show the current configuration.
    Show,
}

#[derive(Subcommand)]
pub enum DaemonCmd {
    /// Run the daemon in the foreground (used by service managers).
    Run,
    /// Start the daemon as a background process.
    Start {
        /// Seconds to wait for the daemon to become ready (default 10).
        #[arg(long)]
        wait: Option<u64>,
        /// Do not wait for readiness; return immediately.
        #[arg(long)]
        no_wait: bool,
    },
    /// Stop the running daemon.
    Stop,
    /// Connect the broker session.
    Connect,
    /// Disconnect the broker session.
    Disconnect,
}

#[derive(Subcommand)]
pub enum PresenceCmd {
    /// Emit a presence beacon (e.g. online/busy/away).
    Set {
        state: String,
        /// Time-to-live in seconds.
        #[arg(long)]
        ttl: Option<i64>,
        /// Free-form detail.
        #[arg(long)]
        detail: Option<String>,
    },
    /// List known presence records.
    List,
}

#[derive(Subcommand)]
pub enum PairCmd {
    /// Broadcast this agent's identity to begin pairing on a topic.
    Start {
        /// Override the publish topic (must be a configured chat topic).
        #[arg(long)]
        topic: Option<String>,
    },
    /// List peers seen pairing, with their SAS codes to compare.
    List,
    /// Confirm a peer into the trust store after the SAS codes match.
    Confirm { name: String },
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
        Error::NoIdentity | Error::IdentityNameMismatch(_) | Error::NoAuthority => 4,
        Error::UnknownAgent(_)
        | Error::InvalidToken(_)
        | Error::TokenCorrupt(_)
        | Error::RotationRequired(_)
        | Error::NotAnAuthorityToken => 5,
        Error::Timeout(_) => 6,
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

/// Send a `Hello` handshake before a new-feature IPC call (best-effort: a
/// successful round-trip confirms the daemon speaks v2 IPC).
fn hello() -> Result<()> {
    let _ = call(Request::Hello {
        ipc_proto: IPC_PROTO_VERSION,
    })?;
    Ok(())
}

fn dispatch(cli: &Cli) -> Result<()> {
    let json = cli.json;
    match &cli.command {
        Command::Id { cmd } => id_cmd(json, cmd),
        Command::Agent { cmd } => agent_cmd(json, cmd),
        Command::Authority { cmd } => authority_cmd(json, cmd),
        Command::Config { cmd } => config_cmd(json, cmd),
        Command::Daemon { cmd } => daemon_cmd(json, cmd),
        Command::Presence { cmd } => presence_cmd(json, cmd),
        Command::Pair { cmd } => pair_cmd(json, cmd),
        Command::Status => status_cmd(json),
        Command::Send {
            body,
            to,
            broadcast,
            ctype,
            reply_to,
            topic,
            kind,
            correlation_id,
            supersedes,
            encrypt,
            grant,
            unsigned,
            file,
        } => send_cmd(SendArgs {
            json,
            to,
            body,
            broadcast: *broadcast,
            ctype,
            reply_to,
            topic,
            kind,
            correlation_id,
            supersedes,
            encrypt: *encrypt,
            grant,
            unsigned: *unsigned,
            file,
        }),
        Command::Read {
            consumer,
            limit,
            wait,
            wait_timeout,
            ack,
            follow,
        } => read_cmd(json, consumer, *limit, *wait, *wait_timeout, *ack, *follow),
        Command::Browse {
            limit,
            from,
            to,
            mine,
            all,
        } => browse_cmd(json, *limit, from, to, *mine, *all),
        Command::Log {
            limit,
            from,
            to,
            peer,
        } => log_cmd(json, *limit, from, to, peer),
        Command::Reply {
            msg_id,
            body,
            ctype,
        } => reply_cmd(json, msg_id, body, ctype),
        Command::Rejections {
            limit,
            reason,
            since,
        } => rejections_cmd(json, *limit, reason, since),
        Command::Consumers => consumers_cmd(json),
        Command::Receipts { id, limit, state } => receipts_cmd(json, id, *limit, state),
        Command::Grant {
            subject,
            action,
            scope,
            expiry,
            out,
        } => grant_cmd(json, subject, action, scope, expiry, out),
        Command::Ack { seq, consumer } => ack_cmd(json, *seq, consumer),
    }
}

// --- shared input helpers -------------------------------------------------

/// Read all of stdin as a UTF-8 string.
fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

/// Resolve a token from an optional positional (`-` = stdin) or `--file`.
fn read_token_input(token: &Option<String>, file: &Option<PathBuf>) -> Result<String> {
    if let Some(f) = file {
        return Ok(std::fs::read_to_string(f)?);
    }
    match token.as_deref() {
        Some("-") => read_stdin(),
        Some(t) => Ok(t.to_string()),
        None => Err(Error::Config(
            "provide a token, --file <f>, or '-' to read stdin".into(),
        )),
    }
}

// --- identity -------------------------------------------------------------

fn id_cmd(json: bool, cmd: &IdCmd) -> Result<()> {
    match cmd {
        IdCmd::Generate { name, force } => {
            validate_name(name)
                .map_err(|e| Error::Config(format!("invalid identity name: {e}")))?;
            // Cross-name guard + backup before overwrite (REQ: id-generate guard).
            if let Some((existing_name, existing_fp)) = identity::load_name_fp()? {
                if !force {
                    if existing_name != *name {
                        return Err(Error::IdentityNameMismatch(format!(
                            "an identity '{existing_name}' ({existing_fp}) already exists; \
                             refusing to generate '{name}' — pass --force to replace it"
                        )));
                    }
                    return Err(Error::IdentityExists("use --force to overwrite".into()));
                }
                // Force: back up the displaced identity first.
                let _ = Identity::backup_existing()?;
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
        AgentCmd::Add {
            token,
            file,
            rotate,
        } => {
            let text = read_token_input(token, file)?;
            let parsed = IdentityToken::decode(&text)?;
            let mut ts = TrustStore::load()?;
            // Refuse a silent key change unless --rotate (REQ: agent rotation).
            let old = ts.current_key(&parsed.name);
            let rotated_from = match &old {
                Some(old_key) if *old_key != parsed.public_key => {
                    if !*rotate {
                        return Err(Error::RotationRequired(format!(
                            "agent '{}' is already known with key {}; pass --rotate to replace it \
                             with {}",
                            parsed.name,
                            fingerprint(old_key),
                            parsed.fingerprint()
                        )));
                    }
                    Some(fingerprint(old_key))
                }
                _ => None,
            };
            ts.add_from_token(&parsed);
            ts.save()?;
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                rotated_from: Option<String>,
            }
            let data = Out {
                name: parsed.name.clone(),
                fingerprint: parsed.fingerprint(),
                rotated_from: rotated_from.clone(),
            };
            ok_json(json, data, || match &rotated_from {
                Some(old_fp) => println!(
                    "Rotated '{}' {} -> {}",
                    parsed.name,
                    old_fp,
                    parsed.fingerprint()
                ),
                None => println!("Added '{}' ({})", parsed.name, parsed.fingerprint()),
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

// --- authorities ----------------------------------------------------------

fn authority_cmd(json: bool, cmd: &AuthorityCmd) -> Result<()> {
    match cmd {
        AuthorityCmd::Generate { name, force } => {
            validate_name(name)
                .map_err(|e| Error::Config(format!("invalid authority name: {e}")))?;
            if Authority::exists() && !force {
                return Err(Error::IdentityExists(
                    "an authority key already exists; use --force to overwrite".into(),
                ));
            }
            if Authority::exists() {
                let _ = Authority::backup_existing()?;
            }
            let auth = Authority::generate(name);
            auth.save()?;
            let token = auth.token().encode();
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
                token: String,
            }
            let data = Out {
                name: auth.name.clone(),
                fingerprint: fingerprint(auth.public_key()),
                token: token.clone(),
            };
            ok_json(json, data, || {
                println!(
                    "Generated authority '{}' ({})",
                    auth.name,
                    fingerprint(auth.public_key())
                );
                println!("\nShare this authority token with agents that must trust it:\n{token}");
            });
            Ok(())
        }
        AuthorityCmd::Show => {
            let auth = Authority::load()?;
            #[derive(Serialize)]
            struct Out {
                name: String,
                fingerprint: String,
                token: String,
            }
            let data = Out {
                name: auth.name.clone(),
                fingerprint: fingerprint(auth.public_key()),
                token: auth.token().encode(),
            };
            ok_json(json, data, || {
                println!("name:        {}", auth.name);
                println!("fingerprint: {}", fingerprint(auth.public_key()));
                println!("token:       {}", auth.token().encode());
            });
            Ok(())
        }
        AuthorityCmd::Token => {
            let auth = Authority::load()?;
            let token = auth.token().encode();
            ok_json(json, &token, || println!("{token}"));
            Ok(())
        }
        AuthorityCmd::Add { token, file } => {
            let text = read_token_input(token, file)?;
            let parsed = AuthorityToken::decode(&text)?;
            let mut ts = TrustStore::load()?;
            ts.add_authority_from_token(&parsed);
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
                println!(
                    "Trusted authority '{}' ({})",
                    parsed.name,
                    parsed.fingerprint()
                );
            });
            Ok(())
        }
        AuthorityCmd::List => {
            let ts = TrustStore::load()?;
            #[derive(Serialize)]
            struct Entry {
                name: String,
                fingerprint: String,
            }
            let list: Vec<Entry> = ts
                .list_authorities()
                .into_iter()
                .map(|a| Entry {
                    name: a.name.clone(),
                    fingerprint: a.fingerprint(),
                })
                .collect();
            ok_json(json, &list, || {
                if list.is_empty() {
                    println!("(no trusted authorities)");
                } else {
                    for e in &list {
                        println!("{}  {}", e.fingerprint, e.name);
                    }
                }
            });
            Ok(())
        }
        AuthorityCmd::Remove { name } => {
            let mut ts = TrustStore::load()?;
            let removed = ts.remove_authority(name);
            ts.save()?;
            ok_json(json, removed, || {
                if removed {
                    println!("Removed authority '{name}'");
                } else {
                    println!("'{name}' was not a trusted authority");
                }
            });
            Ok(())
        }
    }
}

// --- grants ---------------------------------------------------------------

fn grant_cmd(
    json: bool,
    subject: &str,
    action: &str,
    scope: &str,
    expiry: &str,
    out: &Option<PathBuf>,
) -> Result<()> {
    let authority = Authority::load()?;
    let claims = GrantClaims {
        id: Ulid::new().to_string(),
        action: action.to_string(),
        scope: scope.to_string(),
        subject: subject.to_string(),
        expiry: expiry.to_string(),
        nonce: Ulid::new().to_string(),
    };
    let sg = grant::mint(&authority, &claims);
    let token = grant::encode_token(&sg);
    if let Some(path) = out {
        std::fs::write(path, &token)?;
    }
    #[derive(Serialize)]
    struct Out {
        id: String,
        subject: String,
        action: String,
        scope: String,
        expiry: String,
        token: String,
    }
    let data = Out {
        id: claims.id.clone(),
        subject: claims.subject.clone(),
        action: claims.action.clone(),
        scope: claims.scope.clone(),
        expiry: claims.expiry.clone(),
        token: token.clone(),
    };
    ok_json(json, data, || {
        println!(
            "Minted grant {} authorizing '{}' to '{}' (scope '{}', expires {})",
            claims.id, claims.subject, claims.action, claims.scope, claims.expiry
        );
        match out {
            Some(p) => println!("wrote token to {}", p.display()),
            None => println!("\n{token}"),
        }
    });
    Ok(())
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
        ConfigCmd::SetSecurity {
            allow_unsigned,
            accept_v1,
            require_encryption,
            auto_receipts,
        } => {
            let mut c = Config::load()?;
            if let Some(v) = allow_unsigned {
                c.allow_unsigned = *v;
            }
            if let Some(v) = accept_v1 {
                c.accept_v1 = *v;
            }
            if let Some(v) = require_encryption {
                c.require_encryption = *v;
            }
            if let Some(v) = auto_receipts {
                c.auto_receipts = *v;
            }
            c.save()?;
            #[derive(Serialize)]
            struct Sec {
                allow_unsigned: bool,
                accept_v1: bool,
                require_encryption: bool,
                auto_receipts: bool,
            }
            let s = Sec {
                allow_unsigned: c.allow_unsigned,
                accept_v1: c.accept_v1,
                require_encryption: c.require_encryption,
                auto_receipts: c.auto_receipts,
            };
            ok_json(json, &s, || {
                println!("allow_unsigned:     {}", s.allow_unsigned);
                println!("accept_v1:          {}", s.accept_v1);
                println!("require_encryption: {}", s.require_encryption);
                println!("auto_receipts:      {}", s.auto_receipts);
            });
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
                allow_unsigned: bool,
                accept_v1: bool,
                require_encryption: bool,
                auto_receipts: bool,
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
                allow_unsigned: c.allow_unsigned,
                accept_v1: c.accept_v1,
                require_encryption: c.require_encryption,
                auto_receipts: c.auto_receipts,
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
                println!(
                    "security: allow_unsigned={} accept_v1={} require_encryption={} \
                     auto_receipts={}",
                    r.allow_unsigned, r.accept_v1, r.require_encryption, r.auto_receipts
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
        DaemonCmd::Start { wait, no_wait } => {
            let agent = local_agent()?;
            if ipc::daemon_running(&agent) {
                return Err(Error::DaemonAlreadyRunning);
            }
            let exe = std::env::current_exe().map_err(Error::Io)?;
            spawn_detached(&exe)?;
            if *no_wait {
                ok_json(json, true, || println!("daemon started"));
                return Ok(());
            }
            // Readiness poll: Ping until Pong or timeout (REQ: Windows service
            // hardening / readiness).
            let secs = wait.unwrap_or(10);
            let deadline = Instant::now() + Duration::from_secs(secs);
            loop {
                if ipc::daemon_running(&agent) {
                    ok_json(json, true, || println!("daemon started"));
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    let tail = tail_log(20);
                    if !tail.is_empty() {
                        eprintln!("--- daemon.log (tail) ---\n{tail}");
                    }
                    return Err(Error::DaemonNotRunning(format!(
                        "daemon did not become ready within {secs}s"
                    )));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
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

/// Read the tail of the daemon log (best-effort) for readiness diagnostics.
fn tail_log(lines: usize) -> String {
    let Ok(path) = crate::paths::log_path() else {
        return String::new();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].join("\n")
}

#[cfg(windows)]
fn spawn_detached(exe: &std::path::Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;

    let base = DETACHED_PROCESS | CREATE_NO_WINDOW;
    let build = |flags: u32| {
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["daemon", "run"])
            .creation_flags(flags)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    };
    // Break away from any controlling job so the daemon outlives the CLI; some
    // sandboxes deny this, so retry without the flag on ACCESS_DENIED.
    match build(base | CREATE_BREAKAWAY_FROM_JOB).spawn() {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            build(base).spawn().map_err(Error::Io)?;
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
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

// --- presence -------------------------------------------------------------

fn presence_cmd(json: bool, cmd: &PresenceCmd) -> Result<()> {
    match cmd {
        PresenceCmd::Set { state, ttl, detail } => {
            hello()?;
            let resp = call(Request::Presence {
                state: state.clone(),
                ttl_secs: *ttl,
                detail: detail.clone(),
            })?;
            render_simple(json, resp, "presence sent")
        }
        PresenceCmd::List => {
            let resp = call(Request::PresenceList)?;
            match resp {
                Response::Presence(rows) => {
                    ok_json(json, &rows, || print_presence(&rows));
                    Ok(())
                }
                Response::Error { message } => Err(Error::Ipc(message)),
                other => render_simple(json, other, "presence"),
            }
        }
    }
}

// --- pairing --------------------------------------------------------------

fn pair_cmd(json: bool, cmd: &PairCmd) -> Result<()> {
    match cmd {
        PairCmd::Start { topic } => {
            hello()?;
            let resp = call(Request::PairStart {
                topic: topic.clone(),
            })?;
            match resp {
                Response::Ok => {
                    ok_json(json, true, || {
                        println!("broadcast your identity on the pairing topic.");
                        println!(
                            "ask the peer to run `agentmsg pair start` too, then compare the \
                             6-digit code from `agentmsg pair list` and run \
                             `agentmsg pair confirm <name>`."
                        );
                    });
                    Ok(())
                }
                Response::Error { message } => Err(Error::Ipc(message)),
                other => render_simple(json, other, "pair start"),
            }
        }
        PairCmd::List => {
            let resp = call(Request::PairList)?;
            match resp {
                Response::Pairs(rows) => {
                    ok_json(json, &rows, || print_pairs(&rows));
                    Ok(())
                }
                Response::Error { message } => Err(Error::Ipc(message)),
                other => render_simple(json, other, "pair list"),
            }
        }
        PairCmd::Confirm { name } => {
            let resp = call(Request::PairConfirm { name: name.clone() })?;
            match resp {
                Response::Ok => {
                    // Surface the resulting trust-store fingerprint for the prompt.
                    let fp = TrustStore::load()
                        .ok()
                        .and_then(|ts| ts.list().into_iter().find(|a| a.name == *name))
                        .map(|a| a.fingerprint())
                        .unwrap_or_default();
                    #[derive(Serialize)]
                    struct Out {
                        name: String,
                        fingerprint: String,
                    }
                    let data = Out {
                        name: name.clone(),
                        fingerprint: fp.clone(),
                    };
                    ok_json(json, data, || {
                        println!("paired with {name} ({fp}) — added to trust store");
                    });
                    Ok(())
                }
                Response::Error { message } => Err(Error::Ipc(message)),
                other => render_simple(json, other, "pair confirm"),
            }
        }
    }
}

fn print_pairs(rows: &[PendingPairView]) {
    if rows.is_empty() {
        println!("(no peers pairing — ask the peer to run `agentmsg pair start`)");
        return;
    }
    for p in rows {
        let kem = if p.kem { " +kem" } else { "" };
        println!(
            "{name}  SAS {sas}  ({fp}{kem})\n    compare the SAS with the peer, then: \
             agentmsg pair confirm {name}",
            name = p.name,
            sas = p.sas,
            fp = p.fingerprint,
        );
    }
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
                println!(
                    "security:  allow_unsigned={} accept_v1={} require_encryption={} \
                     auto_receipts={}",
                    info.allow_unsigned,
                    info.accept_v1,
                    info.require_encryption,
                    info.auto_receipts
                );
                if !info.presence.is_empty() {
                    println!("presence:  {} record(s)", info.presence.len());
                }
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

/// Grouped `send` arguments (keeps the dispatcher tidy).
struct SendArgs<'a> {
    json: bool,
    to: &'a Option<String>,
    body: &'a Option<String>,
    broadcast: bool,
    ctype: &'a str,
    reply_to: &'a Option<String>,
    topic: &'a Option<String>,
    kind: &'a str,
    correlation_id: &'a Option<String>,
    supersedes: &'a Option<String>,
    encrypt: bool,
    grant: &'a Option<String>,
    unsigned: bool,
    file: &'a Option<String>,
}

/// Resolve the message body from `--file`/stdin or the positional argument.
fn resolve_body(body: &Option<String>, file: &Option<String>) -> Result<String> {
    if let Some(f) = file {
        if f == "-" {
            return read_stdin();
        }
        return Ok(std::fs::read_to_string(f)?);
    }
    body.clone()
        .ok_or_else(|| Error::Config("provide a message body or --file <f>".into()))
}

/// Resolve a grant token from `<token>` or `@<file>`.
fn resolve_grant(grant: &Option<String>) -> Result<Option<String>> {
    match grant {
        None => Ok(None),
        Some(g) => {
            if let Some(path) = g.strip_prefix('@') {
                Ok(Some(std::fs::read_to_string(path)?.trim().to_string()))
            } else {
                Ok(Some(g.clone()))
            }
        }
    }
}

fn send_cmd(args: SendArgs) -> Result<()> {
    let json = args.json;
    let recipient = if args.broadcast {
        BROADCAST.to_string()
    } else {
        args.to
            .clone()
            .ok_or_else(|| Error::Config("specify a recipient or --broadcast".into()))?
    };
    let body = resolve_body(args.body, args.file)?;
    let grant = resolve_grant(args.grant)?;

    hello()?;
    let resp = call(Request::Send {
        to: recipient,
        ctype: args.ctype.to_string(),
        body,
        in_reply_to: args.reply_to.clone(),
        topic: args.topic.clone(),
        kind: args.kind.to_string(),
        correlation_id: args.correlation_id.clone(),
        supersedes: args.supersedes.clone(),
        encrypt: args.encrypt,
        grant,
        unsigned: args.unsigned,
    })?;
    render_sent(json, resp)
}

fn render_sent(json: bool, resp: Response) -> Result<()> {
    match resp {
        Response::Sent { id, delivery_state } => {
            #[derive(Serialize)]
            struct Out {
                id: String,
                delivery_state: String,
            }
            let data = Out {
                id: id.clone(),
                delivery_state: delivery_state.clone(),
            };
            ok_json(json, data, || println!("sent {id} ({delivery_state})"));
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
    wait_timeout: Option<u64>,
    ack: bool,
    follow: bool,
) -> Result<()> {
    let consumer = default_consumer(consumer)?;
    // A bounded `--wait` deadline: `None`/0 means wait indefinitely.
    let deadline = wait_timeout
        .filter(|s| *s > 0)
        .map(|s| Instant::now() + Duration::from_secs(s));
    // Drain the queue first.
    let (msgs, warning) = loop {
        let resp = call(Request::Read {
            consumer: consumer.clone(),
            limit,
        })?;
        match resp {
            Response::Messages {
                msgs: m,
                consumer_warning,
            } => {
                if m.is_empty() && wait && !follow {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Err(Error::Timeout(format!(
                            "no message within {}s",
                            wait_timeout.unwrap_or(0)
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
                break (m, consumer_warning);
            }
            Response::Error { message } => return Err(Error::Ipc(message)),
            other => return render_simple(json, other, "read"),
        }
    };
    if let Some(w) = &warning {
        eprintln!("warning: {w}");
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

    if follow {
        follow_stream(json, &consumer, ack)?;
    }
    Ok(())
}

/// Open a streaming subscription and print frames until the daemon closes it
/// (REQ: read --follow + IPC stream).
fn follow_stream(json: bool, consumer: &str, ack: bool) -> Result<()> {
    let agent = local_agent()?;
    let mut conn = ipc::subscribe(&agent, consumer, ack)?;
    loop {
        let bytes = match ipc::read_frame(&mut conn) {
            Ok(b) => b,
            // A clean close at a frame boundary (EOF) is a normal stream end.
            // Any other I/O error (connection reset, broken pipe, a truncated
            // frame from a daemon that crashed mid-write) is a real failure and
            // must surface as a non-zero exit, not a silent success.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(Error::Ipc(format!("follow stream ended unexpectedly: {e}"))),
        };
        let frame: StreamFrame = serde_json::from_slice(&bytes)?;
        match frame {
            StreamFrame::Message(m) => {
                if json {
                    println!("{}", serde_json::to_string(&m)?);
                } else {
                    print_messages(std::slice::from_ref(&m));
                }
            }
            StreamFrame::Lagged { dropped } => {
                eprintln!("warning: subscription lagged, {dropped} message(s) dropped");
            }
        }
    }
}

fn browse_cmd(
    json: bool,
    limit: i64,
    from: &Option<String>,
    to: &Option<String>,
    mine: bool,
    all: bool,
) -> Result<()> {
    let to = if mine {
        Some(Identity::load()?.name)
    } else {
        to.clone()
    };
    // `--all` spans both directions; the daemon's Browse request is inbound-only,
    // so route it through the chronological transcript instead (see deviations).
    let resp = if all {
        call(Request::Transcript {
            limit,
            from: from.clone(),
            to,
            peer: None,
        })?
    } else {
        call(Request::Browse {
            limit,
            from: from.clone(),
            to,
        })?
    };
    match resp {
        Response::Messages { msgs: m, .. } => {
            ok_json(json, &m, || print_messages(&m));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "browse"),
    }
}

fn log_cmd(
    json: bool,
    limit: i64,
    from: &Option<String>,
    to: &Option<String>,
    peer: &Option<String>,
) -> Result<()> {
    let resp = call(Request::Transcript {
        limit,
        from: from.clone(),
        to: to.clone(),
        peer: peer.clone(),
    })?;
    match resp {
        Response::Messages { msgs: m, .. } => {
            ok_json(json, &m, || print_messages(&m));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "log"),
    }
}

fn reply_cmd(json: bool, msg_id: &str, body: &str, ctype: &str) -> Result<()> {
    hello()?;
    let resp = call(Request::Reply {
        msg_id: msg_id.to_string(),
        ctype: ctype.to_string(),
        body: body.to_string(),
    })?;
    render_sent(json, resp)
}

fn rejections_cmd(
    json: bool,
    limit: i64,
    reason: &Option<String>,
    since: &Option<String>,
) -> Result<()> {
    let resp = call(Request::Rejections {
        limit,
        reason: reason.clone(),
        since: since.clone(),
    })?;
    match resp {
        Response::Rejections(rows) => {
            ok_json(json, &rows, || print_rejections(&rows));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "rejections"),
    }
}

fn consumers_cmd(json: bool) -> Result<()> {
    let resp = call(Request::Consumers)?;
    match resp {
        Response::Consumers(rows) => {
            ok_json(json, &rows, || print_consumers(&rows));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "consumers"),
    }
}

fn receipts_cmd(json: bool, id: &Option<String>, limit: i64, state: &Option<String>) -> Result<()> {
    let resp = call(Request::Receipts {
        id: id.clone(),
        limit,
        state: state.clone(),
    })?;
    match resp {
        Response::Messages { msgs: m, .. } => {
            ok_json(json, &m, || print_receipts(&m));
            Ok(())
        }
        Response::Error { message } => Err(Error::Ipc(message)),
        other => render_simple(json, other, "receipts"),
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
        let enc = if m.encrypted { " [enc]" } else { "" };
        println!(
            "#{seq} [{ts}] {from} -> {to} ({ctype}/{kind}){enc}{reply}\n    {body}",
            seq = m.seq,
            ts = m.ts,
            from = m.from,
            to = m.to,
            ctype = m.ctype,
            kind = m.kind,
            body = m.body,
        );
    }
}

fn print_receipts(msgs: &[crate::store::StoredMsg]) {
    if msgs.is_empty() {
        println!("(no outbound messages)");
        return;
    }
    for m in msgs {
        println!(
            "{id} {state} (to {to}) sent={ts} delivered={d} read={r}",
            id = m.id,
            state = m.delivery_state,
            to = m.to,
            ts = m.ts,
            d = m.delivered_ts.clone().unwrap_or_else(|| "-".into()),
            r = m.read_ts.clone().unwrap_or_else(|| "-".into()),
        );
    }
}

fn print_rejections(rows: &[RejectionRow]) {
    if rows.is_empty() {
        println!("(no rejections)");
        return;
    }
    for r in rows {
        let sender = r.claimed_sender.clone().unwrap_or_else(|| "?".into());
        let topic = r.topic.clone().unwrap_or_default();
        println!(
            "#{seq} [{at}] {reason} from={sender} topic={topic} — {detail}",
            seq = r.seq,
            at = r.at,
            reason = r.reason,
            detail = r.detail,
        );
    }
}

fn print_consumers(rows: &[ConsumerRow]) {
    if rows.is_empty() {
        println!("(no consumers)");
        return;
    }
    for c in rows {
        let last = c.last_read_at.clone().unwrap_or_else(|| "-".into());
        println!(
            "{consumer}  last_seq={last_seq} unread={unread} last_read={last}",
            consumer = c.consumer,
            last_seq = c.last_seq,
            unread = c.unread,
        );
    }
}

fn print_presence(rows: &[PresenceRow]) {
    if rows.is_empty() {
        println!("(no presence records)");
        return;
    }
    for p in rows {
        let state = p.state.clone().unwrap_or_else(|| "?".into());
        let source = p.source.clone().unwrap_or_default();
        let detail = p
            .detail
            .as_ref()
            .map(|d| format!(" — {d}"))
            .unwrap_or_default();
        println!(
            "{agent}  {state} (source={source}, seq={seq}, last_seen={last}){detail}",
            agent = p.agent,
            seq = p.seq,
            last = p.last_seen,
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
