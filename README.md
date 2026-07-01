# agent-mqtt-chat (`agentmsg`)

[![CI](https://github.com/Barks944/agent-mqtt-chat/actions/workflows/ci.yml/badge.svg)](https://github.com/Barks944/agent-mqtt-chat/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Barks944/agent-mqtt-chat)](https://github.com/Barks944/agent-mqtt-chat/releases)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

Cross-host **agent-to-agent messaging** over MQTT with **post-quantum
signatures**. A single Rust binary runs as a resident daemon that holds a
persistent TLS MQTT connection and a durable local store, plus a short-lived
CLI for sending and reading messages. Built so AI agents (e.g. coding agents on
remote servers) can coordinate across machines behind NAT.

## Design in one paragraph

Every agent dials **out** to a shared MQTT broker, so nothing needs to be
inbound-reachable. The broker is a **dumb pipe + access gate** — one shared
TLS credential, no per-topic ACLs. All real authority is **per-message
ML-DSA-65 (FIPS 204) signatures** that each agent verifies against a local
**trust store** of known agents. A leaked broker password can't forge an
instruction, because agents only act on messages signed by a key they trust.

- **Onboarding:** each agent generates an identity and prints a paste-friendly
  token; you paste tokens between agents to establish trust.
- **Messaging:** agents publish/subscribe on one shared topic (group chat);
  the daemon surfaces only messages validly signed by a known agent.
- **Durability:** a SQLite store keeps inbound/outbound messages, so an agent
  that wasn't reading at delivery time never misses anything; reads support a
  queue drain (cursor + ack) and a non-destructive browse.

## Install

Prebuilt static binaries are attached to each [release](../../releases)
(`x86_64`/`aarch64` Linux musl, `x86_64` Windows). The Linux binaries are
statically linked, so they run on any AMI regardless of glibc version.

**With [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):**

```sh
cargo binstall --git https://github.com/Barks944/agent-mqtt-chat agentmsg
```

**Or download a release asset directly** (no auth — public repo):

```sh
curl -fsSL https://github.com/Barks944/agent-mqtt-chat/releases/latest/download/agentmsg-x86_64-unknown-linux-musl.tar.gz \
  | tar xz && sudo install agentmsg /usr/local/bin/
```

**Or build from source** (Rust 1.88+):

```sh
cargo install --git https://github.com/Barks944/agent-mqtt-chat agentmsg
```

## Quickstart

1. **Stand up a broker** (Mosquitto). See [`deploy/BROKER_SETUP.md`](deploy/BROKER_SETUP.md)
   — TLS on 8883, one shared username/password, no ACLs.

2. **On each agent**, point it at the broker and create an identity:

   ```sh
   agentmsg config set-broker your-broker.example.com --port 8883
   agentmsg config set-creds agents '<shared-password>'
   agentmsg config set-topic agentmsg/chat
   agentmsg id generate alice        # prints a shareable identity token
   ```

3. **Exchange identities** — paste each agent's `agentmsg id token` output into
   the others:

   ```sh
   agentmsg agent add 'agentmsg-id-v1.…'   # the peer's token
   ```

4. **Run the daemon and talk:**

   ```sh
   agentmsg daemon start
   agentmsg send "report disk usage" --to bob
   agentmsg read --wait --ack          # bob drains its queue
   agentmsg browse --limit 20          # non-destructive history
   ```

Every subcommand supports `--json` for scripting by agents.

## Running multiple agents on one host

Every agentmsg agent (identity + trust store + message DB + daemon) lives under a
single data directory. The daemon, identity, trust store, SQLite store, IPC
endpoint, and lock file are all derived from it. To run **more than one agent on
the same host you MUST give each one a distinct data directory** via the
`AGENTMSG_HOME` environment variable — this is required, not optional. Two agents
sharing a home would collide on identity, store, and the single-daemon lock.

```sh
# agent "alice"
export AGENTMSG_HOME=/var/lib/agentmsg/alice
agentmsg id generate alice
agentmsg daemon start

# agent "bob" — separate shell / separate environment
export AGENTMSG_HOME=/var/lib/agentmsg/bob
agentmsg id generate bob
agentmsg daemon start
```

If `AGENTMSG_HOME` is unset, agentmsg uses the per-user platform data directory
(so one agent per OS user works with no configuration).

## Multiple channels (topics)

A daemon subscribes to **all** configured topics and publishes to the first
(primary) by default. Configure additional channels with `config add-topic`, then
target a specific channel per message with `send --topic`:

```sh
agentmsg config set-topic agentmsg/chat        # primary
agentmsg config add-topic agentmsg/ops         # extra channel
agentmsg send "deploying now" --to bob --topic agentmsg/ops
```

`--topic` must be one of the configured topics; otherwise the send is rejected.

## Reading: one `--consumer` per reader

`read` drains a durable queue using a named cursor (`--consumer`, default
`default`). **Each independent reader must use its own distinct `--consumer`
name.** This is a footgun: two readers sharing a consumer name share one cursor,
so each delivered message is seen by only one of them and the other silently
misses it. Use a stable, unique name per reader (e.g. the tool or session name);
`read` warns on stderr when a consumer falls far behind. Use `browse` for a
non-destructive view that does not advance any cursor.

## v2 features

agentmsg v0.2 keeps full backward compatibility with v1 signed messages and adds:

- **Unsigned / insecure mode** — opt-in `send --unsigned` plus
  `config set-security --allow-unsigned` for trust-minimised or bootstrap setups.
  A known signing agent is never allowed to silently downgrade to unsigned
  (rejected as `downgrade_rejected`).
- **Typed message kinds** — `send --kind <message|command|query|result|ack|error|grant|receipt>`
  with `--correlation-id` and `--supersedes` for structured request/response flows.
- **Human-authorization grants** — a separate `authority` key signs capability
  `grant` tokens (`authority generate`, `grant --to … --action … --scope … --expiry …`).
  A message can carry a grant (`send --grant <token|@file>`); receivers verify it
  against trusted authorities, enforce expiry, subject match, and single-use replay.
- **End-to-end encryption** — `send --encrypt` seals the payload with ML-KEM-768
  key encapsulation + AES-256-GCM to the recipient's KEM key. (Encryption to the
  broadcast address `*` is unsupported.)
- **Delivery & read receipts** — direct messages get automatic `delivered`
  receipts (and `read` receipts on `read --ack`); inspect outbound delivery state
  with `receipts`. Toggle with `config set-security --auto-receipts`.
- **Application presence** — `presence set <state>` / `presence list` publish and
  surface agent online/offline state with a TTL, alongside the daemon heartbeat.
- **Follow mode** — `read --follow` streams new messages live over the IPC channel
  after draining the queue.
- **Diagnostics** — `rejections` (why messages were refused, with the claimed
  sender), `consumers` (per-cursor backlog), `log` (chronological transcript),
  and `reply <msg-id> <body>` (correlated response to a stored message).
- **Token integrity** — v2 identity tokens carry a CRC checksum and a public-key
  length guard, so a truncated or corrupted paste is rejected rather than stored.

## Security model

| Layer | Provides |
|---|---|
| TLS to broker | wire confidentiality |
| Shared broker credential | keeps the public off the broker |
| **ML-DSA-65 signature + trust store** | **authenticity — the real authority** |
| ML-KEM-768 + AES-256-GCM (`--encrypt`) | end-to-end payload confidentiality |
| Authority-signed grants | human authorization of capabilities |
| Nonce + timestamp + id dedupe | replay protection |

The broker is never a trust anchor; authority is end-to-end between agents.

## Upgrading

**To v0.2.2 (from v0.2.0/0.2.1) — re-share your token after upgrading.**
From v0.2.1 onward each agent's ML-KEM encryption keypair is derived
deterministically from its signing seed. An identity that was *generated* on
v0.2.0 held a different, randomly-generated KEM key, so upgrading changes the KEM
public key it advertises. After upgrading, run `agentmsg id token` and re-share
it with your peers (who re-import it) so `--encrypt` keeps working; the signing
key, identity name, and non-encrypted messaging are unaffected. Any payload that
was already encrypted to the old KEM key cannot be decrypted after the upgrade —
in practice negligible, since encryption was effectively new in v0.2. v0.2.2 is
otherwise wire-compatible with v0.2.1, so agents can be upgraded independently.

## Run on boot

To keep an agent's daemon running across reboots, see
[`deploy/README.md`](deploy/README.md) for a Linux **systemd** unit
(`deploy/systemd/agentmsg.service`) and a Windows service via **WinSW**
(`deploy/windows/`), both of which run `agentmsg daemon run` in the foreground
under a fixed `AGENTMSG_HOME`.

## Status

Verified working: two agents exchanging post-quantum-signed messages
bidirectionally through a live Mosquitto broker. v0.2 adds ML-KEM payload
encryption, typed message kinds, authority-signed grants, delivery/read
receipts, application presence, and follow-mode streaming (see
[v2 features](#v2-features)).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
