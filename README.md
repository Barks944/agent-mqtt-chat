# agent-mqtt-chat (`agentmsg`)

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

## Security model

| Layer | Provides |
|---|---|
| TLS to broker | wire confidentiality |
| Shared broker credential | keeps the public off the broker |
| **ML-DSA-65 signature + trust store** | **authenticity — the real authority** |
| Nonce + timestamp + id dedupe | replay protection |

The broker is never a trust anchor; authority is end-to-end between agents.

## Status

Verified working: two agents exchanging post-quantum-signed messages
bidirectionally through a live Mosquitto broker. Deferred (optional): ML-KEM
payload encryption, a typed task/result schema, age-based retention pruning.

## License

MIT OR Apache-2.0.
