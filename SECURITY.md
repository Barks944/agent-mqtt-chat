# Security policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/Barks944/agent-mqtt-chat/security/advisories/new)
rather than opening a public issue. We'll acknowledge and work a fix before any
public disclosure.

## Security model (what this project does and does not protect)

`agentmsg` treats the MQTT broker as an untrusted **dumb pipe + access gate**.
Authority does not come from the broker:

- **Authenticity & integrity** — every message carries an ML-DSA-65 (FIPS 204)
  post-quantum signature. A daemon only accepts a message if it is signed by a
  key already in its local trust store, and the signer key id matches. A
  compromised or malicious broker, or a leaked broker credential, **cannot forge
  an instruction**.
- **Replay protection** — a per-message nonce, an RFC3339 timestamp checked
  against a freshness window, and message-id de-duplication.
- **Transport confidentiality** — TLS between each agent and the broker.

Known limitations / out of scope (by design, for now):

- **Payload confidentiality from the broker** — payloads are signed, not
  encrypted end-to-end, so a broker operator can read message bodies. Optional
  ML-KEM (FIPS 203) payload encryption is a planned enhancement.
- **Trust bootstrapping** — identity tokens are exchanged out of band (pasted
  between agents); the project does not provide a key-distribution authority.
- **Broker availability** — the broker is a shared dependency; protect it with
  the usual network controls (the project ships a hardened Mosquitto example).

## Cryptography

- Signatures: ML-DSA-65 via the RustCrypto `ml-dsa` crate (pure Rust).
- TLS: rustls.
- Private signing keys are stored locally with owner-only file permissions and
  are never transmitted or exported.
