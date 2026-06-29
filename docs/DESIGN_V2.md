# agentmsg v0.2 — unified implementation contract

This is the single source of truth for the v0.2 work (issues #1–#11). Every
implementation stage MUST implement to the exact signatures below so the seams
line up. Bottom-up layering: each stage only calls layers below it.

Guiding invariant (REQ-0055, unchanged): a signed message's signature is computed
over the EXACT transmitted inner bytes and verified over the EXACT received inner
bytes. v1 and v2 need NOT be byte-identical; each side signs/verifies what it
actually transmits/receives.

---

## Layer 0 — deps, errors, config

### Cargo.toml
Add: `crc32fast = "1"`, `ml-kem = "0.2"`, `aes-gcm = "0.10"`.
(If a crate version is unavailable, pick the nearest published 0.x and adapt.)

### src/error.rs — new `Error` variants
```
IdentityNameMismatch(String)   // exit 4
NoAuthority                    // exit 4
TokenCorrupt(String)           // exit 5  (checksum/length failure)
RotationRequired(String)       // exit 5
NotAnAuthorityToken            // exit 5
```
Wire these into `cli::exit_code` (codes in comments above).

### src/error.rs — new `RejectReason` variants (+ `code()`)
```
UnsignedNotAllowed   => "unsigned_not_allowed"
DowngradeRejected    => "downgrade_rejected"
UnknownAuthority     => "unknown_authority"
InvalidGrant         => "invalid_grant"
GrantExpired         => "grant_expired"
GrantSubjectMismatch => "grant_subject_mismatch"
DecryptFailed        => "decrypt_failed"
UnknownRecipientKey  => "unknown_recipient_key"
EncBroadcastUnsupported => "enc_broadcast_unsupported"
ReplayedGrant        => "replayed_grant"
```

### src/error.rs — `RejectInfo`
```rust
pub struct RejectInfo { pub reason: RejectReason, pub claimed_sender: Option<String> }
impl From<RejectReason> for RejectInfo { /* claimed_sender: None */ }
```

### src/config.rs — new fields (all `#[serde(default)]`)
```
allow_unsigned: bool      (default false)
accept_v1: bool           (default true)
require_encryption: bool  (default false)
auto_receipts: bool       (default true)
```
Add to `Default`, to `config show` (Redacted), and a new CLI `config set-security`.

---

## Layer 1 — wire.rs (KEYSTONE; sole owner of envelope types)

Constants:
```
PROTOCOL_VERSION: u8 = 2;
ALG_ML_DSA_65 = "ML-DSA-65";  ALG_NONE = "none";  ALG_KEM_AEAD = "ML-KEM-768.AES-256-GCM";
CTYPE_TEXT, CTYPE_JSON (existing)
CTYPE_PRESENCE = "application/agentmsg-presence"
CTYPE_RECEIPT  = "application/agentmsg-receipt"
```

```rust
#[derive(Serialize,Deserialize,Clone,Copy,PartialEq,Eq,Debug,Default)]
#[serde(rename_all="snake_case")]
pub enum MsgKind { #[default] Message, Command, Query, Result, Ack, Error, Grant, Receipt }

pub struct Wrapper {
    pub v: u8,
    pub alg: String,
    #[serde(default, skip_serializing_if="Option::is_none")] pub kid: Option<String>,
    pub msg: String,
    #[serde(default, skip_serializing_if="Option::is_none")] pub sig: Option<String>,
}

pub struct Inner {
    pub id: String, pub v: u8, pub from: String, pub to: String,
    pub ts: String, pub nonce: String, pub ctype: String,
    #[serde(default, skip_serializing_if="Option::is_none")] pub in_reply_to: Option<String>,
    pub body: String,
    #[serde(default)] pub kind: MsgKind,
    #[serde(default, skip_serializing_if="Option::is_none")] pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if="Option::is_none")] pub supersedes: Option<String>,
    #[serde(default, skip_serializing_if="Option::is_none")] pub enc: Option<EncInfo>,
    #[serde(default, skip_serializing_if="Option::is_none")] pub grant: Option<SignedGrant>,
    #[serde(default, skip_serializing_if="Option::is_none")] pub receipt: Option<Receipt>,
}

pub struct EncInfo { pub alg:String, pub kem_ct:String, pub recipient_kid:String, pub nonce:String, pub ptype:String }
pub struct SignedGrant { pub alg:String, pub authority_kid:String, pub grant:String, pub sig:String }
pub struct Receipt { pub ref_id:String, pub status:ReceiptStatus }
#[serde(rename_all="snake_case")] pub enum ReceiptStatus { Delivered, Read }
```
Keep `fingerprint`, `make_kid`, `split_kid`, `b64`, `unb64`, `to_bytes`, `from_bytes`,
`inner_bytes`, `sig_bytes`, `parse_inner`, `is_broadcast`, `addressed_to`. Existing
unit tests must be updated for `kid`/`sig` now being `Option`.

GrantClaims (lives in grant.rs, serialized into SignedGrant.grant b64):
```rust
pub struct GrantClaims { pub id:String, pub action:String, pub scope:String,
    pub subject:String, pub expiry:String, pub nonce:String }
```

---

## Layer 2 — crypto / kem / grant / identity / token / trust / authority

### src/crypto.rs (existing `verify` unchanged) — keep PUBLIC_KEY_LEN=1952.

### src/kem.rs (NEW) — ML-KEM-768 + AES-256-GCM
```rust
pub const KEM_PK_LEN: usize = /* ml-kem-768 ek length */;
pub fn generate() -> (Vec<u8> /*dk seed or encoded dk*/, Vec<u8> /*ek*/);
pub fn ek_from_seed(seed:&[u8]) -> Vec<u8>;          // derive ek for token if storing seed
pub fn kem_fingerprint(ek:&[u8]) -> String;          // reuse wire::fingerprint
// Encapsulate to recipient ek -> (kem_ct, shared_secret); decapsulate(dk, kem_ct)->ss
pub fn encapsulate(ek:&[u8]) -> Option<(Vec<u8>, [u8;32])>;
pub fn decapsulate(dk:&[u8], kem_ct:&[u8]) -> Option<[u8;32]>;
// AEAD: seal(key,nonce,aad,pt)->ct ; open(key,nonce,aad,ct)->Option<pt>
pub fn seal(key:&[u8;32], nonce:&[u8;12], aad:&[u8], pt:&[u8]) -> Vec<u8>;
pub fn open(key:&[u8;32], nonce:&[u8;12], aad:&[u8], ct:&[u8]) -> Option<Vec<u8>>;
```
Implementation note: persist ML-KEM via a stored 64-byte seed (d||z) if the crate
supports it, else store the encoded decapsulation key. AAD = the inner routing
fields canonically: `format!("{}|{}|{}|{}", inner.id, inner.from, inner.to, inner.ts)`.

### src/grant.rs (NEW)
```rust
pub fn mint(authority:&Authority, claims:&GrantClaims) -> SignedGrant;  // sign claims bytes
pub fn verify(sg:&SignedGrant, authorities:&TrustStore) -> Result<GrantClaims, RejectReason>;
// verify: resolve authority_kid name in authorities, fp match, ML-DSA verify sig over
// decoded grant bytes, parse claims, check expiry (RFC3339, not past). Replay/subject
// checks happen in message::verify_incoming (needs Inner.from + store).
pub fn encode_token(sg:&SignedGrant) -> String;  // "agentmsg-grant-v1.<b64 json>"
pub fn decode_token(s:&str) -> Result<SignedGrant, Error>;
```

### src/identity.rs — add ML-KEM keypair alongside ML-DSA
- `IdentityFile` gains `kem_seed: Option<String>` (`#[serde(default)]`; old files load,
  then `save()` backfills). `Identity` gains `kem_dk: Vec<u8>`, `kem_ek: Vec<u8>`.
- `generate` makes both keypairs. `token()` returns a v2 token carrying pk + kem_ek.
- Add `kem_ek()`, `kem_dk()`, `kem_fingerprint()`.
- `save()`: if a DIFFERENT identity exists, callers guard; `save()` itself unconditional.
- Add `pub fn backup_existing() -> Result<Option<String>>`: if identity.json exists,
  copy to `identity.json.bak-<fp>` (owner-only perms) and return the fp.
- Add `pub fn load_name_fp() -> Result<Option<(String,String)>>` (name+fp without full load fail).

### src/authority.rs (NEW) — mirrors identity for a human authority key (ML-DSA only)
```rust
pub struct Authority { pub name:String, signing_key, public_key:Vec<u8> }
generate/save/load/exists/token/sign/public_key/kid, file = authority.json,
backup to authority.json.bak-<fp>. Token prefix "agentmsg-auth-v2.".
```

### src/token.rs — v2 + checksum + length guard
- `TOKEN_PREFIX_V2 = "agentmsg-id-v2."`, keep v1 prefix for decode.
- `TokenBodyV2 { name, pk, kem_pk: Option<String> }`.
- Encode: `"{V2PREFIX}{b64body}.{b64 crc32(b64body bytes)}"`.
- `IdentityToken { name, public_key, kem_public_key: Option<Vec<u8>> }`.
- `decode`: accept v1 (no crc) and v2 (verify crc → `TokenCorrupt`). BOTH enforce
  `public_key.len()==1952` else `Error::TokenCorrupt("public key is N bytes, expected 1952 — token truncated/corrupted")`.
- `encode()` emits v2.

### src/trust.rs — agents + authorities; store kem keys
- `KnownAgentRecord` gains `kem_pk: Option<String>` (`#[serde(default)]`).
- `KnownAgent` gains `kem_public_key: Option<Vec<u8>>`.
- `TrustStore` gains `authorities: BTreeMap<String,KnownAgentRecord>` (`#[serde(default, skip_serializing_if="BTreeMap::is_empty")]`).
- New: `add_authority_from_token`, `authority_public_key(name)`, `remove_authority`,
  `list_authorities`, `current_key(name)->Option<Vec<u8>>` (for rotation diff),
  `kem_public_key(name)`.
- `add_from_token` stores kem_pk too.

---

## Layer 3 — message.rs

```rust
pub struct BuildOpts<'a> {
  pub to:&'a str, pub ctype:&'a str, pub body:&'a str, pub kind:MsgKind,
  pub in_reply_to:Option<String>, pub correlation_id:Option<String>,
  pub supersedes:Option<String>, pub grant:Option<SignedGrant>,
  pub receipt:Option<Receipt>,
  pub encrypt_to:Option<Vec<u8>>,  // recipient kem ek; None=cleartext
  pub unsigned:bool,
}
pub fn build(id:&Identity, opts:&BuildOpts) -> Result<(Inner, Wrapper), RejectReason>;
// builds Inner; if encrypt_to: seal body, set enc, body=b64(ct); if unsigned:
// alg=none, kid/sig=None; else sign exact inner bytes, kid=Some, sig=Some.
// reject encrypt_to with to=="*" => EncBroadcastUnsupported.

pub fn verify_incoming(raw:&[u8], me:&Identity, trust:&TrustStore,
    cfg_freshness:i64, max_payload:usize, allow_unsigned:bool, accept_v1:bool)
    -> Result<Inner, RejectInfo>;
```
Pipeline:
1. parse wrapper; `claimed_sender = wrapper.kid.and_then(|k| split_kid).0`.
2. version: v1 → if !accept_v1 reject UnsupportedVersion(1); else legacy signed path.
   v>2 → UnsupportedVersion. v2 → continue.
3. alg: `none` → unsigned path: require allow_unsigned else UnsignedNotAllowed; if the
   claimed sender (inner.from) is a KNOWN signing agent → DowngradeRejected.
   `ML-DSA-65` → signed path (as today). other → UnsupportedAlg.
4. signed: resolve signer in trust, kid fp match, verify sig over inner bytes.
5. parse inner; `inner.from==kid_name` (signed) ; size; freshness.
6. if `inner.enc`: decapsulate with `me.kem_dk()` (recipient_kid must match my kem fp
   else UnknownRecipientKey), AEAD-open with AAD → replace body with plaintext, set
   ctype=enc.ptype. Failure → DecryptFailed.
7. if `inner.grant`: `grant::verify` against authorities (UnknownAuthority/InvalidGrant/
   GrantExpired); require `claims.subject==inner.from` else GrantSubjectMismatch.
   (Replay check via store happens in daemon: store.seen_grant(claims.id).)
8. return inner. claimed_sender carried in every RejectInfo where known.

Update existing unit tests to the new signatures.

---

## Layer 4 — store.rs (owns all schema)

Migration: in `open()`, read `PRAGMA user_version`. If 0 and `messages` table exists →
treat as v1 and run v2 ALTER block; if fresh → run full SCHEMA; set `user_version=2`.
Use `CREATE TABLE IF NOT EXISTS` + idempotent ALTERs.

v2 additions:
```
messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'message';
messages ADD COLUMN correlation_id TEXT;  messages ADD COLUMN supersedes TEXT;
messages ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0;
messages ADD COLUMN delivery_state TEXT NOT NULL DEFAULT 'none';
messages ADD COLUMN broker_ack_ts TEXT; messages ADD COLUMN delivered_ts TEXT; messages ADD COLUMN read_ts TEXT;
rejections ADD COLUMN claimed_sender TEXT; rejections ADD COLUMN topic TEXT;
cursors ADD COLUMN updated_at TEXT;
CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
CREATE TABLE presence(agent TEXT PRIMARY KEY, state TEXT, source TEXT, ttl_secs INTEGER,
   detail TEXT, seq INTEGER NOT NULL DEFAULT 0, last_seen TEXT NOT NULL, updated_at TEXT);
CREATE TABLE seen_grants(grant_id TEXT PRIMARY KEY, at TEXT NOT NULL DEFAULT (datetime('now')));
```
`StoredMsg` gains: `kind:String`, `correlation_id/supersedes:Option<String>`,
`encrypted:bool`(skip default), `delivery_state:String`,
`broker_ack_ts/delivered_ts/read_ts:Option<String>` (skip none). Update `row_to_msg`
and ALL select column lists + insert column lists.

New/changed methods (exact names the upper layers call):
```
insert_inbound(&Inner,&str) -> Result<Option<i64>>   // Some(seq) if inserted, None dup
insert_outbound_log(&Inner,&str) -> Result<()>        // delivery_state='pending'
message_by_seq(i64)->Result<Option<StoredMsg>>
get_message(&str id)->Result<Option<StoredMsg>>
mark_delivered(id) -> also set delivery_state='sent',broker_ack_ts (existing DELETE outbox kept)
apply_delivery_receipt(orig_id,ts); apply_read_receipt(orig_id,ts); mark_failed(id)
record_rejection(&RejectReason, claimed_sender:Option<&str>, topic:&str, detail:&str)
rejections(limit, reason:Option<&str>, since:Option<&str>) -> Vec<RejectionRow>
transcript(limit, from:Option<&str>, to:Option<&str>, peer:Option<&str>) -> Vec<StoredMsg>  // ASC both dirs
browse(limit, from, to, direction:&str)  // "in"|"out"|"all"; default callers pass "in"
consumers() -> Vec<ConsumerRow{consumer,last_seq,unread,last_read_at:Option<String>}>
outbound_receipts(limit, state:Option<&str>) -> Vec<StoredMsg>
upsert_presence(agent,state,source,ttl_secs,seq,detail,last_seen)
list_presence() -> Vec<PresenceRow{agent,state,source,ttl_secs,detail,seq,last_seen}>
seen_grant(grant_id)->Result<bool>  // true if already seen (then reject); inserts if new
ack(consumer,seq) -> also set updated_at
```
`RejectionRow`, `ConsumerRow`, `PresenceRow` are public structs in store.rs (Serialize).
Keep `enforce_bounds` but exclude `direction='out' AND delivery_state NOT IN('delivered','read','failed','none')`
from eviction (don't drop outbound awaiting receipts).

---

## Layer 5 — ipc.rs + daemon.rs + mqtt.rs

### ipc.rs
`IPC_PROTO_VERSION: u32 = 2;`
`Request`: add `Hello{ipc_proto:u32}`; `Send` gains `topic:Option<String>, kind:String,
correlation_id:Option<String>, supersedes:Option<String>, encrypt:bool,
grant:Option<String>, unsigned:bool` (all `#[serde(default)]`); add
`Subscribe{consumer:String, ack:bool}`, `Rejections{limit,reason,since}`,
`Transcript{limit,from,to,peer}`, `Consumers`, `Receipts{id,limit,state}`,
`Reply{msg_id,ctype,body}`, `Presence{state,ttl_secs,detail}`, `PresenceList`.
`Response`: change `Messages(Vec<StoredMsg>)` → `Messages{msgs:Vec<StoredMsg>,
consumer_warning:Option<String>}`; add `Hello{ipc_proto,version,caps:Vec<String>}`,
`Sent{id, delivery_state:String}` (extend existing), `Rejections(Vec<RejectionRow>)`,
`Consumers(Vec<ConsumerRow>)`, `Presence(Vec<PresenceRow>)`. Add a `StreamFrame`
enum `{Message(StoredMsg), Lagged{dropped:u64}}` written as length-prefixed frames
on a Subscribe connection. `StatusInfo` gains `ipc_proto:u32, presence:Vec<PresenceRow>`
(or counts) `#[serde(default)]`, plus security flags.

### daemon.rs
- Subscriber registry: `subscribers: Mutex<Vec<(String /*consumer*/, SyncSender<StreamFrame>)>>`.
- Ingest closure: call `verify_incoming(.., me, .., allow_unsigned, accept_v1)`. On Ok:
  - if `ctype==CTYPE_PRESENCE`: parse body JSON → `store.upsert_presence(...)`; do NOT store as message; do NOT receipt.
  - else if `kind==Receipt` (or ctype==CTYPE_RECEIPT): apply to outbound delivery/read state; not stored visible.
  - else: `insert_inbound`; if `Some(seq)` → push `StreamFrame::Message` to matching subscribers; enforce bounds; if grant present, `store.seen_grant(id)` replay guard (reject if seen); if `auto_receipts` and addressed direct (to==me, not broadcast, not receipt/presence) → build+enqueue a `delivered` receipt to inner.from.
  - On Err(RejectInfo): `record_rejection(reason, claimed_sender, topic, detail)`.
- `send`: accept the new fields; choose topic = requested (validate ∈ cfg.topics) else
  primary; build via `BuildOpts` (encryption looks up recipient kem key from trust;
  UnknownRecipientKey error if --encrypt and none). Return delivery_state.
- presence beacon (existing heartbeat): emit with ctype CTYPE_PRESENCE, body JSON
  {state:"online",source:"daemon",ttl_secs:heartbeat*3,seq,detail:null}.
- `Request::Presence` (agent beacon): build presence message source="agent" and enqueue.
- `Request::Hello` → Response::Hello with caps.
- `handle_conn`: special-case `Subscribe` → register sender, loop forwarding frames
  until peer disconnects; (initial drain handled by CLI via Read first).
- Duplicate-daemon: keep IPC-bind-first (already correct); improve the
  `DaemonAlreadyRunning` message. (Confirmed safe in design.)
- read --ack read-receipt: when `Request::Ack`/Subscribe acks a direct message and
  auto_receipts, emit `read` receipt (best-effort).

### mqtt.rs — no functional change required (PUBACK plumbing out of scope; 'sent'=handed to client).

---

## Layer 6 — cli.rs (wire everything to IPC / files)

- `send`: flags `--topic, --kind, --correlation-id, --supersedes, --encrypt,
  --grant <token|@file>, --unsigned, --file <f>|-` (body from file/stdin). Send Hello
  first; pass through. Print `sent <id> (<delivery_state>)`; JSON `{id,delivery_state}`.
- `read`: `--follow`/`-f` (after drain, open Subscribe, print frames), keep
  `--consumer/--limit/--wait/--ack`; print consumer_warning to stderr.
- `browse`: add `--all` (direction). New `log` subcommand (chronological). New
  `reply <msg-id> <body> [--ctype]`. New `rejections [--limit --reason --since]`.
  New `consumers`. New `receipts [<id>] [--limit --state]`.
- `id generate`: cross-name guard (refuse without --force, naming existing identity via
  `Identity::load_name_fp`), backup before overwrite. `id token/show` emit v2.
- `agent add`: optional positional token, `--file <f>`, `-` stdin, `--rotate` (refuse
  key change without it; print old→new fp). 
- NEW `authority {generate,show,token,add,list,remove}` (file-direct).
- NEW `grant --to/--subject --action(or --capability) --scope --expiry [--out]` (signs
  with authority key, prints grant token).
- NEW `presence {set <state> [--ttl --detail], list}` (via daemon).
- `config set-security --allow-unsigned --accept-v1 --require-encryption --auto-receipts`.
- `daemon start`: `--wait <secs>` readiness poll (Ping until Pong/timeout; on timeout
  print tail of daemon.log, exit non-zero), `--no-wait`. Windows `spawn_detached`: add
  `CREATE_BREAKAWAY_FROM_JOB` (retry without on ACCESS_DENIED) + null stdio.
- `exit_code`: map new Error variants.

## Layer 7 — tests + docs
- Update `tests/pipeline.rs` and all `#[cfg(test)]` modules to new signatures; add tests:
  token length/crc rejection, id-generate guard, agent rotation, unsigned+downgrade,
  encrypt roundtrip, grant verify+expiry+replay, receipts state, transcript, consumers,
  presence upsert, migration of a v1 db.
- README + deploy: per-AGENTMSG_HOME isolation REQUIRED, multi-channel topics, distinct
  --consumer per reader, v2 feature overview. New: `deploy/systemd/agentmsg.service`,
  `deploy/windows/agentmsg.winsw.xml`, `deploy/windows/install-service.ps1`.
- paths.rs: add `log_path()`; daemon `run()` inits tracing to daemon.log.

## req (requirements) — to add during consolidation (do NOT let stages run req)
New requirements for: protocol v2 + compat; unsigned/insecure mode; typed schema;
human-authorization grants; ML-KEM payload encryption; delivery/read receipts;
application presence; token integrity/length; id-generate guard+backup; agent rotation;
file/stdin token+body input; send --topic; read --follow + IPC stream; rejections/
consumers/log/reply diagnostics; Windows service hardening + run-on-boot docs.
