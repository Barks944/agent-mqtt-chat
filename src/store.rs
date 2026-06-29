//! Durable local message store (REQ-0003, REQ-0004): SQLite-backed inbox,
//! outbox, per-consumer cursors, replay dedupe, rejection log, and bounds.
//!
//! v0.2 (REQ: typed schema, receipts, presence, grants) extends the schema with
//! a `user_version`-gated migration that upgrades a v1 database in place.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{Error, RejectReason, Result};
use crate::paths;
use crate::wire::{Inner, MsgKind};

/// Canonical message column list, shared by every SELECT so `row_to_msg` indices
/// stay aligned.
const MSG_COLS: &str = "seq,id,direction,sender,recipient,topic,ts,ctype,in_reply_to,body,\
kind,correlation_id,supersedes,encrypted,delivery_state,broker_ack_ts,delivered_ts,read_ts";

/// A stored message row returned to readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMsg {
    pub seq: i64,
    pub id: String,
    pub direction: String,
    pub from: String,
    pub to: String,
    pub topic: String,
    pub ts: String,
    pub ctype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub body: String,
    /// Typed message kind (REQ: typed schema).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// True if this message was received/sent encrypted (REQ: ML-KEM payload).
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypted: bool,
    /// Delivery lifecycle: none|pending|sent|delivered|read|failed.
    pub delivery_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_ack_ts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_ts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_ts: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A pending outbound message awaiting broker confirmation (REQ-0016).
#[derive(Debug, Clone)]
pub struct Outbound {
    pub id: String,
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
}

/// A recorded rejection row (REQ-0046 diagnostics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionRow {
    pub seq: i64,
    pub at: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub detail: String,
}

/// A per-consumer cursor summary (REQ: consumers diagnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerRow {
    pub consumer: String,
    pub last_seq: i64,
    pub unread: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_read_at: Option<String>,
}

/// An application presence record (REQ: application presence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRow {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub seq: i64,
    pub last_seen: String,
}

/// Thread-safe handle to the SQLite store.
pub struct Store {
    conn: Mutex<Connection>,
}

fn map_err(e: rusqlite::Error) -> Error {
    Error::Store(e.to_string())
}

/// Stable snake_case string for a [`MsgKind`] (matches wire serde).
fn kind_str(kind: &MsgKind) -> &'static str {
    match kind {
        MsgKind::Message => "message",
        MsgKind::Command => "command",
        MsgKind::Query => "query",
        MsgKind::Result => "result",
        MsgKind::Ack => "ack",
        MsgKind::Error => "error",
        MsgKind::Grant => "grant",
        MsgKind::Receipt => "receipt",
    }
}

impl Store {
    /// Open (creating if needed) the store at the default location.
    pub fn open_default() -> Result<Store> {
        paths::ensure_data_dir()?;
        Store::open(paths::store_path()?)
    }

    /// Open a store at a specific path (used in tests).
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Store> {
        let conn = Connection::open(path).map_err(map_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(map_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(map_err)?;
        Self::migrate(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Apply the schema, upgrading a v1 database in place via `user_version`.
    fn migrate(conn: &Connection) -> Result<()> {
        let user_version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(map_err)?;
        if user_version >= 2 {
            return Ok(());
        }

        // A pre-existing `messages` table with user_version 0 is a v1 database
        // that needs in-place ALTERs; a fresh database gets the full schema.
        let has_messages: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='messages'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map_err(map_err)?
            .is_some();

        // Idempotent creates (adds the new tables/indexes; full table on fresh db).
        conn.execute_batch(SCHEMA).map_err(map_err)?;

        if has_messages {
            // v1 -> v2: add the new columns. Ignore "duplicate column" so a
            // partially-migrated database converges cleanly.
            for stmt in MIGRATE_V2 {
                if let Err(e) = conn.execute(stmt, []) {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column") {
                        return Err(map_err(e));
                    }
                }
            }
        }

        conn.pragma_update(None, "user_version", 2)
            .map_err(map_err)?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    /// Has this message id already been stored? (REQ-0013 replay dedupe.)
    pub fn contains_id(&self, id: &str) -> Result<bool> {
        let conn = self.lock();
        let found: Option<i64> = conn
            .query_row("SELECT 1 FROM messages WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(map_err)?;
        Ok(found.is_some())
    }

    /// Store an accepted inbound message. Returns `Some(seq)` for a freshly
    /// inserted row, or `None` if it was a duplicate (REQ-0013).
    pub fn insert_inbound(&self, inner: &Inner, topic: &str) -> Result<Option<i64>> {
        let conn = self.lock();
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO messages
                   (id, direction, sender, recipient, topic, ts, ctype, in_reply_to, body,
                    kind, correlation_id, supersedes, encrypted)
                 VALUES (?1,'in',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    inner.id,
                    inner.from,
                    inner.to,
                    topic,
                    inner.ts,
                    inner.ctype,
                    inner.in_reply_to,
                    inner.body,
                    kind_str(&inner.kind),
                    inner.correlation_id,
                    inner.supersedes,
                    inner.enc.is_some() as i64,
                ],
            )
            .map_err(map_err)?;
        if changed > 0 {
            Ok(Some(conn.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Record a locally-originated outbound message in the message log with a
    /// `pending` delivery state (REQ: delivery receipts).
    pub fn insert_outbound_log(&self, inner: &Inner, topic: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO messages
               (id, direction, sender, recipient, topic, ts, ctype, in_reply_to, body,
                kind, correlation_id, supersedes, encrypted, delivery_state)
             VALUES (?1,'out',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'pending')",
            params![
                inner.id,
                inner.from,
                inner.to,
                topic,
                inner.ts,
                inner.ctype,
                inner.in_reply_to,
                inner.body,
                kind_str(&inner.kind),
                inner.correlation_id,
                inner.supersedes,
                inner.enc.is_some() as i64,
            ],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// Fetch a single message by its monotonic seq.
    pub fn message_by_seq(&self, seq: i64) -> Result<Option<StoredMsg>> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {MSG_COLS} FROM messages WHERE seq = ?1"),
            params![seq],
            row_to_msg,
        )
        .optional()
        .map_err(map_err)
    }

    /// Fetch a single message by its id.
    pub fn get_message(&self, id: &str) -> Result<Option<StoredMsg>> {
        let conn = self.lock();
        conn.query_row(
            &format!("SELECT {MSG_COLS} FROM messages WHERE id = ?1"),
            params![id],
            row_to_msg,
        )
        .optional()
        .map_err(map_err)
    }

    // --- Queue drain (cursor + ack), REQ-0012 ---------------------------------

    /// Current cursor (last acknowledged seq) for a consumer.
    pub fn cursor(&self, consumer: &str) -> Result<i64> {
        let conn = self.lock();
        let v: Option<i64> = conn
            .query_row(
                "SELECT last_seq FROM cursors WHERE consumer = ?1",
                params![consumer],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?;
        Ok(v.unwrap_or(0))
    }

    /// Read inbound messages newer than the consumer's cursor, oldest-first.
    /// Does NOT advance the cursor (ack does that).
    pub fn read_after_cursor(&self, consumer: &str, limit: i64) -> Result<Vec<StoredMsg>> {
        let after = self.cursor(consumer)?;
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MSG_COLS} FROM messages
                 WHERE direction='in' AND seq > ?1
                 ORDER BY seq ASC LIMIT ?2"
            ))
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![after, limit], row_to_msg)
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    /// Acknowledge up to and including `seq`, advancing the cursor (REQ-0012)
    /// and stamping `updated_at`.
    pub fn ack(&self, consumer: &str, seq: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO cursors(consumer,last_seq,updated_at)
             VALUES(?1,?2,datetime('now'))
             ON CONFLICT(consumer) DO UPDATE SET
               last_seq=excluded.last_seq, updated_at=excluded.updated_at
             WHERE excluded.last_seq > cursors.last_seq",
            params![consumer, seq],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// Highest inbound seq currently stored (for wait/no-op checks).
    pub fn max_inbound_seq(&self) -> Result<i64> {
        let conn = self.lock();
        let v: Option<i64> = conn
            .query_row(
                "SELECT MAX(seq) FROM messages WHERE direction='in'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_err)?
            .flatten();
        Ok(v.unwrap_or(0))
    }

    /// Per-consumer cursor summaries with unread counts (REQ: consumers).
    pub fn consumers(&self) -> Result<Vec<ConsumerRow>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT consumer, last_seq,
                   (SELECT COUNT(*) FROM messages
                      WHERE direction='in' AND seq > cursors.last_seq) AS unread,
                   updated_at
                 FROM cursors ORDER BY consumer ASC",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ConsumerRow {
                    consumer: r.get(0)?,
                    last_seq: r.get(1)?,
                    unread: r.get(2)?,
                    last_read_at: r.get(3)?,
                })
            })
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    // --- Non-destructive browse / transcript, REQ-0037 / REQ-0038 ------------

    /// Browse recent messages newest-first, optionally filtered by sender and/or
    /// recipient (None = no filter). `direction` is "in", "out", or "all".
    /// Never advances any cursor.
    pub fn browse(
        &self,
        limit: i64,
        from_filter: Option<&str>,
        to_filter: Option<&str>,
        direction: &str,
    ) -> Result<Vec<StoredMsg>> {
        let conn = self.lock();
        let mut sql = format!("SELECT {MSG_COLS} FROM messages WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if direction != "all" {
            sql.push_str(" AND direction = ?");
            args.push(Box::new(direction.to_string()));
        }
        if let Some(f) = from_filter {
            sql.push_str(" AND sender = ?");
            args.push(Box::new(f.to_string()));
        }
        if let Some(t) = to_filter {
            sql.push_str(" AND (recipient = ? OR recipient = '*')");
            args.push(Box::new(t.to_string()));
        }
        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        args.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql).map_err(map_err)?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(refs), row_to_msg)
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    /// Chronological (oldest-first) transcript across both directions, optionally
    /// filtered by exact sender, recipient, or a `peer` (sender OR recipient).
    pub fn transcript(
        &self,
        limit: i64,
        from_filter: Option<&str>,
        to_filter: Option<&str>,
        peer: Option<&str>,
    ) -> Result<Vec<StoredMsg>> {
        let conn = self.lock();
        let mut sql = format!("SELECT {MSG_COLS} FROM messages WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(f) = from_filter {
            sql.push_str(" AND sender = ?");
            args.push(Box::new(f.to_string()));
        }
        if let Some(t) = to_filter {
            sql.push_str(" AND recipient = ?");
            args.push(Box::new(t.to_string()));
        }
        if let Some(p) = peer {
            sql.push_str(" AND (sender = ? OR recipient = ?)");
            args.push(Box::new(p.to_string()));
            args.push(Box::new(p.to_string()));
        }
        sql.push_str(" ORDER BY seq ASC LIMIT ?");
        args.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql).map_err(map_err)?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(refs), row_to_msg)
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    /// Outbound messages and their delivery state, newest-first, optionally
    /// filtered by `delivery_state` (REQ: delivery/read receipts).
    pub fn outbound_receipts(&self, limit: i64, state: Option<&str>) -> Result<Vec<StoredMsg>> {
        let conn = self.lock();
        let mut sql = format!("SELECT {MSG_COLS} FROM messages WHERE direction='out'");
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(s) = state {
            sql.push_str(" AND delivery_state = ?");
            args.push(Box::new(s.to_string()));
        }
        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        args.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql).map_err(map_err)?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(refs), row_to_msg)
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    // --- Outbox (durable retry), REQ-0016 ------------------------------------

    pub fn enqueue_outbound(&self, ob: &Outbound) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO outbox(id,topic,payload,qos,retain)
             VALUES(?1,?2,?3,?4,?5)",
            params![ob.id, ob.topic, ob.payload, ob.qos, ob.retain as i64],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn pending_outbound(&self) -> Result<Vec<Outbound>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT id,topic,payload,qos,retain FROM outbox ORDER BY seq ASC")
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Outbound {
                    id: r.get(0)?,
                    topic: r.get(1)?,
                    payload: r.get(2)?,
                    qos: r.get(3)?,
                    retain: r.get::<_, i64>(4)? != 0,
                })
            })
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    /// Broker handed off the message (REQ-0016): drop it from the outbox and
    /// advance the outbound log to `sent` with a broker-ack timestamp. Does not
    /// clobber a later `delivered`/`read`/`failed` state.
    pub fn mark_delivered(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE messages SET delivery_state='sent', broker_ack_ts=datetime('now')
             WHERE id=?1 AND direction='out' AND delivery_state IN ('pending','none')",
            params![id],
        )
        .map_err(map_err)?;
        conn.execute("DELETE FROM outbox WHERE id = ?1", params![id])
            .map_err(map_err)?;
        Ok(())
    }

    /// Apply an inbound delivery receipt to the referenced outbound message.
    pub fn apply_delivery_receipt(&self, orig_id: &str, ts: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE messages SET delivery_state='delivered', delivered_ts=?2
             WHERE id=?1 AND direction='out' AND delivery_state NOT IN ('read','failed')",
            params![orig_id, ts],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// Apply an inbound read receipt to the referenced outbound message.
    pub fn apply_read_receipt(&self, orig_id: &str, ts: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE messages SET delivery_state='read', read_ts=?2
             WHERE id=?1 AND direction='out' AND delivery_state != 'failed'",
            params![orig_id, ts],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// Mark an outbound message as permanently failed.
    pub fn mark_failed(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE messages SET delivery_state='failed'
             WHERE id=?1 AND direction='out'",
            params![id],
        )
        .map_err(map_err)?;
        Ok(())
    }

    // --- Rejection log, REQ-0046 ---------------------------------------------

    pub fn record_rejection(
        &self,
        reason: &RejectReason,
        claimed_sender: Option<&str>,
        topic: &str,
        detail: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO rejections(reason,detail,claimed_sender,topic)
             VALUES(?1,?2,?3,?4)",
            params![reason.code(), detail, claimed_sender, topic],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn rejection_count(&self) -> Result<i64> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM rejections", [], |r| r.get(0))
            .map_err(map_err)
    }

    /// Recent rejections newest-first, optionally filtered by reason code and a
    /// `since` lower bound on `at` (REQ: rejections diagnostic).
    pub fn rejections(
        &self,
        limit: i64,
        reason: Option<&str>,
        since: Option<&str>,
    ) -> Result<Vec<RejectionRow>> {
        let conn = self.lock();
        let mut sql = String::from(
            "SELECT seq,at,reason,claimed_sender,topic,detail FROM rejections WHERE 1=1",
        );
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(r) = reason {
            sql.push_str(" AND reason = ?");
            args.push(Box::new(r.to_string()));
        }
        if let Some(s) = since {
            sql.push_str(" AND at >= ?");
            args.push(Box::new(s.to_string()));
        }
        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        args.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql).map_err(map_err)?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(refs), |r| {
                Ok(RejectionRow {
                    seq: r.get(0)?,
                    at: r.get(1)?,
                    reason: r.get(2)?,
                    claimed_sender: r.get(3)?,
                    topic: r.get(4)?,
                    detail: r.get(5)?,
                })
            })
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    // --- Application presence, REQ: presence ---------------------------------

    /// Upsert a presence record, keeping only the highest-seq beacon per agent.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_presence(
        &self,
        agent: &str,
        state: &str,
        source: &str,
        ttl_secs: i64,
        seq: i64,
        detail: Option<&str>,
        last_seen: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO presence(agent,state,source,ttl_secs,detail,seq,last_seen,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,datetime('now'))
             ON CONFLICT(agent) DO UPDATE SET
               state=excluded.state, source=excluded.source, ttl_secs=excluded.ttl_secs,
               detail=excluded.detail, seq=excluded.seq, last_seen=excluded.last_seen,
               updated_at=excluded.updated_at
             WHERE excluded.seq >= presence.seq",
            params![agent, state, source, ttl_secs, detail, seq, last_seen],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// List all known presence records (REQ: presence).
    pub fn list_presence(&self) -> Result<Vec<PresenceRow>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT agent,state,source,ttl_secs,detail,seq,last_seen
                 FROM presence ORDER BY agent ASC",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(PresenceRow {
                    agent: r.get(0)?,
                    state: r.get(1)?,
                    source: r.get(2)?,
                    ttl_secs: r.get(3)?,
                    detail: r.get(4)?,
                    seq: r.get(5)?,
                    last_seen: r.get(6)?,
                })
            })
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    // --- Grant replay guard, REQ: grants -------------------------------------

    /// Record a grant id as seen. Returns `true` if it was ALREADY seen (the
    /// caller should then reject as a replay), `false` if newly recorded.
    pub fn seen_grant(&self, grant_id: &str) -> Result<bool> {
        let conn = self.lock();
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO seen_grants(grant_id) VALUES(?1)",
                params![grant_id],
            )
            .map_err(map_err)?;
        Ok(changed == 0)
    }

    // --- Bounds & retention, REQ-0050 / REQ-0051 -----------------------------

    /// Evict oldest messages until within the configured bounds (REQ-0050).
    /// Returns the number of messages evicted. Outbound messages still awaiting
    /// a receipt (delivery_state pending/sent) are never evicted.
    pub fn enforce_bounds(&self, max_messages: u64, max_bytes: u64) -> Result<u64> {
        const EVICTABLE: &str =
            "NOT (direction='out' AND delivery_state NOT IN ('delivered','read','failed','none'))";
        let conn = self.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .map_err(map_err)?;
        let bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(body)),0) FROM messages",
                [],
                |r| r.get(0),
            )
            .map_err(map_err)?;

        let mut evicted = 0u64;
        if count as u64 > max_messages || bytes as u64 > max_bytes {
            // Evict oldest evictable rows beyond the message cap; byte cap is
            // approximated by repeatedly trimming the oldest until under budget.
            let over = (count as u64).saturating_sub(max_messages);
            if over > 0 {
                let n = conn
                    .execute(
                        &format!(
                            "DELETE FROM messages WHERE seq IN
                               (SELECT seq FROM messages WHERE {EVICTABLE}
                                ORDER BY seq ASC LIMIT ?1)"
                        ),
                        params![over as i64],
                    )
                    .map_err(map_err)?;
                evicted += n as u64;
            }
            // Trim further if still over the byte budget.
            loop {
                let bytes: i64 = conn
                    .query_row(
                        "SELECT COALESCE(SUM(LENGTH(body)),0) FROM messages",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(map_err)?;
                if (bytes as u64) <= max_bytes {
                    break;
                }
                let n = conn
                    .execute(
                        &format!(
                            "DELETE FROM messages WHERE seq IN
                               (SELECT seq FROM messages WHERE {EVICTABLE}
                                ORDER BY seq ASC LIMIT 64)"
                        ),
                        [],
                    )
                    .map_err(map_err)?;
                if n == 0 {
                    break;
                }
                evicted += n as u64;
            }
        }
        Ok(evicted)
    }

    /// Total stored message count (for status/tests).
    pub fn message_count(&self) -> Result<i64> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .map_err(map_err)
    }
}

fn row_to_msg(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMsg> {
    Ok(StoredMsg {
        seq: r.get(0)?,
        id: r.get(1)?,
        direction: r.get(2)?,
        from: r.get(3)?,
        to: r.get(4)?,
        topic: r.get(5)?,
        ts: r.get(6)?,
        ctype: r.get(7)?,
        in_reply_to: r.get(8)?,
        body: r.get(9)?,
        kind: r.get(10)?,
        correlation_id: r.get(11)?,
        supersedes: r.get(12)?,
        encrypted: r.get::<_, i64>(13)? != 0,
        delivery_state: r.get(14)?,
        broker_ack_ts: r.get(15)?,
        delivered_ts: r.get(16)?,
        read_ts: r.get(17)?,
    })
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    id             TEXT NOT NULL UNIQUE,
    direction      TEXT NOT NULL,
    sender         TEXT NOT NULL,
    recipient      TEXT NOT NULL,
    topic          TEXT NOT NULL,
    ts             TEXT NOT NULL,
    ctype          TEXT NOT NULL,
    in_reply_to    TEXT,
    body           TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'message',
    correlation_id TEXT,
    supersedes     TEXT,
    encrypted      INTEGER NOT NULL DEFAULT 0,
    delivery_state TEXT NOT NULL DEFAULT 'none',
    broker_ack_ts  TEXT,
    delivered_ts   TEXT,
    read_ts        TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_dir_seq ON messages(direction, seq);
CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id);
CREATE TABLE IF NOT EXISTS cursors (
    consumer   TEXT PRIMARY KEY,
    last_seq   INTEGER NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    id      TEXT NOT NULL UNIQUE,
    topic   TEXT NOT NULL,
    payload BLOB NOT NULL,
    qos     INTEGER NOT NULL,
    retain  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rejections (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL DEFAULT (datetime('now')),
    reason         TEXT NOT NULL,
    detail         TEXT NOT NULL,
    claimed_sender TEXT,
    topic          TEXT
);
CREATE TABLE IF NOT EXISTS presence (
    agent      TEXT PRIMARY KEY,
    state      TEXT,
    source     TEXT,
    ttl_secs   INTEGER,
    detail     TEXT,
    seq        INTEGER NOT NULL DEFAULT 0,
    last_seen  TEXT NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS seen_grants (
    grant_id TEXT PRIMARY KEY,
    at       TEXT NOT NULL DEFAULT (datetime('now'))
);
";

/// In-place ALTERs applied to a v1 database (user_version 0 with a `messages`
/// table). Idempotent: "duplicate column" errors are swallowed by the caller.
const MIGRATE_V2: &[&str] = &[
    "ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'message'",
    "ALTER TABLE messages ADD COLUMN correlation_id TEXT",
    "ALTER TABLE messages ADD COLUMN supersedes TEXT",
    "ALTER TABLE messages ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE messages ADD COLUMN delivery_state TEXT NOT NULL DEFAULT 'none'",
    "ALTER TABLE messages ADD COLUMN broker_ack_ts TEXT",
    "ALTER TABLE messages ADD COLUMN delivered_ts TEXT",
    "ALTER TABLE messages ADD COLUMN read_ts TEXT",
    "ALTER TABLE rejections ADD COLUMN claimed_sender TEXT",
    "ALTER TABLE rejections ADD COLUMN topic TEXT",
    "ALTER TABLE cursors ADD COLUMN updated_at TEXT",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Inner, MsgKind, BROADCAST, CTYPE_TEXT, PROTOCOL_VERSION};

    fn inner(id: &str, from: &str, to: &str, body: &str) -> Inner {
        Inner {
            id: id.into(),
            v: PROTOCOL_VERSION,
            from: from.into(),
            to: to.into(),
            ts: "2026-06-28T00:00:00Z".into(),
            nonce: "n".into(),
            ctype: CTYPE_TEXT.into(),
            in_reply_to: None,
            body: body.into(),
            kind: MsgKind::default(),
            correlation_id: None,
            supersedes: None,
            enc: None,
            grant: None,
            receipt: None,
        }
    }

    fn tmp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path().join("t.db")).unwrap();
        (dir, s)
    }

    #[test]
    fn dedupe_and_drain_and_ack() {
        let (_d, s) = tmp_store();
        assert!(s
            .insert_inbound(&inner("1", "a", "me", "hi"), "t")
            .unwrap()
            .is_some());
        // duplicate id ignored (REQ-0013)
        assert!(s
            .insert_inbound(&inner("1", "a", "me", "hi"), "t")
            .unwrap()
            .is_none());
        assert!(s
            .insert_inbound(&inner("2", "a", "me", "yo"), "t")
            .unwrap()
            .is_some());

        let batch = s.read_after_cursor("me", 10).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].id, "1"); // oldest first
        s.ack("me", batch[1].seq).unwrap();
        // after ack, nothing new
        assert!(s.read_after_cursor("me", 10).unwrap().is_empty());
    }

    #[test]
    fn browse_is_nondestructive_and_filters() {
        let (_d, s) = tmp_store();
        s.insert_inbound(&inner("1", "alice", "me", "a"), "t")
            .unwrap();
        s.insert_inbound(&inner("2", "bob", "me", "b"), "t")
            .unwrap();
        s.insert_inbound(&inner("3", "alice", BROADCAST, "c"), "t")
            .unwrap();

        let recent = s.browse(10, None, None, "in").unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, "3"); // newest first

        let from_alice = s.browse(10, Some("alice"), None, "in").unwrap();
        assert_eq!(from_alice.len(), 2);

        // browse did not advance the drain cursor
        assert_eq!(s.read_after_cursor("me", 10).unwrap().len(), 3);
    }

    #[test]
    fn bounds_evict_oldest() {
        let (_d, s) = tmp_store();
        for i in 0..10 {
            s.insert_inbound(&inner(&i.to_string(), "a", "me", "x"), "t")
                .unwrap();
        }
        let evicted = s.enforce_bounds(4, u64::MAX).unwrap();
        assert_eq!(evicted, 6);
        assert_eq!(s.message_count().unwrap(), 4);
        let recent = s.browse(10, None, None, "in").unwrap();
        assert_eq!(recent[0].id, "9"); // newest retained
    }

    #[test]
    fn outbox_roundtrip() {
        let (_d, s) = tmp_store();
        s.enqueue_outbound(&Outbound {
            id: "1".into(),
            topic: "t".into(),
            payload: b"raw".to_vec(),
            qos: 1,
            retain: false,
        })
        .unwrap();
        assert_eq!(s.pending_outbound().unwrap().len(), 1);
        s.mark_delivered("1").unwrap();
        assert!(s.pending_outbound().unwrap().is_empty());
    }

    // --- v0.2 (DESIGN_V2 Layer 7) --------------------------------------------

    #[test]
    fn receipts_delivery_state_transitions() {
        let (_d, s) = tmp_store();
        // Log an outbound message (pending), then walk the delivery lifecycle.
        s.insert_outbound_log(&inner("m1", "me", "bob", "hi"), "t")
            .unwrap();
        assert_eq!(
            s.get_message("m1").unwrap().unwrap().delivery_state,
            "pending"
        );

        // Broker hand-off -> sent + broker_ack_ts.
        s.mark_delivered("m1").unwrap();
        let m = s.get_message("m1").unwrap().unwrap();
        assert_eq!(m.delivery_state, "sent");
        assert!(m.broker_ack_ts.is_some());

        // Inbound delivery receipt -> delivered.
        s.apply_delivery_receipt("m1", "2026-06-28T00:00:01Z")
            .unwrap();
        let m = s.get_message("m1").unwrap().unwrap();
        assert_eq!(m.delivery_state, "delivered");
        assert_eq!(m.delivered_ts.as_deref(), Some("2026-06-28T00:00:01Z"));

        // Inbound read receipt -> read.
        s.apply_read_receipt("m1", "2026-06-28T00:00:02Z").unwrap();
        let m = s.get_message("m1").unwrap().unwrap();
        assert_eq!(m.delivery_state, "read");
        assert_eq!(m.read_ts.as_deref(), Some("2026-06-28T00:00:02Z"));

        // outbound_receipts filters on delivery state.
        assert_eq!(s.outbound_receipts(10, None).unwrap().len(), 1);
        assert_eq!(s.outbound_receipts(10, Some("read")).unwrap().len(), 1);
        assert!(s.outbound_receipts(10, Some("pending")).unwrap().is_empty());

        // mark_failed is terminal and read-receipts never downgrade it.
        s.insert_outbound_log(&inner("m2", "me", "bob", "yo"), "t")
            .unwrap();
        s.mark_failed("m2").unwrap();
        s.apply_read_receipt("m2", "2026-06-28T00:00:03Z").unwrap();
        assert_eq!(
            s.get_message("m2").unwrap().unwrap().delivery_state,
            "failed"
        );
    }

    #[test]
    fn transcript_is_chronological_both_directions() {
        let (_d, s) = tmp_store();
        s.insert_inbound(&inner("1", "bob", "me", "hi"), "t")
            .unwrap();
        s.insert_outbound_log(&inner("2", "me", "bob", "hello back"), "t")
            .unwrap();
        s.insert_inbound(&inner("3", "carol", "me", "unrelated"), "t")
            .unwrap();

        // Full transcript spans both directions, oldest-first.
        let all = s.transcript(10, None, None, None).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, "1");
        assert_eq!(all[1].id, "2");

        // peer filter matches sender OR recipient.
        let with_bob = s.transcript(10, None, None, Some("bob")).unwrap();
        assert_eq!(with_bob.len(), 2);
        assert!(with_bob.iter().all(|m| m.from == "bob" || m.to == "bob"));
    }

    #[test]
    fn consumers_report_unread() {
        let (_d, s) = tmp_store();
        s.insert_inbound(&inner("1", "a", "me", "x"), "t").unwrap();
        s.insert_inbound(&inner("2", "a", "me", "y"), "t").unwrap();
        let batch = s.read_after_cursor("worker", 10).unwrap();
        s.ack("worker", batch[0].seq).unwrap();

        let rows = s.consumers().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].consumer, "worker");
        assert_eq!(rows[0].last_seq, batch[0].seq);
        assert_eq!(rows[0].unread, 1); // one message past the cursor
        assert!(rows[0].last_read_at.is_some()); // updated_at stamped on ack
    }

    #[test]
    fn presence_upsert_keeps_highest_seq() {
        let (_d, s) = tmp_store();
        s.upsert_presence("alice", "online", "agent", 30, 5, Some("busy"), "t1")
            .unwrap();
        // A lower-seq beacon must NOT overwrite a newer record.
        s.upsert_presence("alice", "away", "agent", 30, 3, None, "t0")
            .unwrap();
        let rows = s.list_presence().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent, "alice");
        assert_eq!(rows[0].state.as_deref(), Some("online"));
        assert_eq!(rows[0].seq, 5);

        // A higher-or-equal seq beacon updates in place.
        s.upsert_presence("alice", "away", "agent", 30, 6, None, "t2")
            .unwrap();
        let rows = s.list_presence().unwrap();
        assert_eq!(rows[0].state.as_deref(), Some("away"));
        assert_eq!(rows[0].seq, 6);
    }

    #[test]
    fn seen_grant_replay_guard() {
        let (_d, s) = tmp_store();
        assert!(!s.seen_grant("g1").unwrap()); // first use: not yet seen
        assert!(s.seen_grant("g1").unwrap()); // replay: already seen
        assert!(!s.seen_grant("g2").unwrap());
    }

    #[test]
    fn outbound_awaiting_receipt_not_evicted() {
        let (_d, s) = tmp_store();
        // An outbound message still awaiting its receipt (delivery_state='sent')
        // must survive eviction even when over the message cap.
        s.insert_outbound_log(&inner("out1", "me", "bob", "keep"), "t")
            .unwrap();
        s.mark_delivered("out1").unwrap();
        for i in 0..10 {
            s.insert_inbound(&inner(&format!("in{i}"), "a", "me", "x"), "t")
                .unwrap();
        }
        s.enforce_bounds(2, u64::MAX).unwrap();
        // The pending-receipt outbound row is retained.
        assert!(s.get_message("out1").unwrap().is_some());
    }

    #[test]
    fn migrates_v1_database_in_place() {
        // Build a v1-style database by hand: user_version=0, a `messages` table
        // with only the v1 columns plus the v1 cursors/rejections tables.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (
                    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                    id          TEXT NOT NULL UNIQUE,
                    direction   TEXT NOT NULL,
                    sender      TEXT NOT NULL,
                    recipient   TEXT NOT NULL,
                    topic       TEXT NOT NULL,
                    ts          TEXT NOT NULL,
                    ctype       TEXT NOT NULL,
                    in_reply_to TEXT,
                    body        TEXT NOT NULL
                 );
                 CREATE TABLE cursors (
                    consumer TEXT PRIMARY KEY,
                    last_seq INTEGER NOT NULL
                 );
                 CREATE TABLE rejections (
                    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
                    at     TEXT NOT NULL DEFAULT (datetime('now')),
                    reason TEXT NOT NULL,
                    detail TEXT NOT NULL
                 );",
            )
            .unwrap();
            // A pre-existing v1 row.
            conn.execute(
                "INSERT INTO messages(id,direction,sender,recipient,topic,ts,ctype,in_reply_to,body)
                 VALUES('old1','in','alice','me','t','2020-01-01T00:00:00Z','text/plain',NULL,'legacy')",
                [],
            )
            .unwrap();
            // v1 stores left user_version at its default of 0.
            let uv: i64 = conn
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!(uv, 0);
        }

        // Reopen through the real Store: migration must run in place.
        let s = Store::open(&path).unwrap();
        let uv: i64 = s
            .lock()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(uv, 2);

        // The legacy row survives and the new columns exist with their defaults.
        let m = s.get_message("old1").unwrap().unwrap();
        assert_eq!(m.body, "legacy");
        assert_eq!(m.kind, "message");
        assert_eq!(m.delivery_state, "none");
        assert!(!m.encrypted);
        assert!(m.correlation_id.is_none());

        // The migrated cursors/rejections tables gained their v2 columns.
        s.ack("c", 0).unwrap(); // exercises cursors.updated_at
        s.record_rejection(&RejectReason::UnknownSigner, Some("x"), "t", "d")
            .unwrap(); // exercises rejections.claimed_sender / topic
        assert_eq!(s.rejections(10, None, None).unwrap().len(), 1);

        // New v2-only inserts work against the migrated schema.
        assert!(s
            .insert_inbound(&inner("new1", "bob", "me", "fresh"), "t")
            .unwrap()
            .is_some());
    }
}
