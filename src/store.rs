//! Durable local message store (REQ-0003, REQ-0004): SQLite-backed inbox,
//! outbox, per-consumer cursors, replay dedupe, rejection log, and bounds.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::{Error, RejectReason, Result};
use crate::paths;
use crate::wire::Inner;

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

/// Thread-safe handle to the SQLite store.
pub struct Store {
    conn: Mutex<Connection>,
}

fn map_err(e: rusqlite::Error) -> Error {
    Error::Store(e.to_string())
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
        conn.execute_batch(SCHEMA).map_err(map_err)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
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

    /// Store an accepted inbound message. Returns false if it was a duplicate
    /// (REQ-0013) — the row is left untouched in that case.
    pub fn insert_inbound(&self, inner: &Inner, topic: &str) -> Result<bool> {
        let conn = self.lock();
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO messages
                   (id, direction, sender, recipient, topic, ts, ctype, in_reply_to, body)
                 VALUES (?1,'in',?2,?3,?4,?5,?6,?7,?8)",
                params![
                    inner.id,
                    inner.from,
                    inner.to,
                    topic,
                    inner.ts,
                    inner.ctype,
                    inner.in_reply_to,
                    inner.body,
                ],
            )
            .map_err(map_err)?;
        Ok(changed > 0)
    }

    /// Record a locally-originated outbound message in the message log.
    pub fn insert_outbound_log(&self, inner: &Inner, topic: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR IGNORE INTO messages
               (id, direction, sender, recipient, topic, ts, ctype, in_reply_to, body)
             VALUES (?1,'out',?2,?3,?4,?5,?6,?7,?8)",
            params![
                inner.id,
                inner.from,
                inner.to,
                topic,
                inner.ts,
                inner.ctype,
                inner.in_reply_to,
                inner.body,
            ],
        )
        .map_err(map_err)?;
        Ok(())
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
            .prepare(
                "SELECT seq,id,direction,sender,recipient,topic,ts,ctype,in_reply_to,body
                 FROM messages
                 WHERE direction='in' AND seq > ?1
                 ORDER BY seq ASC LIMIT ?2",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![after, limit], row_to_msg)
            .map_err(map_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)
    }

    /// Acknowledge up to and including `seq`, advancing the cursor (REQ-0012).
    pub fn ack(&self, consumer: &str, seq: i64) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO cursors(consumer,last_seq) VALUES(?1,?2)
             ON CONFLICT(consumer) DO UPDATE SET last_seq=excluded.last_seq
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

    // --- Non-destructive browse, REQ-0037 / REQ-0038 -------------------------

    /// Browse recent messages newest-first, optionally filtered by sender and/or
    /// recipient (None = no filter). Never advances any cursor.
    pub fn browse(
        &self,
        limit: i64,
        from_filter: Option<&str>,
        to_filter: Option<&str>,
    ) -> Result<Vec<StoredMsg>> {
        let conn = self.lock();
        let mut sql = String::from(
            "SELECT seq,id,direction,sender,recipient,topic,ts,ctype,in_reply_to,body
             FROM messages WHERE direction='in'",
        );
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
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

    pub fn mark_delivered(&self, id: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM outbox WHERE id = ?1", params![id])
            .map_err(map_err)?;
        Ok(())
    }

    // --- Rejection log, REQ-0046 ---------------------------------------------

    pub fn record_rejection(&self, reason: &RejectReason, detail: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO rejections(reason,detail) VALUES(?1,?2)",
            params![reason.code(), detail],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn rejection_count(&self) -> Result<i64> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM rejections", [], |r| r.get(0))
            .map_err(map_err)
    }

    // --- Bounds & retention, REQ-0050 / REQ-0051 -----------------------------

    /// Evict oldest messages until within the configured bounds (REQ-0050).
    /// Returns the number of messages evicted.
    pub fn enforce_bounds(&self, max_messages: u64, max_bytes: u64) -> Result<u64> {
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
            // Evict oldest rows beyond the message cap; byte cap is approximated
            // by repeatedly trimming the oldest until under budget.
            let over = (count as u64).saturating_sub(max_messages);
            if over > 0 {
                let n = conn
                    .execute(
                        "DELETE FROM messages WHERE seq IN
                           (SELECT seq FROM messages ORDER BY seq ASC LIMIT ?1)",
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
                        "DELETE FROM messages WHERE seq IN
                           (SELECT seq FROM messages ORDER BY seq ASC LIMIT 64)",
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
    })
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
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
CREATE INDEX IF NOT EXISTS idx_messages_dir_seq ON messages(direction, seq);
CREATE TABLE IF NOT EXISTS cursors (
    consumer TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL
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
    seq     INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL DEFAULT (datetime('now')),
    reason  TEXT NOT NULL,
    detail  TEXT NOT NULL
);
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Inner, BROADCAST, CTYPE_TEXT, PROTOCOL_VERSION};

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
        assert!(s.insert_inbound(&inner("1", "a", "me", "hi"), "t").unwrap());
        // duplicate id ignored (REQ-0013)
        assert!(!s.insert_inbound(&inner("1", "a", "me", "hi"), "t").unwrap());
        assert!(s.insert_inbound(&inner("2", "a", "me", "yo"), "t").unwrap());

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

        let recent = s.browse(10, None, None).unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, "3"); // newest first

        let from_alice = s.browse(10, Some("alice"), None).unwrap();
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
        let recent = s.browse(10, None, None).unwrap();
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
}
