use anyhow::{anyhow, Context, Result};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, source TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, dedupe_key TEXT);
CREATE TABLE IF NOT EXISTS upgrades(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, session_id INTEGER NOT NULL,
  hash TEXT NOT NULL, report TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, tool TEXT NOT NULL,
  capability TEXT NOT NULL, tier TEXT NOT NULL, args TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, decided_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
  owner TEXT NOT NULL, status TEXT NOT NULL, interrupt INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  parent_id INTEGER, depth INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS session_log(
  session_id INTEGER NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL,
  payload TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY(session_id, seq));
CREATE TABLE IF NOT EXISTS spend(
  id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, created_at INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON session_log
  BEGIN SELECT RAISE(ABORT, 'session_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON session_log
  BEGIN SELECT RAISE(ABORT, 'session_log is append-only'); END;
";

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub seq: i64,
    pub kind: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub status: String,
    pub created_at: i64,
    pub goal: String,
}

#[derive(Debug, Clone)]
pub struct UpgradeRow {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub session_id: i64,
    pub hash: String,
    pub report: Value,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct ApprovalRow {
    pub id: i64,
    pub session_id: i64,
    pub tool: String,
    pub capability: String,
    pub tier: String,
    pub args: String,
    pub created_at: i64,
}

/// Event queue, sessions, session log and spend ledger in one SQLite file.
/// All writes go through one connection behind a mutex (single writer).
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch(SCHEMA)?;
        // Databases created by stage 1 have no dedupe column yet.
        let has_key: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='dedupe_key'",
            [],
            |r| r.get(0),
        )?;
        if has_key == 0 {
            conn.execute_batch("ALTER TABLE events ADD COLUMN dedupe_key TEXT;")?;
        }
        // Databases created before stage 3 have no parent or depth columns.
        let has_parent: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='parent_id'",
            [],
            |r| r.get(0),
        )?;
        if has_parent == 0 {
            conn.execute_batch(
                "ALTER TABLE sessions ADD COLUMN parent_id INTEGER;
                 ALTER TABLE sessions ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS events_dedupe ON events(source, dedupe_key) WHERE dedupe_key IS NOT NULL;",
        )?;
        restrict_permissions(path);
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Enqueue an event and create its session in a single transaction.
    /// Returns (event_id, session_id). The event payload becomes the first log entry.
    pub fn enqueue_event(&self, source: &str, payload: &str, owner: &str) -> Result<(i64, i64)> {
        Ok(self.enqueue_inner(source, None, payload, owner)?.expect("no dedupe key, so always inserted"))
    }

    /// Idempotent enqueue for event sources, which deliver at least once.
    /// Returns None when this (source, key) pair was already accepted.
    pub fn enqueue_event_once(&self, source: &str, key: &str, payload: &str, owner: &str) -> Result<Option<(i64, i64)>> {
        self.enqueue_inner(source, Some(key), payload, owner)
    }

    fn enqueue_inner(&self, source: &str, key: Option<&str>, payload: &str, owner: &str) -> Result<Option<(i64, i64)>> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(k) = key {
            let seen: i64 = tx.query_row(
                "SELECT COUNT(*) FROM events WHERE source=?1 AND dedupe_key=?2",
                params![source, k],
                |r| r.get(0),
            )?;
            if seen > 0 {
                return Ok(None);
            }
        }
        let t = now();
        tx.execute(
            "INSERT INTO events(source,payload,status,created_at,dedupe_key) VALUES(?1,?2,'accepted',?3,?4)",
            params![source, payload, t, key],
        )?;
        let eid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO sessions(event_id,owner,status,created_at,updated_at) VALUES(?1,?2,'queued',?3,?3)",
            params![eid, owner, t],
        )?;
        let sid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO session_log(session_id,seq,kind,payload,created_at) VALUES(?1,0,'user',?2,?3)",
            params![sid, serde_json::json!({ "text": payload }).to_string(), t],
        )?;
        tx.commit()?;
        Ok(Some((eid, sid)))
    }

    /// Atomically take the oldest queued session for a worker.
    pub fn claim_next(&self) -> Result<Option<i64>> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sid: Option<i64> = tx
            .query_row("SELECT id FROM sessions WHERE status='queued' AND parent_id IS NULL ORDER BY id LIMIT 1", [], |r| r.get(0))
            .optional()?;
        let Some(sid) = sid else { return Ok(None) };
        let n = tx.execute(
            "UPDATE sessions SET status='running', updated_at=?2 WHERE id=?1 AND status='queued'",
            params![sid, now()],
        )?;
        tx.commit()?;
        Ok(if n == 1 { Some(sid) } else { None })
    }

    /// Take one specific session for in-process use (`agent run`, `agent resume`).
    /// False means a daemon or another process already has it.
    pub fn claim_session(&self, sid: i64) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE sessions SET status='running', updated_at=?2
             WHERE id=?1 AND parent_id IS NULL AND status IN ('queued','suspended','interrupted','failed')",
            params![sid, now()],
        )?;
        Ok(n == 1)
    }

    /// Hand a stopped session back to the daemon's queue.
    pub fn requeue(&self, sid: i64) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE sessions SET status='queued', interrupt=0, updated_at=?2
             WHERE id=?1 AND parent_id IS NULL AND status IN ('suspended','interrupted','failed')",
            params![sid, now()],
        )?;
        Ok(n == 1)
    }

    /// On daemon start: sessions still marked running belong to a process that died.
    pub fn recover_running(&self) -> Result<u64> {
        let c = self.conn.lock().unwrap();
        // A child never runs on its own: its grants exist only inside its parent's runner.
        // One left running is suspended, and its parent repairs the unfinished spawn call.
        c.execute(
            "UPDATE sessions SET status='suspended', updated_at=?1 WHERE status='running' AND parent_id IS NOT NULL",
            params![now()],
        )?;
        let n = c.execute(
            "UPDATE sessions SET status='queued', updated_at=?1 WHERE status='running' AND parent_id IS NULL",
            params![now()],
        )?;
        Ok(n as u64)
    }

    pub fn count_sessions(&self, statuses: &[&str]) -> Result<u64> {
        let c = self.conn.lock().unwrap();
        let marks = vec!["?"; statuses.len()].join(",");
        let sql = format!("SELECT COUNT(*) FROM sessions WHERE parent_id IS NULL AND status IN ({marks})");
        let n: i64 = c.query_row(&sql, params_from_iter(statuses.iter()), |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn list_sessions(&self, limit: i64) -> Result<Vec<SessionRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT s.id, s.status, s.created_at,
                    (SELECT payload FROM session_log l WHERE l.session_id=s.id AND l.seq=0), s.parent_id
             FROM sessions s ORDER BY s.id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            let payload: Option<String> = r.get(3)?;
            let goal = payload
                .and_then(|p| serde_json::from_str::<Value>(&p).ok())
                .and_then(|v| v["text"].as_str().map(String::from))
                .unwrap_or_default();
            Ok(SessionRow { id: r.get(0)?, parent_id: r.get(4)?, status: r.get(1)?, created_at: r.get(2)?, goal })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Ask the owner to approve an action. The request holds structured facts only.
    pub fn request_approval(&self, sid: i64, tool: &str, capability: &str, tier: &str, args: &str) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO approvals(session_id,tool,capability,tier,args,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![sid, tool, capability, tier, args, now()],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn approval_status(&self, id: i64) -> Result<String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT status FROM approvals WHERE id=?1", params![id], |r| r.get(0))
            .map_err(|_| anyhow!("unknown approval {id}"))
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id,session_id,tool,capability,tier,args,created_at FROM approvals WHERE status='pending' ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ApprovalRow {
                id: r.get(0)?,
                session_id: r.get(1)?,
                tool: r.get(2)?,
                capability: r.get(3)?,
                tier: r.get(4)?,
                args: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Only a pending request can be decided. False means it was already decided or expired.
    pub fn decide_approval(&self, id: i64, approved: bool) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE approvals SET status=?2, decided_at=?3 WHERE id=?1 AND status='pending'",
            params![id, if approved { "approved" } else { "denied" }, now()],
        )?;
        Ok(n == 1)
    }

    /// Every approval decision the owner made (not the delegate), oldest first, for rule suggestions.
    pub fn approval_history(&self) -> Result<Vec<Value>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT payload FROM session_log WHERE kind='approval' ORDER BY session_id, seq")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let v: Value = serde_json::from_str(&row?)?;
            // Entries written before the delegate existed have no "by" and were the owner's.
            if v["by"].as_str().unwrap_or("owner") == "owner" {
                out.push(v);
            }
        }
        Ok(out)
    }

    pub fn create_upgrade(&self, name: &str, session_id: i64, hash: &str) -> Result<i64> {
        let c = self.conn.lock().unwrap();
        let t = now();
        c.execute(
            "INSERT INTO upgrades(name,status,session_id,hash,report,created_at,updated_at) VALUES(?1,'proposed',?2,?3,'{\"stages\":[]}',?4,?4)",
            params![name, session_id, hash, t],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn set_upgrade(&self, id: i64, status: &str, report: &Value) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE upgrades SET status=?2, report=?3, updated_at=?4 WHERE id=?1",
            params![id, status, report.to_string(), now()],
        )?;
        Ok(())
    }

    pub fn get_upgrade(&self, id: i64) -> Result<UpgradeRow> {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT id,name,status,session_id,hash,report,created_at FROM upgrades WHERE id=?1",
            params![id],
            |r| {
                let report: String = r.get(5)?;
                Ok(UpgradeRow {
                    id: r.get(0)?, name: r.get(1)?, status: r.get(2)?, session_id: r.get(3)?, hash: r.get(4)?,
                    report: serde_json::from_str(&report).unwrap_or(Value::Null), created_at: r.get(6)?,
                })
            },
        )
        .map_err(|_| anyhow!("no upgrade #{id}"))
    }

    pub fn list_upgrades(&self) -> Result<Vec<UpgradeRow>> {
        let ids: Vec<i64> = {
            let c = self.conn.lock().unwrap();
            let mut stmt = c.prepare("SELECT id FROM upgrades ORDER BY id DESC LIMIT 50")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        ids.into_iter().map(|i| self.get_upgrade(i)).collect()
    }

    pub fn expire_approval(&self, id: i64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE approvals SET status='expired', decided_at=?2 WHERE id=?1 AND status='pending'",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn append_log(&self, sid: i64, kind: &str, payload: Value) -> Result<i64> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq)+1,0) FROM session_log WHERE session_id=?1",
            params![sid],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO session_log(session_id,seq,kind,payload,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![sid, seq, kind, payload.to_string(), now()],
        )?;
        tx.commit()?;
        Ok(seq)
    }

    pub fn load_log(&self, sid: i64) -> Result<Vec<LogEntry>> {
        let c = self.conn.lock().unwrap();
        let mut stmt =
            c.prepare("SELECT seq,kind,payload FROM session_log WHERE session_id=?1 ORDER BY seq")?;
        let rows = stmt.query_map(params![sid], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, kind, payload) = row?;
            out.push(LogEntry { seq, kind, payload: serde_json::from_str(&payload)? });
        }
        Ok(out)
    }

    /// Create a child session for `spawn_agent`. It is born "running" so no worker can claim
    /// it, and it carries its parent's id so it can only ever run inside that parent's runner.
    /// Returns the child's session id.
    pub fn create_child_session(&self, parent: i64, task: &str, owner: &str) -> Result<i64> {
        self.create_child_session_as(parent, task, owner, "spawn")
    }

    /// `kind` names who asked for the child ("spawn" for a model's spawn_agent call, "verify" for
    /// the core's verifier). Only "spawn" children count against `max_children_per_session`.
    pub fn create_child_session_as(&self, parent: i64, task: &str, owner: &str, kind: &str) -> Result<i64> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let depth: i64 = tx
            .query_row("SELECT depth FROM sessions WHERE id=?1", params![parent], |r| r.get(0))
            .map_err(|_| anyhow!("unknown parent session {parent}"))?;
        let t = now();
        tx.execute(
            "INSERT INTO events(source,payload,status,created_at) VALUES(?1,?2,'accepted',?3)",
            params![format!("{kind}:{parent}"), task, t],
        )?;
        let eid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO sessions(event_id,owner,status,created_at,updated_at,parent_id,depth)
             VALUES(?1,?2,'running',?3,?3,?4,?5)",
            params![eid, owner, t, parent, depth + 1],
        )?;
        let sid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO session_log(session_id,seq,kind,payload,created_at) VALUES(?1,0,'user',?2,?3)",
            params![sid, serde_json::json!({ "text": task }).to_string(), t],
        )?;
        tx.commit()?;
        Ok(sid)
    }

    pub fn session_parent(&self, sid: i64) -> Result<Option<i64>> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT parent_id FROM sessions WHERE id=?1", params![sid], |r| r.get(0))
            .map_err(|_| anyhow!("unknown session {sid}"))
    }

    pub fn session_depth(&self, sid: i64) -> Result<u32> {
        let c = self.conn.lock().unwrap();
        let d: i64 = c
            .query_row("SELECT depth FROM sessions WHERE id=?1", params![sid], |r| r.get(0))
            .map_err(|_| anyhow!("unknown session {sid}"))?;
        Ok(d as u32)
    }

    pub fn session_owner(&self, sid: i64) -> Result<String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT owner FROM sessions WHERE id=?1", params![sid], |r| r.get(0))
            .map_err(|_| anyhow!("unknown session {sid}"))
    }

    pub fn child_count(&self, parent: i64) -> Result<u32> {
        let c = self.conn.lock().unwrap();
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM sessions s JOIN events e ON e.id=s.event_id WHERE s.parent_id=?1 AND e.source LIKE 'spawn:%'",
            params![parent],
            |r| r.get(0),
        )?;
        Ok(n as u32)
    }

    /// One entry of a session's own log. Used by `recall`, which can only reach the caller's own session.
    pub fn log_entry(&self, sid: i64, seq: i64) -> Result<Option<LogEntry>> {
        let c = self.conn.lock().unwrap();
        let row: Option<(String, String)> = c
            .query_row(
                "SELECT kind,payload FROM session_log WHERE session_id=?1 AND seq=?2",
                params![sid, seq],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((kind, payload)) => Ok(Some(LogEntry { seq, kind, payload: serde_json::from_str(&payload)? })),
            None => Ok(None),
        }
    }

    /// (tokens, cost) for a session and every session below it. A parent's budget pays for its children.
    pub fn tree_spend(&self, sid: i64) -> Result<(u64, f64)> {
        let c = self.conn.lock().unwrap();
        let (t, cost): (i64, f64) = c.query_row(
            "WITH RECURSIVE tree(id) AS (
               SELECT ?1 UNION ALL SELECT s.id FROM sessions s JOIN tree t ON s.parent_id = t.id)
             SELECT COALESCE(SUM(input_tokens+output_tokens),0), COALESCE(SUM(cost_usd),0.0)
             FROM spend WHERE session_id IN (SELECT id FROM tree)",
            params![sid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((t as u64, cost))
    }

    pub fn status(&self, sid: i64) -> Result<String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT status FROM sessions WHERE id=?1", params![sid], |r| r.get(0))
            .map_err(|_| anyhow!("unknown session {sid}"))
    }

    pub fn set_status(&self, sid: i64, status: &str) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE sessions SET status=?2, updated_at=?3 WHERE id=?1",
            params![sid, status, now()],
        )?;
        Ok(())
    }

    pub fn request_interrupt(&self, sid: i64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("UPDATE sessions SET interrupt=1 WHERE id=?1", params![sid])?;
        Ok(())
    }

    pub fn clear_interrupt(&self, sid: i64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("UPDATE sessions SET interrupt=0 WHERE id=?1", params![sid])?;
        Ok(())
    }

    pub fn interrupt_requested(&self, sid: i64) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let v: i64 =
            c.query_row("SELECT interrupt FROM sessions WHERE id=?1", params![sid], |r| r.get(0))?;
        Ok(v != 0)
    }

    pub fn record_spend(&self, sid: i64, input: u64, output: u64, cost: f64) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO spend(session_id,input_tokens,output_tokens,cost_usd,created_at) VALUES(?1,?2,?3,?4,?5)",
            params![sid, input as i64, output as i64, cost, now()],
        )?;
        Ok(())
    }

    /// (tokens, cost) for one session.
    pub fn session_spend(&self, sid: i64) -> Result<(u64, f64)> {
        let c = self.conn.lock().unwrap();
        let (t, cost): (i64, f64) = c.query_row(
            "SELECT COALESCE(SUM(input_tokens+output_tokens),0), COALESCE(SUM(cost_usd),0.0) FROM spend WHERE session_id=?1",
            params![sid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((t as u64, cost))
    }

    /// (tokens, cost) across every session.
    pub fn global_spend(&self) -> Result<(u64, f64)> {
        let c = self.conn.lock().unwrap();
        let (t, cost): (i64, f64) = c.query_row(
            "SELECT COALESCE(SUM(input_tokens+output_tokens),0), COALESCE(SUM(cost_usd),0.0) FROM spend",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((t as u64, cost))
    }
}

#[cfg(unix)]
pub(crate) fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub(crate) fn restrict_permissions(_path: &Path) {}
