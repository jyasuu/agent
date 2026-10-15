use crate::store::{now, restrict_permissions};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL, session_id INTEGER NOT NULL,
  plugin TEXT NOT NULL, tool TEXT NOT NULL, capability TEXT NOT NULL, tier TEXT NOT NULL,
  decision TEXT NOT NULL, reason TEXT NOT NULL, args TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
";

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub session_id: i64,
    pub plugin: String,
    pub tool: String,
    pub capability: String,
    pub tier: String,
    pub decision: String,
    pub reason: String,
    pub args: String,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub seq: i64,
    pub ts: i64,
    pub entry: AuditEntry,
    pub prev_hash: String,
    pub hash: String,
}

/// Hash chain: every row commits to the previous row's hash, so editing or
/// removing a row in the middle breaks verification. Fields are length-prefixed
/// so different field splits can never produce the same hash input.
fn compute_hash(prev: &str, ts: i64, e: &AuditEntry) -> String {
    let mut h = Sha256::new();
    let sid = e.session_id.to_string();
    let ts = ts.to_string();
    for part in [
        prev, &ts, &sid, &e.plugin, &e.tool, &e.capability, &e.tier, &e.decision, &e.reason, &e.args,
    ] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Owned only by the core. No plugin is ever given this path.
pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch(SCHEMA)?;
        restrict_permissions(path);
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn append(&self, e: &AuditEntry) -> Result<i64> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let prev: String = tx
            .query_row("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .unwrap_or_else(|_| GENESIS.to_string());
        let ts = now();
        let hash = compute_hash(&prev, ts, e);
        tx.execute(
            "INSERT INTO audit(ts,session_id,plugin,tool,capability,tier,decision,reason,args,prev_hash,hash)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                ts, e.session_id, e.plugin, e.tool, e.capability, e.tier, e.decision, e.reason, e.args,
                prev, hash
            ],
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;
        Ok(seq)
    }

    pub fn rows(&self) -> Result<Vec<AuditRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT seq,ts,session_id,plugin,tool,capability,tier,decision,reason,args,prev_hash,hash
             FROM audit ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AuditRow {
                seq: r.get(0)?,
                ts: r.get(1)?,
                entry: AuditEntry {
                    session_id: r.get(2)?,
                    plugin: r.get(3)?,
                    tool: r.get(4)?,
                    capability: r.get(5)?,
                    tier: r.get(6)?,
                    decision: r.get(7)?,
                    reason: r.get(8)?,
                    args: r.get(9)?,
                },
                prev_hash: r.get(10)?,
                hash: r.get(11)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Recompute the whole chain. Returns the number of verified rows, or an
    /// error naming the first row that does not match.
    pub fn verify(&self) -> Result<u64> {
        let rows = self.rows()?;
        let mut prev = GENESIS.to_string();
        for row in &rows {
            if row.prev_hash != prev {
                bail!("audit chain broken at seq {}: previous hash does not link", row.seq);
            }
            if compute_hash(&prev, row.ts, &row.entry) != row.hash {
                bail!("audit chain broken at seq {}: row contents were altered", row.seq);
            }
            prev = row.hash.clone();
        }
        Ok(rows.len() as u64)
    }
}
