use crate::config::SourceConfig;
use crate::store::Store;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// Events held in memory between a source and the queue. When this fills up the
/// source's output pipe fills too, so a flood slows the source down instead of
/// growing without bound.
const CHANNEL_DEPTH: usize = 64;
const MAX_PAYLOAD_CHARS: usize = 100_000;
const RESTART_BACKOFF: Duration = Duration::from_secs(2);

/// Source protocol, one JSON object per line:
///   source -> core: {"event":{"key":"<unique id>","payload":"<task text>"}}
///   core -> source: {"ack":"<key>"}   sent only after the event is durably stored
/// A source may repeat an event (for example after a restart). The unique key
/// makes the repeat harmless. A source can only produce events: it never gets a
/// handle to the stores and cannot touch a running session.
struct Live {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
}

struct SourceProc {
    cfg: SourceConfig,
    workspace: PathBuf,
    live: Option<Live>,
    last_start: Option<Instant>,
}

impl SourceProc {
    fn spawn(&mut self) -> Result<()> {
        self.last_start = Some(Instant::now());
        let mut child = Command::new(&self.cfg.command)
            .args(&self.cfg.args)
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting event source '{}'", self.cfg.name))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::sync_channel::<Value>(CHANNEL_DEPTH);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
            }
        });
        self.live = Some(Live { child, stdin, rx });
        Ok(())
    }

    fn kill(&mut self) {
        if let Some(mut l) = self.live.take() {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
    }
}

impl Drop for SourceProc {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct EventSourceHost {
    sources: Vec<SourceProc>,
}

impl EventSourceHost {
    pub fn start(cfgs: &[SourceConfig], workspace: &Path) -> Result<Self> {
        let mut sources = Vec::new();
        for c in cfgs {
            let mut p = SourceProc {
                cfg: c.clone(),
                workspace: workspace.to_path_buf(),
                live: None,
                last_start: None,
            };
            p.spawn()?;
            sources.push(p);
        }
        Ok(Self { sources })
    }

    /// Bring the running sources in line with `desired` without touching the ones that did not change.
    /// Returns a note for each change, for the log. A source that fails to start is reported, and the
    /// daemon keeps running.
    pub fn reload(&mut self, desired: &[SourceConfig], workspace: &Path) -> Vec<String> {
        let mut notes = Vec::new();
        let want: std::collections::HashSet<&str> = desired.iter().map(|c| c.name.as_str()).collect();
        self.sources.retain(|s| {
            let keep = want.contains(s.cfg.name.as_str());
            if !keep {
                notes.push(format!("stopped event source '{}'", s.cfg.name));
            }
            keep
        });
        for c in desired {
            let cv = serde_json::to_value(c).unwrap_or(Value::Null);
            let existing = self.sources.iter().position(|s| s.cfg.name == c.name);
            if let Some(i) = existing {
                if serde_json::to_value(&self.sources[i].cfg).unwrap_or(Value::Null) == cv {
                    continue;
                }
            }
            let mut p = SourceProc { cfg: c.clone(), workspace: workspace.to_path_buf(), live: None, last_start: None };
            match p.spawn() {
                Ok(()) => match existing {
                    Some(i) => {
                        self.sources[i] = p;
                        notes.push(format!("restarted event source '{}' with its new settings", c.name));
                    }
                    None => {
                        self.sources.push(p);
                        notes.push(format!("started event source '{}'", c.name));
                    }
                },
                Err(e) => notes.push(format!("could not start event source '{}': {e:#}", c.name)),
            }
        }
        notes
    }

    /// Move up to `max` events per source into the queue, then acknowledge each one.
    /// Returns how many new sessions were created. Restarts a source that died.
    pub fn drain(&mut self, store: &Store, max: usize) -> Result<usize> {
        let mut created = 0;
        for src in self.sources.iter_mut() {
            if src.live.is_none() {
                let due = src.last_start.map(|t| t.elapsed() >= RESTART_BACKOFF).unwrap_or(true);
                if due {
                    let _ = src.spawn();
                }
                continue;
            }
            for _ in 0..max {
                let msg = {
                    let live = src.live.as_ref().expect("checked above");
                    live.rx.try_recv()
                };
                let v = match msg {
                    Ok(v) => v,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        src.kill();
                        break;
                    }
                };
                let (Some(key), Some(payload)) = (v["event"]["key"].as_str(), v["event"]["payload"].as_str()) else {
                    continue;
                };
                let payload: String = payload.chars().take(MAX_PAYLOAD_CHARS).collect();
                if store.enqueue_event_once(&src.cfg.name, key, &payload, "owner")?.is_some() {
                    created += 1;
                }
                // Acknowledge whether it was new or a repeat: either way it is stored.
                if let Some(live) = src.live.as_mut() {
                    let ack = json!({ "ack": key }).to_string();
                    if writeln!(live.stdin, "{ack}").and_then(|_| live.stdin.flush()).is_err() {
                        src.kill();
                        break;
                    }
                }
            }
        }
        Ok(created)
    }
}
