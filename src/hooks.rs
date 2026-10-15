//! Hooks: owner-written programs the core consults at fixed points in the loop.
//!
//! Modelled on opencode's plugin hooks, with the parts that would break this agent's trust model
//! left out. A hook can *tighten* and *watch*; it can never loosen:
//!
//! - `tool.before`  runs after the gate has allowed a call (and before the owner is asked), and may
//!                  only answer allow or deny. It cannot change the call's arguments, because a
//!                  rewrite after the gate approved the original would be a bypass.
//! - `tool.after`   may keep or replace a tool's result. It runs before the result is written to
//!                  the append-only session log, so a redacted secret never reaches the log.
//! - `event`        a one-way stream of lifecycle events. Fire and forget: it never waits, and a
//!                  consumer that cannot keep up loses events (and is told how many) instead of
//!                  stalling the agent.
//!
//! Protocol, one JSON object per line over the hook's stdin and stdout:
//!   core -> hook   {"id":7,"hook":"tool.before","input":{session,tool,plugin,capability,tier,args}}
//!   hook -> core   {"id":7,"result":{"action":"allow"}}  or  {"action":"deny","reason":"..."}
//!   core -> hook   {"id":8,"hook":"tool.after","input":{...,"content":"...","is_error":false}}
//!   hook -> core   {"id":8,"result":{"action":"keep"}}   or  {"action":"replace","content":"..."}
//!   core -> hook   {"hook":"event","event":"session.started","data":{...},"dropped":0}   (no reply)
//!
//! Hooks start with an empty environment (plus whatever `env` the owner gave them), the workspace as
//! their working directory, and no handle to the stores. They start the first time they are needed and
//! restart after a crash (at most every two seconds). When the session ends, a hook's input is closed so
//! it can finish what is queued (the last events) and exit; one that does not is stopped after a second.
use crate::config::{HookConfig, OnError};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

const OUT_DEPTH: usize = 256;
const IN_DEPTH: usize = 256;
const RESTART_BACKOFF: Duration = Duration::from_secs(2);
/// A result bigger than this is not shown to a `tool.after` hook. A redaction hook that saw only a
/// prefix would let the rest through, so too large counts as a failure and `on_error` decides.
pub const MAX_HOOK_CONTENT: usize = 1_000_000;
const MAX_REASON: usize = 300;
/// When the session ends, hooks get this long to read what is still queued (the final events) and exit.
const STOP_GRACE: Duration = Duration::from_secs(1);

/// What `tool.before` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Before {
    Allow,
    Deny { hook: String, reason: String },
}

/// Something worth an audit row: a hook that failed, replaced a result, or tried to do what it may not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookNote {
    pub hook: String,
    /// `hook_error`, `hook_replaced` or `hook_ignored`.
    pub decision: &'static str,
    pub reason: String,
}

struct Live {
    child: Child,
    tx: SyncSender<String>,
    rx: Receiver<String>,
}

struct HookProc {
    cfg: HookConfig,
    workspace: PathBuf,
    live: Option<Live>,
    last_start: Option<Instant>,
    next_id: u64,
    /// Events lost since the last one that got through.
    dropped: u64,
    dropped_total: u64,
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(n).collect::<String>())
    }
}

impl HookProc {
    fn new(cfg: HookConfig, workspace: PathBuf) -> Self {
        Self { cfg, workspace, live: None, last_start: None, next_id: 0, dropped: 0, dropped_total: 0 }
    }

    fn spawn(&mut self) -> Result<()> {
        self.last_start = Some(Instant::now());
        let (program, args) = match &self.cfg.sandbox {
            Some(sb) => crate::sandbox::wrap(sb, &self.workspace, &self.cfg.command, &self.cfg.args)?,
            None => (self.cfg.command.clone(), self.cfg.args.clone()),
        };
        let mut child = Command::new(&program)
            .args(&args)
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .envs(self.cfg.env.iter())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting hook '{}'", self.cfg.name))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        // Writes go through a bounded queue and their own thread, so a hook that stops reading can
        // never block the agent: the queue fills, the send fails, and the hook is treated as broken.
        let (out_tx, out_rx) = mpsc::sync_channel::<String>(OUT_DEPTH);
        std::thread::spawn(move || {
            for line in out_rx {
                if writeln!(stdin, "{line}").and_then(|_| stdin.flush()).is_err() {
                    break;
                }
            }
        });
        let (in_tx, in_rx) = mpsc::sync_channel::<String>(IN_DEPTH);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if in_tx.send(line).is_err() {
                    break;
                }
            }
        });
        self.live = Some(Live { child, tx: out_tx, rx: in_rx });
        Ok(())
    }

    fn kill(&mut self) {
        if let Some(mut l) = self.live.take() {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
    }

    /// Start the hook if it is not running. A hook that just died is not restarted in a tight loop.
    fn ensure(&mut self) -> Result<()> {
        if self.live.is_some() {
            return Ok(());
        }
        if self.last_start.map(|t| t.elapsed() < RESTART_BACKOFF).unwrap_or(false) {
            bail!("hook '{}' is down and is restarted at most every {}s", self.cfg.name, RESTART_BACKOFF.as_secs());
        }
        self.spawn()
    }

    fn request(&mut self, kind: &str, input: Value) -> Result<Value> {
        self.ensure()?;
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({ "id": id, "hook": kind, "input": input }).to_string();
        let name = self.cfg.name.clone();
        let timeout = Duration::from_millis(self.cfg.timeout_ms);
        let live = self.live.as_mut().ok_or_else(|| anyhow!("hook '{name}' is not running"))?;
        match live.tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.kill();
                bail!("hook '{name}' is not reading its input");
            }
            Err(TrySendError::Disconnected(_)) => {
                self.kill();
                bail!("hook '{name}' closed its input");
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let live = self.live.as_mut().ok_or_else(|| anyhow!("hook '{name}' is not running"))?;
            match live.rx.recv_timeout(remaining) {
                Ok(l) => {
                    let Ok(v) = serde_json::from_str::<Value>(&l) else { continue };
                    if v["id"] != json!(id) {
                        continue; // an answer to a call that already timed out, or noise
                    }
                    if let Some(e) = v.get("error") {
                        bail!("hook '{name}' reported an error: {}", clip(&e.to_string(), 200));
                    }
                    return Ok(v["result"].clone());
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.kill();
                    bail!("hook '{name}' did not answer within {}ms and was stopped", timeout.as_millis());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.kill();
                    bail!("hook '{name}' exited");
                }
            }
        }
    }

    fn wants_event(&self, name: &str) -> bool {
        self.cfg.subscribes("event") && (self.cfg.events.is_empty() || self.cfg.events.iter().any(|e| e == name))
    }

    /// Never waits. Returns quietly if the hook is down or behind.
    fn send_event(&mut self, name: &str, data: &Value) {
        if !self.wants_event(name) {
            return;
        }
        if self.ensure().is_err() {
            self.dropped += 1;
            self.dropped_total += 1;
            return;
        }
        let mut msg = json!({ "hook": "event", "event": name, "data": data });
        if self.dropped > 0 {
            msg["dropped"] = json!(self.dropped);
        }
        let sent = match self.live.as_ref().map(|l| l.tx.try_send(msg.to_string())) {
            Some(Ok(())) => true,
            Some(Err(TrySendError::Full(_))) => false,
            Some(Err(TrySendError::Disconnected(_))) => {
                self.kill();
                false
            }
            None => false,
        };
        if sent {
            self.dropped = 0;
        } else {
            self.dropped += 1;
            self.dropped_total += 1;
        }
    }
}

impl Drop for HookProc {
    fn drop(&mut self) {
        self.kill();
    }
}

impl Drop for HookHost {
    /// Close every hook's input first, so each drains its queue and exits, then give them a shared
    /// second before stopping the stragglers. Killing at once would lose the final events.
    fn drop(&mut self) {
        let mut children = Vec::new();
        for h in self.hooks.iter_mut() {
            if let Some(l) = h.live.take() {
                drop(l.tx);
                drop(l.rx);
                children.push(l.child);
            }
        }
        let deadline = Instant::now() + STOP_GRACE;
        for c in children.iter_mut() {
            loop {
                match c.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    _ => {
                        let _ = c.kill();
                        let _ = c.wait();
                        break;
                    }
                }
            }
        }
    }
}

/// The hooks for one session. Empty when none are configured, and then every method does nothing.
pub struct HookHost {
    hooks: Vec<HookProc>,
}

impl HookHost {
    pub fn empty() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Nothing is started here; each hook starts the first time it is needed.
    pub fn new(cfgs: &[HookConfig], workspace: &Path) -> Self {
        Self { hooks: cfgs.iter().map(|c| HookProc::new(c.clone(), workspace.to_path_buf())).collect() }
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Events that were lost because a hook was down or too slow.
    pub fn dropped_events(&self) -> u64 {
        self.hooks.iter().map(|h| h.dropped_total).sum()
    }

    /// Ask every `tool.before` hook, in config order. The first deny wins. `input` is what the hook sees.
    pub fn before(&mut self, input: &Value) -> (Before, Vec<HookNote>) {
        let mut notes = Vec::new();
        for h in self.hooks.iter_mut().filter(|h| h.cfg.subscribes("tool.before")) {
            let failure = match h.request("tool.before", input.clone()) {
                Ok(v) => {
                    if v.get("args").is_some() {
                        notes.push(HookNote {
                            hook: h.cfg.name.clone(),
                            decision: "hook_ignored",
                            reason: "tried to change the call's arguments; a hook can only allow or deny".into(),
                        });
                    }
                    match v["action"].as_str() {
                        Some("allow") => continue,
                        Some("deny") => {
                            let reason = v["reason"].as_str().filter(|r| !r.is_empty()).unwrap_or("denied by hook");
                            return (Before::Deny { hook: h.cfg.name.clone(), reason: clip(reason, MAX_REASON) }, notes);
                        }
                        _ => "answered with neither allow nor deny".to_string(),
                    }
                }
                Err(e) => format!("{e:#}"),
            };
            match h.cfg.on_error_for("tool.before") {
                OnError::Deny => {
                    let reason = format!("hook '{}' failed ({}), and hooks fail closed", h.cfg.name, failure);
                    notes.push(HookNote { hook: h.cfg.name.clone(), decision: "hook_error", reason: reason.clone() });
                    return (Before::Deny { hook: h.cfg.name.clone(), reason: clip(&reason, MAX_REASON) }, notes);
                }
                OnError::Skip => notes.push(HookNote { hook: h.cfg.name.clone(), decision: "hook_error", reason: format!("{failure}; skipped") }),
            }
        }
        (Before::Allow, notes)
    }

    /// Let every `tool.after` hook keep or replace the result. `base` is the call's description
    /// (the same fields `tool.before` got); the hook also sees the content and whether it was an error.
    pub fn after(&mut self, base: &Value, mut content: String, is_error: bool) -> (String, Vec<HookNote>) {
        let mut notes = Vec::new();
        for h in self.hooks.iter_mut().filter(|h| h.cfg.subscribes("tool.after")) {
            let failure = if content.len() > MAX_HOOK_CONTENT {
                format!("the result is {} bytes, more than the {MAX_HOOK_CONTENT} a hook is shown", content.len())
            } else {
                let mut input = base.clone();
                input["content"] = json!(content);
                input["is_error"] = json!(is_error);
                match h.request("tool.after", input) {
                    Ok(v) => match v["action"].as_str() {
                        Some("keep") => continue,
                        Some("replace") => match v["content"].as_str() {
                            Some(new) => {
                                notes.push(HookNote { hook: h.cfg.name.clone(), decision: "hook_replaced", reason: format!("result changed from {} to {} bytes", content.len(), new.len()) });
                                content = new.to_string();
                                continue;
                            }
                            None => "asked to replace the result but sent no content".to_string(),
                        },
                        _ => "answered with neither keep nor replace".to_string(),
                    },
                    Err(e) => format!("{e:#}"),
                }
            };
            match h.cfg.on_error_for("tool.after") {
                OnError::Deny => {
                    notes.push(HookNote { hook: h.cfg.name.clone(), decision: "hook_error", reason: format!("{failure}; the result was withheld") });
                    content = format!("[result withheld: hook '{}' failed]", h.cfg.name);
                }
                OnError::Skip => notes.push(HookNote { hook: h.cfg.name.clone(), decision: "hook_error", reason: format!("{failure}; skipped") }),
            }
        }
        (content, notes)
    }

    /// Tell every interested hook, without waiting for any of them.
    pub fn emit(&mut self, name: &str, data: Value) {
        for h in self.hooks.iter_mut() {
            h.send_event(name, &data);
        }
    }
}
