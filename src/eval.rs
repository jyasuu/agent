//! Stage 4: the owner's behavioral evaluation suite.
//!
//! Cases live in `<home>/evals/cases/`. The home directory is protected by the gate, so no tool
//! the agent holds can read or write it. The agent's only way in is `propose_eval`, which writes to
//! `<home>/evals/proposed/`; a proposal does nothing until the owner runs `agent eval accept`.
//! Every case runs in a throwaway workspace with its own stores, through the same session runner
//! as real work. Checks are objective (files, exit codes, audit decisions), never a model's opinion.
//!
//! `agent eval compare` diffs a run against the owner's baseline: any case that passed in the
//! baseline and does not pass now is a regression, and the command exits nonzero. Stage 6 hangs
//! the upgrade gate on that exit code.
use crate::audit::AuditLog;
use crate::config::{Config, Grant};
use crate::gate::Gate;
use crate::plugin::PluginHost;
use crate::provider::{Block, ModelProvider, ModelResponse, ScriptedProvider, Usage};
use crate::runner::{ApprovalRequest, Approver, Outcome, Runner};
use crate::store::{now, Store};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub task: String,
    /// Files created in the throwaway workspace before the session starts.
    #[serde(default)]
    pub setup_files: BTreeMap<String, String>,
    /// A fixed model script. Without it the case only runs in live mode.
    #[serde(default)]
    pub script: Option<Vec<Step>>,
    /// Replaces the config's grants for this case (to test what a narrower agent can do).
    #[serde(default)]
    pub grants: Option<Vec<Grant>>,
    /// Irreversible actions are refused unless the case says the owner would approve them.
    #[serde(default)]
    pub approve_irreversible: bool,
    /// Scripted cases skip the verifier unless this is set (the script must then include its answers).
    #[serde(default)]
    pub verify: bool,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    #[serde(default)]
    pub say: Option<String>,
    #[serde(default)]
    pub call: Option<Call>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    pub tool: String,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Check {
    Completed,
    FinalContains { text: String },
    FileExists { path: String },
    FileAbsent { path: String },
    FileContains { path: String, text: String },
    /// Runs in the throwaway workspace. A proposed case may only use a command from `check_commands`.
    CommandOk { command: String },
    /// No tool call was denied or refused during the session.
    NoDenied,
    /// At least one call needing this capability was denied (for cases that guard a boundary).
    Denied { capability: String },
    MaxSteps { n: u32 },
    /// The independent verifier passed the session.
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub id: String,
    /// "pass", "fail", "skipped" or "error".
    pub status: String,
    pub checks: Vec<CheckResult>,
    pub steps: u32,
    pub tokens: u64,
    pub cost_usd: f64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub run_id: String,
    pub at: i64,
    /// "scripted" or "live".
    pub mode: String,
    pub cases: Vec<CaseResult>,
}

impl RunResult {
    pub fn failed(&self) -> Vec<&CaseResult> {
        self.cases.iter().filter(|c| c.status == "fail" || c.status == "error").collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Regression {
    pub id: String,
    pub reason: String,
}

// ---- paths -----------------------------------------------------------------------

pub fn evals_dir(home: &Path) -> PathBuf {
    home.join("evals")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn safe_rel(p: &str) -> bool {
    let path = Path::new(p);
    !p.is_empty()
        && path.is_relative()
        && !path.components().any(|c| matches!(c, std::path::Component::ParentDir))
}

fn validate(case: &Case) -> Result<()> {
    if !valid_id(&case.id) {
        bail!("case id must be 1 to 64 characters of letters, digits, '-' or '_'");
    }
    if case.task.trim().is_empty() {
        bail!("task is empty");
    }
    if case.checks.is_empty() {
        bail!("a case needs at least one check");
    }
    for p in case.setup_files.keys() {
        if !safe_rel(p) {
            bail!("setup file path '{p}' must be relative and stay inside the workspace");
        }
    }
    for c in &case.checks {
        match c {
            Check::FileExists { path } | Check::FileAbsent { path } | Check::FileContains { path, .. } => {
                if !safe_rel(path) {
                    bail!("check path '{path}' must be relative and stay inside the workspace");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---- proposals and the owner's review --------------------------------------------

/// The agent's only way to add to the suite. Only id, task, setup_files and checks are accepted
/// (no script, grants or approvals), and a command check must be one of the owner's check commands.
/// The file lands in `proposed/` and is never run until the owner accepts it.
pub fn propose(home: &Path, check_commands: &[String], raw: &Value) -> Result<String> {
    let obj = raw.as_object().ok_or_else(|| anyhow!("case must be a JSON object"))?;
    for k in obj.keys() {
        if !["id", "task", "setup_files", "checks"].contains(&k.as_str()) {
            bail!("field '{k}' cannot be proposed; only id, task, setup_files and checks");
        }
    }
    let case: Case = serde_json::from_value(raw.clone()).context("not a valid case")?;
    validate(&case)?;
    let allowed: Vec<String> = check_commands.iter().map(|c| norm(c)).collect();
    for c in &case.checks {
        if let Check::CommandOk { command } = c {
            if !allowed.contains(&norm(command)) {
                bail!("command checks in a proposal must be one of the owner's check_commands");
            }
        }
    }
    let dir = evals_dir(home);
    if dir.join("cases").join(format!("{}.json", case.id)).exists() {
        bail!("a case named '{}' already exists", case.id);
    }
    let pdir = dir.join("proposed");
    std::fs::create_dir_all(&pdir)?;
    let path = pdir.join(format!("{}.json", case.id));
    if path.exists() {
        bail!("a proposal named '{}' is already waiting for review", case.id);
    }
    std::fs::write(&path, serde_json::to_string_pretty(&case)?)?;
    Ok(case.id)
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn list_proposed(home: &Path) -> Result<Vec<Case>> {
    load_dir(&evals_dir(home).join("proposed"))
}

/// Owner only (CLI). Moves a proposal into the suite.
pub fn accept(home: &Path, id: &str) -> Result<()> {
    if !valid_id(id) {
        bail!("bad case id");
    }
    let from = evals_dir(home).join("proposed").join(format!("{id}.json"));
    if !from.exists() {
        bail!("no proposal named '{id}'");
    }
    let to_dir = evals_dir(home).join("cases");
    std::fs::create_dir_all(&to_dir)?;
    let to = to_dir.join(format!("{id}.json"));
    if to.exists() {
        bail!("a case named '{id}' is already in the suite");
    }
    std::fs::rename(&from, &to)?;
    Ok(())
}

pub fn reject(home: &Path, id: &str) -> Result<()> {
    if !valid_id(id) {
        bail!("bad case id");
    }
    let from = evals_dir(home).join("proposed").join(format!("{id}.json"));
    if !from.exists() {
        bail!("no proposal named '{id}'");
    }
    std::fs::remove_file(from)?;
    Ok(())
}

fn load_dir(dir: &Path) -> Result<Vec<Case>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();
    for p in paths {
        let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let case: Case = serde_json::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
        validate(&case).with_context(|| format!("case {}", p.display()))?;
        out.push(case);
    }
    Ok(out)
}

pub fn load_cases(home: &Path) -> Result<Vec<Case>> {
    load_dir(&evals_dir(home).join("cases"))
}

// ---- running -----------------------------------------------------------------------

struct FixedApprover(bool);

impl Approver for FixedApprover {
    fn approve(&self, _req: &ApprovalRequest) -> bool {
        self.0
    }
}

fn script_to_responses(steps: &[Step]) -> Vec<ModelResponse> {
    steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut content = Vec::new();
            if let Some(t) = &s.say {
                content.push(Block::Text { text: t.clone() });
            }
            if let Some(c) = &s.call {
                content.push(Block::ToolUse { id: format!("e{i}"), name: c.tool.clone(), input: c.input.clone() });
            }
            ModelResponse { content, usage: Usage { input_tokens: 10, output_tokens: 5 } }
        })
        .collect()
}

/// Run the whole suite. `live` is the real provider; without it only cases with a script run
/// and the rest are reported as skipped.
pub fn run_all(cfg: &Config, live: Option<&dyn ModelProvider>) -> Result<RunResult> {
    let cases = load_cases(&cfg.home)?;
    if cases.is_empty() {
        bail!("the suite is empty: put cases in {}", evals_dir(&cfg.home).join("cases").display());
    }
    let mode = if live.is_some() { "live" } else { "scripted" };
    let mut out = Vec::new();
    for case in &cases {
        let result = match (live, &case.script) {
            (Some(p), _) => run_case(cfg, case, p, true),
            (None, Some(script)) => {
                let p = ScriptedProvider::new(script_to_responses(script));
                run_case(cfg, case, &p, false)
            }
            (None, None) => Ok(CaseResult {
                id: case.id.clone(),
                status: "skipped".into(),
                checks: vec![],
                steps: 0,
                tokens: 0,
                cost_usd: 0.0,
                note: "no script; runs only with --live".into(),
            }),
        };
        out.push(result.unwrap_or_else(|e| CaseResult {
            id: case.id.clone(),
            status: "error".into(),
            checks: vec![],
            steps: 0,
            tokens: 0,
            cost_usd: 0.0,
            note: format!("{e:#}"),
        }));
    }
    let at = now();
    // Unique across processes and across runs in the same second, so a run never overwrites another.
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let run_id = format!("{nanos:024}-{}", std::process::id());
    Ok(RunResult { run_id, at, mode: mode.into(), cases: out })
}

fn run_case(cfg: &Config, case: &Case, provider: &dyn ModelProvider, live: bool) -> Result<CaseResult> {
    let root = std::env::temp_dir().join(format!("agent-eval-{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst), case.id));
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws)?;
    std::fs::create_dir_all(&home)?;
    let (ws, home) = (ws.canonicalize()?, home.canonicalize()?);
    for (p, content) in &case.setup_files {
        let full = ws.join(p);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(full, content)?;
    }

    let mut c = cfg.clone();
    c.workspace = ws.clone();
    c.home = home.clone();
    if let Some(g) = &case.grants {
        c.grants = g.clone();
    }
    if !live && !case.verify {
        c.verification.enabled = false;
    }
    let store = Store::open(&home.join("sessions.db"))?;
    let audit = AuditLog::open(&home.join("audit.db"))?;
    let (_e, sid) = store.enqueue_event("eval", &case.task, "owner")?;
    let mut host = PluginHost::start(&c.plugins_now(), &ws)?;
    let gate = Gate::new(&ws, &c.grants, &[home.clone()]);
    let approver = FixedApprover(case.approve_irreversible);
    let outcome = {
        let mut runner = Runner {
            cfg: &c, store: &store, audit: &audit, provider, approver: &approver,
            host: &mut host, gate: &gate, shutdown: None,
        };
        runner.run_session(sid)?
    };
    drop(host);

    let log = store.load_log(sid)?;
    let rows = audit.rows()?;
    let steps = log.iter().filter(|e| e.kind == "assistant").count() as u32;
    let (tokens, cost_usd) = store.tree_spend(sid)?;
    let final_text = match &outcome {
        Outcome::Completed { summary } => Some(summary.clone()),
        _ => None,
    };

    let mut results = Vec::new();
    for check in &case.checks {
        let (ok, detail) = match check {
            Check::Completed => (final_text.is_some(), format!("outcome: {}", outcome_name(&outcome))),
            Check::FinalContains { text } => {
                let ok = final_text.as_deref().map(|t| t.contains(text.as_str())).unwrap_or(false);
                (ok, if ok { String::new() } else { format!("final answer does not contain '{text}'") })
            }
            Check::FileExists { path } => {
                let ok = ws.join(path).exists();
                (ok, if ok { String::new() } else { format!("{path} does not exist") })
            }
            Check::FileAbsent { path } => {
                let ok = !ws.join(path).exists();
                (ok, if ok { String::new() } else { format!("{path} exists") })
            }
            Check::FileContains { path, text } => match std::fs::read_to_string(ws.join(path)) {
                Ok(t) => (t.contains(text.as_str()), format!("looking for '{text}' in {path}")),
                Err(e) => (false, format!("cannot read {path}: {e}")),
            },
            Check::CommandOk { command } => run_command(command, &ws),
            Check::NoDenied => {
                let bad: Vec<String> = rows
                    .iter()
                    .filter(|r| r.entry.decision == "denied" || r.entry.decision == "rejected_by_owner")
                    .map(|r| format!("{}:{}", r.entry.tool, r.entry.decision))
                    .collect();
                (bad.is_empty(), bad.join(", "))
            }
            Check::Denied { capability } => {
                let ok = rows.iter().any(|r| r.entry.capability == *capability && r.entry.decision == "denied");
                (ok, format!("expected a denied call needing {capability}"))
            }
            Check::MaxSteps { n } => (steps <= *n, format!("{steps} model calls, limit {n}")),
            Check::Verified => {
                let v = log.iter().rev().find(|e| e.kind == "verification").map(|e| e.payload["verdict"].as_str().unwrap_or("").to_string());
                (v.as_deref() == Some("pass"), format!("last verdict: {}", v.unwrap_or_else(|| "none".into())))
            }
        };
        results.push(CheckResult { check: serde_json::to_string(check)?, ok, detail });
    }
    let status = if results.iter().all(|r| r.ok) { "pass" } else { "fail" };
    let _ = std::fs::remove_dir_all(&root);
    Ok(CaseResult { id: case.id.clone(), status: status.into(), checks: results, steps, tokens, cost_usd, note: String::new() })
}

fn outcome_name(o: &Outcome) -> &'static str {
    match o {
        Outcome::Completed { .. } => "completed",
        Outcome::Suspended { .. } => "suspended",
        Outcome::Interrupted => "interrupted",
        Outcome::Paused => "paused",
    }
}

fn run_command(command: &str, ws: &Path) -> (bool, String) {
    let child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(ws)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    match child.and_then(|c| c.wait_with_output()) {
        Ok(o) => (
            o.status.success(),
            format!("exit {} {}", o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stderr).chars().take(200).collect::<String>()),
        ),
        Err(e) => (false, format!("cannot run: {e}")),
    }
}

// ---- results, baseline, compare ------------------------------------------------------

pub fn save_run(home: &Path, run: &RunResult) -> Result<PathBuf> {
    let dir = evals_dir(home).join("results");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", run.run_id));
    std::fs::write(&path, serde_json::to_string_pretty(run)?)?;
    Ok(path)
}

pub fn latest_run(home: &Path) -> Result<RunResult> {
    let dir = evals_dir(home).join("results");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|_| anyhow!("no eval runs yet: run `agent eval run` first"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    // run ids start with a zero-padded nanosecond timestamp, so the newest sorts last
    paths.sort();
    let p = paths.pop().ok_or_else(|| anyhow!("no eval runs yet: run `agent eval run` first"))?;
    Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
}

/// Owner only (CLI). Makes the latest run the baseline every later run is compared with.
pub fn set_baseline(home: &Path) -> Result<RunResult> {
    let run = latest_run(home)?;
    std::fs::write(evals_dir(home).join("baseline.json"), serde_json::to_string_pretty(&run)?)?;
    Ok(run)
}

pub fn load_baseline(home: &Path) -> Result<RunResult> {
    let p = evals_dir(home).join("baseline.json");
    let text = std::fs::read_to_string(&p).map_err(|_| anyhow!("no baseline yet: run `agent eval baseline` after a good run"))?;
    Ok(serde_json::from_str(&text)?)
}

/// Any case that passed in the baseline and does not pass now is a regression. A case that was
/// removed from the suite is one too, so the bar cannot be lowered by deleting cases. Cases that are
/// new since the baseline, or that already failed there, never block.
pub fn compare(base: &RunResult, cur: &RunResult) -> Result<Vec<Regression>> {
    if base.mode != cur.mode {
        bail!("the baseline was a {} run and this one is {}; compare like with like", base.mode, cur.mode);
    }
    let mut out = Vec::new();
    for b in base.cases.iter().filter(|c| c.status == "pass") {
        match cur.cases.iter().find(|c| c.id == b.id) {
            None => out.push(Regression { id: b.id.clone(), reason: "case is missing from this run".into() }),
            Some(c) if c.status != "pass" => {
                let why: Vec<String> = c.checks.iter().filter(|k| !k.ok).map(|k| format!("{} ({})", k.check, k.detail)).collect();
                out.push(Regression {
                    id: b.id.clone(),
                    reason: format!("was pass, now {}: {}{}", c.status, why.join("; "), c.note),
                })
            }
            _ => {}
        }
    }
    Ok(out)
}

pub fn summary_json(run: &RunResult) -> Value {
    json!({ "run": run.run_id, "mode": run.mode,
            "pass": run.cases.iter().filter(|c| c.status == "pass").count(),
            "fail": run.failed().len(),
            "skipped": run.cases.iter().filter(|c| c.status == "skipped").count() })
}
