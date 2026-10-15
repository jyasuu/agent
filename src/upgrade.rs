//! Self-upgrade, for plugins. The agent may write a plugin and *propose* it. It can do nothing else:
//! it cannot run the checks, approve, deploy or roll back. Those are owner commands.
//!
//! The pipeline has a fixed order, and a stage runs only if the one before it passed:
//!   1. static checks      manifest, limits, names, claimed capabilities, syntax (inside the sandbox)
//!   2. permission review  what it asks for, against what is granted and what its predecessor asked for
//!   3. contract tests     errors, garbage input, unknown tools and shutdown are handled
//!   4. eval gate          your baseline suite, run with the candidate in place; any regression blocks
//!   5. canary             recorded read-only calls replayed against the old and new version, answers compared
//!   6. approval           yours, unless an earned auto-approval applies (see `UpgradeConfig`)
//!   7. versioned deploy   then the suite runs again, and a regression rolls back by itself
//!
//! A candidate is copied into a snapshot the moment it is proposed and every later step works from the
//! snapshot, whose hash is re-checked, so changing the source afterwards changes nothing.
//! Everything a plugin runs in is the OS sandbox; its code is never trusted for being "checked".
use crate::audit::{AuditEntry, AuditLog};
use crate::config::{Config, PluginConfig, SandboxConfig, Tier};
use crate::delegate::NEVER_DELEGATED;
use crate::eval::{self, Regression};
use crate::gate::resolve;
use crate::plugin::{PluginHost, ToolEntry};
use crate::store::{now, Store};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const MAX_FILES: usize = 50;
const MAX_TOTAL_BYTES: u64 = 1_000_000;
const MAX_ENTRY_BYTES: u64 = 200_000;
const CORE_TOOL_NAMES: [&str; 7] = ["pin", "recall", "spawn_agent", "propose_eval", "propose_upgrade", "check_plugin", "upgrade_status"];

/// A complete plugin script that passes every check. The guide below shows it to the agent, and a test
/// runs it through the real checks, so the documentation cannot drift away from what the checks accept.
pub const PLUGIN_EXAMPLE_PY: &str = include_str!("plugin_example.py");

/// What the agent is told about writing a plugin.
pub fn plugin_guide() -> String {
    format!(
        "A plugin is a folder with plugin.json and one script.\n\
         plugin.json: {{\"name\": \"lowercase-name\", \"runtime\": \"python3\" or \"sh\", \"entry\": \"plugin.py\", \"tools\": [ {{\"name\": \"shout\", \"description\": \"...\", \"input_schema\": {{JSON schema}}, \"capability\": \"text:shout\", \"scope_args\": []}} ]}}\n\
         - capability says what the tool needs, in the form area:thing. The owner's grants decide whether it may be used; with no grant for it the tool stays denied. Put the names of arguments that hold file paths in scope_args.\n\
         - Set \"recursive\": true on a tool that walks a whole folder tree below a path argument (a search or a listing). The gate then refuses it for a folder that holds the agent's own files. Such a tool needs its folder argument in scope_args.\n\
         - File tools worth having: read (with line numbers and a continue hint), edit by exact text replacement (refused unless the file was read first, and when the text is missing or matches more than once), glob, grep and tree. Use the fs:read and fs:write capabilities, and tool names that differ from the built-in fs_ tools.\n\
         - The tools in plugin.json must be exactly the tools the script reports.\n\
         The script reads one JSON object per line on stdin and writes one per line on stdout:\n\
           {{\"id\":1,\"method\":\"manifest\"}}  ->  {{\"id\":1,\"result\":{{\"tools\":[...the same tools...]}}}}\n\
           {{\"id\":2,\"method\":\"call\",\"params\":{{\"tool\":\"shout\",\"args\":{{...}}}}}}  ->  {{\"id\":2,\"result\":{{\"content\":\"text\",\"is_error\":false}}}}\n\
         Rules: answer every line; never exit on bad input; an unknown tool or bad arguments is is_error true, not a crash; exit when stdin closes. It runs in a sandbox with no network, with only the workspace visible and system files read-only.\n\
         A complete working plugin.py:\n{PLUGIN_EXAMPLE_PY}"
    )
}
static TMP: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    /// "python3" or "sh".
    pub runtime: String,
    /// Script path inside the plugin folder.
    pub entry: String,
    pub tools: Vec<ToolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub name: String,
    /// passed, failed, blocked, skipped or info.
    pub status: String,
    pub findings: Vec<String>,
}

fn stage(name: &str, status: &str, findings: Vec<String>) -> Stage {
    Stage { name: name.into(), status: status.into(), findings }
}

// ---- paths and the registry ------------------------------------------------------------------

pub fn upgrades_dir(home: &Path) -> PathBuf {
    home.join("upgrades")
}

pub fn plugins_dir(home: &Path) -> PathBuf {
    home.join("plugins")
}

fn candidate_dir(home: &Path, id: i64) -> PathBuf {
    upgrades_dir(home).join(id.to_string()).join("candidate")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: u32,
    pub hash: String,
    pub upgrade_id: i64,
    /// "owner" or "auto".
    pub approved_by: String,
    pub deployed_at: i64,
    pub capabilities: Vec<String>,
}

fn versions_path(home: &Path, name: &str) -> PathBuf {
    plugins_dir(home).join(name).join("versions.json")
}

pub fn versions(home: &Path, name: &str) -> Vec<VersionInfo> {
    std::fs::read_to_string(versions_path(home, name))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_versions(home: &Path, name: &str, v: &[VersionInfo]) -> Result<()> {
    std::fs::create_dir_all(plugins_dir(home).join(name))?;
    std::fs::write(versions_path(home, name), serde_json::to_string_pretty(v)?)?;
    Ok(())
}

pub fn active_version(home: &Path, name: &str) -> Option<u32> {
    std::fs::read_to_string(plugins_dir(home).join(name).join("active")).ok()?.trim().parse().ok()
}

fn set_active(home: &Path, name: &str, v: Option<u32>) -> Result<()> {
    let p = plugins_dir(home).join(name).join("active");
    match v {
        Some(n) => {
            std::fs::create_dir_all(p.parent().unwrap())?;
            // Written to a temp name and renamed, so the switch is one atomic step.
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, n.to_string())?;
            std::fs::rename(tmp, p)?;
        }
        None => {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(())
}

fn version_dir(home: &Path, name: &str, v: u32) -> PathBuf {
    plugins_dir(home).join(name).join(v.to_string())
}

fn sandboxed(dir: &Path, home: &Path, readonly_workspace: bool) -> SandboxConfig {
    SandboxConfig {
        network: false,
        workspace_readonly: readonly_workspace,
        ro_binds: vec![dir.to_string_lossy().to_string()],
        rw_binds: vec![],
        hide: vec![home.to_path_buf()],
        program: None,
    }
}

fn plugin_config(m: &PluginManifest, dir: &Path, home: &Path) -> PluginConfig {
    PluginConfig {
        name: m.name.clone(),
        command: m.runtime.clone(),
        args: vec![dir.join(&m.entry).to_string_lossy().to_string()],
        call_timeout_secs: 30,
        sandbox: Some(sandboxed(dir, home, false)),
        mcp: None,
    }
}

/// The deployed plugins to start, one per name, at the active version. Always sandboxed.
pub fn installed_plugins(home: &Path) -> Vec<PluginConfig> {
    let Ok(rd) = std::fs::read_dir(plugins_dir(home)) else { return vec![] };
    let mut names: Vec<String> = rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|name| {
            let v = active_version(home, &name)?;
            let dir = version_dir(home, &name, v);
            let m = read_manifest(&dir).ok()?;
            Some(plugin_config(&m, &dir, home))
        })
        .collect()
}

pub fn read_manifest(dir: &Path) -> Result<PluginManifest> {
    let text = std::fs::read_to_string(dir.join("plugin.json")).context("plugin.json is missing")?;
    serde_json::from_str(&text).context("plugin.json is not valid")
}

// ---- snapshots -------------------------------------------------------------------------------

fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let ft = e.file_type()?;
        let rel = e.path().strip_prefix(base).unwrap().to_path_buf();
        if ft.is_symlink() {
            bail!("'{}' is a symbolic link, which a plugin may not contain", rel.display());
        } else if ft.is_dir() {
            walk(&e.path(), base, out)?;
        } else if ft.is_file() {
            out.push(rel);
        } else {
            bail!("'{}' is not a regular file", rel.display());
        }
    }
    Ok(())
}

/// Hash of every file's path and contents.
pub fn tree_hash(dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    walk(dir, dir, &mut files)?;
    let mut h = Sha256::new();
    for f in files {
        let rel = f.to_string_lossy().to_string();
        let data = std::fs::read(dir.join(&f))?;
        h.update((rel.len() as u64).to_le_bytes());
        h.update(rel.as_bytes());
        h.update((data.len() as u64).to_le_bytes());
        h.update(&data);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Copies a plugin folder, refusing links and anything over the limits.
fn copy_limited(src: &Path, dst: &Path) -> Result<()> {
    let mut files = Vec::new();
    walk(src, src, &mut files)?;
    if files.len() > MAX_FILES {
        bail!("a plugin may have at most {MAX_FILES} files (this has {})", files.len());
    }
    let mut total = 0u64;
    for f in &files {
        total += std::fs::metadata(src.join(f))?.len();
    }
    if total > MAX_TOTAL_BYTES {
        bail!("a plugin may total at most {MAX_TOTAL_BYTES} bytes (this has {total})");
    }
    for f in &files {
        let to = dst.join(f);
        std::fs::create_dir_all(to.parent().unwrap())?;
        std::fs::copy(src.join(f), to)?;
    }
    Ok(())
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 40 && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn valid_capability(c: &str) -> bool {
    match c.split_once(':') {
        Some((a, b)) => {
            !a.is_empty()
                && !b.is_empty()
                && c.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, ':' | '_' | '-' | '.' | '*'))
        }
        None => false,
    }
}

fn audit_row(audit: &AuditLog, sid: i64, plugin: &str, decision: &str, reason: &str) -> Result<()> {
    audit.append(&AuditEntry {
        session_id: sid,
        plugin: plugin.into(),
        tool: "upgrade".into(),
        capability: "upgrade:pipeline".into(),
        tier: "-".into(),
        decision: decision.into(),
        reason: reason.into(),
        args: String::new(),
    })?;
    Ok(())
}

/// The plugin folder an agent named, if it is a folder inside the workspace and not the agent's own home.
fn plugin_folder(cfg: &Config, input: &Value) -> std::result::Result<PathBuf, String> {
    let Some(path) = input["path"].as_str().filter(|p| !p.trim().is_empty()) else {
        return Err("needs a `path` to a plugin folder in the workspace".into());
    };
    if cfg.home.as_os_str().is_empty() {
        return Err("no home directory is configured for upgrades".into());
    }
    let ws = resolve(Path::new("/"), &cfg.workspace.to_string_lossy());
    let src = resolve(&ws, path);
    if !src.starts_with(&ws) || src.starts_with(resolve(Path::new("/"), &cfg.home.to_string_lossy())) {
        return Err("the plugin folder must be inside the workspace".into());
    }
    if !src.is_dir() {
        return Err(format!("'{path}' is not a folder"));
    }
    Ok(src)
}

/// The agent-facing step. Copies the folder into a snapshot and queues it. Nothing runs.
pub fn propose(cfg: &Config, store: &Store, audit: &AuditLog, sid: i64, input: &Value) -> Result<(String, bool)> {
    let src = match plugin_folder(cfg, input) {
        Ok(p) => p,
        Err(m) => return Ok((m, true)),
    };
    let manifest = match read_manifest(&src) {
        Ok(m) => m,
        Err(e) => return Ok((format!("cannot propose: {e:#}"), true)),
    };
    if !valid_name(&manifest.name) {
        return Ok(("the plugin name may use only lowercase letters, digits, '-' and '_' (40 at most)".into(), true));
    }

    let tmp = upgrades_dir(&cfg.home).join(format!(".incoming-{}-{}", std::process::id(), TMP.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&tmp)?;
    if let Err(e) = copy_limited(&src, &tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Ok((format!("cannot propose: {e:#}"), true));
    }
    let hash = tree_hash(&tmp)?;
    let id = store.create_upgrade(&manifest.name, sid, &hash)?;
    std::fs::create_dir_all(upgrades_dir(&cfg.home).join(id.to_string()))?;
    std::fs::rename(&tmp, candidate_dir(&cfg.home, id))?;
    audit_row(audit, sid, &manifest.name, "upgrade_proposed", &format!("upgrade #{id}, snapshot {}", &hash[..12]))?;
    Ok((
        format!(
            "proposed upgrade #{id} for plugin '{}'. It was copied as it is now, so later edits do not change it. \
             The owner runs the checks and decides; nothing has been installed.",
            manifest.name
        ),
        false,
    ))
}

/// Lets the agent run the same static checks and contract tests the owner's pipeline will run, on a
/// throwaway copy, before it proposes. Nothing is queued, stored or installed. The owner's eval
/// suite and canary are not part of this and are never described to the agent.
pub fn check(cfg: &Config, audit: &AuditLog, sid: i64, input: &Value) -> Result<(String, bool)> {
    let src = match plugin_folder(cfg, input) {
        Ok(p) => p,
        Err(m) => return Ok((format!("cannot check: {m}"), true)),
    };
    let tmp = upgrades_dir(&cfg.home).join(format!(".check-{}-{}", std::process::id(), TMP.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&tmp)?;
    let outcome = (|| -> Result<(String, bool)> {
        if let Err(e) = copy_limited(&src, &tmp) {
            return Ok((format!("cannot check: {e:#}"), true));
        }
        let m = match read_manifest(&tmp) {
            Ok(m) => m,
            Err(e) => return Ok((format!("static checks: failed\n- {e:#}"), true)),
        };
        let bad = static_checks(cfg, &tmp, &m);
        if !bad.is_empty() {
            return Ok((format!("static checks: failed\n{}", bad.iter().map(|b| format!("- {b}")).collect::<Vec<_>>().join("\n")), true));
        }
        let bad = contract_tests(cfg, &tmp, &m);
        if !bad.is_empty() {
            return Ok((format!("static checks: passed\ncontract tests: failed\n{}", bad.iter().map(|b| format!("- {b}")).collect::<Vec<_>>().join("\n")), true));
        }
        Ok((
            "static checks: passed\ncontract tests: passed\nThis is the part you can test yourself. The owner's pipeline also runs a private eval suite and a canary, and then decides; propose_upgrade to submit it.".into(),
            false,
        ))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    let (text, failed) = outcome?;
    audit_row(audit, sid, &m_name(&src), if failed { "upgrade_check_failed" } else { "upgrade_check_passed" }, "agent self-check")?;
    Ok((text, failed))
}

fn m_name(dir: &Path) -> String {
    read_manifest(dir).map(|m| m.name).unwrap_or_else(|_| "-".into())
}

/// What the agent may learn about a proposal: where it stands and what is wrong with its own code.
/// Anything that would reveal the owner's private tests (eval case ids, replayed answers) is left out,
/// so the agent cannot tune its output to the suite.
pub fn status_for_agent(store: &Store, input: &Value) -> Result<(String, bool)> {
    let Some(id) = input["id"].as_i64() else {
        let rows = store.list_upgrades()?;
        if rows.is_empty() {
            return Ok(("no upgrades have been proposed".into(), false));
        }
        return Ok((rows.iter().take(10).map(|r| format!("#{} {} [{}]", r.id, r.name, r.status)).collect::<Vec<_>>().join("\n"), false));
    };
    let Ok(row) = store.get_upgrade(id) else {
        return Ok((format!("there is no upgrade #{id}"), true));
    };
    let mut out = format!("upgrade #{} '{}': {}\n", row.id, row.name, row.status);
    for st in row.report["stages"].as_array().into_iter().flatten() {
        let name = st["name"].as_str().unwrap_or("?");
        let status = st["status"].as_str().unwrap_or("?");
        out.push_str(&format!("- {name}: {status}\n"));
        match name {
            // Problems in the agent's own code: shown in full.
            "static checks" | "contract tests" => {
                for f in st["findings"].as_array().into_iter().flatten() {
                    out.push_str(&format!("    {}\n", f.as_str().unwrap_or("")));
                }
            }
            "permission review" => {
                for f in st["findings"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).filter(|f| f.starts_with("asks for") || f.contains("not covered") || f.contains("ASKS FOR MORE") || f.contains("first version")) {
                    out.push_str(&format!("    {f}\n"));
                }
            }
            "eval gate" if status == "blocked" => out.push_str("    the owner's private evaluation suite did not accept it; its contents are not shown\n"),
            "canary" if status == "failed" => out.push_str("    a replayed real call got a different answer than the version in service; details are not shown\n"),
            _ => {}
        }
    }
    out.push_str(match row.status.as_str() {
        "proposed" => "Next: the owner has not run the checks yet.",
        "ready_for_review" => "Next: it passed every check and is waiting for the owner's decision.",
        "deployed" => "It is live from the next session.",
        "rejected" | "rolled_back" => "It is not in service. Fix what you can and propose it again as a new upgrade.",
        _ => "It did not pass. A proposal cannot be edited: fix the folder, check it with check_plugin, and propose again.",
    });
    Ok((out, false))
}

// ---- a raw plugin process, for the contract tests and the canary -----------------------------

struct RawPlugin {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    next: u64,
}

impl RawPlugin {
    fn start(pc: &PluginConfig, ws: &Path) -> Result<Self> {
        let (program, args) = match &pc.sandbox {
            Some(sb) => crate::sandbox::wrap(sb, ws, &pc.command, &pc.args)?,
            None => (pc.command.clone(), pc.args.clone()),
        };
        let mut child = Command::new(program)
            .args(args)
            .current_dir(ws)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("starting the plugin")?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, stdin, rx, next: 0 })
    }

    fn send_raw(&mut self, line: &str) -> Result<()> {
        let s = self.stdin.as_mut().ok_or_else(|| anyhow!("input is closed"))?;
        writeln!(s, "{line}")?;
        s.flush()?;
        Ok(())
    }

    /// The whole reply, `error` field included. Err means no reply in time, or the plugin exited.
    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.next += 1;
        let id = self.next;
        self.send_raw(&json!({ "id": id, "method": method, "params": params }).to_string())?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(l) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&l) {
                        if v["id"] == json!(id) {
                            return Ok(v);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => bail!("no reply within {}s", timeout.as_secs()),
                Err(RecvTimeoutError::Disconnected) => bail!("the plugin exited"),
            }
        }
    }

    fn manifest(&mut self, timeout: Duration) -> Result<Vec<ToolEntry>> {
        let v = self.request("manifest", Value::Null, timeout)?;
        serde_json::from_value(v["result"]["tools"].clone()).context("the manifest reply has no tool list")
    }

    fn call(&mut self, tool: &str, args: &Value, timeout: Duration) -> Result<(String, bool)> {
        let v = self.request("call", json!({ "tool": tool, "args": args }), timeout)?;
        if let Some(e) = v.get("error") {
            return Ok((e.to_string(), true));
        }
        Ok((v["result"]["content"].as_str().unwrap_or("").to_string(), v["result"]["is_error"].as_bool().unwrap_or(false)))
    }

    /// Close the plugin's input and see whether it exits by itself.
    fn closes_cleanly(&mut self, timeout: Duration) -> bool {
        self.stdin = None;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for RawPlugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sig(tools: &[ToolEntry]) -> BTreeSet<(String, String, Vec<String>, bool)> {
    tools.iter().map(|t| (t.name.clone(), t.capability.clone(), t.scope_args.clone(), t.recursive)).collect()
}

// ---- stage 1: static checks ------------------------------------------------------------------

fn static_checks(cfg: &Config, dir: &Path, m: &PluginManifest) -> Vec<String> {
    let mut bad = Vec::new();
    if !valid_name(&m.name) {
        bad.push(format!("plugin name '{}' is not allowed", m.name));
    }
    if !["python3", "sh"].contains(&m.runtime.as_str()) {
        bad.push(format!("runtime '{}' is not supported (python3 or sh)", m.runtime));
    }
    let entry = Path::new(&m.entry);
    if entry.is_absolute() || entry.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bad.push("entry must be a path inside the plugin folder".into());
    }
    match std::fs::metadata(dir.join(&m.entry)) {
        Ok(md) if md.is_file() && md.len() <= MAX_ENTRY_BYTES => {}
        Ok(md) if md.is_file() => bad.push(format!("entry script is {} bytes; the limit is {MAX_ENTRY_BYTES}", md.len())),
        _ => bad.push(format!("entry script '{}' does not exist", m.entry)),
    }
    if m.tools.is_empty() {
        bad.push("the plugin declares no tools".into());
    }
    let mut seen = BTreeSet::new();
    for t in &m.tools {
        let ok_name = !t.name.is_empty() && t.name.len() <= 40 && t.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !ok_name {
            bad.push(format!("tool name '{}' is not allowed", t.name));
        }
        if !seen.insert(t.name.clone()) {
            bad.push(format!("tool '{}' is declared twice", t.name));
        }
        if CORE_TOOL_NAMES.contains(&t.name.as_str()) {
            bad.push(format!("tool '{}' is a name the core reserves", t.name));
        }
        if !valid_capability(&t.capability) {
            bad.push(format!("tool '{}' names capability '{}', which is not in the form area:thing", t.name, t.capability));
        } else if NEVER_DELEGATED.iter().any(|p| t.capability.starts_with(p)) {
            bad.push(format!("tool '{}' claims '{}', a capability that changes authority; a plugin cannot hold it", t.name, t.capability));
        }
    }
    if !bad.is_empty() {
        return bad;
    }

    // Names must not collide with tools that other plugins already provide.
    let mut others = cfg.clone();
    others.plugins.retain(|p| p.name != m.name);
    others.exclude_installed.push(m.name.clone());
    others.extra_plugins.clear();
    match PluginHost::start_for(&others) {
        Ok(host) => {
            let existing: BTreeSet<String> = host.specs().into_iter().map(|s| s.name).collect();
            for t in &m.tools {
                if existing.contains(&t.name) {
                    bad.push(format!("tool '{}' is already provided by another plugin", t.name));
                }
            }
        }
        Err(e) => bad.push(format!("could not inspect the existing plugins: {e:#}")),
    }

    // Syntax, checked inside the sandbox with the folder read-only and no network.
    let sb = sandboxed(dir, &cfg.home, true);
    let entry_abs = dir.join(&m.entry).to_string_lossy().to_string();
    let (cmd, args): (&str, Vec<String>) = if m.runtime == "python3" {
        ("python3", vec!["-c".into(), "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')".into(), entry_abs])
    } else {
        ("sh", vec!["-n".into(), entry_abs])
    };
    match crate::sandbox::wrap(&sb, &cfg.workspace, cmd, &args) {
        Ok((prog, a)) => match Command::new(prog).args(a).env_clear().stdin(Stdio::null()).output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => bad.push(format!("syntax check failed: {}", String::from_utf8_lossy(&out.stderr).trim().lines().last().unwrap_or(""))),
            Err(e) => bad.push(format!("could not run the syntax check: {e}")),
        },
        Err(e) => bad.push(format!("{e:#}")),
    }
    bad
}

// ---- stage 2: permission review --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub requested: Vec<String>,
    /// Capabilities the plugin names that no grant covers. Its tools would be denied until you grant them.
    pub not_granted: Vec<String>,
    /// Capabilities this version asks for that its predecessor did not (all of them, for a first version).
    pub new_versus_predecessor: Vec<String>,
    pub has_predecessor: bool,
}

fn predecessor_tools(cfg: &Config, name: &str) -> Option<Vec<ToolEntry>> {
    if let Some(v) = active_version(&cfg.home, name) {
        return read_manifest(&version_dir(&cfg.home, name, v)).ok().map(|m| m.tools);
    }
    let p = cfg.plugins.iter().find(|p| p.name == name)?;
    let host = PluginHost::start(std::slice::from_ref(p), &cfg.workspace).ok()?;
    let names: Vec<String> = host.specs().into_iter().map(|s| s.name).collect();
    Some(names.iter().filter_map(|n| host.find(n).map(|(_, e)| e)).collect())
}

fn review(cfg: &Config, m: &PluginManifest) -> Review {
    let requested: BTreeSet<String> = m.tools.iter().map(|t| t.capability.clone()).collect();
    let granted: BTreeSet<String> = cfg.grants.iter().map(|g| g.capability.clone()).collect();
    let pred = predecessor_tools(cfg, &m.name);
    let pred_caps: BTreeSet<String> = pred.iter().flatten().map(|t| t.capability.clone()).collect();
    Review {
        requested: requested.iter().cloned().collect(),
        not_granted: requested.difference(&granted).cloned().collect(),
        new_versus_predecessor: requested.difference(&pred_caps).cloned().collect(),
        has_predecessor: pred.is_some(),
    }
}

// ---- stage 3: contract tests -----------------------------------------------------------------

fn contract_tests(cfg: &Config, dir: &Path, m: &PluginManifest) -> Vec<String> {
    let mut bad = Vec::new();
    let t = Duration::from_secs(cfg.upgrades.contract_timeout_secs.max(1));
    let pc = plugin_config(m, dir, &cfg.home);
    let mut p = match RawPlugin::start(&pc, &cfg.workspace) {
        Ok(p) => p,
        Err(e) => return vec![format!("could not start: {e:#}")],
    };
    match p.manifest(t) {
        Ok(tools) => {
            if sig(&tools) != sig(&m.tools) {
                bad.push("the tools the plugin reports at run time differ from plugin.json".into());
            }
        }
        Err(e) => return vec![format!("manifest request failed: {e:#}")],
    }
    // An unknown tool must come back as an error, and the plugin must still be there afterwards.
    match p.call("no_such_tool_x", &json!({}), t) {
        Ok((_, true)) => {}
        Ok(_) => bad.push("an unknown tool was answered as a success".into()),
        Err(e) => bad.push(format!("an unknown tool call was not handled: {e:#}")),
    }
    if p.manifest(t).is_err() {
        bad.push("the plugin stopped answering after an unknown tool call".into());
        return bad;
    }
    // Garbage on the wire must not take it down.
    let _ = p.send_raw("}{ this is not json");
    if p.manifest(t).is_err() {
        bad.push("the plugin stopped answering after malformed input".into());
        return bad;
    }
    // Empty arguments to every tool: an error is fine, silence or a crash is not.
    for tool in &m.tools {
        if let Err(e) = p.call(&tool.name, &json!({}), t) {
            bad.push(format!("tool '{}' did not answer a call with empty arguments: {e:#}", tool.name));
            return bad;
        }
    }
    if !p.closes_cleanly(t) {
        bad.push("the plugin did not exit when its input was closed".into());
    }
    bad
}

// ---- stage 5: canary -------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Canary {
    pub compared: usize,
    pub divergent: usize,
    pub skipped_reason: Option<String>,
}

fn canary(cfg: &Config, audit: &AuditLog, dir: &Path, m: &PluginManifest) -> Result<(Canary, Vec<String>)> {
    // The version currently in service.
    let old_cfg: Option<PluginConfig> = if let Some(v) = active_version(&cfg.home, &m.name) {
        let d = version_dir(&cfg.home, &m.name, v);
        read_manifest(&d).ok().map(|om| plugin_config(&om, &d, &cfg.home))
    } else {
        cfg.plugins.iter().find(|p| p.name == m.name).cloned()
    };
    let Some(mut old_cfg) = old_cfg else {
        let c = Canary { skipped_reason: Some("first version of this plugin: nothing to compare against".into()), ..Default::default() };
        return Ok((c, vec!["first version of this plugin: no earlier version to compare with".into()]));
    };
    // Both run with the workspace read-only and no network, whatever the old one normally gets.
    let mut sb = old_cfg.sandbox.clone().unwrap_or_default();
    sb.workspace_readonly = true;
    sb.network = false;
    if !sb.hide.contains(&cfg.home) {
        sb.hide.push(cfg.home.clone());
    }
    old_cfg.sandbox = Some(sb);
    let mut new_cfg = plugin_config(m, dir, &cfg.home);
    new_cfg.sandbox = Some(sandboxed(dir, &cfg.home, true));

    // Recorded calls: read-only, executed, to a tool the candidate also provides.
    let tools: BTreeSet<&str> = m.tools.iter().map(|t| t.name.as_str()).collect();
    let mut calls: Vec<(String, Value)> = Vec::new();
    for r in audit.rows()?.into_iter().rev() {
        if r.entry.plugin == m.name && r.entry.tier == "read_only" && r.entry.decision == "executed" && tools.contains(r.entry.tool.as_str()) {
            if let Ok(args) = serde_json::from_str::<Value>(&r.entry.args) {
                if !calls.iter().any(|(t, a)| t == &r.entry.tool && a == &args) {
                    calls.push((r.entry.tool.clone(), args));
                }
            }
        }
        if calls.len() >= cfg.upgrades.canary_calls {
            break;
        }
    }
    if calls.is_empty() {
        let c = Canary { skipped_reason: Some("no recorded read-only calls to replay".into()), ..Default::default() };
        return Ok((c, vec!["no recorded read-only calls to replay, so nothing was compared".into()]));
    }

    let t = Duration::from_secs(cfg.upgrades.contract_timeout_secs.max(1));
    let mut old = RawPlugin::start(&old_cfg, &cfg.workspace)?;
    let mut new = RawPlugin::start(&new_cfg, &cfg.workspace)?;
    old.manifest(t)?;
    new.manifest(t)?;
    let mut c = Canary::default();
    let mut notes = Vec::new();
    for (tool, args) in &calls {
        let a = old.call(tool, args, t);
        let b = new.call(tool, args, t);
        c.compared += 1;
        match (a, b) {
            (Ok(x), Ok(y)) if x == y => {}
            (Ok(x), Ok(y)) => {
                c.divergent += 1;
                notes.push(format!("{tool} {args}: old answered {:?}, new answered {:?}", crate::runner::clip(&x.0, 80), crate::runner::clip(&y.0, 80)));
            }
            (_, Err(e)) => {
                c.divergent += 1;
                notes.push(format!("{tool} {args}: the new version did not answer ({e:#})"));
            }
            (Err(_), Ok(_)) => {}
        }
    }
    notes.insert(0, format!("replayed {} recorded read-only call(s); {} differed", c.compared, c.divergent));
    Ok((c, notes))
}

// ---- the pipeline ----------------------------------------------------------------------------

fn save(store: &Store, id: i64, status: &str, stages: &[Stage], extra: Value) -> Result<()> {
    let mut report = json!({ "stages": stages });
    if let (Some(o), Some(e)) = (report.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    store.set_upgrade(id, status, &report)
}

fn skip_rest(stages: &mut Vec<Stage>, names: &[&str]) {
    for n in names {
        stages.push(stage(n, "skipped", vec!["an earlier stage did not pass".into()]));
    }
}

/// Runs stages 1 to 5 on a proposed upgrade. Returns its new status. If the owner enabled earned
/// auto-approval and it applies, the upgrade is deployed too and the status says so.
pub fn run_pipeline(cfg: &Config, store: &Store, audit: &AuditLog, id: i64, verify: &dyn Fn(&Config) -> Result<Vec<Regression>>) -> Result<String> {
    let row = store.get_upgrade(id)?;
    if ["deployed", "rolled_back", "rejected"].contains(&row.status.as_str()) {
        bail!("upgrade #{id} is already {}", row.status);
    }
    let dir = candidate_dir(&cfg.home, id);
    let mut stages: Vec<Stage> = Vec::new();
    const ORDER: [&str; 5] = ["static checks", "permission review", "contract tests", "eval gate", "canary"];

    let finish = |stages: &mut Vec<Stage>, status: &str, from: usize, extra: Value| -> Result<String> {
        skip_rest(stages, &ORDER[from..]);
        save(store, id, status, stages, extra)?;
        audit_row(audit, row.session_id, &row.name, &format!("upgrade_{status}"), &format!("upgrade #{id}"))?;
        Ok(status.to_string())
    };

    // The snapshot must be exactly what was proposed.
    let hash_ok = tree_hash(&dir).map(|h| h == row.hash).unwrap_or(false);
    if !hash_ok {
        stages.push(stage("static checks", "failed", vec!["the snapshot no longer matches the one that was proposed".into()]));
        return finish(&mut stages, "failed_static", 1, json!({}));
    }
    let manifest = match read_manifest(&dir) {
        Ok(m) => m,
        Err(e) => {
            stages.push(stage("static checks", "failed", vec![format!("{e:#}")]));
            return finish(&mut stages, "failed_static", 1, json!({}));
        }
    };

    // 1. static
    let bad = static_checks(cfg, &dir, &manifest);
    if !bad.is_empty() {
        stages.push(stage("static checks", "failed", bad));
        return finish(&mut stages, "failed_static", 1, json!({}));
    }
    stages.push(stage("static checks", "passed", vec![]));

    // 2. review. It never fails the upgrade; it decides who must look.
    let rv = review(cfg, &manifest);
    let mut notes = vec![format!("asks for: {}", rv.requested.join(", "))];
    if !rv.not_granted.is_empty() {
        notes.push(format!("not covered by any grant (its tools stay denied until you grant them): {}", rv.not_granted.join(", ")));
    }
    if !rv.has_predecessor {
        notes.push("first version of this plugin: every capability is new, so it needs your review".into());
    } else if !rv.new_versus_predecessor.is_empty() {
        notes.push(format!("ASKS FOR MORE than the version in service: {}", rv.new_versus_predecessor.join(", ")));
    }
    stages.push(stage("permission review", "info", notes));

    // 3. contract tests
    let bad = contract_tests(cfg, &dir, &manifest);
    if !bad.is_empty() {
        stages.push(stage("contract tests", "failed", bad));
        return finish(&mut stages, "failed_contract", 3, json!({ "review": rv }));
    }
    stages.push(stage("contract tests", "passed", vec![]));

    // 4. the owner's eval suite, with the candidate in place of any earlier version
    let mut trial = cfg.clone();
    trial.plugins.retain(|p| p.name != manifest.name);
    trial.exclude_installed.push(manifest.name.clone());
    trial.extra_plugins = vec![plugin_config(&manifest, &dir, &cfg.home)];
    let gate = (|| -> Result<(Vec<Regression>, usize)> {
        let base = eval::load_baseline(&cfg.home).map_err(|_| anyhow!("there is no baseline eval run; run `agent eval run` then `agent eval baseline`"))?;
        if base.cases.len() < cfg.upgrades.min_eval_cases {
            bail!("the baseline has {} case(s); at least {} are needed before an upgrade can be judged", base.cases.len(), cfg.upgrades.min_eval_cases);
        }
        let cur = eval::run_all(&trial, None)?;
        Ok((eval::compare(&base, &cur)?, base.cases.len()))
    })();
    match gate {
        Err(e) => {
            stages.push(stage("eval gate", "blocked", vec![format!("{e:#}")]));
            return finish(&mut stages, "blocked_eval", 4, json!({ "review": rv }));
        }
        Ok((regs, _)) if !regs.is_empty() => {
            let f = regs.iter().map(|r| format!("{}: {}", r.id, r.reason)).collect();
            stages.push(stage("eval gate", "blocked", f));
            return finish(&mut stages, "blocked_eval", 4, json!({ "review": rv }));
        }
        Ok((_, n)) => stages.push(stage("eval gate", "passed", vec![format!("{n} baseline case(s), no regression")])),
    }

    // 5. canary
    let (can, notes) = canary(cfg, audit, &dir, &manifest)?;
    if can.divergent > cfg.upgrades.canary_max_divergence {
        stages.push(stage("canary", "failed", notes));
        return finish(&mut stages, "failed_canary", 5, json!({ "review": rv, "canary": can }));
    }
    stages.push(stage("canary", if can.compared == 0 { "info" } else { "passed" }, notes));

    // 6. who approves?
    let auto = auto_eligible(cfg, &manifest, &rv, &can);
    let extra = json!({ "review": rv, "canary": can, "auto_eligible": auto.is_ok(), "auto_note": auto.clone().err().unwrap_or_default() });
    save(store, id, "ready_for_review", &stages, extra)?;
    audit_row(audit, row.session_id, &row.name, "upgrade_ready_for_review", &format!("upgrade #{id}"))?;
    if auto.is_ok() {
        return approve(cfg, store, audit, id, "auto", verify);
    }
    Ok("ready_for_review".into())
}

/// Ok when an earned auto-approval applies. Err says why not.
fn auto_eligible(cfg: &Config, m: &PluginManifest, rv: &Review, can: &Canary) -> std::result::Result<(), String> {
    let u = &cfg.upgrades;
    if !u.auto_approve {
        return Err("auto-approval is off".into());
    }
    if !rv.has_predecessor {
        return Err("a first version always needs the owner".into());
    }
    if !rv.new_versus_predecessor.is_empty() {
        return Err("it asks for more than the version in service".into());
    }
    if !rv.not_granted.is_empty() {
        return Err("some of its capabilities are not granted".into());
    }
    for t in &m.tools {
        let top = cfg.grants.iter().filter(|g| g.capability == t.capability).map(|g| g.tier).max();
        if top.map(|t| t > Tier::Reversible).unwrap_or(true) {
            return Err(format!("'{}' is above the reversible tier", t.capability));
        }
    }
    let earned = versions(&cfg.home, &m.name).iter().filter(|v| v.approved_by == "owner").count() as u32;
    if earned < u.earned_after {
        return Err(format!("only {earned} of the {} owner-approved versions needed so far", u.earned_after));
    }
    if can.compared == 0 {
        return Err("the canary had no traffic to compare".into());
    }
    Ok(())
}

/// Deploys a ready upgrade. `by` is "owner" or "auto". Afterwards `verify` runs the owner's suite
/// again with the new version live. A regression rolls the deployment back by itself.
pub fn approve(cfg: &Config, store: &Store, audit: &AuditLog, id: i64, by: &str, verify: &dyn Fn(&Config) -> Result<Vec<Regression>>) -> Result<String> {
    let row = store.get_upgrade(id)?;
    if row.status != "ready_for_review" {
        bail!("upgrade #{id} is '{}', not ready for review", row.status);
    }
    let dir = candidate_dir(&cfg.home, id);
    if tree_hash(&dir).map(|h| h != row.hash).unwrap_or(true) {
        bail!("the snapshot no longer matches the one that was checked; run the checks again");
    }
    let m = read_manifest(&dir)?;
    let mut vs = versions(&cfg.home, &m.name);
    let next = vs.iter().map(|v| v.version).max().unwrap_or(0) + 1;
    let vdir = version_dir(&cfg.home, &m.name, next);
    std::fs::create_dir_all(&vdir)?;
    copy_limited(&dir, &vdir)?;
    let previous = active_version(&cfg.home, &m.name);
    vs.push(VersionInfo {
        version: next,
        hash: row.hash.clone(),
        upgrade_id: id,
        approved_by: by.into(),
        deployed_at: now(),
        capabilities: m.tools.iter().map(|t| t.capability.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
    });
    save_versions(&cfg.home, &m.name, &vs)?;
    set_active(&cfg.home, &m.name, Some(next))?;
    let who = if by == "owner" { "upgrade_approved_by_owner" } else { "upgrade_auto_approved" };
    audit_row(audit, row.session_id, &m.name, who, &format!("upgrade #{id}"))?;
    audit_row(audit, row.session_id, &m.name, "upgrade_deployed", &format!("version {next} (was {})", previous.map(|p| p.to_string()).unwrap_or("none".into())))?;

    // Now live. The suite runs again against what is actually installed.
    match verify(cfg) {
        Ok(regs) if regs.is_empty() => {
            let mut report = row.report.clone();
            report["deployed_version"] = json!(next);
            report["approved_by"] = json!(by);
            store.set_upgrade(id, "deployed", &report)?;
            Ok("deployed".into())
        }
        other => {
            let why = match other {
                Ok(regs) => regs.iter().map(|r| format!("{}: {}", r.id, r.reason)).collect::<Vec<_>>().join("; "),
                Err(e) => format!("the check could not run: {e:#}"),
            };
            set_active(&cfg.home, &m.name, previous)?;
            audit_row(audit, row.session_id, &m.name, "upgrade_auto_rolled_back", &format!("version {next} failed after deploy: {why}"))?;
            let mut report = row.report.clone();
            report["rolled_back_because"] = json!(why);
            store.set_upgrade(id, "rolled_back", &report)?;
            Ok("rolled_back".into())
        }
    }
}

pub fn reject(store: &Store, audit: &AuditLog, id: i64) -> Result<()> {
    let row = store.get_upgrade(id)?;
    if ["deployed", "rolled_back"].contains(&row.status.as_str()) {
        bail!("upgrade #{id} is already {}", row.status);
    }
    store.set_upgrade(id, "rejected", &row.report)?;
    audit_row(audit, row.session_id, &row.name, "upgrade_rejected", &format!("upgrade #{id}"))
}

/// The single switch: make an earlier version the active one (the previous one unless told otherwise),
/// or switch the plugin off if there is none. Nothing is deleted, so a rollback can itself be undone.
pub fn rollback(cfg: &Config, store: &Store, audit: &AuditLog, name: &str, to: Option<u32>) -> Result<String> {
    let vs = versions(&cfg.home, name);
    let cur = active_version(&cfg.home, name).ok_or_else(|| anyhow!("plugin '{name}' has no active version"))?;
    let target = match to {
        Some(t) => {
            if !vs.iter().any(|v| v.version == t) {
                bail!("plugin '{name}' has no version {t}");
            }
            Some(t)
        }
        None => vs.iter().map(|v| v.version).filter(|v| *v < cur).max(),
    };
    set_active(&cfg.home, name, target)?;
    if let Some(v) = vs.iter().find(|v| v.version == cur) {
        if let Ok(row) = store.get_upgrade(v.upgrade_id) {
            let _ = store.set_upgrade(row.id, "rolled_back", &row.report);
        }
    }
    let msg = match target {
        Some(t) => format!("plugin '{name}' is back on version {t} (was {cur})"),
        None => format!("plugin '{name}' is switched off (version {cur} was its first)"),
    };
    audit_row(audit, 0, name, "upgrade_rolled_back", &msg)?;
    Ok(msg)
}
