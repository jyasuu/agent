use crate::config::{McpConfig, PluginConfig};
use crate::delegate::NEVER_DELEGATED;
use crate::provider::ToolSpec;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

const MCP_PROTOCOL: &str = "2025-06-18";
/// What a model is shown of a tool's description. A server controls this text, so it is capped.
const MAX_DESCRIPTION: usize = 1000;
const MAX_TOOLS_PER_SERVER: usize = 500;
const MAX_LIST_PAGES: usize = 20;

/// A tool as declared in a plugin's manifest. The plugin names the capability
/// it needs; the human's grants decide whether that capability is allowed and
/// at which tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub capability: String,
    /// Arguments that hold paths, which the gate checks against the grant's scope.
    #[serde(default)]
    pub scope_args: Vec<String>,
    /// The tool walks a whole tree below its path arguments (grep, glob, tree). The gate refuses
    /// such a call when the tree would contain a path the core protects (the agent's own home).
    #[serde(default, skip_serializing_if = "is_false")]
    pub recursive: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
}

struct Live {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
}

// ---- helpers for MCP -------------------------------------------------------------------------

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect()
}

fn short_hash(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The name the model sees: `<server>__<tool>`. Prefixing keeps two servers (or a server and a native
/// plugin) from fighting over a name like `navigate`, and stays within the 64 characters model APIs allow.
pub fn exposed_name(server: &str, tool: &str) -> String {
    let full = format!("{}__{}", sanitize(server), sanitize(tool));
    if full.len() <= 64 {
        full
    } else {
        format!("{}_{}", &full[..55], short_hash(&full))
    }
}

/// Fingerprint of a server's advertised tools (names, descriptions, schemas), order-independent.
pub fn tools_hash(tools: &[(String, String, Value)]) -> String {
    let mut sorted: Vec<&(String, String, Value)> = tools.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, desc, schema) in sorted {
        for part in [name.as_str(), desc.as_str(), schema.to_string().as_str()] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn clean_description(d: &str) -> String {
    let cleaned: String = d.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect();
    if cleaned.chars().count() > MAX_DESCRIPTION {
        format!("{}...", cleaned.chars().take(MAX_DESCRIPTION).collect::<String>())
    } else {
        cleaned
    }
}

/// MCP results are a list of typed parts. Text is passed on; anything else becomes a short placeholder,
/// because binary data would only fill the context.
fn mcp_result_to_output(r: &Value) -> ToolOutput {
    let mut parts: Vec<String> = Vec::new();
    for c in r["content"].as_array().into_iter().flatten() {
        match c["type"].as_str() {
            Some("text") => parts.push(c["text"].as_str().unwrap_or("").to_string()),
            Some(kind @ ("image" | "audio")) => parts.push(format!(
                "[{kind} omitted: {}, about {} bytes]",
                c["mimeType"].as_str().unwrap_or("unknown type"),
                c["data"].as_str().map(|d| d.len() * 3 / 4).unwrap_or(0)
            )),
            Some("resource") => match c["resource"]["text"].as_str() {
                Some(t) => parts.push(t.to_string()),
                None => parts.push(format!("[resource omitted: {}]", c["resource"]["uri"].as_str().unwrap_or("?"))),
            },
            Some("resource_link") => parts.push(format!("[resource link: {}]", c["uri"].as_str().unwrap_or("?"))),
            Some(other) => parts.push(format!("[unsupported content type: {other}]")),
            None => {}
        }
    }
    if parts.is_empty() && !r["structuredContent"].is_null() {
        parts.push(r["structuredContent"].to_string());
    }
    ToolOutput { content: parts.join("\n"), is_error: r["isError"].as_bool().unwrap_or(false) }
}

/// Handles a message that is not the answer we are waiting for. Servers may ask us things (`ping`) or
/// announce things (`notifications/tools/list_changed`). We declared no capabilities, so every other
/// request is declined, which is what the protocol expects.
fn handle_server_message(stdin: &mut ChildStdin, dirty: &mut bool, v: &Value) {
    let Some(method) = v["method"].as_str() else { return };
    if let Some(id) = v.get("id").filter(|i| !i.is_null()) {
        let reply = if method == "ping" {
            json!({ "jsonrpc": "2.0", "id": id, "result": {} })
        } else {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "this client does not support that request" } })
        };
        let _ = writeln!(stdin, "{reply}").and_then(|_| stdin.flush());
    } else if method == "notifications/tools/list_changed" {
        *dirty = true;
    }
}

// ---- one plugin process ----------------------------------------------------------------------

/// One plugin process. Two protocols:
///
/// Native, one JSON object per line:
///   -> {"id":1,"method":"manifest"}            <- {"id":1,"result":{"tools":[...]}}
///   -> {"id":2,"method":"call","params":{"tool":"x","args":{}}}
///                                              <- {"id":2,"result":{"content":"...","is_error":false}}
///
/// MCP (when the config has an `mcp` section): JSON-RPC 2.0, one message per line. `initialize`, then
/// the `notifications/initialized` notification, `tools/list` (paged), and `tools/call`.
pub struct PluginProcess {
    cfg: PluginConfig,
    cfg_value: Value,
    workspace: PathBuf,
    live: Option<Live>,
    next_id: u64,
    pub tools: Vec<ToolEntry>,
    /// MCP: the name the model sees -> the server's own name for the tool.
    mcp_names: HashMap<String, String>,
    /// MCP: hash of the tool list as last accepted.
    last_hash: Option<String>,
    /// MCP: the server said its tools changed and they have not been re-read yet.
    dirty: bool,
}

impl PluginProcess {
    fn new(cfg: PluginConfig, workspace: PathBuf) -> Self {
        let cfg_value = serde_json::to_value(&cfg).unwrap_or(Value::Null);
        Self { cfg, cfg_value, workspace, live: None, next_id: 0, tools: Vec::new(), mcp_names: HashMap::new(), last_hash: None, dirty: false }
    }

    fn spawn(&mut self) -> Result<()> {
        // The plugin starts with an empty environment and the workspace as its
        // working directory. It is handed no handle to the session or audit stores.
        let (program, args) = match &self.cfg.sandbox {
            Some(sb) => crate::sandbox::wrap(sb, &self.workspace, &self.cfg.command, &self.cfg.args)?,
            None => (self.cfg.command.clone(), self.cfg.args.clone()),
        };
        let mut child = Command::new(&program)
            .args(&args)
            .current_dir(&self.workspace)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting plugin '{}'", self.cfg.name))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        self.live = Some(Live { child, stdin, rx });

        if self.cfg.mcp.is_some() {
            return self.mcp_handshake();
        }

        let result = self.request("manifest", Value::Null, Duration::from_secs(10))?;
        let tools: Vec<ToolEntry> =
            serde_json::from_value(result["tools"].clone()).context("plugin sent a bad manifest")?;
        if self.tools.is_empty() {
            self.tools = tools;
        } else {
            let old: HashSet<_> = self.tools.iter().map(|t| (&t.name, &t.capability)).collect();
            let new: HashSet<_> = tools.iter().map(|t| (&t.name, &t.capability)).collect();
            if old != new {
                self.kill();
                bail!("plugin '{}' changed its manifest after a restart; refusing it", self.cfg.name);
            }
        }
        Ok(())
    }

    fn kill(&mut self) {
        if let Some(mut l) = self.live.take() {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
    }

    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({ "id": id, "method": method, "params": params }).to_string();
        let name = self.cfg.name.clone();
        let live = self.live.as_mut().ok_or_else(|| anyhow!("plugin '{name}' is not running"))?;
        if writeln!(live.stdin, "{line}").and_then(|_| live.stdin.flush()).is_err() {
            self.kill();
            bail!("plugin '{name}' closed its input");
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match live.rx.recv_timeout(remaining) {
                Ok(l) => {
                    let v: Value = match serde_json::from_str(&l) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v["id"] != json!(id) {
                        continue;
                    }
                    if let Some(e) = v.get("error") {
                        bail!("plugin '{name}' error: {e}");
                    }
                    return Ok(v["result"].clone());
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.kill();
                    bail!("plugin '{name}' timed out after {}s and was killed", timeout.as_secs());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.kill();
                    bail!("plugin '{name}' exited unexpectedly");
                }
            }
        }
    }

    // ---- MCP ---------------------------------------------------------------------------------

    /// A JSON-RPC request. Messages from the server that are not our answer (its own requests,
    /// notifications, log lines) are handled as they arrive, so a server that pings us never stalls.
    fn mcp_request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let mut msg = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if !params.is_null() {
            msg["params"] = params;
        }
        let name = self.cfg.name.clone();
        let live = self.live.as_mut().ok_or_else(|| anyhow!("MCP server '{name}' is not running"))?;
        if writeln!(live.stdin, "{msg}").and_then(|_| live.stdin.flush()).is_err() {
            self.kill();
            bail!("MCP server '{name}' closed its input");
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match live.rx.recv_timeout(remaining) {
                Ok(l) => {
                    let Ok(v) = serde_json::from_str::<Value>(&l) else { continue };
                    // Anything with a `method` came from the server (a request or a notification): deal
                    // with it and keep waiting. Only a message with our id and no method is the answer.
                    handle_server_message(&mut live.stdin, &mut self.dirty, &v);
                    if v["method"].is_string() || v["id"] != json!(id) {
                        continue;
                    }
                    if let Some(e) = v.get("error") {
                        bail!("MCP server '{name}' error {}: {}", e["code"], e["message"].as_str().unwrap_or("(no message)"));
                    }
                    return Ok(v["result"].clone());
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.kill();
                    bail!("MCP server '{name}' timed out after {}s and was killed", timeout.as_secs());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.kill();
                    bail!("MCP server '{name}' exited unexpectedly");
                }
            }
        }
    }

    fn mcp_notify(&mut self, method: &str) -> Result<()> {
        let live = self.live.as_mut().ok_or_else(|| anyhow!("MCP server is not running"))?;
        let msg = json!({ "jsonrpc": "2.0", "method": method });
        writeln!(live.stdin, "{msg}").and_then(|_| live.stdin.flush()).context("sending a notification")
    }

    /// Answer anything the server sent while we were idle (a ping, a list-changed notice).
    fn mcp_poll(&mut self) {
        let Some(live) = self.live.as_mut() else { return };
        loop {
            match live.rx.try_recv() {
                Ok(l) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&l) {
                        handle_server_message(&mut live.stdin, &mut self.dirty, &v);
                    }
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.kill();
                    return;
                }
            }
        }
    }

    fn mcp_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.call_timeout_secs.clamp(5, 120))
    }

    fn mcp_handshake(&mut self) -> Result<()> {
        let name = self.cfg.name.clone();
        let init = match self.mcp_request(
            "initialize",
            json!({ "protocolVersion": MCP_PROTOCOL, "capabilities": {}, "clientInfo": { "name": "agent", "version": env!("CARGO_PKG_VERSION") } }),
            self.mcp_timeout(),
        ) {
            Ok(v) => v,
            Err(e) => {
                self.kill();
                return Err(e);
            }
        };
        if init["capabilities"]["tools"].is_null() {
            self.kill();
            bail!("MCP server '{name}' does not offer tools");
        }
        if let Err(e) = self.mcp_notify("notifications/initialized") {
            self.kill();
            return Err(e);
        }
        if let Err(e) = self.mcp_load_tools(true) {
            self.kill();
            return Err(e);
        }
        Ok(())
    }

    /// Read the server's tool list (all pages) and turn it into tool entries under the owner's mapping.
    /// `after_restart` demands the same list as before, because a server that changes what its tools
    /// say when it comes back is the pattern this is meant to catch.
    fn mcp_load_tools(&mut self, after_restart: bool) -> Result<()> {
        let name = self.cfg.name.clone();
        let mc: McpConfig = self.cfg.mcp.clone().unwrap_or_default();
        let timeout = self.mcp_timeout();
        let mut listed: Vec<(String, String, Value)> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => Value::Null,
            };
            let page = self.mcp_request("tools/list", params, timeout)?;
            for t in page["tools"].as_array().into_iter().flatten() {
                let Some(n) = t["name"].as_str() else { continue };
                listed.push((n.to_string(), t["description"].as_str().unwrap_or("").to_string(), t["inputSchema"].clone()));
            }
            if listed.len() > MAX_TOOLS_PER_SERVER {
                bail!("MCP server '{name}' offers more than {MAX_TOOLS_PER_SERVER} tools; narrow it with `tools` in its config");
            }
            cursor = page["nextCursor"].as_str().filter(|c| !c.is_empty()).map(String::from);
            if cursor.is_none() {
                break;
            }
        }
        if let Some(allow) = &mc.tools {
            listed.retain(|(n, _, _)| allow.contains(n));
        }
        let hash = tools_hash(&listed);
        if let Some(pin) = &mc.pin {
            if pin != &hash {
                bail!(
                    "MCP server '{name}' no longer matches the tool list you pinned. It now advertises {hash}, you pinned {pin}. \
                     Run `agent mcp inspect {name}`, read what changed, and update the pin only if you trust it"
                );
            }
        }
        if after_restart {
            if let Some(prev) = &self.last_hash {
                if prev != &hash {
                    bail!("MCP server '{name}' changed its tools after a restart; refusing it");
                }
            }
        }
        let default_cap = mc.capability.clone().unwrap_or_else(|| format!("mcp:{}", sanitize(&name)));
        let mut entries = Vec::new();
        let mut names = HashMap::new();
        for (orig, desc, schema) in listed {
            let capability = mc.tool_capabilities.get(&orig).cloned().unwrap_or_else(|| default_cap.clone());
            if NEVER_DELEGATED.iter().any(|p| capability.starts_with(p)) {
                bail!("tool '{orig}' of '{name}' is mapped to '{capability}', a capability that changes authority; a tool server cannot hold it");
            }
            let exposed = exposed_name(&name, &orig);
            names.insert(exposed.clone(), orig.clone());
            entries.push(ToolEntry {
                name: exposed,
                description: clean_description(&desc),
                input_schema: if schema.is_object() { schema } else { json!({ "type": "object" }) },
                capability,
                scope_args: mc.scope_args.get(&orig).cloned().unwrap_or_default(),
                recursive: false,
            });
        }
        self.tools = entries;
        self.mcp_names = names;
        self.last_hash = Some(hash);
        self.dirty = false;
        Ok(())
    }

    /// Re-read a server's tools after it announced a change. Ok(true) means the list changed.
    fn refresh(&mut self) -> Result<bool> {
        let before = self.last_hash.clone();
        self.mcp_load_tools(false)?;
        Ok(before != self.last_hash)
    }

    // ---- calls -------------------------------------------------------------------------------

    fn call(&mut self, tool: &str, args: &Value) -> Result<ToolOutput> {
        if self.live.is_none() {
            self.spawn()?;
        }
        if self.cfg.mcp.is_some() {
            let original = self.mcp_names.get(tool).cloned().ok_or_else(|| anyhow!("MCP server '{}' has no tool '{tool}'", self.cfg.name))?;
            let arguments = if args.is_object() { args.clone() } else { json!({}) };
            let timeout = Duration::from_secs(self.cfg.call_timeout_secs);
            let r = self.mcp_request("tools/call", json!({ "name": original, "arguments": arguments }), timeout)?;
            return Ok(mcp_result_to_output(&r));
        }
        let timeout = Duration::from_secs(self.cfg.call_timeout_secs);
        let r = self.request("call", json!({ "tool": tool, "args": args }), timeout)?;
        Ok(ToolOutput {
            content: r["content"].as_str().unwrap_or("").to_string(),
            is_error: r["is_error"].as_bool().unwrap_or(false),
        })
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---- the host --------------------------------------------------------------------------------

/// What `reload` did, so the session (and the audit log) can say what changed.
#[derive(Debug, Default, Clone)]
pub struct ReloadReport {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub replaced: Vec<String>,
    /// MCP servers whose tool list changed while running.
    pub refreshed: Vec<String>,
    /// Plugins that were not loaded, and why. The previous version, if any, keeps running.
    pub refused: Vec<(String, String)>,
}

impl ReloadReport {
    pub fn is_quiet(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.replaced.is_empty() && self.refreshed.is_empty() && self.refused.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (label, list) in [("added", &self.added), ("removed", &self.removed), ("replaced", &self.replaced), ("tools changed", &self.refreshed)] {
            if !list.is_empty() {
                parts.push(format!("{label}: {}", list.join(", ")));
            }
        }
        for (name, why) in &self.refused {
            parts.push(format!("refused {name}: {why}"));
        }
        parts.join("; ")
    }
}

/// What `agent mcp inspect` shows about a server.
#[derive(Debug, Clone)]
pub struct McpInspection {
    pub hash: String,
    /// (the server's own tool name, the entry as the model would see it)
    pub tools: Vec<(String, ToolEntry)>,
}

/// Starts every configured plugin and routes tool calls to the right process.
pub struct PluginHost {
    plugins: Vec<PluginProcess>,
    /// The owner's hooks for this session (see `hooks`). Empty unless the host came from `start_for`.
    pub hooks: crate::hooks::HookHost,
    /// Plugin configs that failed to load, so a reload does not retry (and re-report) them every turn.
    failed: HashMap<String, Value>,
}

impl PluginHost {
    pub fn start(cfgs: &[PluginConfig], workspace: &Path) -> Result<Self> {
        let mut plugins = Vec::new();
        let mut seen = HashSet::new();
        for c in cfgs {
            let mut p = PluginProcess::new(c.clone(), workspace.to_path_buf());
            p.spawn()?;
            for t in &p.tools {
                if !seen.insert(t.name.clone()) {
                    bail!("two plugins declare a tool named '{}'", t.name);
                }
            }
            plugins.push(p);
        }
        Ok(Self { plugins, hooks: crate::hooks::HookHost::empty(), failed: HashMap::new() })
    }

    /// Start every plugin for a session: the configured ones plus installed upgrades.
    pub fn start_for(cfg: &crate::config::Config) -> Result<Self> {
        let mut host = Self::start(&cfg.plugins_now(), &cfg.workspace)?;
        // Hooks come only from the owner's config. Nothing is started until a hook is first needed.
        host.hooks = crate::hooks::HookHost::new(&cfg.hooks, &cfg.workspace);
        Ok(host)
    }

    pub fn find(&self, tool: &str) -> Option<(usize, ToolEntry)> {
        self.plugins
            .iter()
            .enumerate()
            .find_map(|(i, p)| p.tools.iter().find(|t| t.name == tool).map(|t| (i, t.clone())))
    }

    pub fn plugin_name(&self, idx: usize) -> &str {
        &self.plugins[idx].cfg.name
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.visible_specs(&|_| true)
    }

    /// Specs for only the tools the caller may use, so the model is not shown (and does not pay
    /// context for) tools that would just be denied.
    pub fn visible_specs(&self, allow: &dyn Fn(&ToolEntry) -> bool) -> Vec<ToolSpec> {
        self.plugins
            .iter()
            .flat_map(|p| p.tools.iter())
            .filter(|t| allow(t))
            .map(|t| ToolSpec { name: t.name.clone(), description: t.description.clone(), input_schema: t.input_schema.clone() })
            .collect()
    }

    pub fn call(&mut self, idx: usize, tool: &str, args: &Value) -> Result<ToolOutput> {
        self.plugins[idx].call(tool, args)
    }

    /// Bring the running plugins in line with `desired` without restarting the ones that did not change:
    /// start new ones, stop removed ones, replace changed ones, and re-read MCP servers that announced a
    /// change. A plugin that fails to load is refused and, if it replaced an older one, the older one
    /// stays. An MCP server whose pinned tool list no longer matches is stopped and removed (fail closed).
    pub fn reload(&mut self, desired: &[PluginConfig], workspace: &Path) -> ReloadReport {
        let mut rep = ReloadReport::default();
        let want: HashSet<&str> = desired.iter().map(|c| c.name.as_str()).collect();
        self.plugins.retain(|p| {
            let keep = want.contains(p.cfg.name.as_str());
            if !keep {
                rep.removed.push(p.cfg.name.clone());
            }
            keep
        });

        // Answer anything MCP servers said while idle, then re-read the ones that announced a change.
        let mut broken: Vec<String> = Vec::new();
        for p in self.plugins.iter_mut().filter(|p| p.cfg.mcp.is_some()) {
            p.mcp_poll();
            if p.dirty && p.live.is_some() {
                match p.refresh() {
                    Ok(true) => rep.refreshed.push(p.cfg.name.clone()),
                    Ok(false) => {}
                    Err(e) => {
                        p.kill();
                        broken.push(p.cfg.name.clone());
                        // Remember it. Without this, the loop below sees "configured but not running" and starts a
                        // fresh copy, which advertises the honest list again and quietly undoes the removal.
                        self.failed.insert(p.cfg.name.clone(), p.cfg_value.clone());
                        rep.refused.push((p.cfg.name.clone(), format!("{e:#}")));
                    }
                }
            }
        }
        self.plugins.retain(|p| !broken.contains(&p.cfg.name));

        for c in desired {
            let cv = serde_json::to_value(c).unwrap_or(Value::Null);
            let existing = self.plugins.iter().position(|p| p.cfg.name == c.name);
            if let Some(i) = existing {
                if self.plugins[i].cfg_value == cv {
                    continue;
                }
            }
            if self.failed.get(&c.name) == Some(&cv) {
                continue; // already tried exactly this and it failed; do not retry or repeat the report every turn
            }
            let mut np = PluginProcess::new(c.clone(), workspace.to_path_buf());
            if let Err(e) = np.spawn() {
                self.failed.insert(c.name.clone(), cv);
                rep.refused.push((c.name.clone(), format!("{e:#}")));
                continue;
            }
            let taken: HashSet<String> = self
                .plugins
                .iter()
                .enumerate()
                .filter(|(j, _)| Some(*j) != existing)
                .flat_map(|(_, p)| p.tools.iter().map(|t| t.name.clone()))
                .collect();
            if let Some(t) = np.tools.iter().find(|t| taken.contains(&t.name)) {
                self.failed.insert(c.name.clone(), cv);
                rep.refused.push((c.name.clone(), format!("tool '{}' is already provided by another plugin", t.name)));
                continue;
            }
            self.failed.remove(&c.name);
            match existing {
                Some(i) => {
                    self.plugins[i] = np;
                    rep.replaced.push(c.name.clone());
                }
                None => {
                    self.plugins.push(np);
                    rep.added.push(c.name.clone());
                }
            }
        }
        rep
    }

    /// Start one MCP server (ignoring any pin) and report what it advertises, with the hash to pin.
    pub fn inspect_mcp(cfg: &PluginConfig, workspace: &Path) -> Result<McpInspection> {
        let mut c = cfg.clone();
        let Some(mc) = c.mcp.as_mut() else { bail!("'{}' is not an MCP server in the config", cfg.name) };
        mc.pin = None;
        let mut p = PluginProcess::new(c, workspace.to_path_buf());
        p.spawn()?;
        let by_exposed: HashMap<String, String> = p.mcp_names.clone();
        let tools = p
            .tools
            .iter()
            .map(|t| (by_exposed.get(&t.name).cloned().unwrap_or_default(), t.clone()))
            .collect();
        Ok(McpInspection { hash: p.last_hash.clone().unwrap_or_default(), tools })
    }
}
