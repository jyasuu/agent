use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Risk tier. Ordering matters: a higher tier is riskier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    ReadOnly,
    Reversible,
    Irreversible,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::ReadOnly => "read_only",
            Tier::Reversible => "reversible",
            Tier::Irreversible => "irreversible",
        }
    }
}

/// A grant is authored by the human. The tier comes from the grant, never from
/// the plugin, so a plugin cannot declare its own actions "safe".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub capability: String,
    pub tier: Tier,
    /// Path root the grant covers, relative to the workspace. Defaults to the workspace.
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,
    /// Run the plugin inside an OS sandbox (bubblewrap). If the sandbox cannot start, the
    /// plugin does not start: there is no fallback to running it unconfined.
    #[serde(default)]
    pub sandbox: Option<SandboxConfig>,
    /// Present means this is a Model Context Protocol server (JSON-RPC 2.0 over stdio), not a native
    /// plugin. Any off-the-shelf MCP server works. The settings say how its tools map onto your grants.
    #[serde(default)]
    pub mcp: Option<McpConfig>,
}

/// How an MCP server's tools fit the permission model. MCP tools do not declare a capability, so you
/// do, and the deny-by-default gate then needs a grant for it. Whatever a server says about its own
/// tools (including "read only" or "destructive" hints) is never trusted: the tier comes from your grants.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Capability for every tool of this server. Default: `mcp:<server name>`.
    pub capability: Option<String>,
    /// Per-tool capability, by the tool's own (unprefixed) name. Overrides `capability`.
    pub tool_capabilities: std::collections::BTreeMap<String, String>,
    /// Per-tool names of arguments that hold file paths, so the gate can check them against a grant's scope.
    pub scope_args: std::collections::BTreeMap<String, Vec<String>>,
    /// Expose only these tools (by their own names). Leave out to expose all.
    pub tools: Option<Vec<String>>,
    /// Hash of the tool list you reviewed (see `agent mcp inspect`). If the server's tools, descriptions
    /// or schemas ever differ, the server is refused. This is the defence against a server that
    /// changes what its tools say after you approved them.
    pub pin: Option<String>,
}

/// What a sandboxed plugin can see. It starts from nothing: system files read-only, the
/// workspace, and whatever is listed here. The agent's home directory (session log, audit
/// log, delegate rules) is hidden from every sandboxed plugin by `Config::seal`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Allow network access. Off unless the owner turns it on for a plugin.
    pub network: bool,
    /// Mount the workspace read-only.
    pub workspace_readonly: bool,
    /// Extra paths made visible read-only (for example a toolchain directory).
    pub ro_binds: Vec<String>,
    /// Extra paths made visible and writable.
    pub rw_binds: Vec<String>,
    /// Paths hidden even when they sit inside a visible directory. Filled in by `Config::seal`.
    pub hide: Vec<PathBuf>,
    /// Path to bwrap, if it is not in a standard location.
    pub program: Option<String>,
}

fn default_call_timeout() -> u64 {
    30
}

/// What a hook does when it fails (crash, timeout, a malformed answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Fail closed: `tool.before` denies the call, `tool.after` withholds the result.
    Deny,
    /// Carry on without the hook and record that it failed.
    Skip,
}

/// A hook: an owner-written program the core consults at fixed points in the loop. It can only
/// tighten what the gate already allowed (veto a call, redact a result) or watch. It is never
/// consulted before the gate, so it cannot turn a denial into an allow. Only you can add one:
/// the upgrade pipeline never installs hooks, and the agent cannot write this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Which points it wants: `tool.before`, `tool.after` and/or `event`.
    pub subscribe: Vec<String>,
    /// For `event`: only these event names (empty means all of them).
    #[serde(default)]
    pub events: Vec<String>,
    /// How long `tool.before` and `tool.after` wait for an answer.
    #[serde(default = "default_hook_timeout_ms")]
    pub timeout_ms: u64,
    /// Default: `deny` for `tool.before`, `skip` for `tool.after` and `event`.
    #[serde(default)]
    pub on_error: Option<OnError>,
    /// Environment for the hook (it starts with an empty one), for example a webhook URL.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Same OS sandbox as for plugins. Leave out for a hook that needs the network.
    #[serde(default)]
    pub sandbox: Option<SandboxConfig>,
}

pub const HOOK_KINDS: [&str; 3] = ["tool.before", "tool.after", "event"];

fn default_hook_timeout_ms() -> u64 {
    5000
}

impl HookConfig {
    pub fn subscribes(&self, kind: &str) -> bool {
        self.subscribe.iter().any(|k| k == kind)
    }

    pub fn on_error_for(&self, kind: &str) -> OnError {
        self.on_error.unwrap_or(if kind == "tool.before" { OnError::Deny } else { OnError::Skip })
    }
}

/// Per-session limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionBudget {
    pub max_steps: u32,
    pub max_tokens: u64,
    pub max_cost_usd: f64,
    pub max_wall_secs: u64,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self { max_steps: 25, max_tokens: 200_000, max_cost_usd: 2.0, max_wall_secs: 600 }
    }
}

/// Limits across all sessions, summed from the spend ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalBudget {
    pub max_tokens: u64,
    pub max_cost_usd: f64,
}

impl Default for GlobalBudget {
    fn default() -> Self {
        Self { max_tokens: 2_000_000, max_cost_usd: 20.0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelConfig {
    /// "anthropic", or "openai" for any server that speaks the OpenAI chat-completions API
    /// (OpenAI itself, Azure-style gateways, Ollama, vLLM, LM Studio, OpenRouter, and so on).
    pub provider: String,
    pub model: String,
    pub max_tokens: u32,
    /// Where the API lives. Anthropic default: https://api.anthropic.com. OpenAI default:
    /// https://api.openai.com/v1. For a local server use something like http://localhost:11434/v1.
    pub base_url: Option<String>,
    /// Name of the environment variable holding the API key. Defaults to ANTHROPIC_API_KEY or
    /// OPENAI_API_KEY. For an OpenAI-compatible server that needs no key, set a custom `base_url`
    /// and leave the variable unset, or set this to an empty string.
    pub api_key_env: Option<String>,
    /// The request field that limits output: "max_tokens" (most servers) or "max_completion_tokens"
    /// (newer OpenAI models). Only used by the "openai" provider.
    pub max_tokens_param: String,
    /// Placeholder prices. Set these to your model's real prices, because the
    /// spending caps are only as accurate as these numbers. Use 0 for a local model.
    pub price_in_per_mtok: f64,
    pub price_out_per_mtok: f64,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "anthropic".into(),
            model: "claude-sonnet-5-5".into(),
            max_tokens: 4096,
            base_url: None,
            api_key_env: None,
            max_tokens_param: "max_tokens".into(),
            price_in_per_mtok: 3.0,
            price_out_per_mtok: 15.0,
        }
    }
}

/// Context compaction (stage 3). The core decides when and what is pinned;
/// the strategy only writes the summary of the span being dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CompactionConfig {
    pub enabled: bool,
    /// Size of the model's context window, in tokens. Set this to your model's real window.
    pub context_window_tokens: u64,
    /// Compact once the estimated context reaches this fraction of the window (spec: 0.70 to 0.80).
    pub threshold: f64,
    /// "mechanical" (no model call) or "model" (asks the model for a summary, falls back to mechanical).
    pub strategy: String,
    /// The most recent model turns are never stubbed or summarized.
    pub keep_recent_steps: usize,
    /// Older tool outputs longer than this are replaced by a short stub and a pointer.
    pub stub_min_bytes: usize,
    pub stub_head_chars: usize,
    pub max_summary_chars: usize,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            context_window_tokens: 200_000,
            threshold: 0.75,
            strategy: "mechanical".into(),
            keep_recent_steps: 4,
            stub_min_bytes: 2000,
            stub_head_chars: 300,
            max_summary_chars: 6000,
        }
    }
}

/// Sub-agents (stage 3). A child runs inside its parent's worker, one at a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SubagentConfig {
    /// 1 means children cannot spawn children.
    pub max_depth: u32,
    pub max_children_per_session: u32,
    /// Ceiling for a child. The parent's remaining budget can shrink it further.
    pub child_budget: SessionBudget,
    /// A child's result is cut to this many characters before it reaches the parent.
    pub max_result_chars: usize,
}

impl Default for SubagentConfig {
    fn default() -> Self {
        Self {
            max_depth: 1,
            max_children_per_session: 4,
            child_budget: SessionBudget { max_steps: 15, max_tokens: 100_000, max_cost_usd: 1.0, max_wall_secs: 300 },
            max_result_chars: 2000,
        }
    }
}

/// Independent verification (stage 4). When enabled, the core will not accept "done" from the
/// model alone: a read-only verifier with a fresh context judges the work first. Needs an
/// `agent:verify` grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VerificationConfig {
    pub enabled: bool,
    /// Sessions that never called a tool (pure answers) are not verified.
    pub skip_without_tools: bool,
    /// How many times a failed verdict is fed back to the worker before the session is suspended.
    pub max_retries: u32,
    /// An uncertain verdict is re-checked once, automatically, with a push for objective evidence.
    pub reverify_on_uncertain: bool,
    /// What to do with a verdict that is still uncertain: "flag" completes the session and marks it
    /// unverified (no human needed), "suspend" holds it for the owner.
    pub on_uncertain: String,
    pub budget: SessionBudget,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            skip_without_tools: true,
            max_retries: 2,
            reverify_on_uncertain: true,
            on_uncertain: "flag".into(),
            budget: SessionBudget { max_steps: 12, max_tokens: 100_000, max_cost_usd: 0.5, max_wall_secs: 240 },
        }
    }
}

/// An out-of-process event source. It can only produce events; the core decides
/// whether and when they become sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

fn default_concurrency() -> usize {
    2
}

fn default_approval_timeout() -> u64 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub workspace: PathBuf,
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    /// Owner-written hooks. See `HookConfig`.
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
    /// Raise this deliberately, once budgets and the audit log have earned your trust.
    #[serde(default = "default_concurrency")]
    pub max_concurrent_sessions: usize,
    /// How long a queued approval waits for you before it counts as a refusal.
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout_secs: u64,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub session_budget: SessionBudget,
    #[serde(default)]
    pub global_budget: GlobalBudget,
    #[serde(default)]
    pub model: ModelConfig,
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub compaction: CompactionConfig,
    #[serde(default)]
    pub subagents: SubagentConfig,
    #[serde(default)]
    pub verification: VerificationConfig,
    /// Exact commands the `exec:check` capability may run (whitespace-normalized match). Owner-written.
    /// They run without a shell, in the sandbox of the check plugin, so a verifier gets objective
    /// evidence (tests, builds) without a per-run approval.
    #[serde(default)]
    pub check_commands: Vec<String>,
    #[serde(default)]
    pub delegate: DelegateConfig,
    #[serde(default)]
    pub upgrades: UpgradeConfig,
    /// Not in the file. The upgrade pipeline uses these to try a candidate in place of an installed plugin.
    #[serde(skip)]
    pub extra_plugins: Vec<PluginConfig>,
    #[serde(skip)]
    pub exclude_installed: Vec<String>,
    /// The agent's home directory (holds the stores and the eval suite). Set by `Config::load`.
    #[serde(skip)]
    pub home: PathBuf,
}

/// Limits and switches for plugin upgrades (stage 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpgradeConfig {
    /// Let a routine upgrade deploy without you. Off by default. Even when on, it applies only when
    /// the new version asks for nothing new, nothing above the reversible tier, and its plugin
    /// has earned it (see `earned_after`). Anything else always waits for you.
    pub auto_approve: bool,
    /// Versions of this plugin you have approved yourself before it may be auto-approved.
    pub earned_after: u32,
    /// The baseline eval suite must have at least this many cases, or no upgrade passes the gate.
    pub min_eval_cases: usize,
    /// How many recorded read-only calls the canary replays against old and new versions.
    pub canary_calls: usize,
    /// Differences the canary tolerates between the old and new version's answers.
    pub canary_max_divergence: usize,
    /// Seconds a candidate gets to answer in the contract tests.
    pub contract_timeout_secs: u64,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self { auto_approve: false, earned_after: 3, min_eval_cases: 3, canary_calls: 20, canary_max_divergence: 0, contract_timeout_secs: 10 }
    }
}

/// The optional delegate: applies owner-written rules to approval requests so you are asked less.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DelegateConfig {
    pub enabled: bool,
    /// Let the delegate adopt a proposed rule without asking you, but only for the lowest tier.
    /// Off by default. Everything above that tier still waits for you to run `agent delegate accept`.
    pub silent_learning: bool,
    /// Owner approvals of the identical action needed before a rule is proposed.
    pub suggest_after: u32,
}

impl Default for DelegateConfig {
    fn default() -> Self {
        Self { enabled: false, silent_learning: false, suggest_after: 3 }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {} (run `agent init` first?)", path.display()))?;
        let mut cfg: Config =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.home = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        cfg.validate_hooks().with_context(|| format!("in {}", path.display()))?;
        cfg.seal();
        Ok(cfg)
    }

    /// A hook that is misspelled must stop the agent from starting. Quietly ignoring a hook you
    /// wrote to protect something would be worse than not starting.
    pub fn validate_hooks(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for h in &self.hooks {
            if h.name.is_empty() || !h.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                anyhow::bail!("hook name '{}' may use only letters, digits, '-' and '_'", h.name);
            }
            if !seen.insert(h.name.as_str()) {
                anyhow::bail!("hook '{}' is listed twice", h.name);
            }
            if h.command.is_empty() {
                anyhow::bail!("hook '{}' has no command", h.name);
            }
            if h.subscribe.is_empty() {
                anyhow::bail!("hook '{}' subscribes to nothing", h.name);
            }
            for k in &h.subscribe {
                if !HOOK_KINDS.contains(&k.as_str()) {
                    anyhow::bail!("hook '{}' subscribes to '{k}'; the choices are {}", h.name, HOOK_KINDS.join(", "));
                }
            }
            if !(50..=60_000).contains(&h.timeout_ms) {
                anyhow::bail!("hook '{}': timeout_ms must be between 50 and 60000", h.name);
            }
        }
        Ok(())
    }

    /// Makes sure no sandboxed plugin can see the agent's home directory, whatever the file says.
    pub fn seal(&mut self) {
        let home = self.home.clone();
        if home.as_os_str().is_empty() {
            return;
        }
        for p in self.plugins.iter_mut().chain(self.extra_plugins.iter_mut()) {
            if let Some(sb) = &mut p.sandbox {
                if !sb.hide.contains(&home) {
                    sb.hide.push(home.clone());
                }
            }
        }
        for h in self.hooks.iter_mut() {
            if let Some(sb) = &mut h.sandbox {
                if !sb.hide.contains(&home) {
                    sb.hide.push(home.clone());
                }
            }
        }
    }

    /// Every plugin to start for a session: the ones in the config file plus the active
    /// versions installed by the upgrade pipeline. Read fresh each time, so a deployment or a
    /// rollback applies to the next session.
    pub fn plugins_now(&self) -> Vec<PluginConfig> {
        let mut out = self.plugins.clone();
        if !self.home.as_os_str().is_empty() {
            for p in crate::upgrade::installed_plugins(&self.home) {
                if !self.exclude_installed.contains(&p.name) && !out.iter().any(|q| q.name == p.name) {
                    out.push(p);
                }
            }
        }
        out.extend(self.extra_plugins.iter().cloned());
        out
    }
}
