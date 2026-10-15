//! The delegate: an optional approver that answers on the owner's behalf, but only
//! inside a rule envelope the owner wrote. It is deliberately not a model. It compares
//! structured facts about an action (tool, capability, tier, arguments) with rules, so
//! text the agent has read, its reasoning, and the task itself never reach it.
//!
//! - Outcomes are approve, deny, or escalate. Anything no rule covers is escalated to the owner.
//! - Rules live in `<home>/delegate/rules.json`. The home directory is protected by the gate,
//!   so no agent tool can read or write them. The delegate itself only reads that file.
//! - It may propose rules from the owner's past approvals. A proposal sits in
//!   `<home>/delegate/proposed/` and does nothing until the owner runs `agent delegate accept`.
//! - Capabilities that change authority are never delegated, whatever the rules say.
use crate::audit::{AuditEntry, AuditLog};
use crate::config::{DelegateConfig, Tier};
use crate::gate::resolve;
use crate::runner::{ApprovalOutcome, ApprovalRequest, Approver, Decider};
use crate::store::{now, Store};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Capabilities that grant or change authority. The delegate escalates these every time.
pub const NEVER_DELEGATED: [&str; 5] = ["upgrade:", "permission:", "grant:", "policy:", "eval:accept"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Approve,
    Deny,
}

/// How one argument must look. There is deliberately no prefix or pattern matcher:
/// "starts with `cargo test`" would also match `cargo test; rm -rf .`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    Exact(Value),
    OneOf(Vec<Value>),
    /// A path that, once resolved, is inside this directory.
    Under(String),
}

impl Matcher {
    fn accepts(&self, v: &Value, workspace: &Path) -> bool {
        match self {
            Matcher::Exact(e) => v == e,
            Matcher::OneOf(list) => list.contains(v),
            Matcher::Under(dir) => match v.as_str() {
                Some(p) => resolve(workspace, p).starts_with(resolve(workspace, dir)),
                None => false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub tool: String,
    #[serde(default)]
    pub capability: Option<String>,
    /// Every argument of the action must be named here and accepted. An argument the rule
    /// does not mention means the rule does not apply, so no rule can approve "any" call.
    #[serde(default)]
    pub args: BTreeMap<String, Matcher>,
    /// Unix seconds. After this the rule is ignored (a time-limited grant).
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
}

impl Rule {
    fn matches(&self, req: &ApprovalRequest, workspace: &Path, at: i64) -> bool {
        if self.expires_at.map(|t| at >= t).unwrap_or(false) {
            return false;
        }
        if self.tool != req.tool {
            return false;
        }
        if self.capability.as_ref().map(|c| c != &req.capability).unwrap_or(false) {
            return false;
        }
        match req.args.as_object() {
            Some(obj) => {
                obj.len() == self.args.len()
                    && self.args.iter().all(|(k, m)| obj.get(k).map(|v| m.accepts(v, workspace)).unwrap_or(false))
            }
            None => req.args.is_null() && self.args.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DelegateDecision {
    Approve { rule: String },
    Deny { rule: String },
    Escalate { reason: String },
}

pub fn delegate_dir(home: &Path) -> PathBuf {
    home.join("delegate")
}

fn rules_path(home: &Path) -> PathBuf {
    delegate_dir(home).join("rules.json")
}

fn proposed_dir(home: &Path) -> PathBuf {
    delegate_dir(home).join("proposed")
}

/// Reads and checks the owner's rules. A missing file means no rules.
pub fn load_rules(home: &Path) -> Result<Vec<Rule>> {
    let path = rules_path(home);
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let rules: Vec<Rule> = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let mut seen = HashSet::new();
    for r in &rules {
        if r.id.trim().is_empty() || r.tool.trim().is_empty() {
            bail!("a rule needs a non-empty id and tool");
        }
        if !seen.insert(r.id.clone()) {
            bail!("rule id '{}' is used twice", r.id);
        }
        if r.args.values().any(|m| matches!(m, Matcher::OneOf(l) if l.is_empty())) {
            bail!("rule '{}' has an empty one_of", r.id);
        }
    }
    Ok(rules)
}

fn save_rules(home: &Path, rules: &[Rule]) -> Result<()> {
    std::fs::create_dir_all(delegate_dir(home))?;
    let tmp = delegate_dir(home).join("rules.json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(rules)?)?;
    std::fs::rename(tmp, rules_path(home))?;
    Ok(())
}

pub struct Delegate {
    home: PathBuf,
    workspace: PathBuf,
}

impl Delegate {
    pub fn new(home: &Path, workspace: &Path) -> Self {
        Self { home: home.to_path_buf(), workspace: workspace.to_path_buf() }
    }

    /// Reads the rules fresh on every request, so an edit or a revocation takes effect at once.
    /// Deny rules are checked first. A broken rules file escalates everything.
    pub fn decide(&self, req: &ApprovalRequest) -> DelegateDecision {
        if NEVER_DELEGATED.iter().any(|p| req.capability.starts_with(p)) {
            return DelegateDecision::Escalate { reason: "this capability is never delegated".into() };
        }
        let rules = match load_rules(&self.home) {
            Ok(r) => r,
            Err(e) => return DelegateDecision::Escalate { reason: format!("rules file is unusable: {e:#}") },
        };
        let at = now();
        let hit = |effect: Effect| rules.iter().find(|r| r.effect == effect && r.matches(req, &self.workspace, at));
        if let Some(r) = hit(Effect::Deny) {
            return DelegateDecision::Deny { rule: r.id.clone() };
        }
        if let Some(r) = hit(Effect::Approve) {
            return DelegateDecision::Approve { rule: r.id.clone() };
        }
        DelegateDecision::Escalate { reason: "no rule covers this action".into() }
    }
}

/// One past decision by the owner, used to suggest rules.
#[derive(Debug, Clone)]
pub struct Past {
    pub tool: String,
    pub capability: Option<String>,
    pub tier: Tier,
    pub args: Value,
    pub approved: bool,
}

impl Past {
    pub fn from_log(entries: &[Value]) -> Vec<Past> {
        entries
            .iter()
            .filter_map(|v| {
                Some(Past {
                    tool: v["tool"].as_str()?.to_string(),
                    capability: v["capability"].as_str().map(String::from),
                    // Old entries have no tier. Unknown counts as the highest.
                    tier: serde_json::from_value(v["tier"].clone()).unwrap_or(Tier::Irreversible),
                    args: v["args"].clone(),
                    approved: v["approved"].as_bool()?,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub rule: Rule,
    pub tier: Tier,
    pub owner_approvals: u32,
}

/// Rules the owner might want, from actions they approved `threshold` or more times and never refused.
/// Each proposal is an exact match on every argument. Nothing here changes any decision.
pub fn suggest(history: &[Past], existing: &[Rule], threshold: u32, workspace: &Path) -> Vec<Proposal> {
    let mut groups: BTreeMap<String, (Past, u32, u32)> = BTreeMap::new();
    for h in history {
        let key = format!("{}|{}", h.tool, h.args);
        let e = groups.entry(key).or_insert_with(|| (h.clone(), 0, 0));
        if h.approved {
            e.1 += 1;
        } else {
            e.2 += 1;
        }
    }
    let mut out = Vec::new();
    for (key, (first, approved, refused)) in groups {
        if refused > 0 || approved < threshold {
            continue;
        }
        let Some(obj) = first.args.as_object() else { continue };
        if first.capability.as_deref().map(|c| NEVER_DELEGATED.iter().any(|p| c.starts_with(p))).unwrap_or(false) {
            continue;
        }
        let digest = Sha256::digest(key.as_bytes());
        let short: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
        let tool_part: String = first.tool.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        let rule = Rule {
            id: format!("auto-{tool_part}-{short}"),
            effect: Effect::Approve,
            tool: first.tool.clone(),
            capability: first.capability.clone(),
            args: obj.iter().map(|(k, v)| (k.clone(), Matcher::Exact(v.clone()))).collect(),
            expires_at: None,
            note: Some(format!("proposed after {approved} owner approvals of this exact action")),
        };
        // Skip what an existing rule already decides.
        let probe = ApprovalRequest {
            session_id: 0,
            plugin: String::new(),
            tool: first.tool.clone(),
            capability: first.capability.clone().unwrap_or_default(),
            tier: first.tier,
            args: first.args.clone(),
        };
        let covered = existing.iter().any(|r| r.matches(&probe, workspace, now()));
        if covered || existing.iter().any(|r| r.id == rule.id) {
            continue;
        }
        out.push(Proposal { rule, tier: first.tier, owner_approvals: approved });
    }
    out
}

pub fn write_proposal(home: &Path, p: &Proposal) -> Result<bool> {
    let dir = proposed_dir(home);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", p.rule.id));
    if path.exists() {
        return Ok(false);
    }
    std::fs::write(path, serde_json::to_string_pretty(p)?)?;
    Ok(true)
}

pub fn list_proposed(home: &Path) -> Result<Vec<Proposal>> {
    let dir = proposed_dir(home);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)?.filter_map(|e| e.ok()).collect();
    files.sort_by_key(|e| e.file_name());
    for f in files {
        if f.path().extension().map(|x| x == "json").unwrap_or(false) {
            out.push(serde_json::from_str(&std::fs::read_to_string(f.path())?)?);
        }
    }
    Ok(out)
}

fn proposal_path(home: &Path, id: &str) -> Result<PathBuf> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        bail!("not a valid proposal id");
    }
    Ok(proposed_dir(home).join(format!("{id}.json")))
}

/// Owner action: make a proposed rule live.
pub fn accept(home: &Path, id: &str) -> Result<()> {
    let path = proposal_path(home, id)?;
    let p: Proposal = serde_json::from_str(&std::fs::read_to_string(&path).with_context(|| format!("no proposal '{id}'"))?)?;
    add_rule(home, p.rule)?;
    std::fs::remove_file(path)?;
    Ok(())
}

pub fn reject(home: &Path, id: &str) -> Result<()> {
    let path = proposal_path(home, id)?;
    if !path.exists() {
        bail!("no proposal '{id}'");
    }
    Ok(std::fs::remove_file(path)?)
}

fn add_rule(home: &Path, rule: Rule) -> Result<()> {
    let mut rules = load_rules(home)?;
    if rules.iter().any(|r| r.id == rule.id) {
        bail!("rule '{}' already exists", rule.id);
    }
    rules.push(rule);
    save_rules(home, &rules)
}

/// Owner action: remove a rule. It stops applying on the very next request.
pub fn revoke(home: &Path, rule_id: &str) -> Result<()> {
    let mut rules = load_rules(home)?;
    let before = rules.len();
    rules.retain(|r| r.id != rule_id);
    if rules.len() == before {
        bail!("no rule '{rule_id}'");
    }
    save_rules(home, &rules)
}

/// Turns the owner's history into proposals, and (only if the owner opted in) adopts the
/// ones at the lowest tier. The actions that need approval at all are the irreversible ones,
/// so with today's three tiers silent learning has nothing it may adopt.
pub struct Learning {
    pub store: Arc<Store>,
    pub audit: Arc<AuditLog>,
    pub cfg: DelegateConfig,
}

impl Learning {
    pub fn run(&self, delegate: &Delegate) -> Result<()> {
        let history = Past::from_log(&self.store.approval_history()?);
        self.apply(delegate, &history)
    }

    pub fn apply(&self, delegate: &Delegate, history: &[Past]) -> Result<()> {
        let existing = load_rules(&delegate.home)?;
        for p in suggest(history, &existing, self.cfg.suggest_after, &delegate.workspace) {
            if self.cfg.silent_learning && p.tier <= Tier::Reversible {
                add_rule(&delegate.home, p.rule.clone())?;
                self.audit.append(&AuditEntry {
                    session_id: 0,
                    plugin: "delegate".into(),
                    tool: p.rule.tool.clone(),
                    capability: p.rule.capability.clone().unwrap_or_default(),
                    tier: p.tier.as_str().into(),
                    decision: "delegate_rule_learned".into(),
                    reason: format!("silent learning adopted rule '{}'", p.rule.id),
                    args: String::new(),
                })?;
            } else {
                write_proposal(&delegate.home, &p)?;
            }
        }
        Ok(())
    }
}

/// The approval hook. Asks the delegate first. When it escalates, the request goes to the
/// owner's own channel (terminal or approval queue) exactly as if no delegate existed.
pub struct DelegatingApprover {
    delegate: Delegate,
    owner: Arc<dyn Approver>,
    learning: Option<Learning>,
}

impl DelegatingApprover {
    pub fn new(delegate: Delegate, owner: Arc<dyn Approver>) -> Self {
        Self { delegate, owner, learning: None }
    }

    pub fn with_learning(mut self, learning: Learning) -> Self {
        self.learning = Some(learning);
        self
    }
}

impl Approver for DelegatingApprover {
    fn approve(&self, req: &ApprovalRequest) -> bool {
        self.decide(req).approved
    }

    fn decide(&self, req: &ApprovalRequest) -> ApprovalOutcome {
        match self.delegate.decide(req) {
            DelegateDecision::Approve { rule } => {
                ApprovalOutcome { approved: true, decider: Decider::Delegate { rule }, escalated: None }
            }
            DelegateDecision::Deny { rule } => {
                ApprovalOutcome { approved: false, decider: Decider::Delegate { rule }, escalated: None }
            }
            DelegateDecision::Escalate { reason } => {
                // Best effort: look for patterns in what the owner has approved before asking again.
                if let Some(l) = &self.learning {
                    let _ = l.run(&self.delegate);
                }
                let mut out = self.owner.decide(req);
                out.escalated = Some(reason);
                out
            }
        }
    }
}
