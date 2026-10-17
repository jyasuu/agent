use crate::config::{Grant, Tier};
use crate::plugin::ToolEntry;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

/// What a parent asks for when it spawns a child: a capability it holds, optionally
/// narrowed to a sub-path of the scope it holds it for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    pub capability: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Proceeds automatically and is logged.
    Allow { tier: Tier, reason: String },
    /// Irreversible or external: the owner must approve first.
    NeedApproval { tier: Tier, reason: String },
    Deny { reason: String },
}

/// The one gate every tool call passes through. Deny by default.
pub struct Gate {
    workspace: PathBuf,
    grants: Vec<Grant>,
    /// Paths no grant can ever cover (the agent's own stores).
    protected: Vec<PathBuf>,
}

impl Gate {
    pub fn new(workspace: &Path, grants: &[Grant], protected: &[PathBuf]) -> Self {
        let root = Path::new("/");
        Self {
            workspace: resolve(root, &workspace.to_string_lossy()),
            grants: grants.to_vec(),
            protected: protected.iter().map(|p| resolve(root, &p.to_string_lossy())).collect(),
        }
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn holds(&self, capability: &str) -> bool {
        self.grants.iter().any(|g| g.capability == capability)
    }

    /// The same gate (same workspace, same protected paths) with different grants.
    pub fn with_grants(&self, grants: Vec<Grant>) -> Gate {
        Gate { workspace: self.workspace.clone(), grants, protected: self.protected.clone() }
    }

    /// Grants for a child session. Every request must be covered by a grant this gate
    /// holds, and the tier is copied from that grant, so a child can only ever hold
    /// less than its parent: never another capability, a wider scope or a lower tier.
    pub fn narrow(&self, requests: &[GrantRequest]) -> std::result::Result<Vec<Grant>, String> {
        let mut out: Vec<Grant> = Vec::new();
        for req in requests {
            let held: Vec<&Grant> = self.grants.iter().filter(|g| g.capability == req.capability).collect();
            if held.is_empty() {
                let mine: Vec<&str> = self.grants.iter().map(|g| g.capability.as_str()).collect();
                return Err(format!(
                    "you do not hold capability '{}', so you cannot give it away (you hold: {})",
                    req.capability,
                    mine.join(", ")
                ));
            }
            match &req.scope {
                None => out.extend(held.into_iter().cloned()),
                Some(scope) => {
                    let wanted = resolve(&self.workspace, scope);
                    let covering: Vec<&Grant> = held
                        .into_iter()
                        .filter(|g| {
                            let root = match &g.scope {
                                Some(s) => resolve(&self.workspace, s),
                                None => self.workspace.clone(),
                            };
                            wanted.starts_with(&root)
                        })
                        .collect();
                    if covering.is_empty() {
                        return Err(format!(
                            "scope '{scope}' for '{}' is outside the scope you hold it for",
                            req.capability
                        ));
                    }
                    for g in covering {
                        out.push(Grant { capability: g.capability.clone(), tier: g.tier, scope: Some(scope.clone()) });
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn decide(&self, tool: &ToolEntry, args: &Value) -> Decision {
        let matching: Vec<&Grant> =
            self.grants.iter().filter(|g| g.capability == tool.capability).collect();
        if matching.is_empty() {
            return Decision::Deny {
                reason: format!("capability '{}' is not granted", tool.capability),
            };
        }

        let mut paths = Vec::new();
        for arg in &tool.scope_args {
            match args.get(arg).and_then(|v| v.as_str()) {
                Some(s) => paths.push(resolve(&self.workspace, s)),
                None => {
                    return Decision::Deny {
                        reason: format!("scope argument '{arg}' is missing or not a string"),
                    }
                }
            }
        }

        if paths.iter().any(|p| self.protected.iter().any(|pr| p.starts_with(pr))) {
            return Decision::Deny { reason: "path is protected by the core".into() };
        }
        // A tool that walks a whole tree must not be pointed at a directory that contains the
        // agent's own files. Name a narrower directory instead.
        if tool.recursive && paths.iter().any(|p| self.protected.iter().any(|pr| pr.starts_with(p))) {
            return Decision::Deny {
                reason: "this directory contains files protected by the core (the agent's home); search a narrower directory".into(),
            };
        }

        let covering: Vec<&Grant> = matching
            .into_iter()
            .filter(|g| {
                if paths.is_empty() {
                    return true;
                }
                let root = match &g.scope {
                    Some(s) => resolve(&self.workspace, s),
                    None => self.workspace.clone(),
                };
                paths.iter().all(|p| p.starts_with(&root))
            })
            .collect();
        if covering.is_empty() {
            return Decision::Deny { reason: "outside the granted scope".into() };
        }

        // If several grants cover the call, the riskiest tier wins.
        let tier = covering.iter().map(|g| g.tier).max().expect("non-empty");
        let reason = format!("granted {} as {}", tool.capability, tier.as_str());
        match tier {
            Tier::Irreversible => Decision::NeedApproval { tier, reason },
            _ => Decision::Allow { tier, reason },
        }
    }
}

fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve a path against `base`, collapse `.` and `..`, and follow symlinks
/// for the deepest part that exists, so a link inside the workspace cannot
/// point the check at a place outside it.
pub fn resolve(base: &Path, p: &str) -> PathBuf {
    let joined = if Path::new(p).is_absolute() { PathBuf::from(p) } else { base.join(p) };
    let lex = lexical(&joined);
    let mut existing = lex.clone();
    let mut tail = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(n) => {
                tail.push(n.to_os_string());
                existing.pop();
            }
            None => break,
        }
    }
    let mut out = existing.canonicalize().unwrap_or(existing);
    for t in tail.iter().rev() {
        out.push(t);
    }
    out
}
