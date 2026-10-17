//! Orchestration: agent templates, and sub-agents that run in the background and are joined later.
//! Behavior only: sessions, logs, audit rows, and what the model was shown.
//!
//! Parallel children make a plain script non-deterministic, so these tests use a provider that answers
//! by *agent and step*: the agent is named by the first word of its task, the step is how many replies
//! it has already given.
mod common;
use agent_core::config::Config;
use agent_core::provider::{Block, Message, ModelProvider, ModelResponse, ToolSpec};
use agent_core::runner::Outcome;
use common::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct Call {
    tag: String,
    step: usize,
    system: String,
    tools: Vec<String>,
    last_user: String,
}

/// `script(tag, step, call)` answers one model call. It may block, set flags or count arrivals.
struct Routed {
    script: Box<dyn Fn(&str, usize, &Call) -> ModelResponse + Send + Sync>,
    calls: Mutex<Vec<Call>>,
}

impl Routed {
    fn new(script: impl Fn(&str, usize, &Call) -> ModelResponse + Send + Sync + 'static) -> Self {
        Self { script: Box::new(script), calls: Mutex::new(Vec::new()) }
    }
    fn of(&self, tag: &str) -> Vec<Call> {
        self.calls.lock().unwrap().iter().filter(|c| c.tag == tag).cloned().collect()
    }
}

fn first_text(m: &Message) -> String {
    m.content.iter().find_map(|b| if let Block::Text { text } = b { Some(text.clone()) } else { None }).unwrap_or_default()
}

fn last_user_text(messages: &[Message]) -> String {
    let mut out = String::new();
    if let Some(m) = messages.iter().rev().find(|m| m.role == "user") {
        for b in &m.content {
            match b {
                Block::Text { text } => out.push_str(text),
                Block::ToolResult { content, .. } => out.push_str(content),
                _ => {}
            }
        }
    }
    out
}

impl ModelProvider for Routed {
    fn complete(&self, system: &str, messages: &[Message], tools: &[ToolSpec]) -> anyhow::Result<ModelResponse> {
        let tag = messages.first().map(first_text).unwrap_or_default().split_whitespace().next().unwrap_or("").to_string();
        let step = messages.iter().filter(|m| m.role == "assistant").count();
        let call = Call {
            tag: tag.clone(),
            step,
            system: system.to_string(),
            tools: tools.iter().map(|t| t.name.clone()).collect(),
            last_user: last_user_text(messages),
        };
        self.calls.lock().unwrap().push(call.clone());
        Ok((self.script)(&tag, step, &call))
    }
}

fn spawn_bg(id: &str, task: &str, extra: Value) -> ModelResponse {
    let mut input = json!({ "task": task, "wait": false });
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        input[k] = v;
    }
    tool(id, "spawn_agent", input)
}

fn join(id: &str, handles: Value) -> ModelResponse {
    tool(id, "join_agent", json!({ "handles": handles }))
}

fn children(env: &Env, parent: i64) -> Vec<(i64, String)> {
    let mut v: Vec<(i64, String)> = env
        .store
        .list_sessions(100)
        .unwrap()
        .into_iter()
        .filter(|r| r.parent_id == Some(parent))
        .map(|r| {
            let first = env.store.load_log(r.id).unwrap().into_iter().next().map(|e| e.payload["text"].as_str().unwrap_or("").to_string());
            (r.id, first.unwrap_or_default())
        })
        .collect();
    v.sort();
    v
}

fn child_named(env: &Env, parent: i64, tag: &str) -> i64 {
    children(env, parent).into_iter().find(|(_, t)| t.starts_with(tag)).unwrap_or_else(|| panic!("no child {tag}")).0
}

fn waited(flag: &AtomicBool, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while !flag.load(Ordering::SeqCst) {
        if Instant::now() > end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

fn templates() -> Value {
    json!({
        "reader": {
            "description": "reads files, nothing else",
            "system_prompt": "READER-PERSONA: you only read.",
            "grants": [{ "capability": "fs:read" }],
            "tools": ["fs_read"]
        },
        "editor": {
            "description": "reads and edits files",
            "system_prompt": "EDITOR-PERSONA",
            "grants": [{ "capability": "fs:read" }, { "capability": "fs:write" }],
            "deny_tools": ["fs_list"]
        }
    })
}

// ---- templates --------------------------------------------------------------------------------

#[test]
fn a_template_sets_the_prompt_the_tools_and_the_powers() {
    let env = setup("tpl", all_grants(), |c| c["agents"] = templates());
    std::fs::write(env.ws.join("a.txt"), "hello").unwrap();
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID read a.txt", "template": "reader" })),
        ("ROOT", _) => text("root done"),
        ("KID", 0) => tool("k1", "fs_read", json!({ "path": "a.txt" })),
        ("KID", 1) => tool("k2", "fs_list", json!({ "path": "." })),
        ("KID", 2) => tool("k3", "fs_write", json!({ "path": "x.txt", "content": "no" })),
        _ => text("kid done"),
    });
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");

    let kid = p.of("KID");
    // Its own instructions, and the core's rules after them.
    assert!(kid[0].system.starts_with("READER-PERSONA"), "{}", kid[0].system);
    assert!(kid[0].system.contains("untrusted_tool_output") && kid[0].system.contains("reader"));
    assert!(!p.of("ROOT")[0].system.contains("READER-PERSONA"));
    // Only the tool it was given (plus pin and recall), not fs_write or fs_list.
    for t in &kid[0].tools {
        assert!(["fs_read", "pin", "recall"].contains(&t.as_str()), "unexpected tool {t}");
    }
    assert!(kid[0].tools.contains(&"fs_read".to_string()));

    let child = child_named(&env, parent, "KID");
    let rows = env.audit.rows().unwrap();
    let by = |tool: &str| rows.iter().find(|r| r.entry.tool == tool && r.entry.session_id == child).map(|r| (r.entry.decision.clone(), r.entry.reason.clone()));
    assert!(rows.iter().any(|r| r.entry.tool == "fs_read" && r.entry.session_id == child && r.entry.decision == "executed"));
    // Called anyway, though never offered: refused by the template's tool list. (The grants are a second,
    // separate wall, covered by the tests below.)
    for name in ["fs_list", "fs_write"] {
        let (d, why) = by(name).unwrap();
        assert_eq!(d, "denied");
        assert!(why.contains("not enabled for the 'reader' agent template"), "{why}");
    }
    assert!(!env.ws.join("x.txt").exists());
}

#[test]
fn a_deny_list_hides_a_tool_that_the_grants_would_allow() {
    let env = setup("deny", all_grants(), |c| c["agents"] = templates());
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID try", "template": "editor" })),
        ("ROOT", _) => text("done"),
        ("KID", 0) => tool("k1", "fs_list", json!({ "path": "." })),
        ("KID", 1) => tool("k2", "fs_write", json!({ "path": "ok.txt", "content": "fine" })),
        _ => text("kid done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let kid = p.of("KID");
    assert!(!kid[0].tools.contains(&"fs_list".to_string()) && kid[0].tools.contains(&"fs_write".to_string()));
    assert!(kid[0].system.starts_with("EDITOR-PERSONA"));
    assert_eq!(std::fs::read_to_string(env.ws.join("ok.txt")).unwrap(), "fine");
    let child = child_named(&env, parent, "KID");
    assert!(env.audit.rows().unwrap().iter().any(|r| r.entry.session_id == child && r.entry.tool == "fs_list" && r.entry.decision == "denied"));
}

#[test]
fn a_template_can_only_narrow_never_widen() {
    // The parent can read and spawn, nothing else. The editor template asks for write as well.
    let grants = json!([
        { "capability": "fs:read", "tier": "read_only" },
        { "capability": "agent:spawn", "tier": "reversible" }
    ]);
    let env = setup("narrow-only", grants, |c| {
        let mut t = templates();
        t["writer"] = json!({ "grants": [{ "capability": "fs:write" }] });
        c["agents"] = t;
    });
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID1 edit", "template": "editor" })),
        ("ROOT", 1) => tool("s2", "spawn_agent", json!({ "task": "KID2 write", "template": "writer" })),
        // The model asks for more than the template carries.
        ("ROOT", 2) => tool("s3", "spawn_agent", json!({ "task": "KID3 more", "template": "reader", "grants": [{ "capability": "fs:write" }] })),
        ("ROOT", _) => text("done"),
        ("KID1", 0) => tool("k1", "fs_write", json!({ "path": "w.txt", "content": "x" })),
        _ => text("kid1 done"),
    });
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let r = results(&env, parent);

    // 1: started, with the capability it could not have left out and told so.
    assert_eq!(r[0]["is_error"], false);
    assert!(r[0]["content"].as_str().unwrap().contains("left out: fs:write"), "{}", r[0]["content"]);
    assert!(!env.ws.join("w.txt").exists(), "the child never held fs:write");
    let kid1 = child_named(&env, parent, "KID1");
    assert!(env.audit.rows().unwrap().iter().any(|r| r.entry.session_id == kid1 && r.entry.tool == "fs_write" && r.entry.decision == "denied"));

    // 2: nothing it needs is held: refused, no child created.
    assert_eq!(r[1]["is_error"], true);
    assert!(r[1]["content"].as_str().unwrap().contains("needs capabilities you do not hold"), "{}", r[1]["content"]);
    // 3: the model cannot add to what the template carries either.
    assert_eq!(r[2]["is_error"], true);
    assert!(r[2]["content"].as_str().unwrap().contains("do not hold capability 'fs:write'"), "{}", r[2]["content"]);
    assert_eq!(children(&env, parent).len(), 1);
}

#[test]
fn a_model_can_narrow_a_template_further() {
    let env = setup("narrow-more", all_grants(), |c| {
        c["agents"] = json!({ "files": { "grants": [{ "capability": "fs:read" }, { "capability": "fs:write" }] } })
    });
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID go", "template": "files", "grants": [{ "capability": "fs:read" }] })),
        ("ROOT", _) => text("done"),
        ("KID", 0) => tool("k1", "fs_write", json!({ "path": "no.txt", "content": "x" })),
        _ => text("kid done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(!env.ws.join("no.txt").exists());
    let kid = child_named(&env, parent, "KID");
    assert!(env.audit.rows().unwrap().iter().any(|r| r.entry.session_id == kid && r.entry.tool == "fs_write" && r.entry.decision == "denied"));
}

#[test]
fn an_unknown_template_is_refused_and_the_choices_are_listed() {
    let env = setup("unknown", all_grants(), |c| c["agents"] = templates());
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID x", "template": "wizard" })),
        _ => text("done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let r = results(&env, parent);
    assert_eq!(r[0]["is_error"], true);
    let c = r[0]["content"].as_str().unwrap();
    assert!(c.contains("unknown template 'wizard'") && c.contains("editor") && c.contains("reader"), "{c}");
    assert!(children(&env, parent).is_empty());
    // The model is shown which templates exist.
    assert!(p.of("ROOT")[0].last_user.contains("ROOT"));
}

#[test]
fn the_model_is_told_which_templates_exist() {
    let env = setup("listed", all_grants(), |c| c["agents"] = templates());
    // Look at the tool description the parent was offered.
    struct Peek(Mutex<String>);
    impl ModelProvider for Peek {
        fn complete(&self, _s: &str, _m: &[Message], tools: &[ToolSpec]) -> anyhow::Result<ModelResponse> {
            *self.0.lock().unwrap() = tools.iter().find(|t| t.name == "spawn_agent").map(|t| t.description.clone()).unwrap_or_default();
            Ok(text("ok"))
        }
    }
    let p = Peek(Mutex::new(String::new()));
    run(&env, &p, &no_approvals(), "go");
    let d = p.0.lock().unwrap().clone();
    assert!(d.contains("reader: reads files, nothing else") && d.contains("editor: reads and edits files"), "{d}");
    assert!(d.contains("join_agent"));
}

#[test]
fn only_a_template_that_allows_it_can_spawn_children_of_its_own() {
    let env = setup("can-spawn", all_grants(), |c| {
        c["subagents"] = json!({ "max_depth": 2 });
        c["agents"] = json!({
            "lead": { "grants": [{ "capability": "fs:read" }], "can_spawn": true },
            "leaf": { "grants": [{ "capability": "fs:read" }] }
        });
    });
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "LEAD x", "template": "lead" })),
        ("ROOT", 1) => tool("s2", "spawn_agent", json!({ "task": "LEAF x", "template": "leaf" })),
        ("ROOT", _) => text("done"),
        _ => text("kid done"),
    });
    run(&env, &p, &no_approvals(), "ROOT go");
    assert!(p.of("LEAD")[0].tools.contains(&"spawn_agent".to_string()));
    assert!(p.of("LEAD")[0].tools.contains(&"join_agent".to_string()));
    assert!(!p.of("LEAF")[0].tools.contains(&"spawn_agent".to_string()));
    assert!(!p.of("LEAF")[0].tools.contains(&"join_agent".to_string()));
}

#[test]
fn template_budgets_are_ceilings_the_owner_ceiling_still_wins() {
    let env = setup("tbudget", all_grants(), |c| {
        c["subagents"] = json!({ "child_budget": { "max_steps": 10, "max_tokens": 5000, "max_cost_usd": 1.0, "max_wall_secs": 100 } });
        c["agents"] = json!({
            "tight": { "grants": [{ "capability": "fs:read" }], "budget": { "max_steps": 3, "max_tokens": 900000 } }
        });
    });
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => tool("s1", "spawn_agent", json!({ "task": "KID x", "template": "tight" })),
        ("ROOT", _) => text("done"),
        _ => text("kid done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let spawn = kinds(&env, parent, "spawn");
    let b = &spawn[0]["budget"];
    assert_eq!(b["max_steps"], 3, "the template can lower a ceiling");
    assert_eq!(b["max_tokens"], 5000, "but never raise the owner's");
}

#[test]
fn a_bad_template_stops_the_agent_from_starting() {
    let load = |agents: Value| -> Result<(), String> {
        let cfg: Result<Config, _> = serde_json::from_value(json!({ "workspace": "/tmp", "plugins": [], "agents": agents }));
        match cfg {
            Err(e) => Err(e.to_string()),
            Ok(c) => c.validate_agents().map_err(|e| e.to_string()),
        }
    };
    assert!(load(json!({ "ok": { "grants": [{ "capability": "fs:read" }] } })).is_ok());
    // A misspelled key must not be quietly ignored: a missing deny list would widen the agent.
    assert!(load(json!({ "x": { "deny_tool": ["fs_write"] } })).is_err());
    let e = load(json!({ "x": { "grants": [{ "capability": "core:pin" }] } })).unwrap_err();
    assert!(e.contains("cannot be listed"), "{e}");
    let e = load(json!({ "x": { "grants": [{ "capability": "agent:spawn" }] } })).unwrap_err();
    assert!(e.contains("can_spawn"), "{e}");
    let e = load(json!({ "x": { "grants": [{ "capability": "upgrade:propose" }] } })).unwrap_err();
    assert!(e.contains("authority"), "{e}");
    assert!(load(json!({ "bad name": {} })).is_err());
    assert!(load(json!({ "x": { "budget": { "max_steps": 0 } } })).is_err());
    assert!(load(json!({ "x": { "tools": [""] } })).is_err());
}

// ---- background children: spawn now, join later ------------------------------------------------

#[test]
fn background_children_really_run_at_the_same_time() {
    let env = setup("parallel", all_grants(), |_| {});
    let arrived = Arc::new(AtomicUsize::new(0));
    let both_met = Arc::new(AtomicBool::new(false));
    let (a2, m2) = (arrived.clone(), both_met.clone());
    let p = Routed::new(move |tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "ALPHA work", json!({})),
        ("ROOT", 1) => spawn_bg("s2", "BETA work", json!({})),
        ("ROOT", 2) => join("j1", json!([])),
        ("ROOT", _) => text("root done"),
        ("ALPHA", 0) | ("BETA", 0) => {
            // Each waits for the other. A sequential run would time out here and the flag would stay false.
            a2.fetch_add(1, Ordering::SeqCst);
            let end = Instant::now() + Duration::from_secs(8);
            while a2.load(Ordering::SeqCst) < 2 && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            if a2.load(Ordering::SeqCst) >= 2 {
                m2.store(true, Ordering::SeqCst);
            }
            text(&format!("{tag}-DONE"))
        }
        _ => text("?"),
    });
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    assert!(both_met.load(Ordering::SeqCst), "the two children never ran together");

    let r = results(&env, parent);
    assert!(r[0]["content"].as_str().unwrap().contains("handle agent-"), "{}", r[0]["content"]);
    let joined = r[2]["content"].as_str().unwrap();
    assert!(joined.contains("ALPHA-DONE") && joined.contains("BETA-DONE"), "{joined}");
    for (id, _) in children(&env, parent) {
        assert_eq!(env.store.status(id).unwrap(), "completed");
    }
    // Every join and spawn went through the gate like any other tool.
    let d = decisions(&env);
    assert!(d.iter().filter(|x| *x == "spawn_agent:executed").count() == 2 && d.contains(&"join_agent:executed".to_string()), "{d:?}");
}

#[test]
fn work_done_while_a_child_runs_is_not_lost_and_join_returns_the_short_result() {
    let env = setup("overlap", all_grants(), |c| c["subagents"] = json!({ "max_result_chars": 40 }));
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "KID think", json!({})),
        ("ROOT", 1) => tool("w1", "fs_write", json!({ "path": "mine.txt", "content": "parent kept working" })),
        ("ROOT", 2) => join("j1", json!(["agent-2"])),
        ("ROOT", _) => text("done"),
        ("KID", _) => text(&"long answer ".repeat(50)),
        _ => text("?"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    assert_eq!(std::fs::read_to_string(env.ws.join("mine.txt")).unwrap(), "parent kept working");
    let kid = child_named(&env, parent, "KID");
    let r = results(&env, parent);
    let joined = r[2]["content"].as_str().unwrap();
    assert!(joined.contains(&format!("agent-{kid}")), "{joined}");
    assert!(joined.len() < 300, "only a short result returns: {} chars", joined.len());
    // The full answer stays in the child's own log.
    let full = kinds(&env, kid, "final");
    assert!(full[0]["text"].as_str().unwrap().len() > 400);
}

#[test]
fn a_joined_handle_can_be_asked_again_and_a_wrong_one_is_refused() {
    let env = setup("rejoin", all_grants(), |_| {});
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "KID go", json!({})),
        ("ROOT", 1) => join("j1", json!([])),
        ("ROOT", 2) => join("j2", json!([])), // nothing left running
        ("ROOT", 3) => join("j3", json!(["agent-999"])),
        ("ROOT", 4) => join("j4", json!(["nonsense"])),
        ("ROOT", _) => text("done"),
        ("KID", _) => text("kid-result"),
        _ => text("?"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let r = results(&env, parent);
    assert!(r[1]["content"].as_str().unwrap().contains("kid-result"));
    assert_eq!(r[2]["is_error"], true);
    assert!(r[2]["content"].as_str().unwrap().contains("no background sub-agents"));
    assert!(r[3]["content"].as_str().unwrap().contains("belongs to this session"), "{}", r[3]["content"]);
    assert!(r[4]["content"].as_str().unwrap().contains("not a handle"));
}

#[test]
fn a_session_cannot_join_another_sessions_child() {
    let env = setup("not-mine", all_grants(), |_| {});
    // Session 1 has a child. Session 2 tries to read it by handle.
    let p1 = Routed::new(|tag, step, _| match (tag, step) {
        ("ONE", 0) => spawn_bg("s1", "KID go", json!({})),
        ("ONE", 1) => join("j1", json!([])),
        ("ONE", _) => text("done"),
        _ => text("kid-secret-result"),
    });
    let (one, _) = run(&env, &p1, &no_approvals(), "ONE go");
    let kid = child_named(&env, one, "KID");
    let p2 = Routed::new(move |_, step, _| match step {
        0 => join("j1", json!([format!("agent-{kid}")])),
        _ => text("done"),
    });
    let (two, _) = run(&env, &p2, &no_approvals(), "TWO go");
    let r = results(&env, two);
    assert_eq!(r[0]["is_error"], true);
    assert!(!r[0]["content"].as_str().unwrap().contains("kid-secret-result"));
    assert!(r[0]["content"].as_str().unwrap().contains("belongs to this session"));
}

#[test]
fn the_number_of_children_running_at_once_is_capped() {
    let env = setup("cap", all_grants(), |c| c["subagents"] = json!({ "max_parallel": 1 }));
    let release = Arc::new(AtomicBool::new(false));
    let (r_set, r_wait) = (release.clone(), release.clone());
    let p = Routed::new(move |tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "FIRST hold", json!({})),
        ("ROOT", 1) => spawn_bg("s2", "SECOND hold", json!({})),
        ("ROOT", 2) => {
            r_set.store(true, Ordering::SeqCst);
            join("j1", json!([]))
        }
        ("ROOT", 3) => spawn_bg("s3", "THIRD go", json!({})),
        ("ROOT", 4) => join("j2", json!([])),
        ("ROOT", _) => text("done"),
        ("FIRST", _) => {
            waited(&r_wait, 8);
            text("first done")
        }
        _ => text("third done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let r = results(&env, parent);
    assert_eq!(r[0]["is_error"], false);
    assert_eq!(r[1]["is_error"], true);
    assert!(r[1]["content"].as_str().unwrap().contains("already running, the limit"), "{}", r[1]["content"]);
    // Once the first is collected there is room again.
    assert_eq!(r[3]["is_error"], false);
    assert_eq!(children(&env, parent).len(), 2);
}

#[test]
fn running_children_hold_back_budget_so_together_they_cannot_overspend() {
    let env = setup("reserve", all_grants(), |c| {
        c["session_budget"] = json!({ "max_steps": 40, "max_tokens": 1000, "max_cost_usd": 1000.0, "max_wall_secs": 600 });
        c["subagents"] = json!({ "max_parallel": 3, "child_budget": { "max_steps": 10, "max_tokens": 800, "max_cost_usd": 100.0, "max_wall_secs": 100 } });
    });
    let release = Arc::new(AtomicBool::new(false));
    let (r_set, r_wait) = (release.clone(), release.clone());
    let p = Routed::new(move |tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "ONE hold", json!({})),
        ("ROOT", 1) => spawn_bg("s2", "TWO hold", json!({})),
        ("ROOT", 2) => {
            r_set.store(true, Ordering::SeqCst);
            join("j1", json!([]))
        }
        ("ROOT", _) => text("done"),
        _ => {
            waited(&r_wait, 8);
            text("kid done")
        }
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    let spawns = kinds(&env, parent, "spawn");
    let (a, b) = (spawns[0]["budget"]["max_tokens"].as_u64().unwrap(), spawns[1]["budget"]["max_tokens"].as_u64().unwrap());
    assert_eq!(a, 800);
    // 1000 - what the parent has spent - what the first child may still spend.
    assert!(b > 0 && b <= 170, "second child got {b}");
    assert!(a + b <= 1000, "children together may not exceed the parent's allowance");
}

#[test]
fn a_session_cannot_finish_while_a_background_child_is_still_working() {
    let env = setup("not-yet", all_grants(), |_| {});
    let release = Arc::new(AtomicBool::new(false));
    let (r_set, r_wait) = (release.clone(), release.clone());
    let p = Routed::new(move |tag, step, call| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "KID slow", json!({})),
        ("ROOT", 1) => text("all done"), // tries to finish with the child still running
        ("ROOT", 2) => {
            assert!(call.last_user.contains("still running") && call.last_user.contains("join_agent"), "{}", call.last_user);
            r_set.store(true, Ordering::SeqCst);
            join("j1", json!([]))
        }
        ("ROOT", _) => text("now really done"),
        ("KID", _) => {
            waited(&r_wait, 8);
            text("kid result")
        }
        _ => text("?"),
    });
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    match out {
        Outcome::Completed { summary } => assert_eq!(summary, "now really done"),
        o => panic!("{o:?}"),
    }
    assert!(results(&env, parent)[1]["content"].as_str().unwrap().contains("kid result"));
}

#[test]
fn a_child_still_running_when_its_parent_stops_is_told_to_stop_and_waited_for() {
    // The parent runs out of steps while a child that never finishes is running.
    let env = setup("orphan", all_grants(), |c| {
        c["session_budget"] = json!({ "max_steps": 3, "max_tokens": 10000000, "max_cost_usd": 1000.0, "max_wall_secs": 600 });
        c["subagents"] = json!({ "child_budget": { "max_steps": 100000, "max_tokens": 100000000, "max_cost_usd": 100.0, "max_wall_secs": 600 } });
    });
    std::fs::write(env.ws.join("a.txt"), "x").unwrap();
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "LOOPER forever", json!({})),
        ("ROOT", n) => tool(&format!("r{n}"), "fs_read", json!({ "path": "a.txt" })),
        _ => {
            std::thread::sleep(Duration::from_millis(5));
            tool(&format!("l{}", rand_id()), "fs_read", json!({ "path": "a.txt" }))
        }
    });
    let started = Instant::now();
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(started.elapsed() < Duration::from_secs(30), "the session hung on its child");
    assert!(matches!(out, Outcome::Suspended { .. }), "{out:?}");
    let kid = child_named(&env, parent, "LOOPER");
    assert_eq!(env.store.status(kid).unwrap(), "interrupted");
    assert!(kinds(&env, parent, "note").iter().any(|n| n["text"].as_str().unwrap_or("").contains("still running; they were told to stop")));
}

fn rand_id() -> u64 {
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst) as u64
}

#[test]
fn cancel_stops_a_background_child_and_join_reports_it() {
    let env = setup("cancel", all_grants(), |c| {
        c["subagents"] = json!({ "child_budget": { "max_steps": 100000, "max_tokens": 100000000, "max_cost_usd": 100.0, "max_wall_secs": 600 } });
    });
    std::fs::write(env.ws.join("a.txt"), "x").unwrap();
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "LOOPER forever", json!({})),
        ("ROOT", 1) => tool("c1", "cancel_agent", json!({ "handle": "agent-2" })),
        ("ROOT", 2) => tool("c2", "cancel_agent", json!({ "handle": "agent-77" })),
        ("ROOT", 3) => join("j1", json!([])),
        ("ROOT", _) => text("done"),
        _ => {
            std::thread::sleep(Duration::from_millis(5));
            tool(&format!("l{}", rand_id()), "fs_read", json!({ "path": "a.txt" }))
        }
    });
    let (parent, out) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let r = results(&env, parent);
    assert_eq!(r[1]["is_error"], false);
    assert_eq!(r[2]["is_error"], true, "a handle that is not this session's is refused");
    assert!(r[3]["content"].as_str().unwrap().contains("interrupted"), "{}", r[3]["content"]);
    assert_eq!(env.store.status(child_named(&env, parent, "LOOPER")).unwrap(), "interrupted");
}

#[test]
fn a_background_child_cannot_widen_its_powers_and_its_denials_are_audited_under_its_own_session() {
    let env = setup("bg-narrow", all_grants(), |_| {});
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "KID write", json!({ "grants": [{ "capability": "fs:read" }] })),
        ("ROOT", 1) => join("j1", json!([])),
        ("ROOT", _) => text("done"),
        ("KID", 0) => tool("k1", "fs_write", json!({ "path": "bg.txt", "content": "x" })),
        _ => text("kid done"),
    });
    let (parent, _) = run(&env, &p, &no_approvals(), "ROOT go");
    assert!(!env.ws.join("bg.txt").exists());
    let kid = child_named(&env, parent, "KID");
    let rows = env.audit.rows().unwrap();
    let w = rows.iter().find(|r| r.entry.tool == "fs_write").unwrap();
    assert_eq!((w.entry.session_id, w.entry.decision.as_str()), (kid, "denied"));
    assert!(env.audit.verify().is_ok(), "the audit chain stays intact with parallel writers");
}

#[test]
fn parallel_children_that_need_the_owner_are_each_asked_and_each_answered_separately() {
    let env = setup("approvals", all_grants(), |_| {});
    let p = Routed::new(|tag, step, _| match (tag, step) {
        ("ROOT", 0) => spawn_bg("s1", "ONE shell", json!({ "grants": [{ "capability": "exec:shell" }] })),
        ("ROOT", 1) => spawn_bg("s2", "TWO shell", json!({ "grants": [{ "capability": "exec:shell" }] })),
        ("ROOT", 2) => join("j1", json!([])),
        ("ROOT", _) => text("done"),
        ("ONE", 0) => tool("k1", "shell_exec", json!({ "command": "touch one.txt" })),
        ("TWO", 0) => tool("k2", "shell_exec", json!({ "command": "touch two.txt" })),
        _ => text("kid done"),
    });
    // The scripted approver answers in the order requests arrive: allow the first, refuse the second.
    // Either child may ask first, so the assertion is that exactly one command ran.
    let approver = agent_core::runner::ScriptedApprover::new(vec![true, false]);
    let (_, out) = run(&env, &p, &approver, "ROOT go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let ran = ["one.txt", "two.txt"].iter().filter(|f| env.ws.join(f).exists()).count();
    assert_eq!(ran, 1, "one approved, one refused");
    assert_eq!(approver.requests.lock().unwrap().len(), 2);
    let sessions: std::collections::HashSet<i64> = approver.requests.lock().unwrap().iter().map(|r| r.session_id).collect();
    assert_eq!(sessions.len(), 2, "each request names its own session");
}
