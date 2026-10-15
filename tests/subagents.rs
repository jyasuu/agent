//! Stage 3, sub-agents. A child is a session with a narrower permission set, a fresh context
//! and a short result. Behavior only: sessions, logs, audit rows and approval requests.
mod common;
use agent_core::provider::ScriptedProvider;
use agent_core::runner::{Outcome, Runner, ScriptedApprover};
use agent_core::gate::Gate;
use agent_core::plugin::PluginHost;
use common::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

fn spawn(task: &str, grants: Value) -> agent_core::provider::ModelResponse {
    tool("s1", "spawn_agent", json!({ "task": task, "grants": grants }))
}

fn child_of(env: &Env, parent: i64) -> i64 {
    let kids: Vec<_> = env.store.list_sessions(50).unwrap().into_iter().filter(|r| r.parent_id == Some(parent)).collect();
    assert_eq!(kids.len(), 1, "expected exactly one child of session {parent}");
    kids[0].id
}

#[test]
fn a_child_holds_only_the_capabilities_it_was_given_and_starts_with_a_fresh_context() {
    let env = setup("narrow", all_grants(), |_| {});
    let p = ScriptedProvider::new(vec![
        spawn("write a file", json!([{ "capability": "fs:read" }])),
        tool("c1", "fs_write", json!({ "path": "child.txt", "content": "x" })),
        text("could not write"),
        text("all done"),
    ]);
    let (parent, out) = run(&env, &p, &no_approvals(), "PARENT-GOAL: organise things");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let child = child_of(&env, parent);

    assert!(!env.ws.join("child.txt").exists());
    let rows = env.audit.rows().unwrap();
    let denied = rows.iter().find(|r| r.entry.tool == "fs_write").expect("the child's write was audited");
    assert_eq!(denied.entry.decision, "denied");
    assert_eq!(denied.entry.session_id, child);

    // Fresh context: the child's first model call holds only its task, none of the parent's.
    let first_child_call = shown(&p, 1);
    assert!(first_child_call.contains("write a file"));
    assert!(!first_child_call.contains("PARENT-GOAL"));
    assert_eq!(p.seen.lock().unwrap()[1].len(), 1);

    let r = results(&env, parent);
    assert_eq!(r[0]["is_error"], false);
    assert!(r[0]["content"].as_str().unwrap().contains("could not write"));
    assert_eq!(env.store.status(child).unwrap(), "completed");
}

#[test]
fn a_child_cannot_be_given_a_capability_its_parent_does_not_hold() {
    let grants = json!([
        { "capability": "fs:read", "tier": "read_only" },
        { "capability": "agent:spawn", "tier": "reversible" }
    ]);
    let env = setup("expand", grants, |_| {});
    let p = ScriptedProvider::new(vec![
        spawn("write", json!([{ "capability": "fs:write" }])),
        spawn("shell", json!([{ "capability": "exec:shell" }])),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    for r in results(&env, parent) {
        assert_eq!(r["is_error"], true);
        assert!(r["content"].as_str().unwrap().contains("do not hold capability"), "{r}");
    }
    assert_eq!(env.store.list_sessions(10).unwrap().len(), 1, "no child session was created");
    let denials: Vec<_> = env.audit.rows().unwrap().into_iter()
        .filter(|r| r.entry.tool == "spawn_agent" && r.entry.decision == "denied").collect();
    assert_eq!(denials.len(), 2);
    assert!(denials.iter().all(|r| r.entry.reason.contains("do not hold capability")));
}

#[test]
fn a_child_can_be_narrowed_to_a_sub_path_but_never_widened() {
    let env = setup("scope", all_grants(), |_| {});
    std::fs::create_dir_all(env.ws.join("docs")).unwrap();
    std::fs::write(env.ws.join("docs/a.txt"), "in docs").unwrap();
    std::fs::write(env.ws.join("secret.txt"), "top secret").unwrap();
    let p = ScriptedProvider::new(vec![
        spawn("read docs", json!([{ "capability": "fs:read", "scope": "docs" }])),
        tool("c1", "fs_read", json!({ "path": "docs/a.txt" })),
        tool("c2", "fs_read", json!({ "path": "secret.txt" })),
        text("child done"),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    let child = child_of(&env, parent);
    let cr = results(&env, child);
    assert!(cr[0]["content"].as_str().unwrap().contains("in docs"));
    assert_eq!(cr[1]["is_error"], true);
    assert!(cr[1]["content"].as_str().unwrap().contains("outside the granted scope"));
    assert!(!cr[1]["content"].as_str().unwrap().contains("top secret"));

    // A parent that holds a capability only for docs/ cannot hand out the whole workspace.
    let grants = json!([
        { "capability": "fs:read", "tier": "read_only", "scope": "docs" },
        { "capability": "agent:spawn", "tier": "reversible" }
    ]);
    let env = setup("scope2", grants, |_| {});
    let p = ScriptedProvider::new(vec![
        spawn("read", json!([{ "capability": "fs:read", "scope": "." }])),
        spawn("read", json!([{ "capability": "fs:read", "scope": "../outside" }])),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    for r in results(&env, parent) {
        assert_eq!(r["is_error"], true);
        assert!(r["content"].as_str().unwrap().contains("outside the scope you hold"), "{r}");
    }
}

#[test]
fn only_a_short_result_returns_to_the_parent() {
    let env = setup("short", all_grants(), |_| {});
    let long = "z".repeat(10000);
    let p = ScriptedProvider::new(vec![
        spawn("be verbose", json!([])),
        text(&long),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    let child = child_of(&env, parent);
    let result = results(&env, parent)[0]["content"].as_str().unwrap().to_string();
    assert!(result.len() < 2200, "the parent got {} bytes", result.len());
    let full = kinds(&env, child, "final");
    assert_eq!(full[0]["text"].as_str().unwrap().len(), 10000, "the child's full answer stays in its own log");
    // And the parent's next model call does not contain it.
    assert!(shown(&p, 2).matches('z').count() < 2200);
}

#[test]
fn a_child_cannot_approve_anything_the_owner_is_asked_and_a_refusal_holds() {
    let env = setup("approve", all_grants(), |_| {});
    let p = ScriptedProvider::new(vec![
        spawn("run it", json!([{ "capability": "exec:shell" }])),
        tool("c1", "shell_exec", json!({ "command": "touch ran.txt" })),
        text("child done"),
        text("done"),
    ]);
    let approver = ScriptedApprover::new(vec![false]);
    let (parent, _) = run(&env, &p, &approver, "go");
    let child = child_of(&env, parent);

    let reqs = approver.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].session_id, child, "the request carries the child's session, and goes to the owner");
    assert_eq!(reqs[0].capability, "exec:shell");
    assert!(!env.ws.join("ran.txt").exists());
    let cr = results(&env, child);
    assert!(cr[0]["content"].as_str().unwrap().contains("owner did not approve"));
    assert!(decisions(&env).contains(&"shell_exec:rejected_by_owner".to_string()));
}

#[test]
fn a_child_cannot_start_children_unless_the_owner_allows_the_depth() {
    let env = setup("depth", all_grants(), |_| {});
    let p = ScriptedProvider::new(vec![
        // Even if the parent asks to pass agent:spawn down, the depth limit strips it.
        spawn("try", json!([{ "capability": "fs:read" }, { "capability": "agent:spawn" }])),
        tool("c1", "spawn_agent", json!({ "task": "grandchild", "grants": [] })),
        text("child done"),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    let child = child_of(&env, parent);
    let cr = results(&env, child);
    assert_eq!(cr[0]["is_error"], true);
    assert!(cr[0]["content"].as_str().unwrap().contains("not granted"));
    assert_eq!(env.store.list_sessions(10).unwrap().len(), 2);

    // With max_depth 2 the same call works one level down, and no further.
    let env = setup("depth2", all_grants(), |c| c["subagents"] = json!({ "max_depth": 2 }));
    let p = ScriptedProvider::new(vec![
        spawn("middle", json!([{ "capability": "agent:spawn" }])),
        tool("c1", "spawn_agent", json!({ "task": "leaf", "grants": [{ "capability": "agent:spawn" }] })),
        tool("g1", "spawn_agent", json!({ "task": "too deep", "grants": [] })),
        text("leaf done"),
        text("middle done"),
        text("done"),
    ]);
    let (_parent, out) = run(&env, &p, &no_approvals(), "go");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let all = env.store.list_sessions(10).unwrap();
    assert_eq!(all.len(), 3);
    let leaf = all.iter().find(|r| r.goal == "leaf").unwrap();
    assert_eq!(env.store.session_depth(leaf.id).unwrap(), 2);
    assert!(results(&env, leaf.id)[0]["content"].as_str().unwrap().contains("not granted"));
}

#[test]
fn the_number_of_children_per_session_is_capped() {
    let env = setup("cap", all_grants(), |c| c["subagents"] = json!({ "max_children_per_session": 2 }));
    let p = ScriptedProvider::new(vec![
        spawn("one", json!([])), text("a"),
        spawn("two", json!([])), text("b"),
        spawn("three", json!([])),
        text("done"),
    ]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    let r = results(&env, parent);
    assert_eq!(r[0]["is_error"], false);
    assert_eq!(r[1]["is_error"], false);
    assert_eq!(r[2]["is_error"], true);
    assert!(r[2]["content"].as_str().unwrap().contains("the limit"));
}

#[test]
fn a_childs_spend_comes_out_of_its_parents_budget() {
    // Each model call costs 15 tokens. The parent may use 40 in total, children included.
    let env = setup("budget", all_grants(), |c| {
        c["session_budget"] = json!({ "max_steps": 40, "max_tokens": 40, "max_cost_usd": 1000.0, "max_wall_secs": 600 });
    });
    std::fs::write(env.ws.join("a.txt"), "a").unwrap();
    let p = ScriptedProvider::new(vec![
        spawn("keep reading", json!([{ "capability": "fs:read" }])),   // parent call: 15
        tool("c1", "fs_read", json!({ "path": "a.txt" })),             // child call: 15
        tool("c2", "fs_read", json!({ "path": "a.txt" })),             // child call: 30 (its cap is the 25 left)
        // a fourth call would run out of script and show up as a model error
    ]);
    let (parent, out) = run(&env, &p, &no_approvals(), "go");
    match out {
        Outcome::Suspended { reason, .. } => assert!(reason.contains("token limit") && reason.contains("45/40"), "{reason}"),
        other => panic!("expected a suspension, got {other:?}"),
    }
    let child = child_of(&env, parent);
    assert_eq!(env.store.status(child).unwrap(), "suspended");
    assert_eq!(p.seen.lock().unwrap().len(), 3, "no model call happened after the budget was gone");
    let r = results(&env, parent);
    assert!(r[0]["content"].as_str().unwrap().contains("stopped before it finished"));
    let (tokens, _) = env.store.tree_spend(parent).unwrap();
    assert_eq!(tokens, 45);
}

#[test]
fn a_session_with_no_budget_left_cannot_spawn() {
    let env = setup("nobudget", all_grants(), |c| {
        c["session_budget"] = json!({ "max_steps": 40, "max_tokens": 10, "max_cost_usd": 1000.0, "max_wall_secs": 600 });
    });
    // The first call itself uses 15 tokens, which is already over 10, so the spawn is refused.
    let p = ScriptedProvider::new(vec![spawn("x", json!([])), text("never")]);
    let (parent, out) = run(&env, &p, &no_approvals(), "go");
    assert!(matches!(out, Outcome::Suspended { .. }), "{out:?}");
    assert!(results(&env, parent)[0]["content"].as_str().unwrap().contains("no budget left"));
    assert_eq!(env.store.list_sessions(10).unwrap().len(), 1);
}

#[test]
fn a_child_session_can_never_run_on_its_own() {
    let env = setup("orphan", all_grants(), |_| {});
    let (_e, parent) = env.store.enqueue_event("test", "go", "owner").unwrap();
    assert_eq!(env.store.claim_next().unwrap(), Some(parent));
    let child = env.store.create_child_session(parent, "t", "owner").unwrap();
    assert_eq!(env.store.status(child).unwrap(), "running");

    // A crash leaves both "running". On recovery the parent is requeued and the child is not.
    assert_eq!(env.store.recover_running().unwrap(), 1);
    assert_eq!(env.store.status(parent).unwrap(), "queued");
    assert_eq!(env.store.status(child).unwrap(), "suspended");
    assert!(!env.store.claim_session(child).unwrap());
    assert!(!env.store.requeue(child).unwrap());
    assert_eq!(env.store.claim_next().unwrap(), Some(parent));
    assert_eq!(env.store.claim_next().unwrap(), None);
    // Even a child forced into the queue is never handed to a worker.
    env.store.set_status(child, "queued").unwrap();
    assert!(!env.store.claim_session(child).unwrap());
    assert_eq!(env.store.claim_next().unwrap(), None);
    env.store.set_status(child, "suspended").unwrap();

    // Running it directly would hand it the root grants, so the runner refuses.
    let mut host = PluginHost::start(&env.cfg.plugins, &env.ws).unwrap();
    let gate = Gate::new(&env.ws, &env.cfg.grants, &[env.home.clone()]);
    let p = ScriptedProvider::new(vec![text("x")]);
    let a = no_approvals();
    let mut r = Runner { cfg: &env.cfg, store: &env.store, audit: &env.audit, provider: &p, approver: &a,
                         host: &mut host, gate: &gate, shutdown: None };
    let err = r.run_session(child).unwrap_err();
    assert!(format!("{err:#}").contains("only runs inside its parent"));
    assert!(p.seen.lock().unwrap().is_empty());
}

#[test]
fn a_crash_during_a_spawn_resumes_without_running_the_child_again() {
    let env = setup("crash", all_grants(), |_| {});
    // First run: the parent spawns, and the process "dies" while the child is mid-call.
    let (_e, parent) = env.store.enqueue_event("test", "go", "owner").unwrap();
    env.store.claim_next().unwrap();
    env.store.append_log(parent, "assistant", json!({ "content": [
        { "type": "tool_use", "id": "s1", "name": "spawn_agent", "input": { "task": "t", "grants": [] } } ] })).unwrap();
    let child = env.store.create_child_session(parent, "t", "owner").unwrap();
    env.store.recover_running().unwrap();

    let p = ScriptedProvider::new(vec![text("recovered")]);
    let out = run_with(&env, parent, &p, &no_approvals(), None).unwrap();
    assert!(matches!(out, Outcome::Completed { .. }));
    assert_eq!(env.store.list_sessions(10).unwrap().len(), 2, "no second child was started");
    assert_eq!(env.store.status(child).unwrap(), "suspended");
    let r = results(&env, parent);
    assert!(r[0]["content"].as_str().unwrap().contains("NOT re-run"));
}

#[test]
fn interrupting_the_parent_stops_its_running_child_too() {
    let env = setup("interrupt", all_grants(), |_| {});
    let store = &env.store;
    let p = Hook::new(
        vec![spawn("long task", json!([])), tool("c1", "fs_list", json!({ "path": "." })), text("never")],
        // On the child's first call, the owner interrupts the parent (session 1).
        |n, _| { if n == 1 { store.request_interrupt(1).unwrap(); } None },
    );
    let (parent, out) = run(&env, &p, &no_approvals(), "go");
    assert_eq!(parent, 1);
    assert!(matches!(out, Outcome::Interrupted), "{out:?}");
    let child = child_of(&env, parent);
    assert_eq!(env.store.status(child).unwrap(), "interrupted");
    assert_eq!(env.store.status(parent).unwrap(), "interrupted");
    assert!(results(&env, parent)[0]["content"].as_str().unwrap().contains("interrupted"));
}

#[test]
fn a_daemon_shutdown_pauses_the_parent_and_parks_the_child() {
    let env = setup("shutdown", all_grants(), |_| {});
    let flag = AtomicBool::new(false);
    let p = Hook::new(
        vec![spawn("long task", json!([])), tool("c1", "fs_list", json!({ "path": "." }))],
        |n, _| { if n == 1 { flag.store(true, Ordering::SeqCst); } None },
    );
    let (_e, parent) = env.store.enqueue_event("test", "go", "owner").unwrap();
    let out = run_with(&env, parent, &p, &no_approvals(), Some(&flag)).unwrap();
    assert!(matches!(out, Outcome::Paused), "{out:?}");
    assert_eq!(env.store.status(parent).unwrap(), "queued", "the parent resumes on the next start");
    let child = child_of(&env, parent);
    assert_eq!(env.store.status(child).unwrap(), "suspended", "the child is parked, never queued");
    assert_eq!(env.store.claim_next().unwrap(), Some(parent));
    assert_eq!(env.store.claim_next().unwrap(), None);
}

#[test]
fn the_parent_waits_so_concurrency_stays_at_one_session_per_worker() {
    // The child runs inside the parent's runner call, so while it works its parent is blocked
    // and the pair occupies one worker slot. Observable as: spawn's tool result arrives only
    // after the child finished, and the child finished before the parent's next model call.
    let env = setup("blocking", all_grants(), |_| {});
    let p = ScriptedProvider::new(vec![spawn("x", json!([])), text("child result"), text("parent done")]);
    let (parent, _) = run(&env, &p, &no_approvals(), "go");
    let child = child_of(&env, parent);
    assert_eq!(env.store.status(child).unwrap(), "completed");
    assert!(shown(&p, 2).contains("child result"));
}

#[test]
fn narrowing_a_grant_to_a_sub_path_keeps_its_tier() {
    // The parent holds fs:write as irreversible, so every write needs the owner. A child narrowed
    // to docs/ must not end up with a lower tier and write without asking.
    let grants = json!([
        { "capability": "fs:write", "tier": "irreversible" },
        { "capability": "agent:spawn", "tier": "reversible" }
    ]);
    let env = setup("tier", grants, |_| {});
    let p = ScriptedProvider::new(vec![
        spawn("write in docs", json!([{ "capability": "fs:write", "scope": "docs" }])),
        tool("c1", "fs_write", json!({ "path": "docs/x.txt", "content": "hi" })),
        text("child done"),
        text("done"),
    ]);
    let approver = ScriptedApprover::new(vec![true]);
    let (parent, _) = run(&env, &p, &approver, "go");
    let child = child_of(&env, parent);
    let reqs = approver.requests.lock().unwrap();
    assert_eq!(reqs.len(), 1, "the child's write still went to the owner");
    assert_eq!(reqs[0].session_id, child);
    assert_eq!(std::fs::read_to_string(env.ws.join("docs/x.txt")).unwrap(), "hi");
}
