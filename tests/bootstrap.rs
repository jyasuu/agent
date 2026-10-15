//! The bootstrap drill. Everything the agent does goes through its own tools (the sandboxed fs
//! plugin and the core tools), exactly as in a real session. Only the owner's steps use the
//! owner's commands. If the loop "write a capability, get it reviewed, use it" has a break,
//! this is where it shows.
mod common;
use agent_core::config::Config;
use agent_core::eval::{self, Regression};
use agent_core::provider::ScriptedProvider;
use agent_core::upgrade;
use common::*;
use serde_json::{json, Value};

fn have_bwrap() -> bool {
    if agent_core::sandbox::available() {
        true
    } else {
        eprintln!("skipped: bubblewrap is not installed here");
        false
    }
}

fn ok_verify(_: &Config) -> anyhow::Result<Vec<Regression>> {
    Ok(vec![])
}

fn grants() -> Value {
    let mut g = all_grants();
    for (cap, tier) in [("upgrade:propose", "reversible"), ("text:shout", "read_only")] {
        g.as_array_mut().unwrap().push(json!({ "capability": cap, "tier": tier }));
    }
    g
}

/// An env that looks like `agent init` output: the fs plugin runs in the sandbox.
fn env(name: &str) -> Env {
    let mut e = setup(name, grants(), |c| c["plugins"][0]["sandbox"] = json!({}));
    e.cfg.home = e.home.clone();
    e.cfg.seal();
    e
}

fn baseline(env: &Env) {
    let dir = env.home.join("evals").join("cases");
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..3 {
        let content = format!("value-{i}");
        let case = json!({
            "id": format!("case-{i}"), "task": "write a file",
            "script": [ { "call": { "tool": "fs_write", "input": { "path": "out.txt", "content": content } } }, { "say": "done" } ],
            "checks": [ { "type": "completed" }, { "type": "file_contains", "path": "out.txt", "text": content } ]
        });
        std::fs::write(dir.join(format!("case-{i}.json")), case.to_string()).unwrap();
    }
    let run = eval::run_all(&env.cfg, None).unwrap();
    assert!(run.failed().is_empty());
    eval::save_run(&env.home, &run).unwrap();
    eval::set_baseline(&env.home).unwrap();
}

const PLUGIN_PY: &str = r#"import sys, json
TOOLS = [{"name": "shout", "description": "Upper-case some text", "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}}, "capability": "text:shout", "scope_args": []}]
for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue
    method, rid = req.get("method"), req.get("id")
    if method == "manifest":
        out = {"id": rid, "result": {"tools": TOOLS}}
    elif method == "call":
        params = req.get("params") or {}
        if params.get("tool") == "shout":
            out = {"id": rid, "result": {"content": str((params.get("args") or {}).get("text", "")).upper(), "is_error": False}}
        else:
            out = {"id": rid, "result": {"content": "unknown tool", "is_error": True}}
    else:
        out = {"id": rid, "error": "unknown method"}
    print(json.dumps(out), flush=True)
"#;

fn plugin_json() -> String {
    json!({
        "name": "shouter", "runtime": "python3", "entry": "plugin.py",
        "tools": [{ "name": "shout", "description": "Upper-case some text", "input_schema": { "type": "object", "properties": { "text": { "type": "string" } } }, "capability": "text:shout", "scope_args": [] }]
    })
    .to_string()
}

#[test]
fn the_agent_can_write_propose_and_later_use_a_capability_it_did_not_have() {
    if !have_bwrap() { return; }
    let env = env("boot");
    baseline(&env);

    // Session 1, the agent: write the plugin with its own file tool, then propose it.
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/shouter/plugin.json", "content": plugin_json() })),
        tool("w2", "fs_write", json!({ "path": "dev/shouter/plugin.py", "content": PLUGIN_PY })),
        tool("p1", "propose_upgrade", json!({ "path": "dev/shouter" })),
        text("I wrote and proposed a plugin called shouter."),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "give yourself a tool that upper-cases text");
    assert!(matches!(out, agent_core::runner::Outcome::Completed { .. }));
    let res = results(&env, sid);
    assert!(res.iter().all(|r| r["is_error"] == false), "every step of the agent's own work succeeded: {res:?}");
    let proposed = env.store.list_upgrades().unwrap();
    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0].status, "proposed");
    assert!(upgrade::installed_plugins(&env.home).is_empty(), "the agent could not install it");

    // The owner: run the checks, read them, approve.
    let id = proposed[0].id;
    let status = upgrade::run_pipeline(&env.cfg, &env.store, &env.audit, id, &ok_verify).unwrap();
    assert_eq!(status, "ready_for_review", "{:?}", env.store.get_upgrade(id).unwrap().report);
    upgrade::approve(&env.cfg, &env.store, &env.audit, id, "owner", &ok_verify).unwrap();

    // Session 2, the agent again: the new capability is simply there.
    let p = ScriptedProvider::new(vec![tool("s1", "shout", json!({ "text": "bootstrapped" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "use the new tool");
    assert_eq!(results(&env, sid)[0]["content"], "BOOTSTRAPPED");
}


// ---- closing the loop: the agent can test its work and see how it went ----------------------

fn example_json() -> String {
    json!({
        "name": "example", "runtime": "python3", "entry": "plugin.py",
        "tools": [{ "name": "shout", "description": "Return the text in capital letters.", "input_schema": { "type": "object" }, "capability": "text:shout", "scope_args": [] }]
    })
    .to_string()
}

#[test]
fn the_example_the_agent_is_shown_really_passes_the_checks() {
    if !have_bwrap() { return; }
    // The guide embeds this exact script. If the checks ever stop accepting it, this fails,
    // so the documentation cannot quietly become wrong.
    let env = env("boot-example");
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/example/plugin.json", "content": example_json() })),
        tool("w2", "fs_write", json!({ "path": "dev/example/plugin.py", "content": upgrade::PLUGIN_EXAMPLE_PY })),
        tool("c1", "check_plugin", json!({ "path": "dev/example" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "check the documented example");
    let check = results(&env, sid).pop().unwrap();
    assert_eq!(check["is_error"], false, "{check}");
    assert!(check["content"].as_str().unwrap().contains("contract tests: passed"), "{check}");
}

#[test]
fn the_guide_carries_everything_needed_to_write_a_plugin_blind() {
    let g = upgrade::plugin_guide();
    for needle in ["plugin.json", "runtime", "entry", "capability", "scope_args", "\"method\":\"manifest\"", "\"method\":\"call\"", "is_error", "stdin", "sandbox", "text:shout", "exactly the tools"] {
        assert!(g.contains(needle), "the guide must mention {needle}");
    }
}

#[test]
fn the_agent_can_fix_its_own_plugin_from_the_findings_before_proposing() {
    if !have_bwrap() { return; }
    let env = env("boot-iterate");
    let broken = PLUGIN_PY.replace("for line in sys.stdin:", "for line in sys.stdin");
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/shouter/plugin.json", "content": plugin_json() })),
        tool("w2", "fs_write", json!({ "path": "dev/shouter/plugin.py", "content": broken })),
        tool("c1", "check_plugin", json!({ "path": "dev/shouter" })),
        tool("w3", "fs_write", json!({ "path": "dev/shouter/plugin.py", "content": PLUGIN_PY })),
        tool("c2", "check_plugin", json!({ "path": "dev/shouter" })),
        tool("p1", "propose_upgrade", json!({ "path": "dev/shouter" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "write a plugin and get it right");
    let r = results(&env, sid);
    assert_eq!(r[2]["is_error"], true, "the first check reports the mistake");
    assert!(r[2]["content"].as_str().unwrap().contains("syntax check failed"), "{}", r[2]);
    assert_eq!(r[4]["is_error"], false, "the second check passes");
    assert_eq!(r[5]["is_error"], false, "and only then does it propose");
    assert_eq!(env.store.list_upgrades().unwrap().len(), 1, "checking proposed nothing; only the final propose did");
    let leftovers: Vec<_> = std::fs::read_dir(env.home.join("upgrades")).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with(".check")).collect();
    assert!(leftovers.is_empty(), "the throwaway copies are removed");
}

#[test]
fn checking_and_status_need_the_same_grant_as_proposing() {
    let mut e = setup("boot-nogrant", all_grants(), |_| {});
    e.cfg.home = e.home.clone();
    let p = ScriptedProvider::new(vec![
        tool("c1", "check_plugin", json!({ "path": "dev/x" })),
        tool("s1", "upgrade_status", json!({})),
        text("done"),
    ]);
    let (sid, _) = run(&e, &p, &no_approvals(), "try without the grant");
    for r in results(&e, sid) {
        assert_eq!(r["is_error"], true);
        assert!(r["content"].as_str().unwrap().contains("DENIED"), "{r}");
    }
}

#[test]
fn the_agent_sees_what_is_wrong_with_its_own_code_through_upgrade_status() {
    if !have_bwrap() { return; }
    let env = env("boot-status");
    baseline(&env);
    let bad = PLUGIN_PY.replace("            out = {\"id\": rid, \"result\": {\"content\": \"unknown tool\", \"is_error\": True}}", "            sys.exit(3)");
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/shouter/plugin.json", "content": plugin_json() })),
        tool("w2", "fs_write", json!({ "path": "dev/shouter/plugin.py", "content": bad })),
        tool("p1", "propose_upgrade", json!({ "path": "dev/shouter" })),
        text("proposed"),
    ]);
    run(&env, &p, &no_approvals(), "write a fragile plugin");
    let id = env.store.list_upgrades().unwrap()[0].id;
    let before = ScriptedProvider::new(vec![tool("s0", "upgrade_status", json!({ "id": id })), text("ok")]);
    let (sid, _) = run(&env, &before, &no_approvals(), "how is it going");
    assert!(results(&env, sid)[0]["content"].as_str().unwrap().contains("has not run the checks"));

    assert_eq!(upgrade::run_pipeline(&env.cfg, &env.store, &env.audit, id, &ok_verify).unwrap(), "failed_contract");
    let after = ScriptedProvider::new(vec![tool("s1", "upgrade_status", json!({ "id": id })), text("ok")]);
    let (sid, _) = run(&env, &after, &no_approvals(), "how is it going now");
    let out = results(&env, sid)[0]["content"].as_str().unwrap().to_string();
    assert!(out.contains("failed_contract") && out.contains("unknown tool"), "it can see its own mistake: {out}");
    assert!(out.contains("propose again"), "{out}");
}

#[test]
fn the_agent_is_never_shown_the_owners_private_tests() {
    let env = env("boot-redact");
    let id = env.store.create_upgrade("shouter", 1, "abc123abc123abc123").unwrap();
    let report = json!({ "stages": [
        { "name": "static checks", "status": "passed", "findings": [] },
        { "name": "permission review", "status": "info", "findings": ["asks for: text:shout", "an internal note that is not for the agent"] },
        { "name": "contract tests", "status": "passed", "findings": [] },
        { "name": "eval gate", "status": "blocked", "findings": ["case-secret-billing: file out.txt missing"] },
        { "name": "canary", "status": "failed", "findings": ["fs_read {\"path\":\"payroll.txt\"}: old answered \"SALARIES: 123\", new answered \"\""] }
    ] });
    env.store.set_upgrade(id, "blocked_eval", &report).unwrap();
    let (out, _) = upgrade::status_for_agent(&env.store, &json!({ "id": id })).unwrap();
    for secret in ["case-secret-billing", "payroll.txt", "SALARIES", "internal note"] {
        assert!(!out.contains(secret), "'{secret}' must not reach the agent: {out}");
    }
    assert!(out.contains("eval gate: blocked") && out.contains("private evaluation suite"), "{out}");
    assert!(out.contains("canary: failed") && out.contains("details are not shown"), "{out}");
    assert!(out.contains("asks for: text:shout"), "what it asked for is its own business: {out}");
}
