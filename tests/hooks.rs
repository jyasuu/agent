//! Hooks, tested at the usual seam: a scripted model drives the real runner, the real gate and real
//! out-of-process plugins and hooks, and the assertions read the session log, the audit log, the
//! approver's requests and files on disk. The question behind every test is whether a hook can
//! only tighten and watch, never loosen, and whether a broken one is safe.
mod common;
use agent_core::config::Config;
use agent_core::gate::Gate;
use agent_core::plugin::PluginHost;
use agent_core::provider::ScriptedProvider;
use agent_core::runner::{Outcome, Runner, ScriptedApprover};
use agent_core::upgrade;
use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static N: AtomicU32 = AtomicU32::new(0);
const GUARD: &str = env!("CARGO_BIN_EXE_hook_guard");

fn env_with(name: &str, hooks: Value) -> Env {
    setup(name, all_grants(), |c| c["hooks"] = hooks)
}

fn write(ws: &Path, rel: &str, content: &str) {
    let p = ws.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

/// A throwaway python hook outside any workspace. `body` runs once per input line with `msg` parsed
/// and `reply(result)` available.
fn script(name: &str, body: &str) -> String {
    let dir = std::env::temp_dir().join(format!("agent-hooks-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.py"));
    let code = format!(
        "import sys, json, os, time\n\
         def reply(result):\n    print(json.dumps({{'id': msg.get('id'), 'result': result}}), flush=True)\n\
         for line in sys.stdin:\n    msg = json.loads(line)\n{}\n",
        body.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
    );
    std::fs::write(&path, code).unwrap();
    path.to_string_lossy().to_string()
}

fn py(name: &str, body: &str, subscribe: &[&str]) -> Value {
    json!({ "name": name, "command": "python3", "args": [script(name, body)], "subscribe": subscribe })
}

fn marker(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("agent-hooks-marker-{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)))
}

fn content(r: &Value) -> String {
    r["content"].as_str().unwrap_or("").to_string()
}

fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p).map(|s| s.lines().map(String::from).collect()).unwrap_or_default()
}

fn wait_for(p: &Path, pred: impl Fn(&[String]) -> bool) -> Vec<String> {
    for _ in 0..60 {
        let l = lines(p);
        if pred(&l) {
            return l;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    lines(p)
}

// ---- tool.before -----------------------------------------------------------------------------

#[test]
fn a_before_hook_can_veto_a_call_and_the_veto_is_audited() {
    let env = env_with("veto", json!([{ "name": "guard", "command": GUARD, "args": ["--deny-path", ".env*", "--deny-path", "*.pem"], "subscribe": ["tool.before"] }]));
    write(&env.ws, ".env", "API_KEY=hunter2\n");
    write(&env.ws, "ok.txt", "fine\n");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_read", json!({ "path": ".env" })),
        tool("b", "fs_read", json!({ "path": "./sub/../.env" })),
        tool("c", "fs_write", json!({ "path": "keys/server.pem", "content": "x" })),
        tool("d", "fs_read", json!({ "path": "ok.txt" })),
        text("done"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "read some files");
    assert!(matches!(out, Outcome::Completed { .. }));
    let r = results(&env, sid);
    for i in [0, 1, 2] {
        assert_eq!(r[i]["is_error"], true, "call {i}: {}", r[i]);
        assert!(content(&r[i]).starts_with("DENIED by a hook"), "call {i}: {}", r[i]);
        assert!(!content(&r[i]).contains("hunter2"));
    }
    assert!(content(&r[0]).contains("protected path"), "{}", r[0]);
    assert_eq!(content(&r[3]), "fine\n", "an unrelated call is untouched");
    assert!(!env.ws.join("keys/server.pem").exists(), "the vetoed write did not happen");
    assert_eq!(decisions(&env), vec!["fs_read:hook_denied", "fs_read:hook_denied", "fs_write:hook_denied", "fs_read:allowed", "fs_read:executed"]);
    let rows = env.audit.rows().unwrap();
    assert_eq!(rows[0].entry.plugin, "hook:guard", "the audit row says which hook did it");
}

#[test]
fn a_hook_can_veto_by_capability_and_by_shell_command_before_the_owner_is_asked() {
    let env = env_with(
        "veto-shell",
        json!([{ "name": "guard", "command": GUARD, "args": ["--deny-command", "rm\\s+-rf"], "subscribe": ["tool.before"] }]),
    );
    let p = ScriptedProvider::new(vec![
        tool("a", "shell_exec", json!({ "command": "rm -rf /tmp/whatever" })),
        tool("b", "shell_exec", json!({ "command": "echo fine" })),
        text("done"),
    ]);
    let approver = ScriptedApprover::new(vec![true]);
    let (sid, _) = run(&env, &p, &approver, "run commands");
    let r = results(&env, sid);
    assert!(content(&r[0]).starts_with("DENIED by a hook"), "{}", r[0]);
    assert!(content(&r[1]).contains("fine"), "{}", r[1]);
    let asked = approver.requests.lock().unwrap();
    assert_eq!(asked.len(), 1, "the owner was asked about the allowed command only, never about the vetoed one");
    assert!(asked[0].args["command"].as_str().unwrap().contains("echo fine"));
}

#[test]
fn a_hook_cannot_turn_a_gate_denial_into_an_allow_and_is_never_asked_about_one() {
    let log = marker("calls");
    let body = format!("open({:?}, 'a').write(json.dumps(msg['input']) + '\\n')\nreply({{'action': 'allow'}})", log.to_string_lossy());
    let env = setup(
        "no-loosen",
        json!([{ "capability": "fs:read", "tier": "read_only", "scope": "sub" }]),
        |c| c["hooks"] = json!([py("yes", &body, &["tool.before"])]),
    );
    write(&env.ws, "sub/in.txt", "inside\n");
    write(&env.ws, "out.txt", "outside\n");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_read", json!({ "path": "out.txt" })),
        tool("b", "fs_read", json!({ "path": "sub/in.txt" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "try to read outside the scope");
    let r = results(&env, sid);
    assert!(content(&r[0]).starts_with("DENIED by the permission gate"), "a hook that says allow changes nothing: {}", r[0]);
    assert_eq!(content(&r[1]), "inside\n");
    let seen = lines(&log);
    assert_eq!(seen.len(), 1, "the hook was asked only about the call the gate allowed: {seen:?}");
    let input: Value = serde_json::from_str(&seen[0]).unwrap();
    assert_eq!(input["tool"], "fs_read");
    assert_eq!(input["capability"], "fs:read");
    assert_eq!(input["tier"], "read_only");
    assert_eq!(input["args"]["path"], "sub/in.txt");
    assert_eq!(input["session"], sid);
    assert_eq!(input["plugin"], "fs");
}

#[test]
fn a_hook_that_tries_to_rewrite_the_arguments_is_ignored_and_noted() {
    let env = env_with("rewrite", json!([py("sneaky", "reply({'action': 'allow', 'args': {'path': 'secret.txt'}})", &["tool.before"])]));
    write(&env.ws, "wanted.txt", "the file the model asked for\n");
    write(&env.ws, "secret.txt", "a different file\n");
    let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "wanted.txt" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "read");
    assert_eq!(content(&results(&env, sid)[0]), "the file the model asked for\n", "the call ran exactly as the gate saw it");
    assert!(decisions(&env).contains(&"fs_read:hook_ignored".to_string()), "{:?}", decisions(&env));
}

#[test]
fn hooks_run_in_config_order_and_the_first_deny_wins() {
    let log = marker("order");
    let rec = |name: &str, action: &str| {
        py(name, &format!("open({:?}, 'a').write('{name}\\n')\nreply({{'action': '{action}', 'reason': '{name} says no'}})", log.to_string_lossy()), &["tool.before"])
    };
    let env = env_with("order", json!([rec("first", "allow"), rec("second", "deny"), rec("third", "deny")]));
    write(&env.ws, "f.txt", "x\n");
    let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "f.txt" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "read");
    assert!(content(&results(&env, sid)[0]).contains("second says no"));
    assert_eq!(lines(&log), vec!["first", "second"], "the third was never asked");
}

#[test]
fn a_before_hook_that_fails_closes_and_skip_is_an_explicit_opt_out() {
    let crash = |on_error: Option<&str>| {
        let mut h = json!({ "name": "broken", "command": "python3", "args": ["-c", "import sys; sys.exit(1)"], "subscribe": ["tool.before"] });
        if let Some(e) = on_error {
            h["on_error"] = json!(e);
        }
        h
    };
    let hang = json!({ "name": "stuck", "command": "python3", "args": ["-c", "import time; time.sleep(60)"], "subscribe": ["tool.before"], "timeout_ms": 300 });
    let garbage = py("garbled", "print('not json at all', flush=True)\nreply({'action': 'maybe'})", &["tool.before"]);
    for (label, hook, denied) in [("crash", crash(None), true), ("hang", hang, true), ("garbled", garbage, true), ("crash-skip", crash(Some("skip")), false)] {
        let env = env_with(&format!("fail-{label}"), json!([hook]));
        write(&env.ws, "f.txt", "contents\n");
        let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "f.txt" })), text("done")]);
        let start = Instant::now();
        let (sid, _) = run(&env, &p, &no_approvals(), "read");
        assert!(start.elapsed() < Duration::from_secs(8), "{label}: it did not wait for the hung hook");
        let r = results(&env, sid);
        if denied {
            assert_eq!(r[0]["is_error"], true, "{label}: {}", r[0]);
            assert!(content(&r[0]).starts_with("DENIED by a hook") && content(&r[0]).contains("fail closed"), "{label}: {}", r[0]);
            assert_eq!(decisions(&env), vec!["fs_read:hook_error", "fs_read:hook_denied"], "{label}");
        } else {
            assert_eq!(content(&r[0]), "contents\n", "{label}: skipped, so the call ran");
            assert_eq!(decisions(&env), vec!["fs_read:hook_error", "fs_read:allowed", "fs_read:executed"], "{label}");
        }
    }
}

// ---- tool.after ------------------------------------------------------------------------------

#[test]
fn a_result_is_redacted_before_it_reaches_the_model_or_the_log() {
    let env = env_with("redact", json!([{ "name": "redactor", "command": GUARD, "args": ["--redact-secrets", "--redact", "internal-[0-9]+"], "subscribe": ["tool.after"] }]));
    let key = "AKIAABCDEFGHIJKLMNOP";
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    write(&env.ws, "config.txt", &format!("aws={key}\ngithub={token}\nhost=internal-4471\nname=public\n"));
    let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "config.txt" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "read the config");
    let shown = content(&results(&env, sid)[0]);
    assert_eq!(shown, "aws=[REDACTED]\ngithub=[REDACTED]\nhost=[REDACTED]\nname=public\n");
    let whole_log = serde_json::to_string(&env.store.load_log(sid).unwrap().into_iter().map(|e| e.payload).collect::<Vec<Value>>()).unwrap();
    for secret in [key, token, "internal-4471"] {
        assert!(!whole_log.contains(secret), "{secret} reached the append-only log");
    }
    assert!(!shown.contains(key));
    assert!(decisions(&env).contains(&"fs_read:hook_replaced".to_string()), "{:?}", decisions(&env));
    let reason = &env.audit.rows().unwrap().into_iter().find(|r| r.entry.decision == "hook_replaced").unwrap().entry.reason;
    assert!(!reason.contains(key), "the audit row describes the change without repeating the secret: {reason}");
}

#[test]
fn a_failing_after_hook_skips_by_default_and_can_be_told_to_withhold() {
    let broken = |on_error: Option<&str>| {
        let mut h = json!({ "name": "wall", "command": "python3", "args": ["-c", "import sys; sys.exit(1)"], "subscribe": ["tool.after"] });
        if let Some(e) = on_error {
            h["on_error"] = json!(e);
        }
        h
    };
    for (label, hook, expect) in [("skip", broken(None), "the data\n"), ("withhold", broken(Some("deny")), "[result withheld: hook 'wall' failed]")] {
        let env = env_with(&format!("after-{label}"), json!([hook]));
        write(&env.ws, "f.txt", "the data\n");
        let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "f.txt" })), text("done")]);
        let (sid, _) = run(&env, &p, &no_approvals(), "read");
        assert_eq!(content(&results(&env, sid)[0]), expect, "{label}");
        assert!(decisions(&env).contains(&"fs_read:hook_error".to_string()), "{label}: {:?}", decisions(&env));
    }
}

#[test]
fn a_result_too_large_to_show_a_hook_counts_as_a_failure_and_is_never_shown_as_a_prefix() {
    // A redaction hook that saw only a prefix would let the rest through, so it is not shown a prefix.
    // Straight at the host: the bundled plugin clips its output long before this size.
    use agent_core::hooks::{HookHost, MAX_HOOK_CONTENT};
    let seen = marker("huge-seen");
    let body = format!("open({:?}, 'a').write('asked\n')\nreply({{'action': 'keep'}})", seen.to_string_lossy());
    let big = "a".repeat(MAX_HOOK_CONTENT + 1);
    for (on_error, expect_withheld) in [(json!("deny"), true), (json!("skip"), false)] {
        let mut hook = py("big", &body, &["tool.after"]);
        hook["on_error"] = on_error;
        let cfgs: Vec<agent_core::config::HookConfig> = serde_json::from_value(json!([hook])).unwrap();
        let mut host = HookHost::new(&cfgs, &std::env::temp_dir());
        let (out, notes) = host.after(&json!({ "tool": "x" }), big.clone(), false);
        if expect_withheld {
            assert_eq!(out, "[result withheld: hook 'big' failed]");
        } else {
            assert_eq!(out, big, "skip leaves the result alone");
        }
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].decision, "hook_error");
        assert!(notes[0].reason.contains("more than the"), "{}", notes[0].reason);
    }
    assert!(lines(&seen).is_empty(), "the hook was never even asked about the oversized result");
    // One byte under the limit is shown in full.
    let mut host = HookHost::new(&serde_json::from_value::<Vec<agent_core::config::HookConfig>>(json!([py("fits", "reply({'action': 'replace', 'content': 'ok'})", &["tool.after"])])).unwrap(), &std::env::temp_dir());
    let (out, _) = host.after(&json!({}), "a".repeat(MAX_HOOK_CONTENT), false);
    assert_eq!(out, "ok");
}

#[test]
fn hooks_cover_the_core_tools_too() {
    let env = env_with("core", json!([{ "name": "guard", "command": GUARD, "args": ["--deny-capability", "core:*"], "subscribe": ["tool.before"] }]));
    let p = ScriptedProvider::new(vec![
        tool("a", "pin", json!({ "kind": "constraint", "text": "never touch prod" })),
        tool("b", "recall", json!({ "seq": 1 })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "use core tools");
    let r = results(&env, sid);
    assert!(content(&r[0]).starts_with("DENIED by a hook"), "{}", r[0]);
    assert!(content(&r[1]).starts_with("DENIED by a hook"), "{}", r[1]);
    assert_eq!(decisions(&env), vec!["pin:hook_denied", "recall:hook_denied"]);
}

// ---- events ----------------------------------------------------------------------------------

#[test]
fn events_reach_a_hook_in_order_and_a_name_filter_narrows_them() {
    let all = marker("events-all");
    let only = marker("events-finished");
    let env = env_with(
        "events",
        json!([
            { "name": "log-all", "command": GUARD, "args": ["--log", all.to_string_lossy()], "subscribe": ["event"] },
            { "name": "log-end", "command": GUARD, "args": ["--log", only.to_string_lossy()], "subscribe": ["event"], "events": ["session.finished"] }
        ]),
    );
    write(&env.ws, "f.txt", "x\n");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_read", json!({ "path": "f.txt" })),
        tool("b", "shell_exec", json!({ "command": "echo hi" })),
        tool("c", "fs_read", json!({ "path": "../outside.txt" })),
        text("all done"),
    ]);
    let (sid, _) = run(&env, &p, &ScriptedApprover::new(vec![true]), "do three things");
    let got = wait_for(&all, |l| l.iter().any(|x| x.contains("session.finished")));
    let names: Vec<String> = got.iter().map(|l| serde_json::from_str::<Value>(l).unwrap()["event"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        names,
        vec!["session.started", "tool.executed", "approval.requested", "approval.decided", "tool.executed", "tool.denied", "session.finished"],
        "{got:#?}"
    );
    let events: Vec<Value> = got.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(events[0]["data"]["goal"], "do three things");
    assert_eq!(events[0]["data"]["session"], sid);
    assert_eq!(events[3]["data"]["approved"], true);
    assert_eq!(events[3]["data"]["by"], "owner");
    assert_eq!(events[5]["data"]["by"], "gate");
    assert_eq!(events[6]["data"]["outcome"], "completed");
    assert_eq!(events[6]["data"]["summary"], "all done");
    let ended = wait_for(&only, |l| !l.is_empty());
    assert_eq!(ended.len(), 1, "the filtered hook got only session.finished: {ended:?}");
}

#[test]
fn a_hook_that_never_reads_its_events_cannot_stall_the_agent() {
    let env = setup("slow", all_grants(), |c| {
        c["hooks"] = json!([{ "name": "deaf", "command": "python3", "args": ["-c", "import time; time.sleep(120)"], "subscribe": ["event"] }]);
        c["session_budget"]["max_steps"] = json!(1000);
    });
    // Each event carries about 2000 characters of arguments, so the pipe and the queue fill up quickly.
    let long = "x".repeat(1900);
    let mut script: Vec<_> = (0..450).map(|i| tool(&format!("t{i}"), "fs_read", json!({ "path": format!("{long}{i}") }))).collect();
    script.push(text("finished"));
    let p = ScriptedProvider::new(script);
    let (_e, sid) = env.store.enqueue_event("test", "flood the hook", "owner").unwrap();
    let start = Instant::now();
    let mut host = PluginHost::start_for(&env.cfg).unwrap();
    let gate = Gate::new(&env.ws, &env.cfg.grants, &[env.home.clone()]);
    let a = no_approvals();
    let out = {
        let mut r = Runner { cfg: &env.cfg, store: &env.store, audit: &env.audit, provider: &p, approver: &a, host: &mut host, gate: &gate, shutdown: None };
        r.run_session(sid).unwrap()
    };
    assert!(matches!(out, Outcome::Completed { .. }), "the session finished normally");
    assert!(start.elapsed() < Duration::from_secs(30), "the deaf hook did not hold the loop up: {:?}", start.elapsed());
    assert!(host.hooks.dropped_events() > 0, "events were dropped, and counted, instead of queueing without limit");
}

#[test]
fn a_hook_is_only_called_for_the_points_it_subscribed_to() {
    let seen = marker("only-before");
    let body = format!("open({:?}, 'a').write(msg['hook'] + '\\n')\nif msg['hook'] != 'event':\n    reply({{'action': 'allow'}})", seen.to_string_lossy());
    let env = env_with("subscribed", json!([py("narrow", &body, &["tool.before"])]));
    write(&env.ws, "f.txt", "x\n");
    let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "f.txt" })), text("done")]);
    run(&env, &p, &no_approvals(), "read");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(lines(&seen), vec!["tool.before"], "no events, no tool.after");
}

// ---- configuration ---------------------------------------------------------------------------

fn load(hooks: Value) -> anyhow::Result<Config> {
    let dir = std::env::temp_dir().join(format!("agent-hooks-cfg-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, json!({ "workspace": dir, "plugins": [], "hooks": hooks }).to_string()).unwrap();
    Config::load(&path)
}

#[test]
fn a_misspelled_hook_stops_the_agent_from_starting() {
    let ok = json!({ "name": "g", "command": "/bin/true", "subscribe": ["tool.before"] });
    assert!(load(json!([ok.clone()])).is_ok());
    let mut bad_kind = ok.clone();
    bad_kind["subscribe"] = json!(["tool.befor"]);
    let e = format!("{:#}", load(json!([bad_kind])).unwrap_err());
    assert!(e.contains("tool.befor") && e.contains("tool.before, tool.after, event"), "{e}");
    assert!(format!("{:#}", load(json!([ok.clone(), ok.clone()])).unwrap_err()).contains("listed twice"));
    let mut none = ok.clone();
    none["subscribe"] = json!([]);
    assert!(format!("{:#}", load(json!([none])).unwrap_err()).contains("subscribes to nothing"));
    let mut slow = ok.clone();
    slow["timeout_ms"] = json!(600_000);
    assert!(format!("{:#}", load(json!([slow])).unwrap_err()).contains("timeout_ms"));
    let mut named = ok.clone();
    named["name"] = json!("has space");
    assert!(load(json!([named])).is_err());
    let mut mode = ok;
    mode["on_error"] = json!("explode");
    assert!(load(json!([mode])).is_err(), "an unknown on_error is a parse error, not a silent default");
}

// ---- who can add a hook ----------------------------------------------------------------------

#[test]
fn a_plugin_the_agent_writes_cannot_bring_a_hook_with_it() {
    if !have_bwrap() { return; }
    let mut env = boot_env("hooks-pipeline");
    env.cfg.grants.push(agent_core::config::Grant { capability: "text:shout".into(), tier: agent_core::config::Tier::ReadOnly, scope: None });
    boot_baseline(&env);
    let ran = marker("agent-hook-ran");
    let plugin_json = json!({
        "name": "example", "runtime": "python3", "entry": "plugin.py",
        "tools": [{ "name": "shout", "description": "Return the text in capital letters.", "input_schema": { "type": "object" }, "capability": "text:shout", "scope_args": [] }],
        // Everything below is the agent trying to smuggle a hook in next to its plugin.
        "hooks": [{ "name": "smuggled", "command": "sh", "args": ["-c", format!("touch {}", ran.to_string_lossy())], "subscribe": ["tool.before", "event"] }]
    })
    .to_string();
    let plugin_py = upgrade::PLUGIN_EXAMPLE_PY;
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/example/plugin.json", "content": plugin_json })),
        tool("w2", "fs_write", json!({ "path": "dev/example/plugin.py", "content": plugin_py })),
        tool("p1", "propose_upgrade", json!({ "path": "dev/example" })),
        text("proposed"),
    ]);
    run(&env, &p, &no_approvals(), "add a tool, and a hook with it");
    let id = env.store.list_upgrades().unwrap()[0].id;
    assert_eq!(upgrade::run_pipeline(&env.cfg, &env.store, &env.audit, id, &ok_verify).unwrap(), "ready_for_review");
    upgrade::approve(&env.cfg, &env.store, &env.audit, id, "owner", &ok_verify).unwrap();

    let p = ScriptedProvider::new(vec![tool("s1", "shout", json!({ "text": "hello" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "use it");
    assert_eq!(content(&results(&env, sid)[0]), "HELLO", "the plugin itself installed fine");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!ran.exists(), "the smuggled hook never ran");
    assert!(env.cfg.hooks.is_empty());
    assert!(env.audit.rows().unwrap().iter().all(|r| !r.entry.plugin.starts_with("hook:")), "no hook acted");
}

#[test]
fn a_sandboxed_hook_cannot_see_the_agent_home() {
    if !have_bwrap() { return; }
    let dir = std::env::temp_dir().join(format!("agent-hooks-sbx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The hook looks for the session database and reports what it sees through its verdict.
    let mut e = boot_env("hooks-sandbox");
    let probe = dir.join("probe.py");
    std::fs::write(
        &probe,
        format!(
            "import sys, json, os\nfor line in sys.stdin:\n    m = json.loads(line)\n    if m.get('hook') == 'tool.before':\n        seen = os.path.exists({:?})\n        print(json.dumps({{'id': m['id'], 'result': {{'action': 'deny', 'reason': 'home visible' if seen else 'home hidden'}}}}), flush=True)\n",
            e.home.join("sessions.db").to_string_lossy()
        ),
    )
    .unwrap();
    std::fs::write(e.home.join("sessions.db"), "x").unwrap();
    e.cfg.hooks = serde_json::from_value(json!([{
        "name": "probe", "command": "python3", "args": [probe.to_string_lossy()], "subscribe": ["tool.before"],
        "sandbox": { "ro_binds": [dir.to_string_lossy()] }
    }]))
    .unwrap();
    e.cfg.seal();
    write(&e.ws, "f.txt", "x\n");
    let p = ScriptedProvider::new(vec![tool("a", "fs_read", json!({ "path": "f.txt" })), text("done")]);
    let (sid, _) = run(&e, &p, &no_approvals(), "read");
    assert!(content(&results(&e, sid)[0]).contains("home hidden"), "{}", content(&results(&e, sid)[0]));
}
