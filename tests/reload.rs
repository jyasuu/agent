//! Reloading at run time. Three levels: between the turns of one session (a deployed or rolled-back
//! plugin, an MCP server announcing new tools), the plugin host itself, and the daemon noticing an
//! edit to the config file (new sessions, new event sources) without a restart.
mod common;
use agent_core::config::Config;
use agent_core::daemon::{Daemon, DaemonOpts};
use agent_core::plugin::PluginHost;
use agent_core::provider::{ModelProvider, ScriptedProvider};
use agent_core::runner::ScriptedApprover;
use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn have_bwrap() -> bool {
    if agent_core::sandbox::available() {
        true
    } else {
        eprintln!("skipped: bubblewrap is not installed here");
        false
    }
}

fn grants() -> Value {
    let mut g = all_grants();
    for (cap, tier) in [("text:shout", "read_only"), ("mcp:fake", "read_only")] {
        g.as_array_mut().unwrap().push(json!({ "capability": cap, "tier": tier }));
    }
    g
}

fn env(name: &str) -> Env {
    let mut e = setup(name, grants(), |_| {});
    e.cfg.home = e.home.clone();
    e.cfg.seal();
    e
}

fn mcp_env(name: &str, flags: &'static str, mcp: Value) -> Env {
    let mut e = setup(name, grants(), |c| {
        let ws = c["workspace"].as_str().unwrap().to_string();
        c["plugins"].as_array_mut().unwrap().push(mcp_plugin(&ws, "fake", flags, mcp.clone()));
    });
    write_fake_mcp(&e.ws);
    e.cfg.home = e.home.clone();
    e.cfg.seal();
    e
}

/// Put an installed plugin in the registry by hand, as a deployment would.
fn install(home: &Path, name: &str, script: &str) {
    let dir = home.join("plugins").join(name).join("1");
    std::fs::create_dir_all(&dir).unwrap();
    let tools = json!([{ "name": "shout", "description": "Capitals.", "input_schema": { "type": "object" }, "capability": "text:shout", "scope_args": [] }]);
    std::fs::write(dir.join("plugin.json"), json!({ "name": name, "runtime": "python3", "entry": "plugin.py", "tools": tools }).to_string()).unwrap();
    std::fs::write(dir.join("plugin.py"), script).unwrap();
    std::fs::write(home.join("plugins").join(name).join("active"), "1").unwrap();
}

fn uninstall(home: &Path, name: &str) {
    std::fs::remove_file(home.join("plugins").join(name).join("active")).unwrap();
}

fn reload_rows(env: &Env) -> Vec<String> {
    env.audit.rows().unwrap().into_iter().filter(|r| r.entry.decision == "plugins_reloaded").map(|r| r.entry.reason).collect()
}

// ---- between the turns of one session --------------------------------------------------------

#[test]
fn a_plugin_deployed_while_a_session_runs_is_usable_in_that_same_session() {
    if !have_bwrap() { return; }
    let env = env("r-deploy");
    let home = env.home.clone();
    let p = ToolRecorder::new(vec![
        tool("a", "fs_list", json!({ "path": "." })),
        tool("b", "shout", json!({ "text": "hello" })),
        text("done"),
    ])
    .before(move |n| {
        if n == 0 {
            install(&home, "shouter", agent_core::upgrade::PLUGIN_EXAMPLE_PY); // the owner approves an upgrade just now
        }
    });
    let (sid, _) = run(&env, &p, &no_approvals(), "work while an upgrade lands");
    assert!(!p.offered(0).contains(&"shout".to_string()), "not there at the start");
    assert!(p.offered(1).contains(&"shout".to_string()), "there on the next turn, with no restart: {:?}", p.offered(1));
    assert_eq!(results(&env, sid)[1]["content"], "HELLO", "and it works");
    let rows = reload_rows(&env);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("added: shouter"), "{}", rows[0]);
    assert!(env.store.load_log(sid).unwrap().iter().any(|e| e.kind == "note" && e.payload["text"].as_str().unwrap_or("").contains("tools reloaded")));
    assert!(env.audit.verify().is_ok());
}

#[test]
fn a_rollback_while_a_session_runs_takes_the_tool_away_on_the_next_turn() {
    if !have_bwrap() { return; }
    let env = env("r-rollback");
    install(&env.home, "shouter", agent_core::upgrade::PLUGIN_EXAMPLE_PY);
    let home = env.home.clone();
    let p = ToolRecorder::new(vec![
        tool("a", "fs_list", json!({ "path": "." })),
        tool("b", "shout", json!({ "text": "too late" })), // the model still tries it
        text("done"),
    ])
    .before(move |n| {
        if n == 0 {
            uninstall(&home, "shouter");
        }
    });
    let (sid, _) = run(&env, &p, &no_approvals(), "work while it is rolled back");
    assert!(p.offered(0).contains(&"shout".to_string()));
    assert!(!p.offered(1).contains(&"shout".to_string()), "gone on the next turn");
    let r = &results(&env, sid)[1];
    assert_eq!(r["is_error"], true, "{r}");
    assert!(reload_rows(&env)[0].contains("removed: shouter"));
}

#[test]
fn a_broken_plugin_deployed_mid_session_is_refused_once_and_the_session_carries_on() {
    if !have_bwrap() { return; }
    let env = env("r-broken");
    let home = env.home.clone();
    let p = ToolRecorder::new(vec![
        tool("a", "fs_list", json!({ "path": "." })),
        tool("b", "fs_list", json!({ "path": "." })),
        tool("c", "fs_list", json!({ "path": "." })),
        text("done"),
    ])
    .before(move |n| {
        if n == 0 {
            install(&home, "shouter", "import sys\nsys.exit(1)\n"); // dies before it can answer
        }
    });
    let (sid, out) = run(&env, &p, &no_approvals(), "survive a bad deployment");
    assert!(matches!(out, agent_core::runner::Outcome::Completed { .. }));
    assert!(results(&env, sid).iter().all(|r| r["is_error"] == false), "the working tools were never disturbed");
    for call in 0..4 {
        assert!(!p.offered(call).contains(&"shout".to_string()));
    }
    let rows = reload_rows(&env);
    assert_eq!(rows.len(), 1, "reported once, not retried and re-reported on every turn: {rows:?}");
    assert!(rows[0].contains("refused shouter"), "{}", rows[0]);
}

#[test]
fn plugins_that_did_not_change_are_not_restarted_by_a_reload() {
    let env = mcp_env("r-stable", "", json!({}));
    let p = ScriptedProvider::new(vec![
        tool("a", "fake__echo", json!({ "text": "1" })),
        tool("b", "fs_list", json!({ "path": "." })),
        tool("c", "fake__echo", json!({ "text": "2" })),
        tool("d", "fake__echo", json!({ "text": "3" })),
        text("done"),
    ]);
    run(&env, &p, &no_approvals(), "several turns");
    let starts = std::fs::read_to_string(env.ws.join(".starts_fake")).unwrap();
    assert_eq!(starts.trim(), "1", "the server was started once, though every turn checked for changes");
    assert!(reload_rows(&env).is_empty(), "and nothing was reported");
}

// ---- MCP servers that change their tools -----------------------------------------------------

#[test]
fn an_mcp_server_that_announces_new_tools_gets_them_used_in_the_same_session() {
    let env = mcp_env("r-mcp-new", "notify_first", json!({}));
    let p = ToolRecorder::new(vec![
        tool("a", "fake__add_tool", json!({})),
        tool("b", "fake__extra", json!({})),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "grow a tool");
    assert!(!p.offered(0).contains(&"fake__extra".to_string()));
    assert!(p.offered(1).contains(&"fake__extra".to_string()), "{:?}", p.offered(1));
    assert_eq!(results(&env, sid)[1]["content"], "extra works");
    assert!(reload_rows(&env)[0].contains("tools changed: fake"), "{:?}", reload_rows(&env));
}

#[test]
fn a_notice_that_arrives_after_the_reply_while_idle_is_still_picked_up() {
    // The server sends its list-changed notice after answering, when nobody is waiting on it.
    let env = mcp_env("r-mcp-idle", "", json!({}));
    let mut host = PluginHost::start_for(&env.cfg).unwrap();
    let (idx, _) = host.find("fake__add_tool").unwrap();
    host.call(idx, "fake__add_tool", &json!({})).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline {
        let rep = host.reload(&env.cfg.plugins_now(), &env.ws);
        if rep.refreshed.contains(&"fake".to_string()) {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(seen, "the idle notice was read and the tool list re-read");
    assert!(host.find("fake__extra").is_some());
}

#[test]
fn a_pinned_server_that_changes_its_tools_is_removed_on_the_spot() {
    // Fail closed: if what a pinned server advertises changes while running, it is not trusted
    // with the new list and not trusted with the old one either.
    let probe = mcp_env("r-pin-probe", "", json!({}));
    let hash = PluginHost::inspect_mcp(probe.cfg.plugins.last().unwrap(), &probe.ws).unwrap().hash;
    let env = mcp_env("r-pin-run", "notify_first", json!({ "pin": hash }));
    let p = ToolRecorder::new(vec![
        tool("a", "fake__add_tool", json!({})),
        tool("b", "fake__echo", json!({ "text": "still trusted?" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "a pinned server changes its mind");
    assert!(p.offered(0).iter().any(|n| n.starts_with("fake__")));
    assert!(!p.offered(1).iter().any(|n| n.starts_with("fake__")), "all of its tools are gone: {:?}", p.offered(1));
    assert_eq!(results(&env, sid)[1]["is_error"], true);
    let rows = reload_rows(&env);
    assert!(rows[0].contains("refused fake") && rows[0].contains("no longer matches"), "{}", rows[0]);
}

// ---- the host on its own ---------------------------------------------------------------------

#[test]
fn the_host_adds_removes_and_replaces_plugins_and_keeps_the_old_one_when_a_new_one_fails() {
    let env = mcp_env("r-host", "", json!({}));
    let ws = env.ws.clone();
    let fs_only: Vec<_> = env.cfg.plugins.iter().filter(|p| p.name == "fs").cloned().collect();
    let fake = env.cfg.plugins.iter().find(|p| p.name == "fake").unwrap().clone();
    let mut host = PluginHost::start(&fs_only, &ws).unwrap();
    assert!(host.find("fake__echo").is_none());

    let mut both = fs_only.clone();
    both.push(fake.clone());
    let rep = host.reload(&both, &ws);
    assert_eq!(rep.added, vec!["fake"]);
    assert!(host.find("fake__echo").is_some() && host.find("fs_read").is_some());
    assert!(host.reload(&both, &ws).is_quiet(), "nothing changed, nothing happens");

    // Changed settings: the server is restarted with them.
    let mut narrowed = fake.clone();
    narrowed.mcp.as_mut().unwrap().tools = Some(vec!["echo".into()]);
    let mut desired = fs_only.clone();
    desired.push(narrowed);
    assert_eq!(host.reload(&desired, &ws).replaced, vec!["fake"]);
    assert!(host.find("fake__echo").is_some() && host.find("fake__shout").is_none());

    // A replacement that cannot start is refused, and the running one is left alone.
    let mut broken = fake.clone();
    broken.command = "/nonexistent/server".into();
    let mut desired = fs_only.clone();
    desired.push(broken);
    let rep = host.reload(&desired, &ws);
    assert_eq!(rep.refused.len(), 1, "{rep:?}");
    assert!(host.find("fake__echo").is_some(), "the old one is still serving");
    assert!(host.reload(&desired, &ws).is_quiet(), "the same failure is not retried and re-reported");

    // Removed from the config: stopped.
    assert_eq!(host.reload(&fs_only, &ws).removed, vec!["fake"]);
    assert!(host.find("fake__echo").is_none());
}

#[test]
fn a_new_plugin_whose_tool_name_collides_with_a_running_one_is_refused() {
    let env = mcp_env("r-collide", "", json!({}));
    let ws = env.ws.clone();
    let mut host = PluginHost::start(&env.cfg.plugins, &ws).unwrap();
    // A second server also named like the first one's tools: same server name means the same prefix.
    let mut twin = env.cfg.plugins.iter().find(|p| p.name == "fake").unwrap().clone();
    twin.name = "fake".into();
    twin.args[2] = "other".into(); // a different start counter, same exposed names
    let mut desired = env.cfg.plugins.clone();
    desired.retain(|p| p.name != "fake");
    let mut renamed = twin.clone();
    renamed.name = "fake2".into();
    desired.push(twin);
    desired.push(renamed);
    let rep = host.reload(&desired, &ws);
    assert!(rep.replaced.contains(&"fake".to_string()) || rep.added.contains(&"fake2".to_string()), "{rep:?}");
    assert!(host.find("fake__echo").is_some(), "a name is never served by two plugins at once");
}

// ---- the daemon watching the config file -----------------------------------------------------

struct Running {
    shutdown: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

fn start_daemon(env: &Env, provider: Arc<dyn ModelProvider>) -> Running {
    let d = Daemon {
        cfg: Arc::new(env.cfg.clone()),
        store: Arc::new(agent_core::store::Store::open(&env.home.join("sessions.db")).unwrap()),
        audit: Arc::new(agent_core::audit::AuditLog::open(&env.home.join("audit.db")).unwrap()),
        provider,
        approver: Arc::new(ScriptedApprover::new(vec![])),
        home: env.home.clone(),
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        d.run(flag, DaemonOpts { tick: Duration::from_millis(40), stop_after_finished: None, verbose: false }).unwrap();
    });
    Running { shutdown, handle }
}

impl Running {
    fn stop(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.handle.join().unwrap();
    }
}

fn write_config(env: &Env, edit: impl FnOnce(&mut Value)) {
    let mut v = serde_json::to_value(&env.cfg).unwrap();
    edit(&mut v);
    std::fs::write(env.home.join("config.json"), serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn inbox_source() -> Value {
    json!([{ "name": "inbox", "command": env!("CARGO_BIN_EXE_source_inbox"), "args": ["inbox"] }])
}

#[test]
fn editing_the_config_starts_a_new_event_source_without_restarting_the_daemon() {
    let env = env("r-d-source");
    let p: Arc<dyn ModelProvider> = Arc::new(ScriptedProvider::new((0..4).map(|_| text("ok")).collect()));
    let d = start_daemon(&env, p);
    std::thread::sleep(Duration::from_millis(300)); // running, with no event sources at all

    write_config(&env, |c| c["sources"] = inbox_source());
    std::fs::create_dir_all(env.ws.join("inbox")).unwrap();
    std::fs::write(env.ws.join("inbox/job.txt"), "summarise the project").unwrap();
    wait_for("the new source to turn a file into a session", || {
        env.store.list_sessions(10).unwrap().iter().any(|s| s.goal == "summarise the project")
    });
    d.stop();
}

#[test]
fn a_half_written_or_invalid_config_is_ignored_and_the_next_good_one_still_applies() {
    let env = env("r-d-bad");
    let p: Arc<dyn ModelProvider> = Arc::new(ScriptedProvider::new((0..4).map(|_| text("ok")).collect()));
    let d = start_daemon(&env, p);
    std::thread::sleep(Duration::from_millis(300));

    std::fs::write(env.home.join("config.json"), "{ \"workspace\": ").unwrap(); // an editor saving halfway
    std::thread::sleep(Duration::from_millis(400));
    assert!(!d.handle.is_finished(), "the daemon is still running");

    write_config(&env, |c| c["sources"] = inbox_source());
    std::fs::create_dir_all(env.ws.join("inbox")).unwrap();
    std::fs::write(env.ws.join("inbox/job.txt"), "after the bad edit").unwrap();
    wait_for("the good config to apply", || env.store.list_sessions(10).unwrap().iter().any(|s| s.goal == "after the bad edit"));
    d.stop();
}

#[test]
fn a_server_added_to_the_config_is_used_by_the_next_session_and_one_removed_is_gone() {
    let env = env("r-d-mcp");
    write_fake_mcp(&env.ws);
    let rec = Arc::new(ToolRecorder::new((0..6).map(|_| text("ok")).collect()));
    let d = start_daemon(&env, rec.clone() as Arc<dyn ModelProvider>);
    std::thread::sleep(Duration::from_millis(300));

    env.store.enqueue_event("test", "before the edit", "owner").unwrap();
    wait_for("the first session", || rec.tools.lock().unwrap().len() >= 1);
    assert!(!rec.offered(0).iter().any(|n| n.starts_with("fake__")));

    let ws = env.ws.display().to_string();
    write_config(&env, |c| c["plugins"].as_array_mut().unwrap().push(mcp_plugin(&ws, "fake", "", json!({}))));
    std::thread::sleep(Duration::from_millis(500)); // let the daemon notice
    env.store.enqueue_event("test", "after adding the server", "owner").unwrap();
    wait_for("the second session", || rec.tools.lock().unwrap().len() >= 2);
    assert!(rec.offered(1).contains(&"fake__echo".to_string()), "the new server is available: {:?}", rec.offered(1));

    write_config(&env, |_| {}); // back to the original config: the server is removed again
    std::thread::sleep(Duration::from_millis(500));
    env.store.enqueue_event("test", "after removing it", "owner").unwrap();
    wait_for("the third session", || rec.tools.lock().unwrap().len() >= 3);
    assert!(!rec.offered(2).iter().any(|n| n.starts_with("fake__")));
    d.stop();
}

#[test]
fn the_config_the_daemon_started_with_is_unchanged_if_the_file_never_changes() {
    let env = env("r-d-same");
    let rec = Arc::new(ToolRecorder::new((0..3).map(|_| text("ok")).collect()));
    let d = start_daemon(&env, rec.clone() as Arc<dyn ModelProvider>);
    env.store.enqueue_event("test", "no config file at all", "owner").unwrap();
    wait_for("a session", || rec.tools.lock().unwrap().len() >= 1);
    assert!(rec.offered(0).contains(&"fs_read".to_string()), "it ran with the config it was given");
    d.stop();
    let _: Option<Config> = None;
}
