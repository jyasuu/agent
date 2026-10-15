//! Stage 6a, the OS sandbox. Behavior only: what a sandboxed plugin can and cannot see or do,
//! measured through a real session, with an unsandboxed control wherever the answer could be
//! "no" for some unrelated reason (a missing file, no network in the test machine).
mod common;
use agent_core::gate::Gate;
use agent_core::plugin::PluginHost;
use agent_core::provider::ScriptedProvider;
use agent_core::runner::{Runner, ScriptedApprover};
use common::*;
use serde_json::{json, Value};
use std::path::Path;

fn have_bwrap() -> bool {
    if agent_core::sandbox::available() {
        true
    } else {
        eprintln!("skipped: bubblewrap is not installed here");
        false
    }
}

/// An env whose fs plugin is sandboxed (or not), with the workspace set to `ws_of(env)`.
fn env_with(name: &str, sandbox: Option<Value>) -> Env {
    let mut e = setup(name, all_grants(), |c| {
        if let Some(sb) = &sandbox {
            c["plugins"][0]["sandbox"] = sb.clone();
        }
    });
    e.cfg.home = e.home.clone();
    e.cfg.seal();
    e
}

/// Runs one shell command through the (maybe sandboxed) fs plugin, owner approving, and returns its output.
fn shell(env: &Env, workspace: &Path, command: &str) -> (String, bool) {
    let p = ScriptedProvider::new(vec![tool("t1", "shell_exec", json!({ "command": command })), text("done")]);
    let (_e, sid) = env.store.enqueue_event("test", "run it", "owner").unwrap();
    let a = ScriptedApprover::new(vec![true]);
    let mut cfg = env.cfg.clone();
    cfg.workspace = workspace.to_path_buf();
    let mut host = PluginHost::start(&cfg.plugins, workspace).expect("plugin starts");
    let gate = Gate::new(workspace, &cfg.grants, &[env.home.clone()]);
    let mut r = Runner {
        cfg: &cfg, store: &env.store, audit: &env.audit,
        provider: &p, approver: &a, host: &mut host, gate: &gate, shutdown: None,
    };
    r.run_session(sid).unwrap();
    let res = results(env, sid);
    (res[0]["content"].as_str().unwrap().to_string(), res[0]["is_error"].as_bool().unwrap())
}

#[test]
fn a_sandboxed_plugin_still_works_normally_inside_the_workspace() {
    if !have_bwrap() { return; }
    let env = env_with("sb-works", Some(json!({})));
    std::fs::write(env.ws.join("a.txt"), "hello").unwrap();
    let (out, err) = shell(&env, &env.ws, "cat a.txt && echo more > b.txt && cat b.txt");
    assert!(!err, "{out}");
    assert!(out.contains("hello") && out.contains("more"), "{out}");
    assert_eq!(std::fs::read_to_string(env.ws.join("b.txt")).unwrap().trim(), "more", "writes reach the real workspace");
}

#[test]
fn the_agents_own_files_are_invisible_even_when_the_home_sits_inside_the_workspace() {
    if !have_bwrap() { return; }
    // Control: with no sandbox the same command reads the session database.
    let open = env_with("sb-ctrl", None);
    let root = open.home.parent().unwrap().to_path_buf();
    let cmd = format!("head -c 15 {}/sessions.db", open.home.display());
    let (out, _) = shell(&open, &root, &cmd);
    assert!(out.contains("SQLite format"), "control should be able to read it: {out}");

    // Sandboxed, with the workspace being the folder that holds the home directory.
    let boxed = env_with("sb-home", Some(json!({})));
    let root = boxed.home.parent().unwrap().to_path_buf();
    let count = |h: &Path| format!("head -c 15 {0}/sessions.db 2>/dev/null; echo \"entries=$(ls -A {0} | wc -l)\"", h.display());
    let (ctrl_out, _) = shell(&open, &open.home.parent().unwrap().to_path_buf(), &count(&open.home));
    assert!(!ctrl_out.contains("entries=0"), "control sees files in the home directory: {ctrl_out}");
    let (out, _) = shell(&boxed, &root, &count(&boxed.home));
    assert!(!out.contains("SQLite format"), "the session log must be unreadable: {out}");
    assert!(out.contains("entries=0"), "the home directory must look empty: {out}");
}

#[test]
fn files_outside_the_workspace_are_invisible() {
    if !have_bwrap() { return; }
    let boxed = env_with("sb-outside", Some(json!({})));
    let secret = boxed.ws.parent().unwrap().join("outside.txt");
    std::fs::write(&secret, "TOP-SECRET").unwrap();
    let cmd = format!("cat {}", secret.display());
    let open = env_with("sb-outside-ctrl", None);
    std::fs::write(open.ws.parent().unwrap().join("outside.txt"), "TOP-SECRET").unwrap();
    let (ctrl, _) = shell(&open, &open.ws, &format!("cat {}", open.ws.parent().unwrap().join("outside.txt").display()));
    assert!(ctrl.contains("TOP-SECRET"), "control reads it: {ctrl}");

    let (out, err) = shell(&boxed, &boxed.ws, &cmd);
    assert!(err && !out.contains("TOP-SECRET"), "{out}");
}

#[test]
fn a_sandboxed_plugin_cannot_open_network_connections() {
    if !have_bwrap() { return; }
    // A listener in this process. Reaching it needs only loopback, so the result does not depend
    // on whether the machine running the tests has internet access.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cmd = format!("python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=2); print('CONNECTED')\" 2>&1");

    let open = env_with("sb-net-ctrl", None);
    let (ctrl, _) = shell(&open, &open.ws, &cmd);
    assert!(ctrl.contains("CONNECTED"), "control must be able to connect: {ctrl}");

    let boxed = env_with("sb-net", Some(json!({})));
    let (out, _) = shell(&boxed, &boxed.ws, &cmd);
    assert!(!out.contains("CONNECTED"), "the sandbox must have no route to the host's network: {out}");

    // And it is a switch the owner controls, not a constant.
    let allowed = env_with("sb-net-on", Some(json!({ "network": true })));
    let (out, _) = shell(&allowed, &allowed.ws, &cmd);
    assert!(out.contains("CONNECTED"), "network: true must turn it on: {out}");
    drop(listener);
}

#[test]
fn a_sandboxed_plugin_cannot_see_other_processes() {
    if !have_bwrap() { return; }
    let count = "ls /proc | grep -c '^[0-9]'";
    let open = env_with("sb-pid-ctrl", None);
    let (ctrl, _) = shell(&open, &open.ws, count);
    let boxed = env_with("sb-pid", Some(json!({})));
    let (out, _) = shell(&boxed, &boxed.ws, count);
    let n = |t: &str| -> usize { t.lines().find_map(|l| l.trim().parse().ok()).unwrap_or_else(|| panic!("no count in {t}")) };
    assert!(n(&out) < 12, "its own process space is small, got {}", n(&out));
    assert!(n(&ctrl) > n(&out), "the control sees more ({}) than the sandbox ({})", n(&ctrl), n(&out));
}

#[test]
fn system_directories_are_read_only() {
    if !have_bwrap() { return; }
    let boxed = env_with("sb-ro", Some(json!({})));
    let (out, err) = shell(&boxed, &boxed.ws, "touch /usr/marker 2>&1; echo exit=$?");
    assert!(err || out.contains("Read-only") || !out.contains("exit=0"), "{out}");
    assert!(!Path::new("/usr/marker").exists());
}

#[test]
fn a_read_only_workspace_cannot_be_written() {
    if !have_bwrap() { return; }
    let boxed = env_with("sb-wsro", Some(json!({ "workspace_readonly": true })));
    std::fs::write(boxed.ws.join("keep.txt"), "x").unwrap();
    let (out, _) = shell(&boxed, &boxed.ws, "cat keep.txt; touch new.txt 2>&1; echo exit=$?");
    assert!(out.contains("x"), "{out}");
    assert!(!boxed.ws.join("new.txt").exists(), "nothing was written: {out}");
}

#[test]
fn extra_read_only_paths_are_visible_but_not_writable() {
    if !have_bwrap() { return; }
    let boxed = env_with("sb-bind", None);
    let tool_dir = boxed.ws.parent().unwrap().join("toolchain");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(tool_dir.join("note.txt"), "from-toolchain").unwrap();
    let mut e = boxed;
    e.cfg.plugins[0].sandbox = Some(agent_core::config::SandboxConfig { ro_binds: vec![tool_dir.to_string_lossy().to_string()], ..Default::default() });
    e.cfg.seal();
    let (out, _) = shell(&e, &e.ws, &format!("cat {0}/note.txt; touch {0}/new 2>&1; echo exit=$?", tool_dir.display()));
    assert!(out.contains("from-toolchain"), "{out}");
    assert!(!tool_dir.join("new").exists(), "{out}");
}

#[test]
fn if_the_sandbox_cannot_start_the_plugin_does_not_run_unconfined() {
    let env = env_with("sb-closed", Some(json!({ "program": "/nonexistent/bwrap" })));
    let err = match PluginHost::start(&env.cfg.plugins, &env.ws) {
        Ok(_) => panic!("the plugin must not start without its sandbox"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("sandbox"), "{err}");
}
