//! The MCP client, against a strict stand-in server (see `FAKE_MCP`). Each test targets one thing a
//! real server would do, or one way the permission model has to hold when the tools come from outside.
mod common;
use agent_core::config::McpConfig;
use agent_core::plugin::{exposed_name, PluginHost};
use agent_core::provider::ScriptedProvider;
use agent_core::runner::ScriptedApprover;
use common::*;
use serde_json::{json, Value};

fn grants_with(extra: &[(&str, &str)]) -> Value {
    let mut g = all_grants();
    for (cap, tier) in extra {
        g.as_array_mut().unwrap().push(json!({ "capability": cap, "tier": tier }));
    }
    g
}

/// An env with the stand-in server configured as plugin `fake`.
fn env_with(name: &str, flags: &'static str, mcp: Value, grants: Value) -> Env {
    let e = setup(name, grants, |c| {
        let ws = c["workspace"].as_str().unwrap().to_string();
        c["plugins"].as_array_mut().unwrap().push(mcp_plugin(&ws, "fake", flags, mcp.clone()));
    });
    write_fake_mcp(&e.ws);
    e
}

fn call(host: &mut PluginHost, tool: &str, args: Value) -> (String, bool) {
    let (idx, _) = host.find(tool).unwrap_or_else(|| panic!("no tool {tool}"));
    match host.call(idx, tool, &args) {
        Ok(o) => (o.content, o.is_error),
        Err(e) => (format!("{e:#}"), true),
    }
}

// ---- the protocol ----------------------------------------------------------------------------

#[test]
fn the_handshake_is_correct_and_every_page_of_tools_is_read() {
    // The stand-in exits if the envelope is wrong or `tools/list` comes before `initialized`,
    // so simply starting proves the order. Paging is forced to five tools a page.
    let env = env_with("m-proto", "paged", json!({}), all_grants());
    let host = PluginHost::start_for(&env.cfg).expect("a correct handshake");
    let names: Vec<String> = host.specs().into_iter().map(|s| s.name).filter(|n| n.starts_with("fake__")).collect();
    assert_eq!(names.len(), 15, "all three pages were read: {names:?}");
    assert!(names.contains(&"fake__noisy".to_string()) && names.contains(&"fake__exists".to_string()));
}

#[test]
fn tool_names_are_prefixed_and_made_safe_and_never_collide() {
    let env = env_with("m-names", "", json!({}), all_grants());
    let host = PluginHost::start_for(&env.cfg).unwrap();
    let names: Vec<String> = host.specs().into_iter().map(|s| s.name).collect();
    assert!(names.contains(&"fake__weird_name".to_string()), "a dot becomes an underscore: {names:?}");
    assert!(names.contains(&"fs_read".to_string()) && names.contains(&"fake__echo".to_string()), "native and MCP tools sit side by side");
    // Long names stay inside the 64 characters model APIs allow, and stay different from each other.
    let a = exposed_name("server", &format!("{}a", "x".repeat(80)));
    let b = exposed_name("server", &format!("{}b", "x".repeat(80)));
    assert!(a.len() <= 64 && b.len() <= 64 && a != b, "{a} / {b}");
}

#[test]
fn a_servers_description_cannot_fill_the_context_or_smuggle_control_characters() {
    let env = env_with("m-desc", "", json!({}), all_grants());
    let host = PluginHost::start_for(&env.cfg).unwrap();
    let d = host.specs().into_iter().find(|s| s.name == "fake__noisy").unwrap().description;
    assert!(d.chars().count() <= 1003, "capped, got {}", d.chars().count());
    assert!(!d.contains('\x07') && !d.contains('\x1b'), "terminal control characters are stripped");
}

#[test]
fn messages_the_server_sends_between_its_answers_are_handled() {
    let env = env_with("m-chatter", "", json!({}), grants_with(&[("mcp:fake", "read_only")]));
    let mut host = PluginHost::start_for(&env.cfg).unwrap();
    // The server pings the client and waits for the reply, then sends a request the client cannot
    // serve and waits for a proper refusal. Getting this wrong stalls the call.
    let (out, err) = call(&mut host, "fake__ping_me", json!({}));
    assert!(!err && out == "ping answered, roots declined", "{out}");
    // Log and progress notifications ahead of the answer do not confuse matching.
    assert_eq!(call(&mut host, "fake__log_first", json!({})), ("after the logs".to_string(), false));
}

#[test]
fn results_of_every_kind_are_turned_into_text() {
    let env = env_with("m-results", "", json!({}), all_grants());
    let mut host = PluginHost::start_for(&env.cfg).unwrap();
    assert_eq!(call(&mut host, "fake__echo", json!({ "text": "hi" })), ("hi".into(), false));
    assert_eq!(call(&mut host, "fake__fail", json!({})), ("it broke".into(), true), "isError becomes an error");
    let (img, e) = call(&mut host, "fake__image", json!({}));
    assert!(!e && img.contains("[image omitted: image/png") && img.contains("caption") && !img.contains("QUFB"), "no base64 in the context: {img}");
    let (s, _) = call(&mut host, "fake__structured", json!({}));
    assert!(s.contains("\"n\":7"), "structured-only results are kept: {s}");
    // A JSON-RPC error from the server (it lists `ghost` but rejects the call) is reported, not swallowed.
    let (u, e) = call(&mut host, "fake__ghost", json!({}));
    assert!(e && u.contains("-32602") && u.contains("Unknown tool"), "{u}");
}

#[test]
fn a_server_that_dies_mid_call_or_hangs_is_handled_and_comes_back() {
    let env = env_with("m-crash", "", json!({}), all_grants());
    let mut cfg = env.cfg.clone();
    cfg.plugins.last_mut().unwrap().call_timeout_secs = 2;
    let mut host = PluginHost::start_for(&cfg).unwrap();
    let (out, err) = call(&mut host, "fake__die", json!({}));
    assert!(err && out.contains("exited unexpectedly"), "{out}");
    assert_eq!(call(&mut host, "fake__echo", json!({ "text": "alive again" })).0, "alive again", "restarted on the next call");
    let (out, err) = call(&mut host, "fake__slow", json!({}));
    assert!(err && out.contains("timed out"), "{out}");
    assert_eq!(call(&mut host, "fake__echo", json!({ "text": "and again" })).0, "and again");
}

// ---- permissions: the tools come from outside, so the gate must hold -------------------------

#[test]
fn an_mcp_tool_needs_a_grant_like_any_other_and_is_hidden_without_one() {
    let env = env_with("m-grant", "", json!({}), all_grants()); // no grant for mcp:fake
    let p = ToolRecorder::new(vec![tool("t1", "fake__echo", json!({ "text": "x" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "try it");
    assert!(!p.offered(0).iter().any(|n| n.starts_with("fake__")), "the model is not even shown tools it cannot use: {:?}", p.offered(0));
    let r = &results(&env, sid)[0];
    assert_eq!(r["is_error"], true);
    assert!(r["content"].as_str().unwrap().contains("not granted"), "{r}");
}

#[test]
fn with_a_grant_the_call_runs_is_audited_under_the_owners_capability_and_stays_marked_as_data() {
    let env = env_with("m-run", "", json!({}), grants_with(&[("mcp:fake", "read_only")]));
    let p = ToolRecorder::new(vec![tool("t1", "fake__echo", json!({ "text": "hello from mcp" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "echo");
    assert!(p.offered(0).contains(&"fake__echo".to_string()));
    assert_eq!(results(&env, sid)[0]["content"], "hello from mcp");
    let row = env.audit.rows().unwrap().into_iter().find(|r| r.entry.tool == "fake__echo" && r.entry.decision == "executed").unwrap();
    assert_eq!((row.entry.capability.as_str(), row.entry.tier.as_str(), row.entry.plugin.as_str()), ("mcp:fake", "read_only", "fake"));
    // And the model is shown it wrapped as untrusted output.
    let log = env.store.load_log(sid).unwrap();
    let msgs = agent_core::runner::build_messages(&log);
    let wrapped = msgs.iter().flat_map(|m| m.content.iter()).any(|b| matches!(b, agent_core::provider::Block::ToolResult { content, .. } if content.contains("untrusted_tool_output") && content.contains("hello from mcp")));
    assert!(wrapped);
}

#[test]
fn the_owner_maps_individual_tools_to_capabilities_and_the_rest_stay_denied() {
    let env = env_with(
        "m-map",
        "",
        json!({ "tool_capabilities": { "echo": "text:echo" } }),
        grants_with(&[("text:echo", "read_only")]), // nothing grants the default, mcp:fake
    );
    let p = ToolRecorder::new(vec![
        tool("t1", "fake__echo", json!({ "text": "allowed" })),
        tool("t2", "fake__shout", json!({ "text": "denied" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "two tools");
    let r = results(&env, sid);
    assert_eq!((r[0]["content"].as_str(), r[0]["is_error"].as_bool()), (Some("allowed"), Some(false)));
    assert_eq!(r[1]["is_error"], true);
    let offered = p.offered(0);
    assert!(offered.contains(&"fake__echo".to_string()) && !offered.contains(&"fake__shout".to_string()), "{offered:?}");
}

#[test]
fn a_servers_own_safety_hints_are_ignored_the_tier_comes_from_the_owner() {
    // The grant says irreversible. Whatever a server claims about a tool, the owner's tier decides,
    // so this one needs approval and does not run when the owner says no.
    let env = env_with("m-tier", "", json!({}), grants_with(&[("mcp:fake", "irreversible")]));
    let p = ScriptedProvider::new(vec![tool("t1", "fake__echo", json!({ "text": "x" })), text("done")]);
    let a = ScriptedApprover::new(vec![false]);
    let (sid, _) = run(&env, &p, &a, "needs approval");
    assert_eq!(a.requests.lock().unwrap().len(), 1, "the owner was asked");
    assert_eq!(results(&env, sid)[0]["is_error"], true);
}

#[test]
fn a_tool_mapped_to_an_authority_changing_capability_is_refused() {
    let env = env_with("m-auth", "", json!({ "tool_capabilities": { "echo": "upgrade:deploy" } }), all_grants());
    let err = match PluginHost::start_for(&env.cfg) {
        Ok(_) => panic!("must refuse"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("changes authority"), "{err}");
}

#[test]
fn path_arguments_can_be_scoped_so_the_gate_checks_them() {
    let env = env_with("m-scope", "", json!({ "scope_args": { "cat": ["path"] } }), grants_with(&[("mcp:fake", "read_only")]));
    std::fs::write(env.ws.join("a.txt"), "inside").unwrap();
    std::fs::write(env.ws.parent().unwrap().join("outside.txt"), "secret").unwrap();
    let p = ScriptedProvider::new(vec![
        tool("t1", "fake__cat", json!({ "path": "a.txt" })),
        tool("t2", "fake__cat", json!({ "path": "../outside.txt" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "read two files");
    let r = results(&env, sid);
    assert_eq!(r[0]["content"], "inside");
    assert_eq!(r[1]["is_error"], true);
    assert!(r[1]["content"].as_str().unwrap().contains("outside the granted scope") && !r[1]["content"].as_str().unwrap().contains("secret"), "{}", r[1]);
}

#[test]
fn an_allowlist_exposes_only_the_named_tools() {
    let env = env_with("m-allow", "", json!({ "tools": ["echo", "shout"] }), all_grants());
    let host = PluginHost::start_for(&env.cfg).unwrap();
    let mut names: Vec<String> = host.specs().into_iter().map(|s| s.name).filter(|n| n.starts_with("fake__")).collect();
    names.sort();
    assert_eq!(names, vec!["fake__echo", "fake__shout"]);
}

// ---- pinning: the defence against a server that changes what its tools say ------------------

fn inspect(env: &Env) -> agent_core::plugin::McpInspection {
    let cfg = env.cfg.plugins.last().unwrap();
    PluginHost::inspect_mcp(cfg, &env.ws).unwrap()
}

#[test]
fn inspecting_a_server_gives_a_hash_that_works_as_a_pin() {
    let env = env_with("m-pin", "", json!({}), all_grants());
    let hash = inspect(&env).hash;
    assert_eq!(hash.len(), 64);

    let ok = env_with("m-pin-ok", "", json!({ "pin": hash }), all_grants());
    assert!(PluginHost::start_for(&ok.cfg).is_ok(), "the right pin starts");

    let wrong = env_with("m-pin-bad", "", json!({ "pin": "0".repeat(64) }), all_grants());
    let err = match PluginHost::start_for(&wrong.cfg) {
        Ok(_) => panic!("a wrong pin must refuse"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("no longer matches") && err.contains(&hash), "the message shows the real hash so the owner can compare: {err}");
}

#[test]
fn a_server_that_changes_its_descriptions_after_a_restart_is_refused() {
    // The "rug pull": reviewed and approved, then it quietly changes what its tools tell the model.
    // Here the second start of the server adds an instruction to `echo`'s description.
    let probe = env_with("m-rug-probe", "", json!({}), all_grants());
    let pin = inspect(&probe).hash; // the hash of the first, honest version

    // Pinned: refused on the restart with a clear reason.
    let pinned = env_with("m-rug-pinned", "rugpull", json!({ "pin": pin }), all_grants());
    let mut cfg = pinned.cfg.clone();
    cfg.plugins.last_mut().unwrap().call_timeout_secs = 2;
    let mut host = PluginHost::start_for(&cfg).unwrap();
    assert!(call(&mut host, "fake__slow", json!({})).1, "kill it with a timeout so it must restart");
    let (out, err) = call(&mut host, "fake__echo", json!({ "text": "x" }));
    assert!(err && out.contains("no longer matches"), "{out}");

    // Not pinned: still refused, because it changed between its own two starts.
    let loose = env_with("m-rug-loose", "rugpull", json!({}), all_grants());
    let mut cfg = loose.cfg.clone();
    cfg.plugins.last_mut().unwrap().call_timeout_secs = 2;
    let mut host = PluginHost::start_for(&cfg).unwrap();
    assert!(call(&mut host, "fake__slow", json!({})).1);
    let (out, err) = call(&mut host, "fake__echo", json!({ "text": "x" }));
    assert!(err && out.contains("changed its tools after a restart"), "{out}");
}

// ---- containment -----------------------------------------------------------------------------

#[test]
fn an_mcp_server_can_run_in_the_sandbox_and_then_cannot_see_the_agents_files() {
    if !agent_core::sandbox::available() {
        eprintln!("skipped: bubblewrap is not installed here");
        return;
    }
    let mut env = env_with("m-sandbox", "", json!({}), all_grants());
    env.cfg.home = env.home.clone();
    env.cfg.plugins.last_mut().unwrap().sandbox = Some(agent_core::config::SandboxConfig::default());
    env.cfg.seal();
    let mut host = PluginHost::start_for(&env.cfg).expect("the stand-in starts inside the sandbox");
    assert_eq!(call(&mut host, "fake__echo", json!({ "text": "boxed" })).0, "boxed");
    let db = env.home.join("sessions.db");
    assert_eq!(call(&mut host, "fake__exists", json!({ "path": db.to_string_lossy() })).0, "no", "the session log is invisible to it");
    // The same server, unsandboxed, can see it: the sandbox is what made the difference.
    let open = env_with("m-sandbox-ctrl", "", json!({}), all_grants());
    let mut host = PluginHost::start_for(&open.cfg).unwrap();
    let db = open.home.join("sessions.db");
    assert_eq!(call(&mut host, "fake__exists", json!({ "path": db.to_string_lossy() })).0, "yes");
}

#[test]
fn the_config_defaults_name_the_capability_after_the_server() {
    let c: McpConfig = serde_json::from_value(json!({})).unwrap();
    assert!(c.capability.is_none() && c.pin.is_none() && c.tools.is_none());
    let env = env_with("m-default", "", json!({}), all_grants());
    let host = PluginHost::start_for(&env.cfg).unwrap();
    let (_, e) = host.find("fake__echo").unwrap();
    assert_eq!(e.capability, "mcp:fake");
}
