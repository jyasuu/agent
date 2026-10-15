//! Stage 4, verification. Behavior only: sessions, logs, audit rows and approval requests.
//! One scripted provider answers the worker and, inline, the verifier it triggers, so the call
//! numbers in each test follow the order: worker calls first, then the verifier's.
mod common;
use agent_core::provider::ScriptedProvider;
use agent_core::runner::Outcome;
use common::*;
use serde_json::{json, Value};

fn write_out() -> agent_core::provider::ModelResponse {
    tool("w1", "fs_write", json!({ "path": "out.txt", "content": "hello" }))
}

/// Children of a session, oldest first (so index 0 is the first verifier pass).
fn verifier_children(env: &Env, parent: i64) -> Vec<i64> {
    let mut v: Vec<i64> = env.store.list_sessions(50).unwrap().into_iter().filter(|r| r.parent_id == Some(parent)).map(|r| r.id).collect();
    v.sort();
    v
}

#[test]
fn a_pass_verdict_lets_the_session_complete() {
    let env = vsetup("v-pass", &[], |_| {});
    let p = ScriptedProvider::new(vec![write_out(), text("done"), verdict("pass", "out.txt exists")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let v = kinds(&env, sid, "verification");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["verdict"], "pass");
    assert_eq!(kinds(&env, sid, "final")[0]["verification"], "pass");
    assert!(decisions(&env).contains(&"verify:verified_pass".to_string()));
    let kids = verifier_children(&env, sid);
    assert_eq!(kids.len(), 1);
    assert_eq!(env.store.status(kids[0]).unwrap(), "completed");
}

#[test]
fn the_verifier_sees_the_task_and_the_artifacts_but_not_the_workers_account() {
    let env = vsetup("v-fresh", &[], |_| {});
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "out.txt", "content": "hello" })),
        text("WORKER-CLAIM-XYZ everything is perfect, trust me"),
        verdict("pass", "ok"),
    ]);
    let (_sid, out) = run(&env, &p, &no_approvals(), "GOAL-ABC make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }));
    let seen = shown(&p, 2);
    assert!(seen.contains("GOAL-ABC"));
    assert!(seen.contains("out.txt"));
    assert!(!seen.contains("WORKER-CLAIM-XYZ"), "the worker's own account must not reach the verifier");
    assert_eq!(p.seen.lock().unwrap()[2].len(), 1, "fresh context: one message");
}

#[test]
fn the_verifier_is_read_only_and_cannot_hand_out_or_spawn_anything() {
    let env = vsetup("v-ro", &[], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        tool("v1", "fs_write", json!({ "path": "evil.txt", "content": "x" })),
        tool("v2", "spawn_agent", json!({ "task": "x", "grants": [{ "capability": "fs:write" }] })),
        tool("v3", "shell_exec", json!({ "command": "touch evil2" })),
        verdict("pass", "ok"),
    ]);
    let a = no_approvals();
    let (sid, out) = run(&env, &p, &a, "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    assert!(!env.ws.join("evil.txt").exists());
    assert!(!env.ws.join("evil2").exists());
    assert!(a.requests.lock().unwrap().is_empty(), "a verifier never causes an approval request");
    let vid = verifier_children(&env, sid)[0];
    let rows = env.audit.rows().unwrap();
    for tool in ["fs_write", "spawn_agent", "shell_exec"] {
        let r = rows.iter().find(|r| r.entry.tool == tool && r.entry.session_id == vid).unwrap_or_else(|| panic!("{tool} not audited"));
        assert_eq!(r.entry.decision, "denied", "{tool}");
    }
}

#[test]
fn a_failed_verdict_goes_back_to_the_worker_which_can_fix_it() {
    let env = vsetup("v-fail-fix", &[], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        verdict("fail", "out.txt should say goodbye"),
        tool("w2", "fs_write", json!({ "path": "out.txt", "content": "goodbye" })),
        text("fixed"),
        verdict("pass", "now says goodbye"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt say goodbye");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let verdicts: Vec<Value> = kinds(&env, sid, "verification").iter().map(|v| v["verdict"].clone()).collect();
    assert_eq!(verdicts, vec![json!("fail"), json!("pass")]);
    let feedback = shown(&p, 3);
    assert!(feedback.contains("Independent verification FAILED"));
    assert!(feedback.contains("should say goodbye"));
    // The verifier's words reach the worker as data, inside the untrusted wrapper.
    assert!(feedback.contains("untrusted_tool_output tool=\\\"verifier\\\""), "{feedback}");
    assert_eq!(std::fs::read_to_string(env.ws.join("out.txt")).unwrap(), "goodbye");
}

#[test]
fn repeated_failure_suspends_with_a_handoff_instead_of_looping() {
    let env = vsetup("v-fail-bound", &[], |c| c["verification"]["max_retries"] = json!(1));
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        verdict("fail", "wrong"),
        text("done again"),
        verdict("fail", "still wrong"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    match out {
        Outcome::Suspended { reason, handoff } => {
            assert!(reason.contains("verification failed"), "{reason}");
            assert!(handoff.contains("HANDOFF"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(env.store.status(sid).unwrap(), "suspended");
    assert_eq!(p.seen.lock().unwrap().len(), 5, "no model calls after the limit");
}

#[test]
fn resuming_after_a_verification_suspend_gives_a_fresh_set_of_retries() {
    let env = vsetup("v-resume", &[], |c| c["verification"]["max_retries"] = json!(0));
    let p = ScriptedProvider::new(vec![write_out(), text("done"), verdict("fail", "wrong")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Suspended { .. }));

    let p2 = ScriptedProvider::new(vec![
        tool("w2", "fs_write", json!({ "path": "out.txt", "content": "right" })),
        text("fixed"),
        verdict("pass", "right"),
    ]);
    let out2 = run_with(&env, sid, &p2, &no_approvals(), None).unwrap();
    assert!(matches!(out2, Outcome::Completed { .. }), "{out2:?}");
    assert!(shown(&p2, 0).contains("Independent verification FAILED"), "the worker resumes knowing why");
}

#[test]
fn an_uncertain_verdict_is_rechecked_once_and_then_flagged_without_asking_the_owner() {
    let env = vsetup("v-uncertain", &[], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        verdict("uncertain", "cannot tell"),
        verdict("uncertain", "still cannot tell"),
    ]);
    let a = no_approvals();
    let (sid, out) = run(&env, &p, &a, "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    assert!(shown(&p, 3).contains("second look"));
    assert_eq!(kinds(&env, sid, "verification").len(), 2);
    assert_eq!(kinds(&env, sid, "final")[0]["verification"], "uncertain");
    assert!(decisions(&env).contains(&"verify:completed_unverified".to_string()));
    assert!(a.requests.lock().unwrap().is_empty(), "uncertainty does not interrupt the owner");
}

#[test]
fn an_uncertain_first_look_can_become_a_pass_on_the_second() {
    let env = vsetup("v-uncertain-pass", &[], |_| {});
    let p = ScriptedProvider::new(vec![write_out(), text("done"), verdict("uncertain", "?"), verdict("pass", "checked")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }));
    assert_eq!(kinds(&env, sid, "final")[0]["verification"], "pass");
}

#[test]
fn on_uncertain_suspend_holds_the_session_for_the_owner() {
    let env = vsetup("v-uncertain-hold", &[], |c| {
        c["verification"]["on_uncertain"] = json!("suspend");
        c["verification"]["reverify_on_uncertain"] = json!(false);
    });
    let p = ScriptedProvider::new(vec![write_out(), text("done"), verdict("uncertain", "?")]);
    let (_sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Suspended { .. }), "{out:?}");
}

#[test]
fn an_answer_without_a_structured_verdict_counts_as_uncertain() {
    let env = vsetup("v-malformed", &[], |_| {});
    let p = ScriptedProvider::new(vec![write_out(), text("done"), text("looks fine to me"), text("yes, fine")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }));
    assert_eq!(kinds(&env, sid, "final")[0]["verification"], "uncertain");
}

#[test]
fn a_session_that_used_no_tools_is_not_verified() {
    let env = vsetup("v-notools", &[], |_| {});
    let p = ScriptedProvider::new(vec![text("4")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "what is 2+2");
    assert!(matches!(out, Outcome::Completed { .. }));
    assert!(kinds(&env, sid, "verification").is_empty());
    assert_eq!(p.seen.lock().unwrap().len(), 1);
}

#[test]
fn without_the_verify_grant_or_the_setting_nothing_changes() {
    let env = setup("v-off", all_grants(), |c| c["verification"] = json!({ "enabled": true }));
    let p = ScriptedProvider::new(vec![write_out(), text("done")]);
    let (sid, out) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }));
    assert!(kinds(&env, sid, "verification").is_empty(), "no agent:verify grant, no verifier");

    let env = vsetup("v-off2", &[], |c| c["verification"] = json!({ "enabled": false }));
    let p = ScriptedProvider::new(vec![write_out(), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "make out.txt");
    assert!(kinds(&env, sid, "verification").is_empty());
}

#[test]
fn a_crash_after_the_model_said_done_does_not_call_the_worker_again() {
    let env = vsetup("v-crash", &[], |_| {});
    let (_e, sid) = env.store.enqueue_event("test", "make out.txt", "owner").unwrap();
    env.store.append_log(sid, "assistant", json!({ "content": [{ "type": "tool_use", "id": "w1", "name": "fs_write", "input": { "path": "out.txt", "content": "hello" } }] })).unwrap();
    env.store.append_log(sid, "tool_result", json!({ "tool_use_id": "w1", "tool": "fs_write", "content": "ok", "is_error": false })).unwrap();
    env.store.append_log(sid, "assistant", json!({ "content": [{ "type": "text", "text": "done" }] })).unwrap();
    // The process died here. On restart only the verifier needs the model.
    let p = ScriptedProvider::new(vec![verdict("pass", "ok")]);
    let out = run_with(&env, sid, &p, &no_approvals(), None).unwrap();
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    assert_eq!(p.seen.lock().unwrap().len(), 1);
    assert!(shown(&p, 0).contains("TASK SPEC"));
}

#[test]
fn verifier_runs_do_not_use_up_the_spawn_limit_and_their_cost_counts_against_the_parent() {
    let env = vsetup("v-limit", &[], |c| c["subagents"] = json!({ "max_children_per_session": 1 }));
    let p = ScriptedProvider::new(vec![
        tool("s1", "spawn_agent", json!({ "task": "look around", "grants": [{ "capability": "fs:read" }] })),
        text("child result"),
        text("done"),
        verdict("pass", "ok"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "look around");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    assert_eq!(verifier_children(&env, sid).len(), 2);
    let (tokens, _) = env.store.tree_spend(sid).unwrap();
    let (own, _) = env.store.session_spend(sid).unwrap();
    assert!(tokens > own, "the verifier's tokens are part of the parent's tree");
}

// ---- sandboxed check commands ---------------------------------------------------------------

#[test]
fn a_verifier_can_run_an_owner_allowed_check_command_without_asking() {
    if !sandbox_ok() {
        eprintln!("skipped: no user and network namespaces here");
        return;
    }
    let env = vsetup("c-ok", &["cat out.txt"], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        tool("v1", "check_exec", json!({ "command": "cat   out.txt" })),
        verdict("pass", "cat shows hello"),
    ]);
    let a = no_approvals();
    let (sid, out) = run(&env, &p, &a, "make out.txt");
    assert!(matches!(out, Outcome::Completed { .. }), "{out:?}");
    let vid = verifier_children(&env, sid)[0];
    let r = results(&env, vid);
    assert!(r[0]["content"].as_str().unwrap().contains("exit code: 0"), "{r:?}");
    assert!(r[0]["content"].as_str().unwrap().contains("hello"));
    assert!(a.requests.lock().unwrap().is_empty());
    assert!(shown(&p, 2).contains("cat out.txt"), "the verifier is told which checks exist");
}

#[test]
fn a_command_outside_the_owners_list_is_refused_by_the_core() {
    let env = vsetup("c-deny", &["cat out.txt"], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        tool("v1", "check_exec", json!({ "command": "rm -rf ." })),
        tool("v2", "check_exec", json!({ "command": "cat out.txt; touch pwned" })),
        verdict("uncertain", "could not check"),
        verdict("uncertain", "could not check"),
    ]);
    let (sid, _out) = run(&env, &p, &no_approvals(), "make out.txt");
    let vid = verifier_children(&env, sid)[0];
    let rows: Vec<_> = env.audit.rows().unwrap().into_iter().filter(|r| r.entry.session_id == vid && r.entry.tool == "check_exec").collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.entry.decision == "denied" && r.entry.reason.contains("check_commands")));
    assert!(!env.ws.join("pwned").exists());
    assert!(env.ws.join("out.txt").exists());
}

#[test]
fn a_check_command_runs_with_no_network() {
    if !sandbox_ok() {
        eprintln!("skipped: no user and network namespaces here");
        return;
    }
    let env = vsetup("c-net", &["cat /proc/net/dev"], |_| {});
    let p = ScriptedProvider::new(vec![
        write_out(),
        text("done"),
        tool("v1", "check_exec", json!({ "command": "cat /proc/net/dev" })),
        verdict("pass", "ok"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "make out.txt");
    let vid = verifier_children(&env, sid)[0];
    let out = results(&env, vid)[0]["content"].as_str().unwrap().to_string();
    assert!(out.contains("lo:"), "{out}");
    assert!(!out.contains("eth0") && !out.contains("ens") && !out.contains("enp"), "the sandbox must have no real interface: {out}");
}

#[test]
fn check_exec_is_unreachable_without_the_grant() {
    let env = setup("c-nogrant", all_grants(), |c| {
        c["check_commands"] = json!(["cat out.txt"]);
        c["plugins"].as_array_mut().unwrap().push(json!({ "name": "check", "command": env!("CARGO_BIN_EXE_plugin_check") }));
    });
    let p = ScriptedProvider::new(vec![tool("w1", "check_exec", json!({ "command": "cat out.txt" })), text("done")]);
    let (_sid, _) = run(&env, &p, &no_approvals(), "try it");
    let rows = env.audit.rows().unwrap();
    let r = rows.iter().find(|r| r.entry.tool == "check_exec").unwrap();
    assert_eq!(r.entry.decision, "denied");
    assert!(r.entry.reason.contains("not granted"));
}

