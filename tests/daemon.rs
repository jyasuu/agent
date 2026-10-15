//! Stage 2 behavior tests. They drive the daemon the way the CLI does: events go in,
//! and we look at session states, the session and audit logs, approval requests and files.
use agent_core::audit::AuditLog;
use agent_core::config::Config;
use agent_core::daemon::{Daemon, DaemonLock, DaemonOpts};
use agent_core::provider::{Block, Message, ModelProvider, ModelResponse, ScriptedProvider, ToolSpec, Usage};
use agent_core::runner::{Approver, DbApprover, ScriptedApprover};
use agent_core::store::Store;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static N: AtomicU32 = AtomicU32::new(0);

struct Env {
    ws: PathBuf,
    home: PathBuf,
    cfg: Arc<Config>,
    store: Arc<Store>,
    audit: Arc<AuditLog>,
}

fn setup(name: &str, tweak: impl FnOnce(&mut Value)) -> Env {
    let root = std::env::temp_dir().join(format!("agent-dtest-{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let ws = root.join("ws");
    let home = root.join("home");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let (ws, home) = (ws.canonicalize().unwrap(), home.canonicalize().unwrap());
    let mut cfg = json!({
        "workspace": ws,
        "plugins": [{ "name": "fs", "command": env!("CARGO_BIN_EXE_plugin_fs") }],
        "grants": [
            { "capability": "fs:read", "tier": "read_only" },
            { "capability": "fs:write", "tier": "reversible" },
            { "capability": "exec:shell", "tier": "irreversible" }
        ],
        "session_budget": { "max_steps": 25, "max_tokens": 1000000, "max_cost_usd": 100.0, "max_wall_secs": 600 },
        "global_budget": { "max_tokens": 10000000, "max_cost_usd": 1000.0 },
        "max_concurrent_sessions": 2
    });
    tweak(&mut cfg);
    Env {
        cfg: Arc::new(serde_json::from_value(cfg).unwrap()),
        store: Arc::new(Store::open(&home.join("sessions.db")).unwrap()),
        audit: Arc::new(AuditLog::open(&home.join("audit.db")).unwrap()),
        ws,
        home,
    }
}

fn daemon(env: &Env, provider: Arc<dyn ModelProvider>, approver: Arc<dyn Approver>) -> Daemon {
    Daemon {
        cfg: Arc::clone(&env.cfg),
        store: Arc::clone(&env.store),
        audit: Arc::clone(&env.audit),
        provider,
        approver,
        home: env.home.clone(),
    }
}

fn opts(n: u64) -> DaemonOpts {
    DaemonOpts { tick: Duration::from_millis(30), stop_after_finished: Some(n), verbose: false }
}

/// Runs the daemon, with a watchdog so a bug cannot hang the test run.
fn run_daemon(d: &Daemon, o: DaemonOpts) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let guard = Arc::clone(&shutdown);
    let dog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(40));
        guard.store(true, Ordering::SeqCst);
    });
    d.run(shutdown, o).unwrap();
    drop(dog);
}

fn text(t: &str) -> ModelResponse {
    ModelResponse { content: vec![Block::Text { text: t.into() }], usage: Usage { input_tokens: 10, output_tokens: 5 } }
}

fn tool(id: &str, name: &str, input: Value) -> ModelResponse {
    ModelResponse {
        content: vec![Block::ToolUse { id: id.into(), name: name.into(), input }],
        usage: Usage { input_tokens: 10, output_tokens: 5 },
    }
}

/// Answers with plain text after a delay, and records how many calls overlapped.
struct SlowProvider {
    delay: Duration,
    inflight: AtomicUsize,
    max_inflight: AtomicUsize,
    always_tool: bool,
}

impl SlowProvider {
    fn new(delay_ms: u64, always_tool: bool) -> Self {
        Self { delay: Duration::from_millis(delay_ms), inflight: AtomicUsize::new(0), max_inflight: AtomicUsize::new(0), always_tool }
    }
}

impl ModelProvider for SlowProvider {
    fn complete(&self, _s: &str, _m: &[Message], _t: &[ToolSpec]) -> Result<ModelResponse> {
        let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_inflight.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        Ok(if self.always_tool { tool("t", "fs_list", json!({ "path": "." })) } else { text("done") })
    }
}

#[test]
fn never_more_sessions_run_at_once_than_the_cap_allows() {
    let env = setup("cap", |_| {});
    for i in 0..6 {
        env.store.enqueue_event("test", &format!("task {i}"), "owner").unwrap();
    }
    let provider = Arc::new(SlowProvider::new(150, false));
    run_daemon(&daemon(&env, provider.clone(), Arc::new(ScriptedApprover::new(vec![]))), opts(6));
    assert_eq!(env.store.count_sessions(&["completed"]).unwrap(), 6);
    assert_eq!(provider.max_inflight.load(Ordering::SeqCst), 2, "cap of 2 reached and never exceeded");
}

#[test]
fn raising_the_cap_lets_more_sessions_overlap() {
    let env = setup("cap3", |c| c["max_concurrent_sessions"] = json!(3));
    for i in 0..6 {
        env.store.enqueue_event("test", &format!("task {i}"), "owner").unwrap();
    }
    let provider = Arc::new(SlowProvider::new(150, false));
    run_daemon(&daemon(&env, provider.clone(), Arc::new(ScriptedApprover::new(vec![]))), opts(6));
    assert_eq!(provider.max_inflight.load(Ordering::SeqCst), 3);
}

#[test]
fn a_session_left_running_by_a_crash_resumes_without_rerunning_its_call() {
    let env = setup("recover", |_| {});
    let (_e, sid) = env.store.enqueue_event("test", "touch a marker", "owner").unwrap();
    assert_eq!(env.store.claim_next().unwrap(), Some(sid)); // a worker took it, then the process died
    env.store
        .append_log(sid, "assistant", json!({ "content": [
            { "type": "tool_use", "id": "x1", "name": "shell_exec", "input": { "command": "touch marker.txt" } }
        ] }))
        .unwrap();
    assert_eq!(env.store.status(sid).unwrap(), "running");

    run_daemon(&daemon(&env, Arc::new(ScriptedProvider::new(vec![text("recovered")])), Arc::new(ScriptedApprover::new(vec![]))), opts(1));

    assert_eq!(env.store.status(sid).unwrap(), "completed");
    assert!(!env.ws.join("marker.txt").exists(), "the unfinished call must not run again");
    assert!(env.audit.rows().unwrap().iter().any(|r| r.entry.decision == "not_rerun"));
}

#[test]
fn an_event_source_feeds_the_queue_and_the_file_moves_only_after_the_event_is_stored() {
    let env = setup("source", |c| {
        c["sources"] = json!([{ "name": "inbox", "command": env!("CARGO_BIN_EXE_source_inbox"), "args": ["inbox"] }]);
    });
    std::fs::create_dir_all(env.ws.join("inbox")).unwrap();
    std::fs::write(env.ws.join("inbox/task1.txt"), "summarise the project").unwrap();

    run_daemon(&daemon(&env, Arc::new(ScriptedProvider::new(vec![text("ok")])), Arc::new(ScriptedApprover::new(vec![]))), opts(1));

    let sessions = env.store.list_sessions(10).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].goal, "summarise the project");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !env.ws.join("inbox/.processed/task1.txt").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(env.ws.join("inbox/.processed/task1.txt").exists(), "acknowledged file is moved aside");
    assert!(!env.ws.join("inbox/task1.txt").exists());
}

#[test]
fn a_source_that_repeats_an_event_creates_only_one_session() {
    let env = setup("dedupe", |_| {});
    let first = env.store.enqueue_event_once("inbox", "a.txt@1", "do it", "owner").unwrap();
    let again = env.store.enqueue_event_once("inbox", "a.txt@1", "do it", "owner").unwrap();
    let other = env.store.enqueue_event_once("inbox", "a.txt@2", "do it", "owner").unwrap();
    assert!(first.is_some());
    assert!(again.is_none());
    assert!(other.is_some());
    assert_eq!(env.store.list_sessions(10).unwrap().len(), 2);
}

#[test]
fn an_approval_waits_in_the_queue_until_the_owner_answers() {
    let env = setup("approval", |_| {});
    env.store.enqueue_event("test", "touch a file", "owner").unwrap();
    let approver = Arc::new(DbApprover::new(Arc::clone(&env.store), Duration::from_secs(20), Duration::from_millis(30)));

    // The owner, in another terminal, sees the structured request and approves it.
    let store = Arc::clone(&env.store);
    let owner = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some(a) = store.pending_approvals().unwrap().first() {
                assert_eq!(a.tool, "shell_exec");
                assert_eq!(a.tier, "irreversible");
                assert!(store.decide_approval(a.id, true).unwrap());
                return true;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        false
    });

    let provider = Arc::new(ScriptedProvider::new(vec![tool("t1", "shell_exec", json!({ "command": "touch approved.txt" })), text("done")]));
    run_daemon(&daemon(&env, provider, approver), opts(1));
    assert!(owner.join().unwrap(), "the request showed up in the approval queue");
    assert!(env.ws.join("approved.txt").exists());
}

#[test]
fn an_unanswered_approval_expires_and_the_action_is_refused() {
    let env = setup("expire", |_| {});
    env.store.enqueue_event("test", "touch a file", "owner").unwrap();
    let approver = Arc::new(DbApprover::new(Arc::clone(&env.store), Duration::from_millis(300), Duration::from_millis(30)));
    let provider = Arc::new(ScriptedProvider::new(vec![tool("t1", "shell_exec", json!({ "command": "touch nope.txt" })), text("done")]));
    run_daemon(&daemon(&env, provider, approver), opts(1));
    assert!(!env.ws.join("nope.txt").exists());
    assert!(env.store.pending_approvals().unwrap().is_empty(), "the request was closed, not left dangling");
    assert!(env.audit.rows().unwrap().iter().any(|r| r.entry.decision == "rejected_by_owner"));
}

#[test]
fn a_denied_approval_is_refused_and_cannot_be_flipped_afterwards() {
    let env = setup("deny", |_| {});
    let id = env.store.request_approval(1, "shell_exec", "exec:shell", "irreversible", "{}").unwrap();
    assert!(env.store.decide_approval(id, false).unwrap());
    assert!(!env.store.decide_approval(id, true).unwrap(), "a decided request stays decided");
    assert_eq!(env.store.approval_status(id).unwrap(), "denied");
}

#[test]
fn shutdown_pauses_running_sessions_and_the_next_start_finishes_them() {
    let env = setup("shutdown", |_| {});
    let (_e, sid) = env.store.enqueue_event("test", "long job", "owner").unwrap();

    // A model that never finishes. The daemon is asked to stop after a moment.
    let looping = Arc::new(SlowProvider::new(60, true));
    let d1 = daemon(&env, looping, Arc::new(ScriptedApprover::new(vec![])));
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        flag.store(true, Ordering::SeqCst);
    });
    d1.run(shutdown, opts(u64::MAX)).unwrap();
    stopper.join().unwrap();
    assert_eq!(env.store.status(sid).unwrap(), "queued", "paused, not lost");
    let calls_before = env.store.load_log(sid).unwrap().iter().filter(|e| e.kind == "assistant").count();
    assert!(calls_before >= 1, "it made progress before the pause");

    // The next daemon picks it up and finishes it.
    let d2 = daemon(&env, Arc::new(ScriptedProvider::new(vec![text("finished")])), Arc::new(ScriptedApprover::new(vec![])));
    run_daemon(&d2, opts(1));
    assert_eq!(env.store.status(sid).unwrap(), "completed");
}

#[test]
fn the_stop_file_asks_the_daemon_to_exit() {
    let env = setup("stopfile", |_| {});
    let d = daemon(&env, Arc::new(ScriptedProvider::new(vec![])), Arc::new(ScriptedApprover::new(vec![])));
    let stop = env.home.join("stop");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(stop, "").unwrap();
    });
    let started = Instant::now();
    run_daemon(&d, DaemonOpts { tick: Duration::from_millis(30), stop_after_finished: None, verbose: false });
    writer.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_worker_that_cannot_start_fails_its_session_and_the_daemon_keeps_running() {
    let env = setup("failed", |c| c["plugins"][0]["command"] = json!("/nonexistent/plugin"));
    let (_e1, a) = env.store.enqueue_event("test", "first", "owner").unwrap();
    let (_e2, b) = env.store.enqueue_event("test", "second", "owner").unwrap();
    let provider = Arc::new(ScriptedProvider::new(vec![]));
    run_daemon(&daemon(&env, provider.clone(), Arc::new(ScriptedApprover::new(vec![]))), opts(2));
    for sid in [a, b] {
        assert_eq!(env.store.status(sid).unwrap(), "failed");
        let note = env.store.load_log(sid).unwrap().into_iter().find(|e| e.kind == "note").expect("a note explains the failure");
        assert!(note.payload["text"].as_str().unwrap().contains("worker error"));
    }
    assert!(provider.seen.lock().unwrap().is_empty(), "the model was never called without its tools");
}

#[test]
fn only_one_daemon_can_hold_the_lock() {
    let env = setup("lock", |_| {});
    let first = DaemonLock::acquire(&env.home).unwrap();
    assert!(DaemonLock::acquire(&env.home).is_err());
    drop(first);
    assert!(DaemonLock::acquire(&env.home).is_ok());
}

#[test]
fn a_stale_lock_from_a_dead_process_is_ignored() {
    let env = setup("stale", |_| {});
    std::fs::write(env.home.join("daemon.pid"), "4294967").unwrap(); // no such process
    assert!(DaemonLock::acquire(&env.home).is_ok());
}
