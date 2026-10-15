//! The code tools ported from hostmcp (fs_edit, fs_glob, fs_grep, fs_tree, and the extended fs_read
//! and shell_exec), tested at the same seam as everything else: a scripted model drives the real
//! out-of-process plugin through the real gate, and the assertions look at the session log, the
//! audit log and files on disk. A few tests talk to the plugin binary directly, for the things the
//! seam cannot see (its manifest, its own process state, what it does when it is not gated).
mod common;
use agent_core::provider::ScriptedProvider;
use agent_core::runner::{Outcome, ScriptedApprover};
use agent_core::upgrade;
use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

fn env(name: &str) -> Env {
    setup(name, all_grants(), |_| {})
}

fn write(ws: &Path, rel: &str, content: &str) {
    let p = ws.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn content(r: &Value) -> String {
    r["content"].as_str().unwrap_or("").to_string()
}

// ---- the plugin on its own ---------------------------------------------------------------------

struct Direct {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
    id: u64,
}

impl Direct {
    fn start(cwd: &Path, args: &[&str]) -> Self {
        Self::start_cmd(env!("CARGO_BIN_EXE_plugin_fs"), args, cwd)
    }

    fn start_cmd(program: &str, args: &[&str], cwd: &Path) -> Self {
        let mut child = Command::new(program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Direct { child, stdin, out, id: 0 }
    }

    fn ask(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        writeln!(self.stdin, "{}", json!({ "id": self.id, "method": method, "params": params })).unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()["result"].clone()
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        self.ask("call", json!({ "tool": tool, "args": args }))
    }
}

impl Drop for Direct {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("agent-codetools-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

#[test]
fn the_manifest_names_the_capability_and_marks_exactly_the_tree_walkers_recursive() {
    let d = tmp("manifest");
    let mut p = Direct::start(&d, &[]);
    let m = p.ask("manifest", json!({}));
    let tools = m["tools"].as_array().unwrap();
    let by = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap_or_else(|| panic!("no tool {n}"));
    for (name, cap) in [("fs_read", "fs:read"), ("fs_list", "fs:read"), ("fs_glob", "fs:read"), ("fs_grep", "fs:read"), ("fs_tree", "fs:read"), ("fs_write", "fs:write"), ("fs_edit", "fs:write"), ("shell_exec", "exec:shell")] {
        assert_eq!(by(name)["capability"], cap, "{name}");
    }
    for name in ["fs_glob", "fs_grep", "fs_tree"] {
        assert_eq!(by(name)["recursive"], true, "{name} walks a tree");
        assert_eq!(by(name)["scope_args"], json!(["path"]));
        assert!(by(name)["input_schema"]["required"].as_array().unwrap().contains(&json!("path")), "{name}: the gate cannot default a missing path, so it is required");
    }
    for name in ["fs_read", "fs_list", "fs_write", "fs_edit", "shell_exec"] {
        assert!(by(name).get("recursive").is_none(), "{name} does not walk a tree");
    }
}

#[test]
fn the_tree_tools_never_enter_the_agent_home_or_git_even_when_asked_directly() {
    // Defense in depth. The gate is what refuses; this is what an honest plugin does anyway.
    let d = tmp("skip");
    write(&d, ".agent/sessions.db", "SESSION_SECRET");
    write(&d, ".git/config", "SESSION_SECRET");
    write(&d, ".agent-undo/old.txt", "SESSION_SECRET");
    write(&d, "src/a.rs", "SESSION_SECRET in the open");
    let mut p = Direct::start(&d, &[]);
    for (tool, args) in [
        ("fs_grep", json!({ "pattern": "SESSION_SECRET", "path": "." })),
        ("fs_glob", json!({ "pattern": "**/*", "path": "." })),
        ("fs_tree", json!({ "path": "." })),
    ] {
        let r = p.call(tool, args);
        let out = content(&r);
        assert!(out.contains("a.rs"), "{tool} still finds ordinary files: {out}");
        for hidden in [".agent", ".git", "sessions.db", "old.txt"] {
            assert!(!out.contains(hidden), "{tool} must not show {hidden}: {out}");
        }
    }
}

#[test]
fn read_before_edit_is_per_plugin_process() {
    let d = tmp("process");
    write(&d, "f.txt", "one\n");
    let mut a = Direct::start(&d, &[]);
    assert_eq!(a.call("fs_read", json!({ "path": "f.txt" }))["is_error"], false);
    let r = a.call("fs_edit", json!({ "path": "f.txt", "old_string": "one", "new_string": "two" }));
    assert_eq!(r["is_error"], false, "{r}");
    // A fresh process (for example after the host restarted a hung plugin) has read nothing.
    let mut b = Direct::start(&d, &[]);
    let r = b.call("fs_edit", json!({ "path": "f.txt", "old_string": "two", "new_string": "three" }));
    assert_eq!(r["is_error"], true);
    assert!(content(&r).contains("must read"), "{r}");
    assert_eq!(std::fs::read_to_string(d.join("f.txt")).unwrap(), "two\n");
}

#[test]
fn a_command_that_runs_too_long_is_stopped_with_everything_it_started() {
    let d = tmp("timeout");
    let mut p = Direct::start(&d, &["--max-shell-secs", "2"]);
    let start = Instant::now();
    // Asks for far more than the configured maximum; the maximum wins. The background child must die too.
    let r = p.call("shell_exec", json!({ "command": "sleep 30 & echo $! > child.pid; wait", "timeout_secs": 100 }));
    assert_eq!(r["is_error"], true);
    assert!(content(&r).contains("timed out after 2s"), "{r}");
    assert!(start.elapsed() < Duration::from_secs(10), "it did not wait for the 30 second sleep");
    let pid: u32 = std::fs::read_to_string(d.join("child.pid")).unwrap().trim().parse().unwrap();
    let mut gone = false;
    for _ in 0..40 {
        // A killed child may linger as a zombie until its parent reaps it; both mean "not running".
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rsplit(')').next().and_then(|r| r.trim().chars().next()));
        if state.map_or(true, |c| c == 'Z') {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "the background child of the timed-out command is still running");
}

#[test]
fn the_default_shell_timeout_and_a_bad_timeout_argument() {
    let d = tmp("shellargs");
    let mut p = Direct::start(&d, &[]);
    let r = p.call("shell_exec", json!({ "command": "echo hi" }));
    assert_eq!(r["is_error"], false);
    assert!(content(&r).contains("exit code: 0") && content(&r).contains("hi"), "{r}");
    let r = p.call("shell_exec", json!({ "command": "echo hi", "timeout_secs": 0 }));
    assert_eq!(r["is_error"], true, "a zero timeout is refused, not treated as no limit: {r}");
    let r = p.call("shell_exec", json!({ "command": "echo hi", "timeout_secs": "soon" }));
    assert_eq!(r["is_error"], true, "{r}");
}

// ---- through the session runner ----------------------------------------------------------------

#[test]
fn fs_edit_needs_a_read_first_then_edits_and_keeps_an_undo_copy() {
    let env = env("edit");
    write(&env.ws, "notes.txt", "alpha\nbeta\n");
    let p = ScriptedProvider::new(vec![
        tool("e0", "fs_edit", json!({ "path": "notes.txt", "old_string": "beta", "new_string": "gamma" })),
        tool("r1", "fs_read", json!({ "path": "notes.txt" })),
        tool("e1", "fs_edit", json!({ "path": "notes.txt", "old_string": "beta", "new_string": "gamma" })),
        text("done"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "edit the notes");
    assert!(matches!(out, Outcome::Completed { .. }));
    let r = results(&env, sid);
    assert_eq!(r[0]["is_error"], true, "no edit without a read: {}", r[0]);
    assert!(content(&r[0]).contains("must read"), "{}", r[0]);
    assert_eq!(r[2]["is_error"], false, "{}", r[2]);
    assert_eq!(std::fs::read_to_string(env.ws.join("notes.txt")).unwrap(), "alpha\ngamma\n");
    let undo: Vec<_> = std::fs::read_dir(env.ws.join(".agent-undo")).unwrap().filter_map(|e| e.ok()).collect();
    assert_eq!(undo.len(), 1, "exactly one undo copy, made by the successful edit");
    assert_eq!(std::fs::read_to_string(undo[0].path()).unwrap(), "alpha\nbeta\n", "it holds the old content");
    assert!(decisions(&env).iter().all(|d| !d.contains("approved_by_owner") && !d.contains("rejected")), "reversible and read-only calls need no approval: {:?}", decisions(&env));
}

#[test]
fn fs_edit_refuses_ambiguous_missing_empty_and_identical_edits_and_replace_all_works() {
    let env = env("edit-rules");
    write(&env.ws, "dup.txt", "x\nx\ny\n");
    let p = ScriptedProvider::new(vec![
        tool("r", "fs_read", json!({ "path": "dup.txt" })),
        tool("a", "fs_edit", json!({ "path": "dup.txt", "old_string": "x", "new_string": "z" })),
        tool("b", "fs_edit", json!({ "path": "dup.txt", "old_string": "nope", "new_string": "z" })),
        tool("c", "fs_edit", json!({ "path": "dup.txt", "old_string": "", "new_string": "z" })),
        tool("d", "fs_edit", json!({ "path": "dup.txt", "old_string": "x", "new_string": "x" })),
        tool("e", "fs_edit", json!({ "path": "missing.txt", "old_string": "x", "new_string": "z" })),
        tool("f", "fs_edit", json!({ "path": "dup.txt", "old_string": "x", "new_string": "z", "replace_all": true })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "try the edit rules");
    let r = results(&env, sid);
    assert!(content(&r[1]).contains("2 matches"), "ambiguous: {}", r[1]);
    assert!(content(&r[2]).contains("not found"), "{}", r[2]);
    assert!(content(&r[3]).contains("must not be empty"), "{}", r[3]);
    assert!(content(&r[4]).contains("identical"), "{}", r[4]);
    assert!(content(&r[5]).contains("not found") || content(&r[5]).contains("File not found"), "{}", r[5]);
    for i in 1..=5 {
        assert_eq!(r[i]["is_error"], true, "call {i}");
    }
    assert_eq!(r[6]["is_error"], false, "{}", r[6]);
    assert!(content(&r[6]).contains("2 replacements"), "{}", r[6]);
    assert_eq!(std::fs::read_to_string(env.ws.join("dup.txt")).unwrap(), "z\nz\ny\n", "only the last call changed the file");
}

#[test]
fn fs_read_with_offset_and_limit_numbers_lines_and_says_where_to_continue() {
    let env = env("read");
    let body: String = (1..=10).map(|i| format!("line{i}\n")).collect();
    write(&env.ws, "ten.txt", &body);
    write(&env.ws, "empty.txt", "");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_read", json!({ "path": "ten.txt" })),
        tool("b", "fs_read", json!({ "path": "ten.txt", "offset": 3, "limit": 2 })),
        tool("c", "fs_read", json!({ "path": "ten.txt", "offset": 9 })),
        tool("d", "fs_read", json!({ "path": "ten.txt", "offset": 99 })),
        tool("e", "fs_read", json!({ "path": "empty.txt", "limit": 5 })),
        tool("f", "fs_read", json!({ "path": "ten.txt", "offset": 0 })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "read in slices");
    let r = results(&env, sid);
    assert_eq!(content(&r[0]), body, "without offset or limit the answer is the file, exactly as before");
    assert!(content(&r[1]).starts_with("3: line3\n4: line4\n"), "{}", r[1]);
    assert!(content(&r[1]).contains("Showing 3-4 of 10") && content(&r[1]).contains("offset=5"), "{}", r[1]);
    assert!(content(&r[2]).contains("9: line9\n10: line10\n") && !content(&r[2]).contains("more lines"), "{}", r[2]);
    assert!(content(&r[3]).contains("past the end"), "{}", r[3]);
    assert_eq!(content(&r[4]), "(empty file)");
    assert_eq!(r[5]["is_error"], true, "offset 0 is not a line number: {}", r[5]);
}

#[test]
fn glob_grep_and_tree_find_files_honour_gitignore_and_the_include_braces() {
    let env = env("search");
    write(&env.ws, ".gitignore", "target/\n");
    write(&env.ws, "src/main.rs", "fn main() { println!(\"needle\"); }\n");
    write(&env.ws, "src/lib/util.rs", "// needle again\n");
    write(&env.ws, "web/app.ts", "const needle = 1;\n");
    write(&env.ws, "web/app.tsx", "const needle = 2;\n");
    write(&env.ws, "web/app.css", "needle {}\n");
    write(&env.ws, "target/debug/out.rs", "needle in build output\n");
    let p = ScriptedProvider::new(vec![
        tool("g1", "fs_glob", json!({ "pattern": "**/*.rs", "path": "." })),
        tool("g2", "fs_grep", json!({ "pattern": "needle", "path": "." , "include": "*.{ts,tsx}" })),
        tool("g3", "fs_grep", json!({ "pattern": "n[e", "path": "." })),
        tool("g4", "fs_grep", json!({ "pattern": "needle", "path": "src/main.rs" })),
        tool("g5", "fs_grep", json!({ "pattern": "absent-from-everything", "path": "." })),
        tool("t1", "fs_tree", json!({ "path": ".", "depth": 1 })),
        tool("t2", "fs_tree", json!({ "path": "src" })),
        tool("g6", "fs_glob", json!({ "pattern": "*.nothing", "path": "web" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "look around");
    let r = results(&env, sid);
    let g1 = content(&r[0]);
    assert!(g1.contains("src/main.rs") && g1.contains("src/lib/util.rs"), "{g1}");
    assert!(!g1.contains("target"), ".gitignore is respected: {g1}");
    let g2 = content(&r[1]);
    assert!(g2.contains("app.ts:") && g2.contains("app.tsx:") && !g2.contains("app.css"), "braces in include work: {g2}");
    assert!(g2.contains("Line 1: const needle = 1;"), "{g2}");
    assert_eq!(r[2]["is_error"], true, "a bad regex is an error, not a crash: {}", r[2]);
    assert!(content(&r[2]).contains("invalid regex"), "{}", r[2]);
    assert!(content(&r[3]).contains("Found 1 match") && content(&r[3]).contains("main.rs"), "a single file can be searched: {}", r[3]);
    assert!(content(&r[4]).contains("No matches found"), "{}", r[4]);
    let t1 = content(&r[5]);
    assert!(t1.contains("src/") && t1.contains("web/") && !t1.contains("main.rs"), "depth 1 stops at the top level: {t1}");
    assert!(!t1.contains("target"), "{t1}");
    let t2 = content(&r[6]);
    assert!(t2.ends_with("src/\nlib/\n  util.rs\nmain.rs"), "children of the root are not indented, deeper levels are: {t2}");
    assert!(content(&r[7]).contains("No files found"), "{}", r[7]);
    assert!(r.iter().enumerate().all(|(i, x)| i == 2 || x["is_error"] == false), "{r:?}");
}

#[test]
fn grep_reports_when_there_were_more_than_the_limit() {
    let env = env("limit");
    let many: String = (0..150).map(|i| format!("hit {i}\n")).collect();
    write(&env.ws, "many.txt", &many);
    let p = ScriptedProvider::new(vec![tool("g", "fs_grep", json!({ "pattern": "hit", "path": "many.txt" })), text("done")]);
    let (sid, _) = run(&env, &p, &no_approvals(), "find lots");
    let out = content(&results(&env, sid)[0]);
    assert!(out.contains("Found 100 matches (more matches available)"), "{out}");
    assert!(out.contains("Line 100: hit 99") && !out.contains("Line 101"), "{out}");
}

#[test]
fn the_gate_applies_the_grants_scope_to_the_new_tools() {
    let env = setup("scope", json!([{ "capability": "fs:read", "tier": "read_only", "scope": "sub" }, { "capability": "fs:write", "tier": "reversible", "scope": "sub" }]), |_| {});
    write(&env.ws, "sub/in.txt", "inside needle\n");
    write(&env.ws, "out.txt", "outside needle\n");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_grep", json!({ "pattern": "needle", "path": "sub" })),
        tool("b", "fs_grep", json!({ "pattern": "needle", "path": "." })),
        tool("c", "fs_glob", json!({ "pattern": "*", "path": "../" })),
        tool("d", "fs_tree", json!({ "path": "/" })),
        tool("e", "fs_read", json!({ "path": "out.txt" })),
        tool("f", "fs_edit", json!({ "path": "out.txt", "old_string": "outside", "new_string": "changed" })),
        tool("g", "fs_grep", json!({ "pattern": "needle" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "stay in scope");
    let r = results(&env, sid);
    assert_eq!(r[0]["is_error"], false, "{}", r[0]);
    assert!(content(&r[0]).contains("in.txt"));
    for i in 1..=6 {
        assert_eq!(r[i]["is_error"], true, "call {i} must be refused: {}", r[i]);
        assert!(content(&r[i]).contains("DENIED"), "call {i}: {}", r[i]);
    }
    assert!(content(&r[6]).contains("missing"), "a missing path is refused by the gate, never defaulted: {}", r[6]);
    assert_eq!(std::fs::read_to_string(env.ws.join("out.txt")).unwrap(), "outside needle\n");
}

#[test]
fn a_recursive_tool_cannot_be_pointed_at_a_directory_that_holds_the_agent_home() {
    // The default layout: the home (.agent) sits inside the workspace.
    let mut env = env("home-inside");
    env.home = env.ws.join(".agent");
    write(&env.ws, ".agent/delegate/rules.json", "TOP_SECRET_RULES");
    write(&env.ws, "src/a.rs", "TOP_SECRET_RULES leaked?\n");
    write(&env.ws, "README.md", "hello\n");
    let p = ScriptedProvider::new(vec![
        tool("a", "fs_grep", json!({ "pattern": "TOP_SECRET", "path": "." })),
        tool("b", "fs_glob", json!({ "pattern": "**/*", "path": "." })),
        tool("c", "fs_tree", json!({ "path": "." })),
        tool("d", "fs_grep", json!({ "pattern": "TOP_SECRET", "path": ".agent" })),
        tool("e", "fs_grep", json!({ "pattern": "TOP_SECRET", "path": "src" })),
        tool("f", "fs_list", json!({ "path": "." })),
        tool("g", "fs_read", json!({ "path": ".agent/delegate/rules.json" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "search everything");
    let r = results(&env, sid);
    for i in [0, 1, 2] {
        assert_eq!(r[i]["is_error"], true, "call {i}: {}", r[i]);
        assert!(content(&r[i]).contains("DENIED") && content(&r[i]).contains("narrower directory"), "call {i}: {}", r[i]);
        assert!(!content(&r[i]).contains("TOP_SECRET"), "{}", r[i]);
    }
    assert!(content(&r[3]).contains("protected"), "the home itself is protected: {}", r[3]);
    assert_eq!(r[4]["is_error"], false, "a narrower directory is fine: {}", r[4]);
    assert!(content(&r[4]).contains("a.rs"));
    assert_eq!(r[5]["is_error"], false, "fs_list does not recurse, so it is unaffected: {}", r[5]);
    assert_eq!(r[6]["is_error"], true, "{}", r[6]);
}

#[test]
fn shell_exec_still_needs_the_owner_and_accepts_a_timeout() {
    let env = env("shell");
    let p = ScriptedProvider::new(vec![
        tool("s1", "shell_exec", json!({ "command": "sleep 5", "timeout_secs": 1 })),
        tool("s2", "shell_exec", json!({ "command": "echo ok" })),
        text("done"),
    ]);
    let a = ScriptedApprover::new(vec![true, false]);
    let start = Instant::now();
    let (sid, _) = run(&env, &p, &a, "run things");
    assert!(start.elapsed() < Duration::from_secs(5), "the timeout, not the sleep, ended the first command");
    let r = results(&env, sid);
    assert!(content(&r[0]).contains("timed out after 1s"), "{}", r[0]);
    assert_eq!(r[1]["is_error"], true, "the second was refused by the owner: {}", r[1]);
    assert_eq!(decisions(&env), vec!["shell_exec:approved_by_owner", "shell_exec:failed", "shell_exec:rejected_by_owner"]);
    assert_eq!(a.requests.lock().unwrap().len(), 2, "every shell call went to the owner");
}


// ---- bootstrapping: the same tools, written and deployed at run time ---------------------------
//
// Plugins the upgrade pipeline installs are sandboxed python3 or sh. `plugins/codetools` is a
// standard-library port of the built-in code tools. Two things must hold for "the agent can
// bootstrap these tools": the port really behaves like the built-in tools, and an agent that
// writes it goes through the real pipeline and gets working tools in its next session.

const CODETOOLS_PY: &str = include_str!("../plugins/codetools/plugin.py");
const CODETOOLS_JSON: &str = include_str!("../plugins/codetools/plugin.json");
const PLUGIN_PY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/codetools/plugin.py");

fn fixture(dir: &Path) {
    write(dir, ".gitignore", "target/\n*.log\n");
    write(dir, "src/main.rs", "fn main() {\n    println!(\"needle\");\n}\n");
    write(dir, "src/lib/util.rs", "// needle again\r\npub fn f() {}\n");
    write(dir, "src/lib/mod.rs", "mod util;\n");
    write(dir, "web/app.ts", "const needle = 1;\n");
    write(dir, "web/app.tsx", "const needle = 2;\n");
    write(dir, "web/app.css", "needle {}\n");
    write(dir, "web/deep/er/x.ts", "needle\n");
    write(dir, "target/debug/out.rs", "needle in build output\n");
    write(dir, "build.log", "needle in a log\n");
    write(dir, "build.rs", "fn main() {}\n");
    write(dir, "long.txt", &format!("{}\n", "x".repeat(2500)));
    write(dir, "ten.txt", &(1..=10).map(|i| format!("line{i}\n")).collect::<String>());
    write(dir, "empty.txt", "");
    // Distinct modification times, so "newest first" has one answer.
    let base = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for (i, f) in ["src/main.rs", "src/lib/util.rs", "build.rs", "web/app.ts", "web/deep/er/x.ts", "src/lib/mod.rs"].iter().enumerate() {
        let file = std::fs::OpenOptions::new().write(true).open(dir.join(f)).unwrap();
        file.set_modified(base + Duration::from_secs(100 * i as u64)).unwrap();
    }
}

/// The text a call returns, with the tool-name prefix and the undo timestamp made comparable.
fn comparable(r: &Value) -> (bool, String) {
    let re_ms = |s: &str| {
        let mut out = String::new();
        let mut run = 0;
        for c in s.chars() {
            if c.is_ascii_digit() { run += 1; } else { run = 0; }
            if run == 11 { out.truncate(out.len().saturating_sub(10)); out.push_str("<ms>"); }
            if run <= 10 || !c.is_ascii_digit() { out.push(c); }
        }
        out
    };
    let text = content(r).replace("code_", "fs_");
    let text = match text.find(" (os error ") { Some(i) => text[..i].to_string(), None => text };
    (r["is_error"].as_bool().unwrap(), re_ms(&text))
}

#[test]
fn the_python_port_behaves_like_the_built_in_tools() {
    let (a, b) = (tmp("parity-rust"), tmp("parity-py"));
    fixture(&a);
    fixture(&b);
    let mut rust = Direct::start(&a, &[]);
    let mut py = Direct::start_cmd("python3", &[PLUGIN_PY], &b);
    let pairs: Vec<(&str, Value)> = vec![
        ("read", json!({ "path": "ten.txt" })),
        ("read", json!({ "path": "ten.txt", "offset": 3, "limit": 2 })),
        ("read", json!({ "path": "ten.txt", "offset": 9 })),
        ("read", json!({ "path": "ten.txt", "offset": 99 })),
        ("read", json!({ "path": "ten.txt", "offset": 0 })),
        ("read", json!({ "path": "empty.txt", "limit": 5 })),
        ("read", json!({ "path": "long.txt", "limit": 1 })),
        ("read", json!({ "path": "src/lib/util.rs", "offset": 1 })),
        ("read", json!({ "path": "nope.txt" })),
        ("glob", json!({ "pattern": "**/*.rs", "path": "." })),
        ("glob", json!({ "pattern": "*.ts", "path": "web" })),
        ("glob", json!({ "pattern": "src/**/*.rs", "path": "." })),
        ("glob", json!({ "pattern": "**/x.ts", "path": "." })),
        ("glob", json!({ "pattern": "*.nothing", "path": "." })),
        ("glob", json!({ "pattern": "*.rs", "path": "nope" })),
        ("grep", json!({ "pattern": "needle", "path": "." })),
        ("grep", json!({ "pattern": "needle", "path": ".", "include": "*.{ts,tsx}" })),
        ("grep", json!({ "pattern": "needle", "path": "src/main.rs" })),
        ("grep", json!({ "pattern": "^pub fn", "path": "src" })),
        ("grep", json!({ "pattern": "absent-from-everything", "path": "." })),
        ("grep", json!({ "pattern": "n[e", "path": "." })),
        ("tree", json!({ "path": "." })),
        ("tree", json!({ "path": ".", "depth": 1 })),
        ("tree", json!({ "path": "src", "depth": 2 })),
        ("tree", json!({ "path": "ten.txt" })),
    ];
    for (name, args) in pairs {
        let (r, p) = (rust.call(&format!("fs_{name}"), args.clone()), py.call(&format!("code_{name}"), args.clone()));
        let (r, p) = (comparable(&r), comparable(&p));
        if name == "grep" && args["pattern"] == "n[e" {
            assert!(r.0 && p.0, "a bad pattern is an error in both: {r:?} {p:?}");
            continue; // the two regex engines word their complaints differently
        }
        assert_eq!(r, p, "{name} {args}");
    }
    // The edit rules, step by step, on the same file, with the same answers.
    let steps: Vec<(&str, Value)> = vec![
        ("edit", json!({ "path": "ten.txt", "old_string": "line1\n", "new_string": "first\n" })),
        ("read", json!({ "path": "ten.txt" })),
        ("edit", json!({ "path": "ten.txt", "old_string": "line", "new_string": "L" })),
        ("edit", json!({ "path": "ten.txt", "old_string": "nope", "new_string": "L" })),
        ("edit", json!({ "path": "ten.txt", "old_string": "", "new_string": "L" })),
        ("edit", json!({ "path": "ten.txt", "old_string": "line2", "new_string": "line2" })),
        ("edit", json!({ "path": "missing.txt", "old_string": "a", "new_string": "b" })),
        ("edit", json!({ "path": "ten.txt", "old_string": "line", "new_string": "L", "replace_all": true })),
    ];
    for (name, args) in steps {
        let (r, p) = (comparable(&rust.call(&format!("fs_{name}"), args.clone())), comparable(&py.call(&format!("code_{name}"), args.clone())));
        assert_eq!(r, p, "{name} {args}");
    }
    assert_eq!(std::fs::read_to_string(a.join("ten.txt")).unwrap(), std::fs::read_to_string(b.join("ten.txt")).unwrap());
    assert_eq!(std::fs::read_dir(a.join(".agent-undo")).unwrap().count(), std::fs::read_dir(b.join(".agent-undo")).unwrap().count(), "same number of undo copies");
}

#[test]
fn the_shipped_plugin_json_is_exactly_what_the_script_reports() {
    let d = tmp("pjson");
    let mut py = Direct::start_cmd("python3", &[PLUGIN_PY], &d);
    let reported = py.ask("manifest", json!({}))["tools"].clone();
    let declared: Value = serde_json::from_str(CODETOOLS_JSON).unwrap();
    assert_eq!(declared["tools"], reported, "regenerate plugin.json from the script when the script changes");
    assert_eq!(declared["name"], "codetools");
    let names: Vec<_> = reported.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    let mut builtin = Direct::start(&d, &[]);
    let builtin_names: Vec<String> = builtin.ask("manifest", json!({}))["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    assert!(names.iter().all(|n| !builtin_names.contains(n)), "no clash with the built-in tools: {names:?}");
}

#[test]
fn the_guide_tells_an_agent_about_the_recursive_flag_and_the_file_tools() {
    let g = upgrade::plugin_guide();
    for needle in ["recursive", "scope_args", "edit by exact text replacement", "refused unless the file was read first", "fs:read and fs:write"] {
        assert!(g.contains(needle), "the guide must mention {needle}");
    }
}

#[test]
fn an_agent_can_write_check_propose_and_next_session_use_the_code_tools() {
    if !have_bwrap() { return; }
    let env = boot_env("bootstrap-code");
    boot_baseline(&env);
    fixture(&env.ws);

    // Session 1, the agent: write the plugin with its own tools, check it, propose it.
    let p = ScriptedProvider::new(vec![
        tool("w1", "fs_write", json!({ "path": "dev/codetools/plugin.json", "content": CODETOOLS_JSON })),
        tool("w2", "fs_write", json!({ "path": "dev/codetools/plugin.py", "content": CODETOOLS_PY })),
        tool("c1", "check_plugin", json!({ "path": "dev/codetools" })),
        tool("p1", "propose_upgrade", json!({ "path": "dev/codetools" })),
        text("proposed codetools"),
    ]);
    let (sid, out) = run(&env, &p, &no_approvals(), "give yourself better code tools");
    assert!(matches!(out, Outcome::Completed { .. }));
    let r = results(&env, sid);
    assert!(r.iter().all(|x| x["is_error"] == false), "every step of the agent's own work succeeded: {r:?}");
    assert!(content(&r[2]).contains("contract tests: passed"), "{}", r[2]);
    let proposed = env.store.list_upgrades().unwrap();
    assert_eq!(proposed.len(), 1);
    assert!(upgrade::installed_plugins(&env.home).is_empty(), "the agent could not install it");

    // The owner: checks, then approval. Every capability asked for is already granted.
    let id = proposed[0].id;
    let status = upgrade::run_pipeline(&env.cfg, &env.store, &env.audit, id, &ok_verify).unwrap();
    assert_eq!(status, "ready_for_review", "{:?}", env.store.get_upgrade(id).unwrap().report);
    upgrade::approve(&env.cfg, &env.store, &env.audit, id, "owner", &ok_verify).unwrap();

    // Session 2: the tools are simply there, behind the same gate, with the recursive rule intact.
    let p = ScriptedProvider::new(vec![
        tool("t1", "code_tree", json!({ "path": "src" })),
        tool("e0", "code_edit", json!({ "path": "src/main.rs", "old_string": "needle", "new_string": "found" })),
        tool("r1", "code_read", json!({ "path": "src/main.rs", "offset": 1, "limit": 2 })),
        tool("e1", "code_edit", json!({ "path": "src/main.rs", "old_string": "needle", "new_string": "found" })),
        tool("g1", "code_grep", json!({ "pattern": "found", "path": "src" })),
        tool("g2", "code_grep", json!({ "pattern": "found", "path": "." })),
        tool("g3", "code_glob", json!({ "pattern": "**/*.rs", "path": "src" })),
        text("done"),
    ]);
    let (sid, _) = run(&env, &p, &no_approvals(), "use the new tools");
    let r = results(&env, sid);
    assert!(content(&r[0]).contains("main.rs") && content(&r[0]).contains("util.rs"), "{}", r[0]);
    assert_eq!(r[1]["is_error"], true, "read before edit holds in the installed plugin too: {}", r[1]);
    assert!(content(&r[2]).starts_with("1: fn main() {"), "{}", r[2]);
    assert_eq!(r[3]["is_error"], false, "{}", r[3]);
    assert!(std::fs::read_to_string(env.ws.join("src/main.rs")).unwrap().contains("found"));
    assert!(content(&r[4]).contains("Found 1 match"), "{}", r[4]);
    assert_eq!(r[5]["is_error"], true, "the installed plugin's own recursive flag reaches the gate: {}", r[5]);
    assert!(content(&r[5]).contains("DENIED") && content(&r[5]).contains("narrower directory"), "{}", r[5]);
    assert!(content(&r[6]).contains("main.rs"), "{}", r[6]);
}

#[test]
fn an_installed_code_plugin_cannot_see_the_agent_home_even_if_asked_to_look() {
    // The gate refuses the root. This is the second wall: the sandbox hides the home from the plugin.
    if !have_bwrap() { return; }
    let env = boot_env("bootstrap-hidden");
    write(&env.ws, ".agent/delegate/rules.json", "TOP_SECRET_RULES");
    write(&env.ws, "src/a.rs", "ordinary\n");
    let pc = upgrade::installed_plugins(&env.home);
    assert!(pc.is_empty());
    // Run the plugin the way the host runs an installed one: python3, sandboxed, home hidden.
    let sb = agent_core::config::SandboxConfig { network: false, workspace_readonly: false, ro_binds: vec![PLUGIN_PY.trim_end_matches("plugin.py").into()], rw_binds: vec![], hide: vec![env.home.clone()], program: None };
    let (prog, args) = agent_core::sandbox::wrap(&sb, &env.ws, "python3", &[PLUGIN_PY.to_string()]).unwrap();
    let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let mut py = Direct::start_cmd(&prog, &args, &env.ws);
    let r = py.call("code_grep", json!({ "pattern": "TOP_SECRET", "path": "." }));
    assert!(content(&r).contains("No matches"), "{r}");
    let r = py.call("code_read", json!({ "path": ".agent/delegate/rules.json" }));
    assert_eq!(r["is_error"], true, "{r}");
}
