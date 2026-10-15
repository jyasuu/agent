//! Stage 4 tool plugin: run an owner-approved check command (tests, builds, linters) and return
//! its output, so a verifier can gather objective evidence without a per-run approval.
//!
//! This process is untrusted like every plugin. The core, not this file, decides which commands are
//! allowed: it matches the command against the owner's `check_commands` before the call reaches
//! here. What this plugin adds is the sandbox. Commands run without a shell, with an empty
//! environment, and (with `--sandbox unshare`, the default) in fresh user and network namespaces,
//! so a check cannot reach the network. If the sandbox is requested and cannot be created, the
//! plugin refuses to run anything: it fails closed.
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const MAX_OUT: usize = 100_000;
const TIMEOUT: Duration = Duration::from_secs(120);

fn manifest() -> Value {
    json!({ "tools": [
        { "name": "check_exec", "capability": "exec:check", "scope_args": [],
          "description": "Run one of the owner's allowed check commands (for example the project's test or build command) in a sandbox with no network, and return its exit code and output. The command must match an allowed command exactly.",
          "input_schema": { "type": "object", "properties": { "command": { "type": "string" } }, "required": ["command"] } }
    ] })
}

fn ok(content: String) -> Value {
    json!({ "content": content, "is_error": false })
}

fn err(content: String) -> Value {
    json!({ "content": content, "is_error": true })
}

fn clip(mut s: String) -> String {
    if s.len() > MAX_OUT {
        let mut cut = MAX_OUT;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n[output truncated]");
    }
    s
}

fn sandbox_works() -> bool {
    Command::new("unshare")
        .args(["-r", "-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(command: &str, sandbox: &str) -> Value {
    let argv: Vec<&str> = command.split_whitespace().collect();
    if argv.is_empty() {
        return err("empty command".into());
    }
    let mut cmd;
    match sandbox {
        "unshare" => {
            if !sandbox_works() {
                return err("sandbox unavailable (cannot create user and network namespaces); refusing to run the check".into());
            }
            cmd = Command::new("unshare");
            cmd.args(["-r", "-n", "--"]).args(&argv);
        }
        "none" => {
            cmd = Command::new(argv[0]);
            cmd.args(&argv[1..]);
        }
        other => return err(format!("unknown sandbox mode '{other}'")),
    }
    let child = cmd
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => return err(format!("cannot start '{}': {e}", argv[0])),
    };
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(out)) => {
            let text = format!(
                "exit code: {}\nstdout:\n{}\nstderr:\n{}",
                out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            // A failing check is a result, not a tool error: the verifier reads the exit code.
            ok(clip(text))
        }
        Ok(Err(e)) => err(format!("check failed to run: {e}")),
        Err(_) => {
            let _ = Command::new("pkill").args(["-KILL", "-P", &pid.to_string()]).status();
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            err(format!("check timed out after {}s and was killed", TIMEOUT.as_secs()))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sandbox = args
        .windows(2)
        .find(|w| w[0] == "--sandbox")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "unshare".into());
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let id = req["id"].clone();
        let resp = match req["method"].as_str() {
            Some("manifest") => json!({ "id": id, "result": manifest() }),
            Some("call") => {
                let tool = req["params"]["tool"].as_str().unwrap_or("");
                let result = if tool == "check_exec" {
                    run(req["params"]["args"]["command"].as_str().unwrap_or(""), &sandbox)
                } else {
                    err(format!("unknown tool '{tool}'"))
                };
                json!({ "id": id, "result": result })
            }
            _ => json!({ "id": id, "error": "unknown method" }),
        };
        if writeln!(out, "{resp}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}
