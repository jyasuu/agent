//! Example hook: a guard that vetoes risky calls, redacts secrets from results, and logs events.
//! Everything is a command-line flag, so one binary serves several hooks with different settings.
//!
//!   hook_guard --deny-path '.env*' --deny-path '*.pem' --deny-capability 'exec:*'
//!              --deny-command 'rm\s+-rf' --redact-secrets --redact 'internal-[0-9]+'
//!              --log /var/log/agent-events.jsonl
//!
//! Config:  { "name": "guard", "command": "/path/to/hook_guard",
//!            "args": ["--deny-path", ".env*", "--redact-secrets"],
//!            "subscribe": ["tool.before", "tool.after"] }
//!
//! `tool.before`: deny when the capability matches --deny-capability (exact, or a trailing `*`),
//! when any string in the call's arguments matches --deny-path (the whole value or its last path
//! component, as a glob), or when the `command` argument matches --deny-command (a regex).
//! `tool.after`: replace every match of --redact (and, with --redact-secrets, of common token
//! shapes) with [REDACTED]. `event`: with --log, append each event to a file as one JSON line.
//! Matching is on text: it is a seat belt, not a sandbox. The gate and the sandbox are the walls.
use regex::Regex;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const SECRET_PATTERNS: [&str; 6] = [
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    r"AKIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
];

struct Guard {
    deny_caps: Vec<String>,
    deny_paths: Vec<glob::Pattern>,
    deny_commands: Vec<Regex>,
    redact: Vec<Regex>,
    log: Option<std::path::PathBuf>,
}

fn usage(msg: &str) -> ! {
    eprintln!("hook_guard: {msg}");
    std::process::exit(2);
}

fn parse() -> Guard {
    let mut g = Guard { deny_caps: vec![], deny_paths: vec![], deny_commands: vec![], redact: vec![], log: None };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--deny-capability" => g.deny_caps.push(value()),
            "--deny-path" => {
                let v = value();
                g.deny_paths.push(glob::Pattern::new(&v).unwrap_or_else(|e| usage(&format!("bad --deny-path '{v}': {e}"))));
            }
            "--deny-command" => {
                let v = value();
                g.deny_commands.push(Regex::new(&v).unwrap_or_else(|e| usage(&format!("bad --deny-command '{v}': {e}"))));
            }
            "--redact" => {
                let v = value();
                g.redact.push(Regex::new(&v).unwrap_or_else(|e| usage(&format!("bad --redact '{v}': {e}"))));
            }
            "--redact-secrets" => g.redact.extend(SECRET_PATTERNS.iter().map(|p| Regex::new(p).expect("built-in pattern"))),
            "--log" => g.log = Some(value().into()),
            other => usage(&format!("unknown flag {other}")),
        }
    }
    g
}

fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

impl Guard {
    fn before(&self, input: &Value) -> Value {
        let cap = input["capability"].as_str().unwrap_or("");
        for pat in &self.deny_caps {
            let hit = match pat.strip_suffix('*') {
                Some(prefix) => cap.starts_with(prefix),
                None => cap == pat,
            };
            if hit {
                return json!({ "action": "deny", "reason": format!("capability {cap} is blocked by the guard") });
            }
        }
        let mut values = Vec::new();
        strings(&input["args"], &mut values);
        for v in &values {
            let name = v.trim_end_matches('/').rsplit('/').next().unwrap_or(v);
            let plain = v.strip_prefix("./").unwrap_or(v);
            if self.deny_paths.iter().any(|p| p.matches(plain) || p.matches(name)) {
                return json!({ "action": "deny", "reason": format!("'{}' is a protected path", v.chars().take(80).collect::<String>()) });
            }
        }
        if let Some(cmd) = input["args"]["command"].as_str() {
            if self.deny_commands.iter().any(|r| r.is_match(cmd)) {
                return json!({ "action": "deny", "reason": "this command is blocked by the guard" });
            }
        }
        json!({ "action": "allow" })
    }

    fn after(&self, input: &Value) -> Value {
        let original = input["content"].as_str().unwrap_or("");
        let mut text = original.to_string();
        for r in &self.redact {
            text = r.replace_all(&text, "[REDACTED]").into_owned();
        }
        if text == original {
            json!({ "action": "keep" })
        } else {
            json!({ "action": "replace", "content": text })
        }
    }

    fn event(&self, msg: &Value) {
        let Some(path) = &self.log else { return };
        let line = json!({ "event": msg["event"], "data": msg["data"], "dropped": msg["dropped"] });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn main() {
    let guard = parse();
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        let result = match msg["hook"].as_str() {
            Some("tool.before") => guard.before(&msg["input"]),
            Some("tool.after") => guard.after(&msg["input"]),
            Some("event") => {
                guard.event(&msg);
                continue; // events get no answer
            }
            _ => json!({ "action": "allow" }),
        };
        if writeln!(out, "{}", json!({ "id": msg["id"], "result": result })).and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}
