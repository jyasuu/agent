//! Event source: every new file in a directory becomes one event (the file's text is
//! the task). The file is moved to `<dir>/.processed/` only after the core confirms the
//! event is durably stored, so a crash anywhere before that re-emits it instead of losing it.
//! The unique key (name plus modification time) lets the core ignore the repeat.
//!
//! usage: source_inbox [dir]      (default: inbox, relative to the working directory)
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

const MAX_BYTES: u64 = 100_000;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "inbox".into()));
    let processed = dir.join(".processed");
    if std::fs::create_dir_all(&processed).is_err() {
        std::process::exit(1);
    }

    // key -> file name, for files emitted but not yet acknowledged
    let in_flight: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // When the core acknowledges a key, move that file out of the inbox right away.
    {
        let in_flight = Arc::clone(&in_flight);
        let dir = dir.clone();
        let processed = processed.clone();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                let Some(key) = v["ack"].as_str() else { continue };
                if let Some(name) = in_flight.lock().unwrap().remove(key) {
                    let from = dir.join(&name);
                    let mut to = processed.join(&name);
                    if to.exists() {
                        to = processed.join(format!("{}-{}", key.replace('/', "_"), name));
                    }
                    let _ = std::fs::rename(from, to);
                }
            }
            // The core went away; there is nothing left to report to.
            std::process::exit(0);
        });
    }

    let mut out = std::io::stdout().lock();
    loop {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut files: Vec<_> = rd.filter_map(|e| e.ok()).collect();
            files.sort_by_key(|e| e.file_name());
            for e in files {
                let name = e.file_name().to_string_lossy().to_string();
                let Ok(meta) = e.metadata() else { continue };
                if !meta.is_file() || name.starts_with('.') || meta.len() > MAX_BYTES {
                    continue;
                }
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let key = format!("{name}@{mtime}");
                if in_flight.lock().unwrap().contains_key(&key) {
                    continue;
                }
                let Ok(payload) = std::fs::read_to_string(e.path()) else { continue };
                in_flight.lock().unwrap().insert(key.clone(), name);
                let line = json!({ "event": { "key": key, "payload": payload } });
                if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
