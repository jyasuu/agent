//! Stage 1 tool plugin: file read/list/write and shell, over line-delimited JSON on stdio.
//!
//! This process is untrusted by design. It enforces nothing about permissions; the
//! core's gate checks every call before it gets here. Its manifest only names the
//! capability each tool needs.
use ignore::WalkBuilder;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_READ: u64 = 1_000_000;
const MAX_OUT: usize = 100_000;
const DEFAULT_SHELL_SECS: u64 = 20;
/// Must stay below the plugin's `call_timeout_secs` (30 in `agent init`), or the host kills the whole
/// plugin before the command's own timeout fires. Raise both together: `--max-shell-secs N`.
const DEFAULT_MAX_SHELL_SECS: u64 = 25;
const DEFAULT_READ_LINES: usize = 2000;
const MAX_LINE_CHARS: usize = 2000;
const MATCH_LIMIT: usize = 100;
const TREE_DEFAULT_DEPTH: usize = 3;
const TREE_MAX_ENTRIES: usize = 500;
/// Directories the tree tools never enter: version control, the agent's home and its undo copies.
const SKIP_DIRS: [&str; 3] = [".git", ".agent", ".agent-undo"];

fn manifest() -> Value {
    let path = json!({ "type": "string" });
    json!({ "tools": [
        { "name": "fs_read", "capability": "fs:read", "scope_args": ["path"],
          "description": "Read a UTF-8 text file (up to 1 MB). Path is relative to the workspace. With offset (1-based line) and/or limit (default 2000 lines) the result has numbered lines and says where to continue. A file must be read before fs_edit can change it.",
          "input_schema": { "type": "object", "properties": { "path": path, "offset": { "type": "integer", "minimum": 1 }, "limit": { "type": "integer", "minimum": 1 } }, "required": ["path"] } },
        { "name": "fs_list", "capability": "fs:read", "scope_args": ["path"],
          "description": "List the entries of a directory. Directories end with '/'.",
          "input_schema": { "type": "object", "properties": { "path": path }, "required": ["path"] } },
        { "name": "fs_write", "capability": "fs:write", "scope_args": ["path"],
          "description": "Write a text file, creating parent directories. An existing file is copied to .agent-undo/ first.",
          "input_schema": { "type": "object", "properties": { "path": path, "content": { "type": "string" } }, "required": ["path", "content"] } },
        { "name": "fs_edit", "capability": "fs:write", "scope_args": ["path"],
          "description": "Replace exact text in a file you have read with fs_read. Fails if old_string is not found, or matches more than once unless replace_all is true. Keep indentation exactly as in the file; never include the line-number prefix. The old file is copied to .agent-undo/ first.",
          "input_schema": { "type": "object", "properties": { "path": path, "old_string": { "type": "string" }, "new_string": { "type": "string" }, "replace_all": { "type": "boolean" } }, "required": ["path", "old_string", "new_string"] } },
        { "name": "fs_glob", "capability": "fs:read", "scope_args": ["path"], "recursive": true,
          "description": "Find files by name pattern (for example **/*.rs) below a directory. Respects .gitignore. Newest first, at most 100.",
          "input_schema": { "type": "object", "properties": { "pattern": { "type": "string" }, "path": path }, "required": ["pattern", "path"] } },
        { "name": "fs_grep", "capability": "fs:read", "scope_args": ["path"], "recursive": true,
          "description": "Search file contents with a regular expression (Rust regex syntax) in a directory or one file. include filters file names, for example *.rs or *.{ts,tsx}. Respects .gitignore. At most 100 matches.",
          "input_schema": { "type": "object", "properties": { "pattern": { "type": "string" }, "path": path, "include": { "type": "string" } }, "required": ["pattern", "path"] } },
        { "name": "fs_tree", "capability": "fs:read", "scope_args": ["path"], "recursive": true,
          "description": "Show the files and directories below a directory as an indented tree (default depth 3, at most 500 entries). Respects .gitignore.",
          "input_schema": { "type": "object", "properties": { "path": path, "depth": { "type": "integer", "minimum": 1 } }, "required": ["path"] } },
        { "name": "shell_exec", "capability": "exec:shell", "scope_args": [],
          "description": "Run a shell command in the workspace (default 20 second limit; timeout_secs may raise it up to the configured maximum). Always needs the owner's approval.",
          "input_schema": { "type": "object", "properties": { "command": { "type": "string" }, "timeout_secs": { "type": "integer", "minimum": 1 } }, "required": ["command"] } }
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

/// Plugin state. Each session has its own plugin process, so this is per session: the set of files
/// the agent has read, which `fs_edit` insists on. If the host restarts the process the set is empty
/// again and an edit fails closed with "read it first".
struct Plugin {
    read_files: HashSet<PathBuf>,
    max_shell_secs: u64,
}

fn norm(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn walker(root: &Path) -> WalkBuilder {
    let mut b = WalkBuilder::new(root);
    b.hidden(false).require_git(false).filter_entry(|e| {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        !(e.depth() > 0 && is_dir && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
    });
    b
}

/// `*.{ts,tsx}` becomes `*.ts` and `*.tsx` (one level of braces, which is what the description promises).
fn expand_braces(p: &str) -> Vec<String> {
    if let (Some(a), Some(b)) = (p.find('{'), p.find('}')) {
        if a < b {
            let (pre, post) = (&p[..a], &p[b + 1..]);
            return p[a + 1..b].split(',').flat_map(|alt| expand_braces(&format!("{pre}{alt}{post}"))).collect();
        }
    }
    vec![p.to_string()]
}

fn opt_usize(args: &Value, key: &str) -> Result<Option<usize>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) if n >= 1 => Ok(Some(n as usize)),
            _ => Err(format!("{key} must be a whole number of at least 1")),
        },
    }
}

impl Plugin {
    fn call(&mut self, tool: &str, args: &Value) -> Value {
        let path = args["path"].as_str().unwrap_or("");
        match tool {
            "fs_read" => self.read(path, args),
            "fs_list" => match std::fs::read_dir(path) {
                Ok(rd) => {
                    let mut names: Vec<String> = rd
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let n = e.file_name().to_string_lossy().to_string();
                            if e.path().is_dir() { format!("{n}/") } else { n }
                        })
                        .collect();
                    names.sort();
                    ok(names.join("\n"))
                }
                Err(e) => err(format!("cannot list {path}: {e}")),
            },
            "fs_write" => {
                let content = args["content"].as_str().unwrap_or("");
                let p = Path::new(path);
                let note = match save_undo(p) {
                    Ok(n) => n,
                    Err(e) => return err(e),
                };
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                match std::fs::write(p, content) {
                    Ok(()) => ok(format!("wrote {} bytes to {path}{note}", content.len())),
                    Err(e) => err(format!("cannot write {path}: {e}")),
                }
            }
            "fs_edit" => self.edit(path, args),
            "fs_glob" => glob_files(path, args),
            "fs_grep" => grep_files(path, args),
            "fs_tree" => tree(path, args),
            "shell_exec" => self.shell(args),
            other => err(format!("unknown tool '{other}'")),
        }
    }

    fn read(&mut self, path: &str, args: &Value) -> Value {
        let numbered = args.get("offset").map_or(false, |v| !v.is_null()) || args.get("limit").map_or(false, |v| !v.is_null());
        let (offset, limit) = match (opt_usize(args, "offset"), opt_usize(args, "limit")) {
            (Ok(o), Ok(l)) => (o.unwrap_or(1), l.unwrap_or(DEFAULT_READ_LINES)),
            (Err(e), _) | (_, Err(e)) => return err(e),
        };
        let md = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return err(format!("cannot read {path}: {e}")),
        };
        if md.len() > MAX_READ {
            return err(format!("file is {} bytes; limit is {MAX_READ}", md.len()));
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => return err(format!("cannot read {path}: {e}")),
        };
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => return err(format!("cannot read {path}: not a UTF-8 text file")),
        };
        self.read_files.insert(norm(Path::new(path)));
        if !numbered {
            return ok(clip(text));
        }
        let lines: Vec<&str> = text.lines().collect();
        let total = lines.len();
        let start = (offset - 1).min(total);
        let mut out = String::new();
        let mut end = start;
        while end < total && end - start < limit && out.len() < MAX_OUT {
            let line = lines[end];
            if line.chars().count() > MAX_LINE_CHARS {
                let cut: String = line.chars().take(MAX_LINE_CHARS).collect();
                out.push_str(&format!("{}: {cut}... (line truncated to {MAX_LINE_CHARS} chars)\n", end + 1));
            } else {
                out.push_str(&format!("{}: {line}\n", end + 1));
            }
            end += 1;
        }
        if end < total {
            out.push_str(&format!("\n(File has more lines. Showing {}-{end} of {total}. Call again with offset={} to continue.)\n", start + 1, end + 1));
        }
        if out.is_empty() {
            out = if total == 0 { "(empty file)".into() } else { format!("(offset {offset} is past the end; the file has {total} lines)") };
        }
        ok(out)
    }

    fn edit(&mut self, path: &str, args: &Value) -> Value {
        let (Some(old), Some(new)) = (args["old_string"].as_str(), args["new_string"].as_str()) else {
            return err("old_string and new_string are required".into());
        };
        let replace_all = args["replace_all"].as_bool().unwrap_or(false);
        let p = Path::new(path);
        if !p.is_file() {
            return err(format!("File not found: {path}. fs_edit only changes existing files; use fs_write to create one."));
        }
        if !self.read_files.contains(&norm(p)) {
            return err(format!("You must read {path} with fs_read before editing it."));
        }
        if old.is_empty() {
            return err("old_string must not be empty.".into());
        }
        if old == new {
            return err("old_string and new_string are identical; nothing to do.".into());
        }
        let content = match std::fs::read_to_string(p) {
            Ok(c) => c,
            Err(e) => return err(format!("cannot read {path}: {e}")),
        };
        let count = content.matches(old).count();
        if count == 0 {
            return err("old_string not found in the file.".into());
        }
        if count > 1 && !replace_all {
            return err(format!("Found {count} matches for old_string. Add surrounding lines to make it unique, or set replace_all to true."));
        }
        let updated = if replace_all { content.replace(old, new) } else { content.replacen(old, new, 1) };
        let note = match save_undo(p) {
            Ok(n) => n,
            Err(e) => return err(e),
        };
        if let Err(e) = std::fs::write(p, &updated) {
            return err(format!("cannot write {path}: {e}"));
        }
        let n = if replace_all { count } else { 1 };
        ok(format!("Edited {path} ({n} replacement{}){note}\n\n- {}\n+ {}", if n == 1 { "" } else { "s" }, preview(old), preview(new)))
    }

    fn shell(&mut self, args: &Value) -> Value {
        let command = args["command"].as_str().unwrap_or("");
        let secs = match opt_usize(args, "timeout_secs") {
            Ok(v) => (v.unwrap_or(DEFAULT_SHELL_SECS as usize) as u64).min(self.max_shell_secs),
            Err(e) => return err(e),
        };
        // Its own process group, so a timeout can stop the whole tree and not just the shell.
        let child = match Command::new("sh")
            .arg("-c")
            .arg(command)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return err(format!("cannot start shell: {e}")),
        };
        let pid = child.id();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(Duration::from_secs(secs)) {
            Ok(Ok(out)) => {
                let text = format!(
                    "exit code: {}\nstdout:\n{}\nstderr:\n{}",
                    out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let failed = !out.status.success();
                let v = clip(text);
                if failed { err(v) } else { ok(v) }
            }
            Ok(Err(e)) => err(format!("shell failed: {e}")),
            Err(_) => {
                let _ = Command::new("kill").arg("-9").arg("--").arg(format!("-{pid}")).status();
                err(format!("command timed out after {secs}s and was killed"))
            }
        }
    }
}

/// Copy an existing file to .agent-undo/ before it is changed. Ok("") when there was nothing to save.
fn save_undo(p: &Path) -> Result<String, String> {
    if !p.exists() {
        return Ok(String::new());
    }
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let flat = p.to_string_lossy().replace(['/', '\\'], "_");
    let backup = format!(".agent-undo/{ms}-{flat}");
    if std::fs::create_dir_all(".agent-undo").is_err() || std::fs::copy(p, &backup).is_err() {
        return Err("could not save an undo copy; write refused".into());
    }
    Ok(format!(" (previous version saved to {backup})"))
}

fn preview(s: &str) -> String {
    let s = s.replace('\n', "\\n");
    if s.chars().count() > 120 { format!("{}…", s.chars().take(120).collect::<String>()) } else { s }
}

fn glob_files(path: &str, args: &Value) -> Value {
    let Some(pat) = args["pattern"].as_str().filter(|p| !p.is_empty()) else { return err("pattern is required".into()) };
    let pattern = match glob::Pattern::new(pat) {
        Ok(p) => p,
        Err(e) => return err(format!("invalid glob pattern '{pat}': {e}")),
    };
    let root = Path::new(path);
    if !root.is_dir() {
        return err(format!("not a directory: {path}"));
    }
    let mut found: Vec<(PathBuf, SystemTime)> = Vec::new();
    for entry in walker(root).build().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let rel = p.strip_prefix(root).unwrap_or(p);
        if pattern.matches_path(rel) {
            let mtime = entry.metadata().ok().and_then(|m| m.modified().ok()).unwrap_or(SystemTime::UNIX_EPOCH);
            found.push((p.to_path_buf(), mtime));
        }
    }
    found.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let truncated = found.len() > MATCH_LIMIT;
    found.truncate(MATCH_LIMIT);
    if found.is_empty() {
        return ok("No files found".into());
    }
    let mut out: Vec<String> = found.iter().map(|(p, _)| p.display().to_string()).collect();
    if truncated {
        out.push(String::new());
        out.push(format!("(Results are truncated: showing the first {MATCH_LIMIT}. Use a more specific path or pattern.)"));
    }
    ok(out.join("\n"))
}

fn grep_files(path: &str, args: &Value) -> Value {
    let Some(pat) = args["pattern"].as_str().filter(|p| !p.is_empty()) else { return err("pattern is required".into()) };
    let re = match Regex::new(pat) {
        Ok(r) => r,
        Err(e) => return err(format!("invalid regex '{pat}': {e}")),
    };
    let includes: Vec<glob::Pattern> = match args["include"].as_str() {
        Some(inc) => {
            let mut v = Vec::new();
            for alt in expand_braces(inc) {
                match glob::Pattern::new(&alt) {
                    Ok(p) => v.push(p),
                    Err(e) => return err(format!("invalid include pattern '{inc}': {e}")),
                }
            }
            v
        }
        None => vec![],
    };
    let root = Path::new(path);
    if !root.exists() {
        return err(format!("path not found: {path}"));
    }
    // One more than the limit, so "more matches available" is true when it is.
    let mut rows: Vec<(PathBuf, usize, String)> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    if root.is_file() {
        files.push(root.to_path_buf());
    } else {
        for entry in walker(root).sort_by_file_path(|a, b| a.cmp(b)).build().flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if !includes.is_empty() {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if !includes.iter().any(|i| i.matches(&name)) {
                    continue;
                }
            }
            files.push(p.to_path_buf());
        }
    }
    'files: for f in files {
        if std::fs::metadata(&f).map(|m| m.len() > MAX_READ).unwrap_or(true) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&f) else { continue };
        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) {
                rows.push((f.clone(), i + 1, line.chars().take(500).collect()));
                if rows.len() > MATCH_LIMIT {
                    break 'files;
                }
            }
        }
    }
    if rows.is_empty() {
        return ok(format!("No matches found for pattern: {pat}"));
    }
    let truncated = rows.len() > MATCH_LIMIT;
    rows.truncate(MATCH_LIMIT);
    let total = rows.len();
    let mut out = vec![format!("Found {total} match{}{}", if total == 1 { "" } else { "es" }, if truncated { " (more matches available)" } else { "" })];
    let mut current: Option<&PathBuf> = None;
    for (p, line, text) in &rows {
        if current != Some(p) {
            if current.is_some() {
                out.push(String::new());
            }
            current = Some(p);
            out.push(format!("{}:", p.display()));
        }
        out.push(format!("  Line {line}: {text}"));
    }
    if truncated {
        out.push(String::new());
        out.push("(Results truncated. Use a more specific path or pattern.)".into());
    }
    ok(clip(out.join("\n")))
}

fn tree(path: &str, args: &Value) -> Value {
    let depth = match opt_usize(args, "depth") {
        Ok(d) => d.unwrap_or(TREE_DEFAULT_DEPTH),
        Err(e) => return err(e),
    };
    let root = Path::new(path);
    if !root.exists() {
        return err(format!("path not found: {path}"));
    }
    if !root.is_dir() {
        return err(format!("not a directory: {path}"));
    }
    let mut out = vec![format!("{}/", root.display())];
    let mut count = 0usize;
    for entry in walker(root).max_depth(Some(depth)).sort_by_file_path(|a, b| a.cmp(b)).build().flatten() {
        if entry.depth() == 0 {
            continue;
        }
        if count >= TREE_MAX_ENTRIES {
            out.push(format!("… (truncated at {TREE_MAX_ENTRIES} entries)"));
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push(format!("{}{}", "  ".repeat(entry.depth() - 1), if is_dir { format!("{name}/") } else { name }));
        count += 1;
    }
    ok(out.join("\n"))
}

fn main() {
    let mut max_shell_secs = DEFAULT_MAX_SHELL_SECS;
    let argv: Vec<String> = std::env::args().collect();
    if let Some(i) = argv.iter().position(|a| a == "--max-shell-secs") {
        if let Some(n) = argv.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
            max_shell_secs = n.max(1);
        }
    }
    let mut plugin = Plugin { read_files: HashSet::new(), max_shell_secs };
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
                json!({ "id": id, "result": plugin.call(tool, &req["params"]["args"]) })
            }
            _ => json!({ "id": id, "error": "unknown method" }),
        };
        if writeln!(out, "{resp}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}
