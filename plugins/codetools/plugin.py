"""codetools: read, edit, glob, grep and tree for a workspace, as a sandboxed agent plugin.

Standard library only. It is a port of the code tools built into the agent's own fs plugin, so an
agent that does not have them can write this folder, propose it, and have the owner deploy it.
The permission gate enforces what the agent may touch; this script enforces nothing about
permissions and only names the capability each tool needs.

Known differences from the built-in tools: .gitignore is read from the search directory and the
workspace root only (no negation lines), and patterns use Python's regex syntax.
"""
import sys, os, re, json, time, fnmatch

MAX_READ = 1000000
MAX_OUT = 100000
DEFAULT_READ_LINES = 2000
MAX_LINE_CHARS = 2000
MATCH_LIMIT = 100
TREE_DEFAULT_DEPTH = 3
TREE_MAX_ENTRIES = 500
SKIP_DIRS = {".git", ".agent", ".agent-undo"}

PATH = {"type": "string"}
TOOLS = [
    {"name": "code_read", "capability": "fs:read", "scope_args": ["path"],
     "description": "Read a UTF-8 text file (up to 1 MB). With offset (1-based line) and/or limit (default 2000 lines) the result has numbered lines and says where to continue. A file must be read before code_edit can change it.",
     "input_schema": {"type": "object", "properties": {"path": PATH, "offset": {"type": "integer", "minimum": 1}, "limit": {"type": "integer", "minimum": 1}}, "required": ["path"]}},
    {"name": "code_edit", "capability": "fs:write", "scope_args": ["path"],
     "description": "Replace exact text in a file you have read with code_read. Fails if old_string is not found, or matches more than once unless replace_all is true. Keep indentation exactly as in the file; never include the line-number prefix. The old file is copied to .agent-undo/ first.",
     "input_schema": {"type": "object", "properties": {"path": PATH, "old_string": {"type": "string"}, "new_string": {"type": "string"}, "replace_all": {"type": "boolean"}}, "required": ["path", "old_string", "new_string"]}},
    {"name": "code_glob", "capability": "fs:read", "scope_args": ["path"], "recursive": True,
     "description": "Find files by name pattern (for example **/*.rs) below a directory. Respects .gitignore. Newest first, at most 100.",
     "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": PATH}, "required": ["pattern", "path"]}},
    {"name": "code_grep", "capability": "fs:read", "scope_args": ["path"], "recursive": True,
     "description": "Search file contents with a regular expression in a directory or one file. include filters file names, for example *.py or *.{ts,tsx}. Respects .gitignore. At most 100 matches.",
     "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": PATH, "include": {"type": "string"}}, "required": ["pattern", "path"]}},
    {"name": "code_tree", "capability": "fs:read", "scope_args": ["path"], "recursive": True,
     "description": "Show the files and directories below a directory as an indented tree (default depth 3, at most 500 entries). Respects .gitignore.",
     "input_schema": {"type": "object", "properties": {"path": PATH, "depth": {"type": "integer", "minimum": 1}}, "required": ["path"]}},
]

read_files = set()


def clip(s):
    b = s.encode("utf-8")
    if len(b) <= MAX_OUT:
        return s
    return b[:MAX_OUT].decode("utf-8", "ignore") + "\n[output truncated]"


def norm(p):
    return os.path.realpath(p)


def text_lines(text):
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return [x[:-1] if x.endswith("\r") else x for x in parts]


def opt_int(args, key):
    v = args.get(key)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ValueError("%s must be a whole number of at least 1" % key)
    return v


def save_undo(p):
    if not os.path.exists(p):
        return ""
    flat = p.replace("/", "_").replace("\\", "_")
    backup = ".agent-undo/%d-%s" % (int(time.time() * 1000), flat)
    try:
        os.makedirs(".agent-undo", exist_ok=True)
        with open(p, "rb") as f, open(backup, "wb") as g:
            g.write(f.read())
    except OSError:
        raise IOError("could not save an undo copy; write refused")
    return " (previous version saved to %s)" % backup


def preview(s):
    s = s.replace("\n", "\\n")
    return s[:120] + "\u2026" if len(s) > 120 else s


# ---- .gitignore, simplified ------------------------------------------------------------------

def load_ignores(root):
    rules = []
    seen = set()
    for base in (os.getcwd(), root):
        base = os.path.abspath(base)
        if base in seen:
            continue
        seen.add(base)
        try:
            with open(os.path.join(base, ".gitignore"), encoding="utf-8") as f:
                for line in f.read().split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    dir_only = line.endswith("/")
                    body = line.rstrip("/")
                    anchored = "/" in body  # a slash anywhere but the end ties it to the .gitignore's folder
                    rules.append((base, body.lstrip("/"), dir_only, anchored))
        except OSError:
            pass
    return rules


def is_ignored(path, is_dir, rules):
    ap = os.path.abspath(path)
    for base, pat, dir_only, anchored in rules:
        if dir_only and not is_dir:
            continue
        if not (ap == base or ap.startswith(base + os.sep)):
            continue
        rel = os.path.relpath(ap, base).replace(os.sep, "/")
        if anchored:
            if fnmatch.fnmatchcase(rel, pat):
                return True
        else:
            if any(fnmatch.fnmatchcase(part, pat) for part in rel.split("/")):
                return True
    return False


def walk(root, max_depth=None):
    """Yield (path, is_dir, depth), siblings sorted by name, a directory before its children."""
    rules = load_ignores(root)

    def rec(d, depth):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            return
        for name in names:
            p = os.path.join(d, name)
            isdir = os.path.isdir(p) and not os.path.islink(p)
            if isdir and name in SKIP_DIRS:
                continue
            if is_ignored(p, isdir, rules):
                continue
            yield p, isdir, depth
            if isdir and (max_depth is None or depth < max_depth):
                for x in rec(p, depth + 1):
                    yield x

    return rec(root, 1)


def glob_to_regex(pat):
    out, i = "", 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
            continue
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            continue
        if c == "*":
            out += ".*"
        elif c == "?":
            out += "."
        elif c == "[":
            j = pat.find("]", i + 2)
            if j == -1:
                raise ValueError("unclosed [ in pattern")
            body = pat[i + 1:j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out += "[" + body.replace("\\", "\\\\") + "]"
            i = j
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out + r"\Z", re.S)


def expand_braces(p):
    a, b = p.find("{"), p.find("}")
    if a != -1 and b > a:
        pre, post = p[:a], p[b + 1:]
        out = []
        for alt in p[a + 1:b].split(","):
            out.extend(expand_braces(pre + alt + post))
        return out
    return [p]


# ---- tools ------------------------------------------------------------------------------------

def code_read(args):
    path = args.get("path")
    if not isinstance(path, str):
        return "path is required", True
    numbered = args.get("offset") is not None or args.get("limit") is not None
    try:
        offset, limit = opt_int(args, "offset") or 1, opt_int(args, "limit") or DEFAULT_READ_LINES
    except ValueError as e:
        return str(e), True
    try:
        size = os.path.getsize(path)
        if size > MAX_READ:
            return "file is %d bytes; limit is %d" % (size, MAX_READ), True
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return "cannot read %s: %s" % (path, e.strerror or e), True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "cannot read %s: not a UTF-8 text file" % path, True
    read_files.add(norm(path))
    if not numbered:
        return clip(text), False
    lines = text_lines(text)
    total = len(lines)
    start = min(offset - 1, total)
    out, end = "", start
    while end < total and end - start < limit and len(out) < MAX_OUT:
        line = lines[end]
        if len(line) > MAX_LINE_CHARS:
            out += "%d: %s... (line truncated to %d chars)\n" % (end + 1, line[:MAX_LINE_CHARS], MAX_LINE_CHARS)
        else:
            out += "%d: %s\n" % (end + 1, line)
        end += 1
    if end < total:
        out += "\n(File has more lines. Showing %d-%d of %d. Call again with offset=%d to continue.)\n" % (start + 1, end, total, end + 1)
    if not out:
        out = "(empty file)" if total == 0 else "(offset %d is past the end; the file has %d lines)" % (offset, total)
    return out, False


def code_edit(args):
    path, old, new = args.get("path"), args.get("old_string"), args.get("new_string")
    if not isinstance(path, str) or not isinstance(old, str) or not isinstance(new, str):
        return "path, old_string and new_string are required", True
    replace_all = args.get("replace_all") is True
    if not os.path.isfile(path):
        return "File not found: %s. code_edit only changes existing files; use fs_write to create one." % path, True
    if norm(path) not in read_files:
        return "You must read %s with code_read before editing it." % path, True
    if old == "":
        return "old_string must not be empty.", True
    if old == new:
        return "old_string and new_string are identical; nothing to do.", True
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return "cannot read %s: %s" % (path, e), True
    count = content.count(old)
    if count == 0:
        return "old_string not found in the file.", True
    if count > 1 and not replace_all:
        return "Found %d matches for old_string. Add surrounding lines to make it unique, or set replace_all to true." % count, True
    updated = content.replace(old, new) if replace_all else content.replace(old, new, 1)
    try:
        note = save_undo(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(updated)
    except (OSError, IOError) as e:
        return str(e), True
    n = count if replace_all else 1
    return "Edited %s (%d replacement%s)%s\n\n- %s\n+ %s" % (path, n, "" if n == 1 else "s", note, preview(old), preview(new)), False


def code_glob(args):
    pat, path = args.get("pattern"), args.get("path")
    if not isinstance(pat, str) or not pat:
        return "pattern is required", True
    if not isinstance(path, str) or not os.path.isdir(path):
        return "not a directory: %s" % path, True
    try:
        rx = glob_to_regex(pat)
    except (ValueError, re.error) as e:
        return "invalid glob pattern '%s': %s" % (pat, e), True
    found = []
    for p, isdir, _ in walk(path):
        if isdir or not os.path.isfile(p):
            continue
        rel = os.path.relpath(p, path).replace(os.sep, "/")
        if rx.match(rel):
            found.append((p, os.path.getmtime(p)))
    found.sort(key=lambda x: (-x[1], x[0]))
    truncated = len(found) > MATCH_LIMIT
    found = found[:MATCH_LIMIT]
    if not found:
        return "No files found", False
    out = [p for p, _ in found]
    if truncated:
        out += ["", "(Results are truncated: showing the first %d. Use a more specific path or pattern.)" % MATCH_LIMIT]
    return "\n".join(out), False


def code_grep(args):
    pat, path, inc = args.get("pattern"), args.get("path"), args.get("include")
    if not isinstance(pat, str) or not pat:
        return "pattern is required", True
    try:
        rx = re.compile(pat)
    except re.error as e:
        return "invalid regex '%s': %s" % (pat, e), True
    if not isinstance(path, str) or not os.path.exists(path):
        return "path not found: %s" % path, True
    includes = expand_braces(inc) if isinstance(inc, str) else []
    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for p, isdir, _ in walk(path):
            if isdir or not os.path.isfile(p):
                continue
            if includes and not any(fnmatch.fnmatchcase(os.path.basename(p), i) for i in includes):
                continue
            files.append(p)
    rows = []
    for f in files:
        try:
            if os.path.getsize(f) > MAX_READ:
                continue
            with open(f, encoding="utf-8") as fh:
                lines = text_lines(fh.read())
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines):
            if rx.search(line):
                rows.append((f, i + 1, line[:500]))
                if len(rows) > MATCH_LIMIT:
                    break
        if len(rows) > MATCH_LIMIT:
            break
    if not rows:
        return "No matches found for pattern: %s" % pat, False
    truncated = len(rows) > MATCH_LIMIT
    rows = rows[:MATCH_LIMIT]
    out = ["Found %d match%s%s" % (len(rows), "" if len(rows) == 1 else "es", " (more matches available)" if truncated else "")]
    current = None
    for p, n, t in rows:
        if current != p:
            if current is not None:
                out.append("")
            current = p
            out.append("%s:" % p)
        out.append("  Line %d: %s" % (n, t))
    if truncated:
        out += ["", "(Results truncated. Use a more specific path or pattern.)"]
    return clip("\n".join(out)), False


def code_tree(args):
    path = args.get("path")
    try:
        depth = opt_int(args, "depth") or TREE_DEFAULT_DEPTH
    except ValueError as e:
        return str(e), True
    if not isinstance(path, str) or not os.path.exists(path):
        return "path not found: %s" % path, True
    if not os.path.isdir(path):
        return "not a directory: %s" % path, True
    out, count = ["%s/" % path], 0
    for p, isdir, d in walk(path, depth):
        if count >= TREE_MAX_ENTRIES:
            out.append("\u2026 (truncated at %d entries)" % TREE_MAX_ENTRIES)
            break
        name = os.path.basename(p)
        out.append("  " * (d - 1) + (name + "/" if isdir else name))
        count += 1
    return "\n".join(out), False


HANDLERS = {"code_read": code_read, "code_edit": code_edit, "code_glob": code_glob, "code_grep": code_grep, "code_tree": code_tree}


def call(tool, args):
    handler = HANDLERS.get(tool)
    if handler is None:
        return "unknown tool: %s" % tool, True
    if not isinstance(args, dict):
        args = {}
    try:
        return handler(args)
    except Exception as e:  # a bad call is an error result, never a crash
        return "%s failed: %s" % (tool, e), True


for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue  # never exit on bad input
    if not isinstance(req, dict):
        continue
    method, rid = req.get("method"), req.get("id")
    if method == "manifest":
        out = {"id": rid, "result": {"tools": TOOLS}}
    elif method == "call":
        p = req.get("params") or {}
        content, is_error = call(p.get("tool"), p.get("args") or {})
        out = {"id": rid, "result": {"content": content, "is_error": is_error}}
    else:
        out = {"id": rid, "error": "unknown method"}
    print(json.dumps(out), flush=True)  # one JSON object per line
