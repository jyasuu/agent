import sys, json

TOOLS = [{
    "name": "shout",
    "description": "Return the text in capital letters.",
    "input_schema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
    "capability": "text:shout",
    "scope_args": [],
}]

def call(tool, args):
    if tool == "shout":
        return str(args.get("text", "")).upper(), False
    return "unknown tool: %s" % tool, True

for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue                      # never exit on bad input
    method, rid = req.get("method"), req.get("id")
    if method == "manifest":
        out = {"id": rid, "result": {"tools": TOOLS}}
    elif method == "call":
        p = req.get("params") or {}
        content, is_error = call(p.get("tool"), p.get("args") or {})
        out = {"id": rid, "result": {"content": content, "is_error": is_error}}
    else:
        out = {"id": rid, "error": "unknown method"}
    print(json.dumps(out), flush=True)   # one JSON object per line
