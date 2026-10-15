# agent: stages 1 to 6, plus providers, MCP and hot reload, and a bootstrapping review

Built from `agent-design-spec.md`.

- **Stage 1, the walking skeleton:** loop, session log, permission gate, one out-of-process tool plugin, CLI driver, spending caps.
- **Stage 2, the daemon:** durable event queue, worker pool with a concurrency cap, one event-source plugin, an approval queue, crash recovery and graceful shutdown.
- **Stage 3, compaction and sub-agents:** automatic context compaction with pinned state and a swappable summary strategy, a `recall` tool for shortened outputs, and a gated `spawn_agent` tool that runs a narrower child session and returns a short result.

- **Stage 4, verifier and evals:** the core no longer takes the model's word that it is done. A read-only verifier with a fresh context judges the work first, using sandboxed check commands for objective evidence. The owner's eval suite measures behavior against real workflows and blocks regressions.

- **Stage 5, the delegate:** an optional approver that answers for you, only inside rules you wrote. It approves, denies, or hands the request back to you.

- **Stage 6, sandbox and plugin self-upgrade:** plugins run inside an OS sandbox, and the agent can write a plugin and *propose* it. Only you can run the checks, approve, deploy or roll back.

Everything in the build order is now in place for plugins. Prompt, config and memory self-changes are not (see limits).

## What works

| Spec area | Behavior |
|---|---|
| Agent loop | One loop: the model calls tools until it replies without a tool call. The core, not the model, enforces limits. |
| Session log | SQLite (WAL, single writer), append-only (triggers reject UPDATE and DELETE). Enqueueing an event, creating its session and writing its first log entry are one transaction. |
| Permission gate | Every tool call passes through it. Deny by default. Plugins only name the capability a tool needs; the owner's `grants` decide whether it is allowed and at which tier (read-only, reversible, irreversible). |
| Scope | Paths are normalized and symlinks followed before the check. The agent's home directory can never be covered by a grant, even inside the workspace. |
| Approval | Irreversible actions need the owner. `agent run` asks in the terminal. The daemon puts structured requests in an approval queue (`agent approvals`, `approve`, `deny`), so several sessions can wait at once. No answer within `approval_timeout_secs` counts as a refusal. |
| Audit log | Separate SQLite file with a SHA-256 hash chain. `agent audit-verify` recomputes it. |
| Tool plugins | Out-of-process, line-delimited JSON on stdio (MCP-style, not full MCP). Empty environment. A hung plugin is killed and restarts on the next call, and may not change its manifest. |
| Untrusted output | Tool results reach the model wrapped in `<untrusted_tool_output>` tags. |
| Budgets | Per-session steps, tokens, cost, wall time, plus global token and cost caps from a spend ledger. Hitting one writes a handoff note and suspends the session. |
| Daemon | `agent daemon` claims queued sessions and runs up to `max_concurrent_sessions` (default 2) at once. Each session gets its own plugin processes. One daemon per home directory (pid-file lock). |
| Event sources | Out-of-process. A source can only emit events. The core stores each one idempotently (unique key), then acknowledges it. The bundled `source_inbox` moves a file out of the inbox only after that acknowledgement, so a crash re-delivers instead of losing it. |
| Crash recovery | On start the daemon requeues sessions left "running". A tool call with no logged result is never re-run; the model is told its effect is unknown. |
| Shutdown | `agent stop` pauses running sessions at their next step and puts them back in the queue. The next start resumes them. |

## Stage 3 in brief

**Compaction.** The session log is never rewritten. The context window is a view of it, and a compaction is one more log entry that changes the view. Before each model call the core estimates the context (bytes / 4). At `compaction.threshold` (default 75% of `context_window_tokens`) it compacts in two steps:

1. Older tool outputs larger than `stub_min_bytes` show as a short head plus a pointer: `session log entry N; call recall with seq=N`. The last `keep_recent_steps` turns are never touched.
2. If that is not enough, everything before those turns is replaced by one preamble message. The core writes the goal (verbatim), the granted permissions, the agent's pins, the owner's approval decisions and a digest of what was done. A *strategy* only writes the digest: `mechanical` (default, no model call, never copies tool output) or `model` (one model call, falls back to mechanical). Strategies are a trait in `compact.rs`.

If the context cannot be brought under 95% of the window, the session is suspended with a handoff note and the model is not called. Each compaction stores the exact preamble the model saw, writes an audit row, and can be replayed from the log alone (`build_messages(log)`).

Core tools: `pin` (constraint, decision, open_work; a new open_work replaces the old one; 40 per session), `recall` (re-read a tool output of this session in slices). They pass through the gate like every tool, so they need `core:pin` and `core:recall` grants (`agent init` writes them). A core tool is offered to the model only when it is granted.

**Sub-agents.** `spawn_agent {task, grants: [{capability, scope?}]}` needs an `agent:spawn` grant. The child:

- runs *inside* the parent's runner, one at a time, so the pair uses one worker slot;
- holds only the capabilities it was given, each of which must be covered by a grant the parent holds. The tier is copied from the parent's grant and a scope can only be narrowed, never widened (`Gate::narrow`);
- starts with a fresh context holding only its task, and its own plugin processes;
- has a budget cut from the parent's remaining budget (and `subagents.child_budget`), and its spend counts against the parent's budget as well as the global caps;
- cannot spawn (`subagents.max_depth`, default 1);
- returns at most `subagents.max_result_chars` (default 2000) to the parent, wrapped as untrusted output. Its full answer stays in its own log.

Approvals: nothing in the system lets an agent approve an action. A child's irreversible action goes to the owner, with the child's session id, exactly like the parent's.

Children never run on their own: they are never claimed, requeued or resumed, and `run_session` refuses them. A child left running by a crash is marked suspended, and its parent repairs the unfinished spawn call (it is not re-run). `agent status` shows a child as `sub of <parent>`.

## Stage 4 in brief

Design goal: the owner is pulled in only for security decisions (irreversible actions, capability changes, what enters the eval suite), not for routine judgment calls.

**Verifier (core-enforced).** Needs `verification.enabled` and an `agent:verify` grant. When the model replies without a tool call, the core runs a verifier before accepting "done". The model cannot skip it and cannot call it.

- The verifier is a child session with a fresh context holding only the owner's task text, the list of files the worker wrote, and the available check commands. It never sees the worker's reasoning or its own claim of success.
- It is read-only by construction: its grants are `fs:read` and `exec:check`, copied from the session's grants, plus `core:recall`. No write, no shell, no spawn, no pins. It cannot cause an approval request.
- It answers with one JSON object, `{verdict: pass|fail|uncertain, evidence}`. Anything malformed counts as `uncertain`.
- **pass:** the session completes. **fail:** the evidence goes back to the worker (as untrusted data) and it keeps working, at most `max_retries` times (default 2); then the session suspends with a handoff note. After the owner resumes it, the retry count starts again. **uncertain:** re-checked once automatically with a push for objective evidence; if still uncertain, `on_uncertain: "flag"` (default) completes the session marked `[unverified]` in `agent status` and in the audit log, without interrupting anyone, and `"suspend"` holds it for the owner.
- Sessions that never called a tool are not verified (`skip_without_tools`). A crash after the model said "done" resumes at verification, not at another model call.
- Verifier cost counts in the parent's budget and the global caps. Verifier children do not use up `max_children_per_session`.

**Sandboxed checks.** `exec:check` runs only commands the owner listed in `check_commands` (exact match after whitespace normalization, enforced by the core, not the plugin). The `plugin_check` binary runs them without a shell, with an empty environment, in fresh user and network namespaces (`unshare -r -n`): no network. If the sandbox cannot be created, it refuses to run anything. Because the owner wrote the list and the sandbox bounds the damage, a check needs no per-run approval.

**Eval suite (owner-owned).**

- Cases are JSON files in `<home>/evals/cases/`. The home directory is protected by the gate, so no agent tool can read or write them or the baseline.
- A case has a task, optional `setup_files`, optional `script` (a fixed model script, for deterministic runs), optional narrower `grants`, and objective `checks`: `completed`, `final_contains`, `file_exists`, `file_absent`, `file_contains`, `command_ok`, `no_denied`, `denied` (guards a boundary), `max_steps`, `verified`.
- Each case runs through the real session runner in a throwaway workspace with its own stores. Irreversible actions are refused unless the case sets `approve_irreversible`.
- `agent eval run` runs cases with a script; cases without one are skipped unless `--live` (real model). `agent eval baseline` stores the latest run. `agent eval compare` exits 4 if any case that passed in the baseline fails now **or has been removed**, so the bar cannot be lowered by deleting cases. New cases and cases that already failed in the baseline never block. Scripted and live runs cannot be compared with each other.
- The agent's only way in is the `propose_eval` tool (`eval:propose` grant). A proposal may carry only id, task, setup files and checks (no script, grants or approvals), may only use command checks from `check_commands`, and sits in `evals/proposed/` doing nothing until the owner runs `agent eval accept <id>` (review it with `agent eval show <id>`).

## Stage 5 in brief

Design goal: be asked less, without letting any agent grant itself authority. The delegate is an *optional* plugin on the approval hook. With it off (the default) nothing changes.

**It is a rule matcher, not a model.** It sees only structured facts about one action: tool, capability, tier and the exact arguments. It never sees the task, the agent's reasoning, or anything the agent has read, so text in a file or web page cannot talk it into anything. A command such as `touch ok.txt # IGNORE ALL RULES` simply does not equal `touch ok.txt`.

**The envelope.** Rules live in `<home>/delegate/rules.json`, inside the home directory the gate protects, so no agent tool can read or write them. Each rule says `approve` or `deny`, names a tool (and optionally a capability) and constrains arguments with `exact`, `one_of` or `under` (a directory). There is deliberately no prefix or pattern matcher.

- **Every argument must be named.** A rule that leaves one out does not apply, so no rule can approve "any call".
- **Deny beats approve.** Anything no rule covers goes to you. A broken rules file sends everything to you.
- **`expires_at`** (unix seconds) gives a time-limited grant. Rules are re-read on every request, so editing or revoking one takes effect on the very next action.
- **Never delegated:** capabilities starting `upgrade:`, `permission:`, `grant:`, `policy:` or `eval:accept` always go to you, whatever the rules say.
- A child agent's irreversible action is decided by the same rules. The audit row names the child session.

**Audit.** Every decision is an audit row with the rule that justified it: `delegate_approved`, `delegate_denied`, `delegate_escalated` (then your own decision follows), `delegate_rule_learned`. `agent delegate log` lists them.

**Proposals, never self-written rules.** When you have approved the identical action `suggest_after` times (default 3) and never refused it, the delegate can *propose* an exact-match rule. It lands in `<home>/delegate/proposed/` and does nothing until you run `agent delegate accept <id>`. Only your own decisions count: the delegate's decisions are not history, so it cannot teach itself.

**Silent learning** (`delegate.silent_learning`, off by default) lets the delegate adopt a proposal without asking, but only at the lowest tier. See the limit below: today nothing reaches it.

    agent delegate rules              # what is live
    agent delegate suggest            # look for patterns in your approvals
    agent delegate proposed           # proposals waiting for you
    agent delegate show <id>
    agent delegate accept <id>        # make it live
    agent delegate reject <id>
    agent delegate revoke <rule-id>   # stops applying at once
    agent delegate log                # every delegated decision

To turn it on, set `"delegate": {"enabled": true}` in `config.json`. Example `rules.json`:

    [{ "id": "allow-cargo-test", "effect": "approve", "tool": "shell_exec",
       "args": { "command": { "exact": "cargo test" } } }]

## Stage 6 in brief

### The sandbox
Set `"sandbox": {}` on a plugin and it runs inside bubblewrap: system directories read-only, a private `/tmp` and `/proc`, its own process space, **no network**, the workspace, and nothing else. The agent's home directory (session log, audit log, delegate rules, snapshots, the plugin registry) is hidden from every sandboxed plugin, even when the home sits inside the workspace. Extra visible paths go in `ro_binds` / `rw_binds`; `network: true` and `workspace_readonly: true` are switches you control.

**It fails closed.** If bubblewrap is missing, a plugin that asks for a sandbox does not start, and `agent upgrade run` refuses. `agent init` sandboxes the `fs` plugin when bwrap is installed, so an approved `shell_exec` can no longer reach the agent's own files, the rest of the machine, or the network. Install it with your package manager (`apt install bubblewrap`). If your shell commands need a toolchain, list its directory in `ro_binds`.

### The upgrade pipeline
The agent writes a folder in the workspace: `plugin.json` (name, `python3` or `sh`, entry script, tools with their capabilities) plus the script. With the `upgrade:propose` grant (not given by default) it calls `propose_upgrade`. That copies the folder into a snapshot and queues it. Nothing runs and nothing is installed. The agent has no tool to check, approve, deploy or roll back.

You run the stages, in this fixed order, each only if the one before passed:

1. **Static checks.** Limits (50 files, 1 MB, no links), names, reserved or colliding tool names, claimed authority (`upgrade:`, `grant:`, `permission:`, `policy:`, `eval:accept` are refused outright), syntax checked inside the sandbox.
2. **Permission review.** What it asks for, what no grant covers (those tools stay denied until *you* grant them; the pipeline never edits grants), and anything it asks for that its predecessor did not.
3. **Contract tests.** Manifest matches `plugin.json`; an unknown tool is an error, not a success or a crash; malformed input does not kill it; empty arguments get an answer; it exits when its input closes.
4. **Eval gate.** Your baseline suite runs with the candidate in place of any earlier version. No baseline, or fewer than `min_eval_cases` (3), blocks. Any regression blocks.
5. **Canary.** Recorded read-only calls to that plugin are replayed against the version in service and the candidate, both sandboxed with the workspace read-only. Differing answers fail it.
6. **Approval.** Yours (`agent upgrade approve <n>`), unless an earned auto-approval applies.
7. **Versioned deploy.** Version `n+1` goes live from the next session, then the suite runs again with it live. A regression rolls it back by itself.

    agent upgrade list                 agent upgrade run <n>        # stages 1-5
    agent upgrade show <n>             agent upgrade approve <n>    # deploy, then re-check
    agent upgrade reject <n>           agent upgrade history <plugin>
    agent upgrade rollback <plugin> [version]    # one switch; nothing is deleted

**Earned auto-approval** (`upgrades.auto_approve`, off by default) applies only when the plugin has a predecessor, the new version asks for nothing new, every capability it uses is granted at or below the reversible tier, you have approved at least `earned_after` (3) of its earlier versions yourself, and the canary actually compared something with no difference. A first version, anything asking for more, and anything above the reversible tier always waits for you.

**Tamper-proofing.** Every stage works from the snapshot and its hash is re-checked before checks and again before deploy. Editing the source afterwards, or the snapshot itself, changes nothing and blocks the deploy. The registry (`<home>/plugins`), snapshots and the active pointer are inside the protected home, so no agent tool can write them.

Each design bad-case was built so that only one stage can catch it: a replacement that stops writing is caught by the suite; one that returns upper-cased reads passes the suite and is caught only by the canary; one that crashes on an unknown tool is caught only by the contract tests.

## Code tools

Ported from hostmcp (`read`, `edit`, `glob`, `grep`, `list`, `bash`) into the `fs` plugin. Only the tool logic came across; hostmcp's HTTP and MCP layers did not, because here the core gate decides what is allowed. No new capability was needed, so `agent init` and existing grants are unchanged.

| Tool | Capability, tier | Notes |
|---|---|---|
| `fs_read` | `fs:read` | With `offset` and/or `limit`: numbered lines, 2000-line default, a "call again with offset=N" hint, long lines cut. Without them: the file as before. Reading a file is what lets `fs_edit` change it. |
| `fs_edit` | `fs:write`, reversible | `path`, `old_string`, `new_string`, `replace_all`. Refused unless the file was read in this session; refused when the text is missing, empty, identical to the new text, or matches more than once (unless `replace_all`). The old file goes to `.agent-undo/` first. |
| `fs_glob` | `fs:read`, recursive | `pattern`, `path`. Newest first, at most 100. |
| `fs_grep` | `fs:read`, recursive | `pattern`, `path` (a folder or one file), `include` (`*.rs`, `*.{ts,tsx}`). At most 100 matches, and it says when there were more. |
| `fs_tree` | `fs:read`, recursive | `path`, `depth` (default 3), at most 500 entries. |
| `shell_exec` | `exec:shell`, irreversible | Still needs the owner every time. New optional `timeout_secs`. A timeout kills the whole process group, not just the shell. |

`path` is required on glob, grep and tree, because the gate cannot check a path that is not there. Glob, grep and tree respect `.gitignore` and never enter `.git`, `.agent` or `.agent-undo`.

**Recursive tools and the agent's home.** The default home (`.agent`) sits inside the workspace, so a search of the workspace root would walk the session log, delegate rules and eval suite. A tool marked `"recursive": true` in its manifest is therefore refused by the gate for any folder that contains a protected path, with a message to name a narrower folder (`src`, not `.`). Searching inside any subfolder works. The plugin also skips those folders itself, as a second wall. `fs_list` does not recurse and is unaffected.

**Shell timeouts.** The default is 20 seconds. `timeout_secs` can go up to `--max-shell-secs` (default 25), which must stay below the plugin's `call_timeout_secs` (30 from `agent init`), or the host kills the plugin first. For long builds raise both: `"args": ["--max-shell-secs", "290"], "call_timeout_secs": 300`.

### Bootstrapping them at run time

An agent that does not have these tools can build them. `plugins/codetools/` is a standard-library Python port (`code_read`, `code_edit`, `code_glob`, `code_grep`, `code_tree`, with other names so they never clash with the built-in `fs_` tools). The agent writes the folder, `check_plugin` runs the real static checks and contract tests, `propose_upgrade` queues it, and you run `agent upgrade run <n>` and `agent upgrade approve <n>`. The tools appear in the agent's next turn with no restart, behind the same gate, sandboxed, with the home hidden. Every capability they ask for (`fs:read`, `fs:write`) is already granted, so nothing new needs your review beyond the code itself.

Two things make that more than a claim, and both are tested: the port returns the same answers as the built-in tools on the same inputs (reads, globs, greps, trees and every edit rule), and a scripted agent really goes write, check, propose, pipeline, approve, use. The agent is told about the `recursive` flag and the shape of these tools in the `propose_upgrade` guide. `plugin.json` must equal what the script reports; a test fails if it drifts.

## Hooks

Programs you write that the core consults at fixed points in the loop. The design follows opencode's plugin hooks, minus what would break this agent's trust model: **a hook can tighten and watch, never loosen.** It is consulted only after the gate has said yes, so it cannot turn a denial into an allow, and it cannot change a call's arguments (a rewrite after the gate approved the original would be a bypass). Only you can add one: they come from `config.json`, the upgrade pipeline never installs them (a `hooks` key in an agent-written `plugin.json` is ignored, and a test checks it), and the agent cannot write the file.

```json
"hooks": [
  { "name": "guard", "command": "/path/to/hook_guard",
    "args": ["--deny-path", ".env*", "--deny-path", "*.pem", "--deny-command", "rm\\s+-rf", "--redact-secrets"],
    "subscribe": ["tool.before", "tool.after"] },
  { "name": "audit-log", "command": "/path/to/hook_guard", "args": ["--log", "/var/log/agent-events.jsonl"],
    "subscribe": ["event"], "events": ["session.started", "session.finished"] }
]
```

| Point | When | A hook may |
|---|---|---|
| `tool.before` | After the gate allows, and **before the owner is asked**, so a vetoed call costs no approval prompt. All tools, core ones included. | answer `allow` or `deny` with a reason (the model sees `DENIED by a hook: <reason>`) |
| `tool.after` | After the tool ran, **before the result is written to the append-only log**, so a redacted secret is never stored. | `keep` the result or `replace` its content |
| `event` | `session.started`, `session.finished`, `tool.executed`, `tool.denied`, `approval.requested`, `approval.decided`. | watch. No answer is expected and none is waited for. |

Hooks run in config order and the first deny wins. A later hook sees what an earlier `tool.after` hook produced.

**Protocol.** One JSON object per line. The core sends `{"id":7,"hook":"tool.before","input":{session,tool,plugin,capability,tier,args}}` and reads `{"id":7,"result":{"action":"allow"}}` or `{"action":"deny","reason":"..."}`. `tool.after` input adds `content` and `is_error`; the answer is `{"action":"keep"}` or `{"action":"replace","content":"..."}`. Events are `{"hook":"event","event":"tool.executed","data":{...},"dropped":0}` with no reply.

**When a hook fails.** `on_error` decides. `tool.before` defaults to `deny`: a crash, a timeout (`timeout_ms`, default 5000) or a garbled answer blocks the call, because a guard that quietly stops guarding is worse than one that is loud. `tool.after` and `event` default to `skip`; set `"on_error": "deny"` on a redaction hook to withhold the result when it fails. A result larger than 1 MB is not shown to a `tool.after` hook at all and counts as a failure, since a redactor that saw only a prefix would let the rest through. A hook that crashed is restarted at most every two seconds. An invalid hook entry (misspelled `subscribe`, duplicate name, absurd timeout) stops the agent from starting.

**Events never block the agent.** They go through a bounded queue. A consumer that is slow, stuck or down loses events, and the next one it receives carries `"dropped": N`. When a session ends, hooks get their input closed and one second to finish what is queued, so the final events still arrive.

**Audit.** Every verdict is a row, attributed `hook:<name>`: `hook_denied`, `hook_replaced` (the reason says how many bytes changed, never the content), `hook_error`, and `hook_ignored` (a hook tried to change arguments).

**Isolation.** A hook starts with an empty environment plus the `env` you give it, runs in the workspace, and gets no handle to the stores. Add a `sandbox` section as for plugins (the home directory is hidden from it) unless it needs the network.

`hook_guard` is the bundled example and a usable guard: `--deny-capability` (exact or `prefix*`), `--deny-path` (globs, matched against each string argument and its last path component), `--deny-command` (regex on `command`), `--redact` and `--redact-secrets` (private keys, AWS, GitHub, `sk-`, bearer and Slack tokens), `--log` (events as JSON lines).

## MCP servers (stdio)

Any MCP server that speaks JSON-RPC 2.0 over stdio can be a plugin: add an `mcp` section to its entry in `config.json`. The client does the `initialize` handshake, sends `notifications/initialized`, reads the tool list (all pages), calls tools, answers the server's `ping`, declines the requests it does not support, and re-reads the tool list when the server announces a change.

    { "name": "browser", "command": "/path/to/chromium-mcp", "args": [], "call_timeout_secs": 90,
      "sandbox": { "network": true, "ro_binds": ["/path/to/chrome"] },
      "mcp": {
        "capability": "web:browse",                         // default for every tool of this server
        "tool_capabilities": { "screenshot": "web:capture" },   // per tool, by the server's own tool name
        "scope_args": { "save_page": ["path"] },            // arguments that hold file paths
        "tools": ["navigate", "screenshot", "save_page"],   // expose only these (leave out for all)
        "pin": "<hash from `agent mcp inspect browser`>" } }

**How tools fit the permission model.** MCP tools do not declare a capability, so you do. Without a mapping a tool gets `mcp:<server>`. The gate is still deny by default: a tool with no grant for its capability is hidden from the model and denied if called. **The tier always comes from your grants.** A server's own claims about a tool (`readOnlyHint`, `destructiveHint`) are ignored, because a server cannot label itself safe. Mapping a tool to an authority-changing capability (`upgrade:`, `grant:`, ...) is refused. Tools appear to the model as `<server>__<tool>` so two servers, or a server and a native plugin, never fight over a name like `navigate`.

**What a server can do to you through its descriptions.** The model reads each tool's description, and the server's author wrote it. So descriptions are capped at 1000 characters and stripped of control characters, and **pinning** exists:

    agent mcp inspect browser          # starts it, lists every tool with its capability and whether it is granted,
                                       # and prints the hash of the tool list (names, descriptions, schemas)

Read the descriptions, then put the hash in `pin`. From then on a server whose tools differ in any way is refused, at startup and when it announces a change while running. Without a pin, a server that comes back from a restart with different tools is still refused. The pin defends against a server that *changes* what its tools say after you approved them (a "rug pull"). It cannot tell you the descriptions were honest in the first place.

Output from an MCP tool reaches the model wrapped as untrusted data, like any tool output. Images and audio are replaced by a short placeholder, and a server can run in the sandbox like any plugin (a browser needs `network: true` and its install directory in `ro_binds`).

## Reloading at run time

| What | When a change takes effect |
|---|---|
| A plugin the upgrade pipeline deploys or rolls back | **The next turn of a running session**, and every later session. No restart. |
| An MCP server's tool list (it announces `tools/list_changed`) | The next turn of a running session. A pinned server whose list no longer matches is removed on the spot and stays out. |
| `config.json` edits (plugins, MCP servers, grants, budgets, event sources) with the daemon running | **The next session.** Event sources are started, stopped or restarted at once. A half-written or invalid file is ignored and the daemon keeps the last good settings. |
| Sessions already running | They keep the settings they started with, except installed plugins (above). |

Between turns the host compares what should be running with what is: it starts what is new, stops what is gone, replaces what changed, and leaves everything else alone, so a stateful server is not restarted for no reason. A plugin that fails to load is refused and reported once, and the old version, if there was one, keeps serving.

## Model providers

`model.provider` is `"anthropic"` (default) or `"openai"`, which means *any server that speaks the OpenAI chat-completions API with function calling*: OpenAI, OpenRouter, Ollama, vLLM, LM Studio, llama.cpp's server, and gateways in front of other vendors.

    "model": { "provider": "openai", "model": "gpt-4o", "max_tokens": 4096,
               "price_in_per_mtok": 2.5, "price_out_per_mtok": 10.0 }                  // needs OPENAI_API_KEY

    "model": { "provider": "openai", "model": "qwen2.5:14b",                            // a local Ollama
               "base_url": "http://localhost:11434/v1", "api_key_env": "",
               "price_in_per_mtok": 0, "price_out_per_mtok": 0 }

    "model": { "provider": "openai", "model": "anthropic/claude-sonnet-4.5",            // OpenRouter
               "base_url": "https://openrouter.ai/api/v1", "api_key_env": "OPENROUTER_API_KEY" }

    "model": { "provider": "openai", "model": "big-pickle",                            // OpenCode Zen's free model
               "base_url": "https://opencode.ai/zen/v1", "api_key_env": "OPENCODE_API_KEY",
               "price_in_per_mtok": 0, "price_out_per_mtok": 0 }

- `base_url` works for Anthropic too (a proxy or gateway). `api_key_env` names the environment variable; an empty string means no key. With a custom `base_url` and the variable unset, no key is sent, because many local servers need none.
- `max_tokens_param` is `"max_tokens"` by default; set `"max_completion_tokens"` for newer OpenAI models that reject the old name.
- **The key is handed to curl on stdin, never on the command line, and is never sent over plain `http://` to any machine but this one.** Config values are escaped, so a hostile environment value cannot add curl options (curl really does obey option lines hidden in a value; this is tested with the realistic attack shapes).
- Set the prices for the model you use. The spending caps are only as good as those numbers, and `0` is right for a local model.
- Each call writes its request to its own file. An earlier version used one fixed name, so two sessions running at once in the daemon could overwrite each other's prompt. That is fixed and tested.

### Try a provider before trusting it: `agent model-check`

    export OPENCODE_API_KEY=...        # whichever variable your config names
    agent model-check

Three small calls, each reported as ok or FAIL with a hint at the cause, and the key is never printed:

1. **plain reply**: can it answer at all (reachability, key, model name)?
2. **tool call**: when asked, does it actually call a tool? This is what decides whether a model can drive an agent. Many small or local models answer in text instead, and the report says so plainly.
3. **tool result round trip**: does it accept a tool result sent back and carry on? This is the step servers most often get subtly wrong.

It stops at the first failure and exits non-zero. Run it whenever you change `provider`, `model` or `base_url`.

**OpenCode Zen (`big-pickle`).** Its documentation gives the base URL `https://opencode.ai/zen/v1`, a plain `Authorization: Bearer` key from your OpenCode account, and `big-pickle` as a free chat-completions model, which is the shape this provider speaks. It has **not been run against the live service**: the environment this was built in blocks `opencode.ai` at its network egress, so only a local stand-in was used. I have not read the service's data-handling terms for free models either; check them before pointing it at private code.

## The bootstrapping review

*Can the agent extend itself without a person doing the work?* The loop has seven steps. This is where each one stands.

| Step | Status |
|---|---|
| 1. **Know how.** Be told the plugin format and protocol | **Added.** `propose_upgrade` carries a full guide with a working example. A test runs that exact example through the real checks, so the documentation cannot drift away from what the checks accept. |
| 2. **Write** it | Works. `fs_write` inside the sandbox. |
| 3. **Self-test** before bothering anyone | **Added.** `check_plugin` runs the same static checks and contract tests on a throwaway copy and returns the findings. Nothing is proposed or stored. |
| 4. **Submit** | Works. `propose_upgrade` snapshots the folder. |
| 5. **Hear back** | **Added.** `upgrade_status` shows where it stands and what is wrong with its own code. It never shows the owner's eval case ids or the canary's replayed answers: an agent that could read the test suite could tune its output to the suite. |
| 6. **Review and deploy** | Owner only, by design (checks, approval, versioned deploy, rollback). This is the deliberate bottleneck. |
| 7. **Use it** | Works from the next session. |

The agent needs the `upgrade:propose` grant for steps 1 to 5. It is not given by default.

**What the review found.** The first drill, with a scripted model that already knew the format, passed. That showed the pipeline was whole, and nothing about whether a model could use it. Inspecting what an agent is actually told found three breaks: it was never given the plugin format or protocol, it could not learn how a proposal went, and it could only test its work through an approval-gated shell command. Those are the three additions above.

**What bootstrapping does *not* mean here, by design.** The agent cannot change the loop, the plugin contracts, the permission layer or the sandbox; those are human-only. It also cannot build this program's own source: the sandbox has no network and no toolchain, so there is no self-hosting of the Rust core. "Self-upgrade" means *new capabilities as sandboxed plugins, reviewed by a person*.

**Still open, most important first.**
1. **Nothing has been tried with a real model.** Every test uses a scripted one. The guide is shown to be correct and complete; it is not shown to be *sufficient for a language model to write a working plugin from*. That is the biggest unknown and the first thing to try with a live key.
2. **A new tool's own behavior is tested by no one but you.** Contract tests check the protocol and the eval gate checks that existing behavior did not break. Neither checks that `shout` actually shouts. For a first version your review is the only functional check. The agent can `propose_eval` cases that call its new tool, but nothing ties a case to a candidate: you accept the case, rebuild the baseline, and only then does the gate cover it.
3. **No nudge for the owner.** A proposal sits until you run `agent upgrade list`.
4. **Plugins are python3 or sh, standard library only** (no network inside the sandbox to install anything).
5. **Prompt, config and memory self-changes** are not covered.

## Build and run

Needs Rust 1.75+ and a C compiler (SQLite is bundled). Linux for the daemon lock.

    cargo build --release
    cargo test

    cd your-project
    agent init                        # writes ./.agent/config.json
    export ANTHROPIC_API_KEY=...

    # one task, in this terminal
    agent run "list the files here and summarise the README"

    # or as a service
    agent daemon                      # terminal 1
    agent submit "summarise the README"   # terminal 2
    agent status
    agent approvals                   # actions waiting for you
    agent approve 3
    agent stop

Edit `.agent/config.json` first: set `model.price_in_per_mtok` and `price_out_per_mtok` to your
model's real prices (the defaults are placeholders, and the spending caps depend on them).

To feed the daemon from a folder, add a source to the config:

    "sources": [{ "name": "inbox", "command": "/path/to/source_inbox", "args": ["inbox"] }]

Every file dropped into `<workspace>/inbox/` becomes one task. **The file's text is the task**, so
only point a source at a channel you trust. The gate still bounds what a hostile task can do.

## Layout

    src/config.rs     tiers, grants, budgets, plugins, sources
    src/store.rs      queue, sessions, session log, spend ledger, approval queue
    src/audit.rs      hash-chained audit log
    src/gate.rs       the permission gate and path resolution
    src/plugin.rs     plugin host: native protocol, MCP client, reload, inspection
    src/source.rs     event-source host (enqueue, ack, restart)
    src/hooks.rs      hook host (tool.before, tool.after, event)
    src/modelcheck.rs the three-step provider check behind `agent model-check`
    src/provider.rs   model contract, scripted provider, Anthropic and OpenAI-compatible providers
    src/runner.rs     the loop, budgets, approvers, crash repair, handoff notes, core tools, sub-agents
    src/compact.rs    compaction records, pins, summary strategies
    src/daemon.rs     worker pool, recovery, shutdown, daemon lock
    src/plugin_example.py   the example plugin shown to the agent (and tested)
    src/sandbox.rs    bubblewrap wrapper for plugins
    src/upgrade.rs    propose, the pipeline, registry, deploy, rollback
    src/delegate.rs   rule envelope, delegate approver, proposals, learning
    src/eval.rs       eval suite: cases, checks, runs, baseline, compare, proposals
    src/bin/plugin_check.rs  tool plugin: sandboxed check_exec
    src/bin/plugin_fs.rs     tool plugin: fs_read, fs_list, fs_write, fs_edit, fs_glob, fs_grep, fs_tree, shell_exec
    plugins/codetools/       python port of the code tools, for the upgrade pipeline (plugin.json + plugin.py)
    src/bin/source_inbox.rs  event source: a folder of task files
    src/bin/hook_guard.rs    example hook: veto by path, capability or command; redact secrets; log events
    tests/seam.rs     19 tests through the session runner
    tests/daemon.rs   13 tests through the daemon
    tests/compaction.rs  10 tests: stubbing, recall, pins, summary, replay, strategy swap, too-large
    tests/subagents.rs   15 tests: narrowing, tiers, scope, depth, budget, orphans, crash, interrupt, shutdown
    tests/verify.rs   18 tests: verdicts, retries, independence, read-only, crash window, sandboxed checks
    tests/eval.rs     16 tests: cases, checks, baseline and compare, protection, proposals
    tests/mcp.rs      17 tests: the MCP client against a strict stand-in server, permissions, pinning, containment
    tests/reload.rs   13 tests: between turns, MCP list changes, the host, the daemon watching the config
    tests/bootstrap.rs 7 tests: the write, check, propose, deploy, use drill; the guide; what the agent may and may not see
    tests/provider.rs 19 tests: both providers against a local stand-in server, key handling, concurrency, injection
    tests/sandbox.rs  9 tests: what a sandboxed plugin can and cannot reach, with unsandboxed controls
    tests/upgrade.rs  26 tests: proposing, every stage, approval, deploy, rollback, auto-approval, tamper-proofing
    tests/delegate.rs 23 tests: envelope, escalation, deny, expiry, revoke, protection, proposals, silent learning
    tests/hooks.rs 16 tests: veto, never-loosen, ordering, fail-closed, redaction before the log, events and drops, config, who can add one, sandbox
    tests/codetools.rs 18 tests: edit rules, read slices, search, scope, the recursive rule, shell timeouts, python parity, the bootstrap drill

## Known limits (read before trusting it)

1. **Isolation depends on the sandbox being switched on for a plugin.** A plugin with `"sandbox"` set runs in bubblewrap: no network, and no view of the agent's own files. `agent init` sets it for `fs` only if bubblewrap is installed; without it an approved `shell_exec` is unrestricted and a hostile plugin binary could open the database files directly. Plugins the upgrade pipeline installs are always sandboxed, and `agent upgrade run` refuses without bubblewrap. The `check` plugin keeps its own namespace sandbox, which cannot be nested inside another.
2. **No provider has been tried against a live API.** Both are verified against a local stand-in for their APIs: the exact request (path, headers, body), a full multi-turn session, errors, and key handling. That shows the code does what it should, not that a particular vendor accepts it. Every model-written thing (summaries, verifier verdicts, plugins) has so far been produced by scripted models only.
3. **Verification is only as good as its evidence.** With no `check_commands` the verifier can only read files, and a verifier model can be wrong or be steered by what it reads (its output is data to the worker, and it cannot change anything, but a false `pass` completes the session). Put your real test and build commands in `check_commands`.
4. **The audit chain detects edits and mid-chain deletion, not truncation of the last rows.**
5. **Budgets are checked before each model call**, so one call can overshoot a limit, and concurrent
   sessions can overshoot the global cap by up to one call each. Wall time is per run, not across resumes.
6. **The daemon handles `agent stop` but not SIGINT or SIGTERM.** Killing it is safe, because the next
   start recovers, but running sessions are repaired instead of paused cleanly.
7. **The daemon lock checks `/proc`**, so it is Linux-only.
8. **A malformed assistant entry in a session log is skipped when rebuilding context** instead of
   failing the session. The model call that follows then usually fails and suspends it.
9. Undo copies are saved before `fs_write` overwrites a file, but there is no undo command yet.
10. A failed `agent run` (for example a missing API key) leaves its session queued. A running daemon
   will pick it up.
11. **The context estimate is bytes / 4**, not a real tokenizer. The 75% trigger leaves room for the error, but an unusual text (code, non-Latin scripts) can cost more tokens per byte. Set `context_window_tokens` below the real window if in doubt.
12. **The `model` summary strategy has only been run against the scripted provider**. A summary written by a model is also not guaranteed to be faithful; the goal, permissions and pins do not depend on it.
13. **Pins are written by the model.** A prompt-injected agent could pin a false "constraint". The gate still enforces permissions, and the permissions block in the preamble comes from the owner's grants, but a pinned note is only as trustworthy as the agent.
14. **Children run one at a time** and block their parent, so there is no parallel fan-out yet. A parent's wall-time budget includes the time its children take.
15. **A child stopped by a crash or shutdown is not resumed.** The parent is told and may spawn a new one, which starts from scratch (partial work may be on disk). `agent resume` and `requeue` refuse child sessions on purpose.
16. **The sub-agent depth rule is enforced twice** (the child is not given `agent:spawn`, and the spawn tool checks depth), but the default of 1 is the only value the tests exercise beyond 2 levels.
17. Compaction after a very large `recall` can be repeated every few steps if the model keeps recalling big outputs. The context cannot exceed 95% of the window because of the hard stop, but the model can waste budget this way; the step and token budgets bound it.
18. **The verifier's success path has only run against the scripted provider**. The verdict parser takes the last JSON object with a `verdict` field in the answer.
19. **A verifier sees only files the worker wrote through `fs_write`.** Changes made by an approved `shell_exec` are not listed; the verifier is told to look in the workspace, but may miss them.
20. **Eval `command_ok` checks run with `sh` in the throwaway workspace, not in the check sandbox.** Owner-written cases are trusted; proposed ones may only use `check_commands`.
21. **Scripted eval runs test the harness (gate, plugins, verifier flow), not the model.** Whether a prompt or model change is better is only measured by `--live` runs, which cost money and have not been run against the real API.
22. **`agent eval compare` looks at pass or fail only.** It does not flag cost or step-count growth.
23. **Verification does not wait for a pass from a human even when uncertain** (by default). A flagged session is visible in `agent status` but nothing alerts you.
24. **Silent learning has nothing it may adopt today.** The spec limits it to the lowest tier, but only
   irreversible actions ever ask for approval (read-only and reversible ones proceed on their own), so a
   request that reaches the delegate always has the highest tier. The switch and its guard exist and are
   tested, but in practice every proposal waits for you. Making it useful needs a decision: add a finer
   tier inside "needs approval", or drop the setting.
25. **A rule trusts the exact thing it names.** Approving `cargo test` approves it in every session and for every
   child agent, and it runs as your OS user, unsandboxed. Keep rules narrow, give risky ones an `expires_at`,
   and note that rules are not scoped to one session or one task.
26. **Proposals are only looked for when the delegate has to escalate, or when you run `agent delegate suggest`.**
   Only exact repeats count, so a command that changes slightly each time never becomes a proposal.
27. **The delegate cannot be fooled by text, but it can be wrong about what you meant.** It does what the rules say.
   A rule that is too broad is the owner's mistake, not something the delegate can catch.
28. **Only plugins are upgradeable.** The spec also lets the agent change its own prompts, configuration and memory.
   Those have no versioning, checks or rollback yet; this stage covers plugin code (python3 or sh scripts).
29. **The sandbox contains a plugin; it does not limit what a granted tool may do inside it.** Capabilities are
   enforced by the gate on *calls*. An installed plugin that you granted `text:shout` still has a writable
   workspace and could change files there, because the sandbox gives it the workspace. Installed plugins always
   get a writable workspace today. It cannot reach the agent's files, the network, or the rest of the machine.
   What a plugin *returns* is untrusted data like any tool output.
30. **The canary replays only recorded read-only calls**, taken from the audit log, whose arguments are stored up
   to 2000 characters. Reversible and irreversible tools are never replayed, a plugin with nondeterministic
   output will look different, and a brand-new plugin has nothing to compare with.
31. **Automatic rollback happens at deploy time**, when the suite runs again with the new version live. A plugin that
   starts failing later is not rolled back by itself; `agent upgrade rollback` is the switch.
32. **Refresh the baseline** (`agent eval run`, `agent eval baseline`) after an upgrade changes behavior on purpose,
   or later upgrades are judged against the old behavior. The gate also runs scripted cases only, never live ones.
33. **OpenAI-compatible means chat-completions with function calling.** A server or model without tool calling cannot drive this agent, and there is no fallback. Not supported: Azure OpenAI's `api-key` header and `?api-version=` URLs, streaming, the Responses API, and a `tool_choice` setting. Reasoning models may need `max_tokens_param` set to `max_completion_tokens`. A tool result's error flag becomes the text prefix `ERROR:` because the API has no such field.
34. **The bootstrapping review's open items** (a real model, tests of a new tool's own behavior, an owner notification) are listed under "The bootstrapping review".
35. **The MCP client has not been tried against a real MCP server.** Only a strict stand-in was used: it checks the
    envelope and the handshake order, pages its list, and mixes pings, unsupported requests and notifications in with
    its answers, which is what real servers do. Servers differ in small ways. Run `agent mcp inspect <name>` against each
    real one (your own, and any off-the-shelf one) before trusting it.
36. **MCP support is stdio and tools only.** Not supported: HTTP or SSE transports, resources, prompts, and server-initiated
    sampling or elicitation (those requests are declined). Image and audio results become a placeholder.
37. **Pinning detects change, not dishonesty.** A server's first description is whatever its author wrote, and a model
    reads it. Read the output of `agent mcp inspect` before you pin, and keep the capability grants narrow.
38. **Only you can add an MCP server or an event source.** The upgrade pipeline installs native tool plugins; an agent
    cannot install an MCP server or write an event source. Tool-list changes are noticed between turns, not in the
    middle of a model call.
39. **A config edit applies to new sessions, not to ones already running**, except event sources (immediately) and
    installed plugins (next turn). Grants and budgets in a running session do not change under it.

40. **The `recursive` flag is declared by the plugin**, like `scope_args`, so the gate trusts a manifest you reviewed. For a sandboxed plugin the home is hidden anyway. MCP tools cannot be marked recursive (there is no config for it yet), so do not point an MCP search tool at a folder that holds the agent's home without scoping its grant.
41. **With the default layout a recursive search cannot start at the workspace root**, because `.agent` is inside it. The model must name a subfolder. Moving the home outside the workspace removes the restriction.
42. **Read-before-edit is remembered by the plugin process.** If the host restarts a hung plugin the memory is gone and the next edit says to read the file first (it fails closed). There is no check that the file changed after it was read; the exact-text match is the only guard against editing stale content.
43. **Shell commands are limited to `--max-shell-secs` (25 by default)**, much shorter than hostmcp's 2 minutes. hostmcp's `cwd` and `description` arguments were not carried over (`cwd` would be a path the gate does not check). `fs_edit` also refuses an empty `old_string`, which hostmcp did not. The `*.{ts,tsx}` include syntax hostmcp promised but never matched now works.
44. **The Python port is a reference, not a clone.** It reads `.gitignore` only in the search folder and the workspace root, ignores negation lines, and uses Python's regex dialect. It has been compared with the built-in tools on a fixed set of inputs, not on every possible one, and has not been written by a live model: whether a model can produce it from the guide alone is the same open question as item 1 of the bootstrapping review.

45. **Hooks are not part of evals or the upgrade checks.** Evals and the pipeline's contract and canary runs start plugins without them, so a passing eval does not show that your hooks leave the agent's behavior alone. Every real session, including a verifier's, gets them.
46. **A hook is trusted code.** It sees every tool call's arguments and every result, secrets included, and runs with your privileges unless you give it a `sandbox`. A hook's deny reason is shown to the model, so keep secrets out of reasons. The `tool.before` timeout is added to every tool call's latency.
47. **`hook_guard` matches text, not meaning.** It does not resolve `..` or symlinks and cannot see what a shell will expand, so `rm -rf` has variants it will not catch. It is a seat belt. The gate and the sandbox are the walls.
48. **Events are at most once.** A crash or a full queue loses events (counted in `dropped`). Use them for notification, metrics and logs, not as a source of truth: the audit log is that.
49. **Not built:** a hook that rewrites arguments (it would have to go back through the gate and the audit log), an "ask the owner" verdict, and hooks for compaction, the system prompt or tool definitions. Sub-agent sessions share their parent's hooks.
