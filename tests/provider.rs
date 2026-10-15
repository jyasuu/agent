//! The real providers, against a local stand-in for each API. There is no live key here, so this
//! cannot prove a particular vendor accepts the requests. What it does prove: the exact request
//! each provider sends (path, headers, body), that a full multi-turn session round-trips, how errors
//! surface, that the key never goes where it should not, and that concurrent sessions do not mix up.
mod common;
use agent_core::config::ModelConfig;
use agent_core::modelcheck;
use agent_core::provider::{self, Block, Message, ModelProvider, OpenAiProvider, ToolSpec};
use common::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---- a tiny HTTP server that records what it receives ----------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct Mock {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    /// `reply` gets each request and returns (status, body text).
    fn start(reply: impl Fn(&Seen, usize) -> (u16, String) + Send + Sync + 'static) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(vec![]));
        let reply = Arc::new(reply);
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let (reply, log) = (Arc::clone(&reply), Arc::clone(&log));
                std::thread::spawn(move || serve(stream, reply, log));
            }
        });
        Mock { port, seen }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve(mut s: TcpStream, reply: Arc<dyn Fn(&Seen, usize) -> (u16, String) + Send + Sync>, log: Arc<Mutex<Vec<Seen>>>) {
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let path = lines.next().unwrap_or("").split_whitespace().nth(1).unwrap_or("").to_string();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect();
    if headers.get("expect").map(|e| e.contains("100")).unwrap_or(false) {
        let _ = s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let len: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
    let seen = Seen { path, headers, body };
    let index = {
        let mut l = log.lock().unwrap();
        l.push(seen.clone());
        l.len() - 1
    };
    let (status, text) = reply(&seen, index);
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = s.write_all(resp.as_bytes());
}

fn cfg(provider: &str, base: &str, key_env: &str) -> ModelConfig {
    ModelConfig {
        provider: provider.into(),
        model: "test-model".into(),
        max_tokens: 321,
        base_url: Some(base.into()),
        api_key_env: Some(key_env.into()),
        ..Default::default()
    }
}

fn tmp() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("agent-prov-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::SeqCst)
}

fn user(text: &str) -> Message {
    Message { role: "user".into(), content: vec![Block::Text { text: text.into() }] }
}

fn spec() -> ToolSpec {
    ToolSpec { name: "fs_read".into(), description: "read a file".into(), input_schema: json!({ "type": "object", "properties": { "path": { "type": "string" } } }) }
}

fn chat_tool_call(id: &str, name: &str, args: &str) -> String {
    json!({ "choices": [{ "message": { "role": "assistant", "content": null,
        "tool_calls": [{ "id": id, "type": "function", "function": { "name": name, "arguments": args } }] } }],
        "usage": { "prompt_tokens": 120, "completion_tokens": 30 } })
    .to_string()
}

fn chat_text(t: &str) -> String {
    json!({ "choices": [{ "message": { "role": "assistant", "content": t } }], "usage": { "prompt_tokens": 150, "completion_tokens": 10 } }).to_string()
}

// ---- OpenAI-compatible: the request ----------------------------------------------------------

#[test]
fn the_openai_request_has_the_shape_the_api_expects() {
    let messages = vec![
        user("read a.txt"),
        Message { role: "assistant".into(), content: vec![
            Block::Text { text: "reading".into() },
            Block::ToolUse { id: "call_1".into(), name: "fs_read".into(), input: json!({ "path": "a.txt" }) },
            Block::ToolUse { id: "call_2".into(), name: "fs_read".into(), input: json!({ "path": "b.txt" }) },
        ] },
        Message { role: "user".into(), content: vec![
            Block::ToolResult { tool_use_id: "call_1".into(), content: "hello".into(), is_error: false },
            Block::ToolResult { tool_use_id: "call_2".into(), content: "no such file".into(), is_error: true },
        ] },
    ];
    let body = provider::openai_request("m", 99, "max_tokens", "be brief", &messages, &[spec()]);
    let msgs = body["messages"].as_array().unwrap();
    assert_eq!(msgs[0], json!({ "role": "system", "content": "be brief" }));
    assert_eq!(msgs[1], json!({ "role": "user", "content": "read a.txt" }));
    assert_eq!(msgs[2]["role"], "assistant");
    assert_eq!(msgs[2]["content"], "reading");
    let calls = msgs[2]["tool_calls"].as_array().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["type"], "function");
    assert_eq!(calls[0]["function"]["arguments"], "{\"path\":\"a.txt\"}", "arguments travel as a JSON string");
    // Each result is its own tool message, in order, straight after the assistant message.
    assert_eq!(msgs[3], json!({ "role": "tool", "tool_call_id": "call_1", "content": "hello" }));
    assert_eq!(msgs[4], json!({ "role": "tool", "tool_call_id": "call_2", "content": "ERROR: no such file" }));
    assert_eq!(body["tools"][0]["function"]["name"], "fs_read");
    assert_eq!(body["tools"][0]["function"]["parameters"]["type"], "object");
    assert_eq!(body["max_tokens"], 99);
}

#[test]
fn the_output_limit_field_can_be_renamed_for_newer_openai_models() {
    let body = provider::openai_request("m", 50, "max_completion_tokens", "s", &[user("hi")], &[]);
    assert_eq!(body["max_completion_tokens"], 50);
    assert!(body.get("max_tokens").is_none());
    assert!(body.get("tools").is_none(), "no tools field when there are no tools");
}

// ---- OpenAI-compatible: the reply ------------------------------------------------------------

#[test]
fn replies_from_different_servers_are_all_understood() {
    // Content as a list of parts, arguments already an object, and a missing call id.
    let v = json!({ "choices": [{ "message": { "content": [{ "type": "text", "text": "he" }, { "type": "text", "text": "llo" }],
        "tool_calls": [{ "type": "function", "function": { "name": "fs_read", "arguments": { "path": "x" } } }] } }],
        "usage": { "prompt_tokens": 7, "completion_tokens": 3 } });
    let r = provider::openai_parse(&v).unwrap();
    assert_eq!(r.content[0], Block::Text { text: "hello".into() });
    let Block::ToolUse { id, name, input } = &r.content[1] else { panic!("expected a tool call") };
    assert!(!id.is_empty(), "an id is made up when the server sends none");
    assert_eq!((name.as_str(), input), ("fs_read", &json!({ "path": "x" })));
    assert_eq!((r.usage.input_tokens, r.usage.output_tokens), (7, 3));

    // Two calls without ids get different ids, or the next request could not tell them apart.
    let v = json!({ "choices": [{ "message": { "content": "", "tool_calls": [
        { "function": { "name": "a", "arguments": "{}" } }, { "function": { "name": "b", "arguments": "" } }] } }] });
    let r = provider::openai_parse(&v).unwrap();
    let ids: Vec<&String> = r.content.iter().filter_map(|b| if let Block::ToolUse { id, .. } = b { Some(id) } else { None }).collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn arguments_that_are_not_a_json_object_are_kept_for_the_tool_to_reject() {
    let v = json!({ "choices": [{ "message": { "content": null, "tool_calls": [
        { "id": "c", "function": { "name": "fs_read", "arguments": "{not json" } }] } }] });
    let r = provider::openai_parse(&v).unwrap();
    let Block::ToolUse { input, .. } = &r.content[0] else { panic!() };
    assert_eq!(input["_unparsed"], "{not json", "nothing is guessed, and nothing is silently dropped");
}

#[test]
fn an_error_object_and_an_empty_reply_become_errors() {
    let e = provider::openai_parse(&json!({ "error": { "message": "invalid api key" } })).unwrap_err().to_string();
    assert!(e.contains("invalid api key"), "{e}");
    assert!(provider::openai_parse(&json!({ "choices": [] })).is_err());
}

// ---- OpenAI-compatible: a whole session over HTTP --------------------------------------------

#[test]
fn a_full_session_works_through_an_openai_compatible_server() {
    std::env::set_var("AGENT_TEST_KEY_A", "sk-test-123");
    let mock = Mock::start(|_, i| (200, if i == 0 { chat_tool_call("call_abc", "fs_read", "{\"path\":\"a.txt\"}") } else { chat_text("The file says hello.") }));
    let env = setup("prov-openai", all_grants(), |_| {});
    std::fs::write(env.ws.join("a.txt"), "hello from the file").unwrap();
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), "AGENT_TEST_KEY_A"), &tmp()).unwrap();

    let (sid, out) = run(&env, &p, &no_approvals(), "what does a.txt say?");
    assert!(matches!(out, agent_core::runner::Outcome::Completed { ref summary } if summary == "The file says hello."), "{out:?}");
    assert_eq!(results(&env, sid)[0]["content"], "hello from the file", "the tool really ran");

    let seen = mock.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, "/v1/chat/completions");
    assert_eq!(seen[0].headers["authorization"], "Bearer sk-test-123");
    assert_eq!(seen[0].body["model"], "test-model");
    assert_eq!(seen[0].body["max_tokens"], 321);
    assert!(seen[0].body["tools"].as_array().unwrap().iter().any(|t| t["function"]["name"] == "fs_read"));

    // The second request replays the conversation so far, with the result tied to the call id.
    let msgs = seen[1].body["messages"].as_array().unwrap();
    let assistant = msgs.iter().find(|m| m["role"] == "assistant").expect("the earlier turn is replayed");
    assert_eq!(assistant["tool_calls"][0]["id"], "call_abc");
    let tool_msg = msgs.iter().find(|m| m["role"] == "tool").expect("the result is sent back");
    assert_eq!(tool_msg["tool_call_id"], "call_abc");
    assert!(tool_msg["content"].as_str().unwrap().contains("hello from the file"));
    assert!(tool_msg["content"].as_str().unwrap().contains("untrusted_tool_output"), "tool output stays marked as data");

    // Spending is recorded from the usage the server reports.
    assert_eq!(env.store.session_spend(sid).unwrap().0, 120 + 30 + 150 + 10);
}

#[test]
fn a_local_server_that_needs_no_key_gets_no_authorization_header() {
    let mock = Mock::start(|_, _| (200, chat_text("ok")));
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), ""), &tmp()).unwrap();
    p.complete("s", &[user("hi")], &[]).unwrap();
    assert!(!mock.requests()[0].headers.contains_key("authorization"));

    // Same when the variable simply is not set and the server is not OpenAI itself.
    let mock = Mock::start(|_, _| (200, chat_text("ok")));
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1/"), "AGENT_TEST_KEY_UNSET_XYZ"), &tmp()).unwrap();
    p.complete("s", &[user("hi")], &[]).unwrap();
    assert_eq!(mock.requests()[0].path, "/v1/chat/completions", "a trailing slash in base_url is harmless");
    assert!(!mock.requests()[0].headers.contains_key("authorization"));
}

#[test]
fn openai_itself_needs_a_key() {
    let mut c = ModelConfig { provider: "openai".into(), api_key_env: Some("AGENT_TEST_KEY_UNSET_ABC".into()), ..Default::default() };
    c.base_url = None;
    let e = match OpenAiProvider::from_env(&c, &tmp()) {
        Ok(_) => panic!("must refuse to start without a key"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("AGENT_TEST_KEY_UNSET_ABC"), "{e}");
}

#[test]
fn a_key_is_never_sent_over_plain_http_to_another_machine() {
    std::env::set_var("AGENT_TEST_KEY_B", "sk-secret");
    let p = OpenAiProvider::from_env(&cfg("openai", "http://example.com/v1", "AGENT_TEST_KEY_B"), &tmp()).unwrap();
    let e = p.complete("s", &[user("hi")], &[]).unwrap_err().to_string();
    assert!(e.contains("unencrypted"), "{e}");
    // This machine is fine, and so is a server that gets no key at all.
    assert!(OpenAiProvider::from_env(&cfg("openai", "http://localhost:11434/v1", "AGENT_TEST_KEY_B"), &tmp()).is_ok());
}

#[test]
fn the_key_does_not_appear_on_the_command_line() {
    // curl reads its options, key included, from stdin. This checks the one place it could leak.
    std::env::set_var("AGENT_TEST_KEY_C", "sk-must-not-leak-9f8e7d");
    let mock = Mock::start(|_, _| {
        std::thread::sleep(Duration::from_millis(600)); // keep curl alive long enough to inspect
        (200, chat_text("ok"))
    });
    let p = Arc::new(OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), "AGENT_TEST_KEY_C"), &tmp()).unwrap());
    let worker = { let p = Arc::clone(&p); std::thread::spawn(move || p.complete("s", &[user("hi")], &[]).unwrap()) };
    std::thread::sleep(Duration::from_millis(250));
    let mut leaked = false;
    for e in std::fs::read_dir("/proc").unwrap().filter_map(|e| e.ok()) {
        if let Ok(cmd) = std::fs::read(e.path().join("cmdline")) {
            if String::from_utf8_lossy(&cmd).contains("sk-must-not-leak") {
                leaked = true;
            }
        }
    }
    worker.join().unwrap();
    assert!(!leaked, "the API key was visible in a process command line");
}

#[test]
fn server_errors_surface_with_their_message() {
    let mock = Mock::start(|_, i| if i == 0 { (401, json!({ "error": { "message": "Incorrect API key provided" } }).to_string()) } else { (502, "<html>Bad Gateway</html>".into()) });
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), ""), &tmp()).unwrap();
    let e = p.complete("s", &[user("hi")], &[]).unwrap_err().to_string();
    assert!(e.contains("Incorrect API key provided"), "{e}");
    let e = p.complete("s", &[user("hi")], &[]).unwrap_err().to_string();
    assert!(e.contains("not JSON") && e.contains("Bad Gateway"), "a non-JSON reply shows what it was: {e}");
}

// ---- Anthropic, against the same kind of stand-in --------------------------------------------

#[test]
fn the_anthropic_success_path_round_trips_a_full_session() {
    std::env::set_var("AGENT_TEST_KEY_D", "ak-test-456");
    let mock = Mock::start(|_, i| {
        (200, if i == 0 {
            json!({ "content": [{ "type": "text", "text": "Let me look." }, { "type": "tool_use", "id": "toolu_1", "name": "fs_read", "input": { "path": "a.txt" } }],
                    "usage": { "input_tokens": 100, "output_tokens": 20 } }).to_string()
        } else {
            json!({ "content": [{ "type": "text", "text": "It says hi." }], "usage": { "input_tokens": 140, "output_tokens": 8 } }).to_string()
        })
    });
    let env = setup("prov-anthropic", all_grants(), |_| {});
    std::fs::write(env.ws.join("a.txt"), "hi there").unwrap();
    let p = provider::from_config(&cfg("anthropic", &format!("http://127.0.0.1:{}", mock.port), "AGENT_TEST_KEY_D"), &tmp()).unwrap();
    let (sid, out) = run(&env, p.as_ref(), &no_approvals(), "read a.txt");
    assert!(matches!(out, agent_core::runner::Outcome::Completed { ref summary } if summary == "It says hi."), "{out:?}");
    assert_eq!(results(&env, sid)[0]["content"], "hi there");

    let seen = mock.requests();
    assert_eq!(seen[0].path, "/v1/messages");
    assert_eq!(seen[0].headers["x-api-key"], "ak-test-456");
    assert_eq!(seen[0].headers["anthropic-version"], "2023-06-01");
    assert!(seen[0].body["system"].is_string() && seen[0].body["messages"].is_array());
    assert_eq!(seen[1].body["messages"].as_array().unwrap().last().unwrap()["content"][0]["tool_use_id"], "toolu_1");
    assert_eq!(env.store.session_spend(sid).unwrap().0, 100 + 20 + 140 + 8);
}

// ---- the shared HTTP layer -------------------------------------------------------------------

#[test]
fn concurrent_sessions_never_overwrite_each_others_requests() {
    // The daemon runs sessions on threads of one process. Every call must write its own request
    // file, or one session's prompt can be replaced by another's before it is sent.
    let dir = tmp();
    let paths: std::collections::BTreeSet<_> = (0..200).map(|_| provider::unique_request_path(&dir)).collect();
    assert_eq!(paths.len(), 200);

    // And end to end: many callers at once, each must get the answer to *its own* question.
    let mock = Mock::start(|req, _| {
        let said = req.body["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap().to_string();
        std::thread::sleep(Duration::from_millis(30));
        (200, chat_text(&format!("echo:{said}")))
    });
    let p = Arc::new(OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), ""), &dir).unwrap());
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let p = Arc::clone(&p);
            std::thread::spawn(move || {
                let r = p.complete("s", &[user(&format!("question-{i}"))], &[]).unwrap();
                (i, r)
            })
        })
        .collect();
    for h in handles {
        let (i, r) = h.join().unwrap();
        assert_eq!(r.content[0], Block::Text { text: format!("echo:question-{i}") }, "caller {i} got someone else's answer");
    }
    let leftovers = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("request-")).count();
    assert_eq!(leftovers, 0, "request files are removed after each call");
}

#[test]
fn a_hostile_environment_value_cannot_inject_curl_options() {
    // curl really does obey extra option lines hidden in a value, so long as nothing escapes the newline.
    // Three shapes: one that closes the quote, one that quotes its own value, and one that needs no quotes
    // at all (curl accepts an unquoted value, which is what a careful attacker would use).
    let shapes = ["sk-x\"\noutput = \"{V}\"\nheader = \"x-evil: 1", "sk-x\noutput = \"{V}\"", "sk-x\noutput = {V}"];
    for (i, shape) in shapes.iter().enumerate() {
        let dir = tmp();
        let var = format!("AGENT_TEST_KEY_E{i}");
        std::env::set_var(&var, shape.replace("{V}", &dir.join("injected.txt").display().to_string()));
        let mock = Mock::start(|_, _| (200, chat_text("ok")));
        let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), &var), &dir).unwrap();
        let _ = p.complete("s", &[user("hi")], &[]);
        let written: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        assert!(written.is_empty(), "shape {i}: the injected `output` option wrote {written:?}");
        assert!(!mock.requests().iter().any(|r| r.headers.contains_key("x-evil")), "shape {i}: nor did the injected header");
    }
}

#[test]
fn an_unknown_provider_name_is_refused_with_the_valid_choices() {
    let c = ModelConfig { provider: "mystery".into(), ..Default::default() };
    let e = match provider::from_config(&c, &tmp()) {
        Ok(_) => panic!("must refuse"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("anthropic") && e.contains("openai"), "{e}");
}


// ---- `agent model-check` ---------------------------------------------------------------------

/// A server that behaves: plain reply, then a tool call when tools are offered, then a reply to the result.
fn good_server() -> Mock {
    Mock::start(|req, _| {
        let msgs = req.body["messages"].as_array().unwrap();
        let has_tools = req.body.get("tools").is_some();
        let has_result = msgs.iter().any(|m| m["role"] == "tool");
        (200, if has_result { chat_text("The number is 42.") } else if has_tools { chat_tool_call("call_1", "get_number", "{\"n\":7}") } else { chat_text("pong") })
    })
}

#[test]
fn model_check_passes_for_a_server_that_replies_calls_tools_and_reads_results() {
    let mock = good_server();
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), ""), &tmp()).unwrap();
    let steps = modelcheck::self_check(&p);
    assert_eq!(steps.len(), 3);
    assert!(steps.iter().all(|s| s.ok), "{steps:?}");
    assert!(steps[1].detail.contains("get_number") && steps[1].detail.contains("\"n\""), "{}", steps[1].detail);
    // The third request really carried the result back as a tool message tied to the call id.
    let third = &mock.requests()[2].body["messages"];
    let tool_msg = third.as_array().unwrap().iter().find(|m| m["role"] == "tool").unwrap();
    assert_eq!((tool_msg["tool_call_id"].as_str(), tool_msg["content"].as_str()), (Some("call_1"), Some("42")));
}

#[test]
fn model_check_says_plainly_when_a_model_will_not_call_tools() {
    // Answers in text no matter what: fine for chat, useless for an agent.
    let mock = Mock::start(|_, _| (200, chat_text("Sure, the number is seven!")));
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), ""), &tmp()).unwrap();
    let steps = modelcheck::self_check(&p);
    assert!(steps[0].ok, "it can talk");
    assert!(!steps[1].ok && steps[1].detail.contains("cannot drive this agent"), "{}", steps[1].detail);
    assert!(!steps[2].ok && steps[2].detail.contains("skipped"), "later steps do not pretend to run");
}

#[test]
fn model_check_stops_at_the_first_failure_and_explains_it_without_the_key() {
    std::env::set_var("AGENT_TEST_KEY_F", "sk-never-print-me-123");
    let mock = Mock::start(|_, _| (401, json!({ "error": { "message": "Invalid API key." } }).to_string()));
    let p = OpenAiProvider::from_env(&cfg("openai", &mock.url("/v1"), "AGENT_TEST_KEY_F"), &tmp()).unwrap();
    let steps = modelcheck::self_check(&p);
    assert!(!steps[0].ok && steps[0].detail.contains("Invalid API key"), "{steps:?}");
    assert!(steps[1..].iter().all(|s| !s.ok && s.detail.contains("skipped")));
    assert_eq!(mock.requests().len(), 1, "no further calls once the first one failed");
    let printed = format!("{steps:?}");
    assert!(!printed.contains("sk-never-print-me"), "the key must never appear in the report");
    assert!(modelcheck::hint(&steps[0].detail).contains("key"));
}

#[test]
fn the_hints_point_at_the_right_cause() {
    assert!(modelcheck::hint("curl failed: Host not in allowlist: opencode.ai (host_not_allowed)").contains("reached"));
    assert!(modelcheck::hint("OPENCODE_API_KEY is not set").contains("key"));
    assert!(modelcheck::hint("model API error: The model `x` does not exist (404)").contains("model name"));
    assert!(modelcheck::hint("refusing to send an API key over unencrypted http").contains("https"));
}
