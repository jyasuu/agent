use crate::config::ModelConfig;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Block {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse { id: String, name: String, input: Value },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub role: String,
    pub content: Vec<Block>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone)]
pub struct ModelResponse {
    pub content: Vec<Block>,
    pub usage: Usage,
}

/// Extension point: any model backend implements this.
pub trait ModelProvider: Send + Sync {
    fn complete(&self, system: &str, messages: &[Message], tools: &[ToolSpec]) -> Result<ModelResponse>;
}

/// Deterministic provider for tests: replays a fixed script and records what
/// the model was shown on every call.
pub struct ScriptedProvider {
    queue: Mutex<VecDeque<ModelResponse>>,
    repeat: bool,
    counter: Mutex<u64>,
    pub seen: Mutex<Vec<Vec<Message>>>,
}

impl ScriptedProvider {
    pub fn new(script: Vec<ModelResponse>) -> Self {
        Self {
            queue: Mutex::new(script.into()),
            repeat: false,
            counter: Mutex::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Repeats one response forever (with fresh tool-call ids). Used to test budgets.
    pub fn repeating(resp: ModelResponse) -> Self {
        Self {
            queue: Mutex::new(VecDeque::from(vec![resp])),
            repeat: true,
            counter: Mutex::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl ModelProvider for ScriptedProvider {
    fn complete(&self, _system: &str, messages: &[Message], _tools: &[ToolSpec]) -> Result<ModelResponse> {
        self.seen.lock().unwrap().push(messages.to_vec());
        let mut q = self.queue.lock().unwrap();
        if self.repeat {
            let mut n = self.counter.lock().unwrap();
            *n += 1;
            let mut r = q.front().cloned().ok_or_else(|| anyhow!("script empty"))?;
            for b in r.content.iter_mut() {
                if let Block::ToolUse { id, .. } = b {
                    *id = format!("{id}-{n}");
                }
            }
            return Ok(r);
        }
        q.pop_front().ok_or_else(|| anyhow!("scripted provider ran out of responses"))
    }
}

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// A request-body file name that no other call, in this process or another, will use.
/// (A single fixed name would let two sessions running at once overwrite each other's prompts.)
pub fn unique_request_path(dir: &Path) -> PathBuf {
    dir.join(format!("request-{}-{}.json", std::process::id(), REQUEST_SEQ.fetch_add(1, Ordering::SeqCst)))
}

/// Escapes a value for a curl config file, where a newline or quote would otherwise end the
/// line or the string and let the rest be read as further options.
fn curl_quote(v: &str) -> String {
    let mut out = String::from("\"");
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn is_loopback(url: &str) -> bool {
    let rest = url.trim_start_matches("http://");
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let host = if rest.starts_with('[') { rest.trim_start_matches('[').split(']').next().unwrap_or("") } else { host };
    matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
}

/// POSTs JSON with curl and returns the parsed reply. Headers (which may hold the API key) go to curl
/// on stdin, never on the command line where `ps` would show them. A key is never sent over plain
/// http to anything but this machine.
fn post_json(url: &str, headers: &[(String, String)], body: &Value, tmp_dir: &Path, secret: bool) -> Result<Value> {
    if secret && url.starts_with("http://") && !is_loopback(url) {
        bail!("refusing to send an API key over unencrypted http to {url}; use https, or a server on this machine");
    }
    let req_path = unique_request_path(tmp_dir);
    std::fs::write(&req_path, body.to_string())?;
    crate::store::restrict_permissions(&req_path);

    let mut config = format!("url = {}\nrequest = \"POST\"\n", curl_quote(url));
    for (k, v) in headers {
        config.push_str(&format!("header = {}\n", curl_quote(&format!("{k}: {v}"))));
    }
    config.push_str(&format!("header = {}\n", curl_quote("content-type: application/json")));
    config.push_str(&format!("data-binary = {}\n", curl_quote(&format!("@{}", req_path.display()))));

    let result = (|| -> Result<Value> {
        let mut child = Command::new("curl")
            .args(["-sS", "--max-time", "180", "-K", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting curl")?;
        child.stdin.take().unwrap().write_all(config.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!("curl failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        serde_json::from_slice(&out.stdout).map_err(|_| {
            let head: String = String::from_utf8_lossy(&out.stdout).chars().take(200).collect();
            anyhow!("model response was not JSON: {head}")
        })
    })();
    let _ = std::fs::remove_file(&req_path);
    result
}

fn api_key(cfg: &ModelConfig, default_env: &str, required: bool) -> Result<Option<String>> {
    let name = cfg.api_key_env.clone().unwrap_or_else(|| default_env.to_string());
    if name.is_empty() {
        return Ok(None);
    }
    match std::env::var(&name) {
        Ok(k) if !k.trim().is_empty() => Ok(Some(k)),
        _ if required => bail!("{name} is not set"),
        _ => Ok(None),
    }
}

/// Builds the provider named in the config.
pub fn from_config(cfg: &ModelConfig, tmp_dir: &Path) -> Result<Box<dyn ModelProvider>> {
    match cfg.provider.as_str() {
        "anthropic" => Ok(Box::new(AnthropicProvider::from_env(cfg, tmp_dir)?)),
        "openai" | "openai-compatible" | "openai_compatible" => Ok(Box::new(OpenAiProvider::from_env(cfg, tmp_dir)?)),
        other => bail!("unknown model provider '{other}' (use \"anthropic\" or \"openai\")"),
    }
}

/// The Anthropic Messages API, through curl so there is no HTTP dependency.
pub struct AnthropicProvider {
    key: String,
    model: String,
    max_tokens: u32,
    url: String,
    tmp_dir: PathBuf,
}

impl AnthropicProvider {
    pub fn from_env(cfg: &ModelConfig, tmp_dir: &Path) -> Result<Self> {
        let key = api_key(cfg, "ANTHROPIC_API_KEY", true)?.expect("required");
        let base = cfg.base_url.clone().unwrap_or_else(|| "https://api.anthropic.com".into());
        Ok(Self {
            key,
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            url: format!("{}/v1/messages", base.trim_end_matches('/')),
            tmp_dir: tmp_dir.to_path_buf(),
        })
    }
}

impl ModelProvider for AnthropicProvider {
    fn complete(&self, system: &str, messages: &[Message], tools: &[ToolSpec]) -> Result<ModelResponse> {
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools)?;
        }
        let headers = [("x-api-key".to_string(), self.key.clone()), ("anthropic-version".to_string(), "2023-06-01".to_string())];
        let v = post_json(&self.url, &headers, &body, &self.tmp_dir, true)?;
        if v["type"] == "error" {
            bail!("model API error: {}", v["error"]["message"].as_str().unwrap_or("unknown"));
        }
        let mut content = Vec::new();
        for b in v["content"].as_array().cloned().unwrap_or_default() {
            match b["type"].as_str() {
                Some("text") => content.push(Block::Text { text: b["text"].as_str().unwrap_or("").into() }),
                Some("tool_use") => content.push(Block::ToolUse {
                    id: b["id"].as_str().unwrap_or("").into(),
                    name: b["name"].as_str().unwrap_or("").into(),
                    input: b["input"].clone(),
                }),
                _ => {}
            }
        }
        Ok(ModelResponse {
            content,
            usage: Usage {
                input_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0),
                output_tokens: v["usage"]["output_tokens"].as_u64().unwrap_or(0),
            },
        })
    }
}

// ---- OpenAI-compatible chat completions ------------------------------------------------------

/// Turns the agent's messages into an OpenAI chat-completions request. The differences that matter:
/// the system prompt is a message, a tool result is its own `tool` message keyed by call id, tool
/// arguments travel as a JSON *string*, and there is no error flag on a tool result, so an error
/// is marked in the text.
pub fn openai_request(model: &str, max_tokens: u32, max_tokens_param: &str, system: &str, messages: &[Message], tools: &[ToolSpec]) -> Value {
    let mut out = vec![json!({ "role": "system", "content": system })];
    for m in messages {
        if m.role == "assistant" {
            let text: Vec<&str> = m.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect();
            let calls: Vec<Value> = m
                .content
                .iter()
                .filter_map(|b| match b {
                    Block::ToolUse { id, name, input } => {
                        Some(json!({ "id": id, "type": "function", "function": { "name": name, "arguments": input.to_string() } }))
                    }
                    _ => None,
                })
                .collect();
            let mut msg = json!({ "role": "assistant", "content": text.join("\n") });
            if !calls.is_empty() {
                msg["tool_calls"] = Value::Array(calls);
            }
            out.push(msg);
        } else {
            // Tool results first, in order: they must directly follow the assistant message that made the calls.
            for b in &m.content {
                if let Block::ToolResult { tool_use_id, content, is_error } = b {
                    let content = if *is_error { format!("ERROR: {content}") } else { content.clone() };
                    out.push(json!({ "role": "tool", "tool_call_id": tool_use_id, "content": content }));
                }
            }
            let text: Vec<&str> = m.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect();
            if !text.is_empty() {
                out.push(json!({ "role": "user", "content": text.join("\n") }));
            }
        }
    }
    let mut body = json!({ "model": model, "messages": out });
    body[max_tokens_param] = json!(max_tokens);
    if !tools.is_empty() {
        body["tools"] = Value::Array(
            tools
                .iter()
                .map(|t| json!({ "type": "function", "function": { "name": t.name, "description": t.description, "parameters": t.input_schema } }))
                .collect(),
        );
    }
    body
}

static GENERATED_IDS: AtomicU64 = AtomicU64::new(0);

/// Reads a chat-completions reply. Servers differ, so this is forgiving: content may be a string or
/// a list of parts, arguments may be a string or already an object, and a missing call id is made up
/// (uniquely) because the next request must name it.
pub fn openai_parse(v: &Value) -> Result<ModelResponse> {
    if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
        let msg = e["message"].as_str().map(String::from).unwrap_or_else(|| e.to_string());
        bail!("model API error: {msg}");
    }
    let msg = &v["choices"][0]["message"];
    if msg.is_null() {
        bail!("the reply has no choices");
    }
    let mut content = Vec::new();
    let text = match &msg["content"] {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join(""),
        _ => String::new(),
    };
    if !text.trim().is_empty() {
        content.push(Block::Text { text });
    }
    for c in msg["tool_calls"].as_array().cloned().unwrap_or_default() {
        let id = match c["id"].as_str().filter(|i| !i.is_empty()) {
            Some(i) => i.to_string(),
            None => format!("call_gen_{}", GENERATED_IDS.fetch_add(1, Ordering::SeqCst)),
        };
        let input = match &c["function"]["arguments"] {
            Value::String(s) if s.trim().is_empty() => json!({}),
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(v) if v.is_object() => v,
                _ => json!({ "_unparsed": s }),
            },
            v if v.is_object() => v.clone(),
            _ => json!({}),
        };
        content.push(Block::ToolUse { id, name: c["function"]["name"].as_str().unwrap_or("").into(), input });
    }
    Ok(ModelResponse {
        content,
        usage: Usage {
            input_tokens: v["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
            output_tokens: v["usage"]["completion_tokens"].as_u64().unwrap_or(0),
        },
    })
}

/// Any server that speaks the OpenAI chat-completions API with function calling.
pub struct OpenAiProvider {
    key: Option<String>,
    model: String,
    max_tokens: u32,
    max_tokens_param: String,
    url: String,
    tmp_dir: PathBuf,
}

impl OpenAiProvider {
    pub fn from_env(cfg: &ModelConfig, tmp_dir: &Path) -> Result<Self> {
        // A key is required for OpenAI itself. A server you pointed `base_url` at may need none.
        let custom = cfg.base_url.is_some();
        let key = api_key(cfg, "OPENAI_API_KEY", !custom && cfg.api_key_env.as_deref() != Some(""))?;
        let base = cfg.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1".into());
        Ok(Self {
            key,
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            max_tokens_param: if cfg.max_tokens_param.is_empty() { "max_tokens".into() } else { cfg.max_tokens_param.clone() },
            url: format!("{}/chat/completions", base.trim_end_matches('/')),
            tmp_dir: tmp_dir.to_path_buf(),
        })
    }
}

impl ModelProvider for OpenAiProvider {
    fn complete(&self, system: &str, messages: &[Message], tools: &[ToolSpec]) -> Result<ModelResponse> {
        let body = openai_request(&self.model, self.max_tokens, &self.max_tokens_param, system, messages, tools);
        let headers: Vec<(String, String)> = self.key.iter().map(|k| ("Authorization".to_string(), format!("Bearer {k}"))).collect();
        let v = post_json(&self.url, &headers, &body, &self.tmp_dir, self.key.is_some())?;
        openai_parse(&v)
    }
}
