//! `agent model-check`: three small calls that show whether a provider and model can drive this agent.
//! The thing that decides it is tool calling, so that is what is tested, including sending a tool
//! result back, which is the step servers most often get subtly wrong.
use crate::provider::{Block, Message, ModelProvider, ToolSpec};
use serde_json::json;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct CheckStep {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn tool() -> ToolSpec {
    ToolSpec {
        name: "get_number".into(),
        description: "Returns a number. Takes the integer n.".into(),
        input_schema: json!({ "type": "object", "properties": { "n": { "type": "integer" } }, "required": ["n"] }),
    }
}

fn user(text: &str) -> Message {
    Message { role: "user".into(), content: vec![Block::Text { text: text.into() }] }
}

fn text_of(blocks: &[Block]) -> String {
    blocks.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join(" ")
}

fn short(s: &str) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > 80 { format!("{}...", one.chars().take(80).collect::<String>()) } else { one }
}

/// What to try when a step fails, from the error text alone. Never includes the key.
pub fn hint(error: &str) -> &'static str {
    let e = error.to_lowercase();
    if e.contains("host_not_allowed") || e.contains("not in allowlist") || e.contains("could not resolve") || e.contains("connection refused") || e.contains("curl failed") {
        "the server could not be reached from here: check base_url, and any network or firewall allowlist"
    } else if e.contains("401") || e.contains("invalid api key") || e.contains("incorrect api key") || e.contains("unauthorized") || e.contains("is not set") {
        "the key was missing or refused: check the environment variable named by api_key_env"
    } else if e.contains("unencrypted") {
        "an API key will not be sent over plain http to another machine: use https"
    } else if e.contains("not found") || e.contains("404") || e.contains("model") {
        "the model name may be wrong for this server: check model (and base_url)"
    } else if e.contains("429") || e.contains("rate") {
        "rate limited: wait and try again"
    } else {
        "see the message above"
    }
}

pub fn self_check(p: &dyn ModelProvider) -> Vec<CheckStep> {
    let mut steps: Vec<CheckStep> = Vec::new();
    let system = "You are a test of an API connection. Follow the instruction exactly and briefly.";
    let skip = |name: &'static str| CheckStep { name, ok: false, detail: "skipped because an earlier step failed".into() };

    // 1. A plain reply.
    let t = Instant::now();
    let first = user("Reply with the single word: pong");
    match p.complete(system, std::slice::from_ref(&first), &[]) {
        Ok(r) if !text_of(&r.content).trim().is_empty() => steps.push(CheckStep {
            name: "plain reply",
            ok: true,
            detail: format!("{:.1}s, {} tokens, answered \"{}\"", t.elapsed().as_secs_f32(), r.usage.input_tokens + r.usage.output_tokens, short(&text_of(&r.content))),
        }),
        Ok(_) => steps.push(CheckStep { name: "plain reply", ok: false, detail: "the reply was empty".into() }),
        Err(e) => steps.push(CheckStep { name: "plain reply", ok: false, detail: format!("{e:#}") }),
    }
    if !steps[0].ok {
        steps.push(skip("tool call"));
        steps.push(skip("tool result round trip"));
        return steps;
    }

    // 2. Does it call a tool when asked? Without this it cannot drive the agent.
    let ask = user("Call the get_number tool with n set to 7. Do not answer in text.");
    let t = Instant::now();
    let (call_id, call_blocks) = match p.complete(system, std::slice::from_ref(&ask), &[tool()]) {
        Ok(r) => match r.content.iter().find_map(|b| match b {
            Block::ToolUse { id, name, input } => Some((id.clone(), name.clone(), input.clone())),
            _ => None,
        }) {
            Some((id, name, input)) if name == "get_number" && input.is_object() && input.get("n").is_some() => {
                steps.push(CheckStep { name: "tool call", ok: true, detail: format!("{:.1}s, called {name} with {input}", t.elapsed().as_secs_f32()) });
                (id, r.content)
            }
            Some((_, name, input)) => {
                steps.push(CheckStep { name: "tool call", ok: false, detail: format!("it called '{name}' with {input}, which is not what was asked") });
                steps.push(skip("tool result round trip"));
                return steps;
            }
            None => {
                steps.push(CheckStep {
                    name: "tool call",
                    ok: false,
                    detail: format!("it answered in text instead of calling the tool (\"{}\"). A model that will not call tools cannot drive this agent; try another model or server.", short(&text_of(&r.content))),
                });
                steps.push(skip("tool result round trip"));
                return steps;
            }
        },
        Err(e) => {
            steps.push(CheckStep { name: "tool call", ok: false, detail: format!("{e:#}") });
            steps.push(skip("tool result round trip"));
            return steps;
        }
    };

    // 3. Send the result back, as the agent does after every tool call.
    let convo = vec![
        ask,
        Message { role: "assistant".into(), content: call_blocks },
        Message { role: "user".into(), content: vec![Block::ToolResult { tool_use_id: call_id, content: "42".into(), is_error: false }] },
    ];
    let t = Instant::now();
    match p.complete(system, &convo, &[tool()]) {
        Ok(r) if !text_of(&r.content).trim().is_empty() => steps.push(CheckStep {
            name: "tool result round trip",
            ok: true,
            detail: format!("{:.1}s, it read the result and said \"{}\"", t.elapsed().as_secs_f32(), short(&text_of(&r.content))),
        }),
        Ok(r) if r.content.iter().any(|b| matches!(b, Block::ToolUse { .. })) => steps.push(CheckStep {
            name: "tool result round trip",
            ok: true,
            detail: "it accepted the result and asked for another tool call".into(),
        }),
        Ok(_) => steps.push(CheckStep { name: "tool result round trip", ok: false, detail: "it accepted the request but the reply was empty".into() }),
        Err(e) => steps.push(CheckStep { name: "tool result round trip", ok: false, detail: format!("{e:#}") }),
    }
    steps
}
