use agent_core::audit::AuditLog;
use agent_core::config::{Config, Grant, ModelConfig, PluginConfig, Tier, VerificationConfig};
use agent_core::config::SandboxConfig;
use agent_core::daemon::{Daemon, DaemonLock, DaemonOpts};
use agent_core::delegate::{self, Delegate, DelegatingApprover, Learning};
use agent_core::eval::Regression;
use agent_core::gate::Gate;
use agent_core::upgrade;
use agent_core::plugin::PluginHost;
use agent_core::provider::{self, ModelProvider};
use agent_core::runner::{clip, Approver, DbApprover, Outcome, Runner, TerminalApprover};
use agent_core::store::Store;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "\
agent: stage 4 (loop, daemon, compaction, sub-agents, verifier, evals)

usage: agent [--home DIR] <command>

  init                 write a starter config in the home directory
  run <task...>        enqueue one event, run its session here, wait for the result
  resume <session>     continue a stopped session here (not while a daemon runs it)

  daemon               run as a service: queue, workers, event sources
  submit <task...>     put a task in the queue for the daemon
  status               list recent sessions
  stop                 ask the daemon to pause its sessions and exit
  requeue <session>    hand a stopped session back to the daemon

  approvals            list actions waiting for your approval (daemon mode)
  approve <id>         approve a waiting action
  deny <id>            refuse a waiting action

  eval run [--live]    run the owner's eval suite in throwaway workspaces (scripted cases by default)
  eval baseline        make the latest run the baseline
  eval compare         latest run against the baseline; exits 4 on any regression
  eval list            cases in the suite and proposals waiting for review
  eval show <id>       print a proposal, for review
  eval accept <id>     move a proposal into the suite (owner decision)
  eval reject <id>     delete a proposal

  delegate <rules|suggest|proposed|show|accept|reject|revoke|log>
                       owner-written rules that approve actions for you (see README)

  upgrade <list|show|run|approve|reject|rollback|history>
                       review and deploy plugins the agent wrote (see README)

  mcp inspect <server> start an MCP server from the config and show what it advertises, with the hash to pin
  model-check          try the configured provider and model: reply, tool call, tool result

  interrupt <session>  ask a running session to stop at its next step
  log <session>        print the session log
  audit-verify         check the audit log's hash chain

The home directory (default ./.agent, or $AGENT_HOME) holds config.json,
sessions.db and audit.db. ANTHROPIC_API_KEY must be set for run and resume.";

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut home = std::env::var("AGENT_HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(".agent"));
    if args.first().map(|a| a == "--home").unwrap_or(false) {
        if args.len() < 2 {
            bail!("--home needs a directory");
        }
        home = PathBuf::from(args[1].clone());
        args.drain(0..2);
    }
    let Some(cmd) = args.first().cloned() else {
        println!("{USAGE}");
        return Ok(());
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "init" => cmd_init(&home),
        "run" => {
            if rest.is_empty() {
                bail!("run needs a task, e.g. agent run \"summarise README.md\"");
            }
            cmd_run(&home, &rest.join(" "))
        }
        "resume" => cmd_resume(&home, parse_session(rest)?),
        "daemon" => cmd_daemon(&home),
        "submit" => {
            if rest.is_empty() {
                bail!("submit needs a task");
            }
            let store = Store::open(&home.join("sessions.db"))?;
            let (_e, sid) = store.enqueue_event("cli", &rest.join(" "), "owner")?;
            println!("queued as session {sid}");
            Ok(())
        }
        "status" => {
            let store = Store::open(&home.join("sessions.db"))?;
            for r in store.list_sessions(30)? {
                let kind = match r.parent_id {
                    Some(p) => format!("sub of {p}"),
                    None => String::new(),
                };
                // A session the verifier could not judge is completed but flagged, never blocked.
                let flag = if r.status == "completed" && r.parent_id.is_none() {
                    let log = store.load_log(r.id)?;
                    match log.iter().rev().find(|e| e.kind == "final").and_then(|e| e.payload["verification"].as_str()) {
                        Some("uncertain") => " [unverified]",
                        _ => "",
                    }
                } else {
                    ""
                };
                println!("{:>4}  {:<12} {:<10} {}{}", r.id, r.status, kind, clip(&r.goal.replace('\n', " "), 70), flag);
            }
            Ok(())
        }
        "stop" => {
            std::fs::write(home.join("stop"), "")?;
            println!("stop requested; the daemon will pause its sessions and exit");
            Ok(())
        }
        "requeue" => {
            let sid = parse_session(rest)?;
            let store = Store::open(&home.join("sessions.db"))?;
            if store.requeue(sid)? {
                println!("session {sid} is back in the queue");
            } else {
                println!("session {sid} cannot be requeued (only suspended, interrupted or failed sessions can)");
            }
            Ok(())
        }
        "approvals" => {
            let store = Store::open(&home.join("sessions.db"))?;
            let pending = store.pending_approvals()?;
            if pending.is_empty() {
                println!("nothing is waiting for approval");
            }
            for a in pending {
                println!(
                    "#{}  session {}  {} ({})  tier {}\n    args: {}",
                    a.id, a.session_id, a.tool, a.capability, a.tier, clip(&a.args, 500)
                );
            }
            Ok(())
        }
        "approve" | "deny" => {
            let id: i64 = rest.first().context("needs an approval id")?.parse().context("approval id must be a number")?;
            let store = Store::open(&home.join("sessions.db"))?;
            if store.decide_approval(id, cmd == "approve")? {
                println!("approval #{id}: {cmd}d");
            } else {
                println!("approval #{id} is not pending (already decided or expired)");
            }
            Ok(())
        }
        "interrupt" => {
            let sid = parse_session(rest)?;
            let store = Store::open(&home.join("sessions.db"))?;
            store.request_interrupt(sid)?;
            println!("interrupt requested for session {sid}");
            Ok(())
        }
        "log" => {
            let sid = parse_session(rest)?;
            let store = Store::open(&home.join("sessions.db"))?;
            for e in store.load_log(sid)? {
                println!("[{}] {}: {}", e.seq, e.kind, clip(&e.payload.to_string(), 300));
            }
            Ok(())
        }
        "eval" => cmd_eval(&home, rest),
        "delegate" => cmd_delegate(&home, rest),
        "upgrade" => cmd_upgrade(&home, rest),
        "model-check" => cmd_model_check(&home),
        "mcp" => cmd_mcp(&home, rest),
        "audit-verify" => {
            let audit = AuditLog::open(&home.join("audit.db"))?;
            let n = audit.verify()?;
            println!("audit log OK: {n} entries, chain intact");
            Ok(())
        }
        _ => {
            println!("{USAGE}");
            Ok(())
        }
    }
}

fn parse_session(rest: &[String]) -> Result<i64> {
    rest.first().context("needs a session id")?.parse().context("session id must be a number")
}

fn cmd_init(home: &Path) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let path = home.join("config.json");
    if path.exists() {
        bail!("{} already exists; not overwriting it", path.display());
    }
    let workspace = std::env::current_dir()?;
    let plugin = std::env::current_exe()?.with_file_name("plugin_fs");
    let check_plugin = std::env::current_exe()?.with_file_name("plugin_check");
    let cfg = Config {
        workspace,
        sources: vec![],
        hooks: vec![],
        max_concurrent_sessions: 2,
        approval_timeout_secs: 600,
        plugins: vec![
            // Sandboxed when bubblewrap is installed, so an approved shell command cannot reach the
            // agent's own files, the rest of the machine, or the network.
            PluginConfig {
                name: "fs".into(),
                command: plugin.to_string_lossy().into(),
                args: vec![],
                call_timeout_secs: 30,
                sandbox: if agent_core::sandbox::available() { Some(SandboxConfig::default()) } else { None },
                mcp: None,
            },
            // Runs the owner's check_commands in a sandbox with no network. Fails closed if it cannot sandbox.
            PluginConfig {
                name: "check".into(),
                command: check_plugin.to_string_lossy().into(),
                args: vec!["--sandbox".into(), "unshare".into()],
                call_timeout_secs: 130,
                // It builds its own namespace sandbox, which cannot be nested inside another.
                sandbox: None,
                mcp: None,
            },
        ],
        grants: vec![
            Grant { capability: "fs:read".into(), tier: Tier::ReadOnly, scope: None },
            Grant { capability: "fs:write".into(), tier: Tier::Reversible, scope: None },
            Grant { capability: "exec:shell".into(), tier: Tier::Irreversible, scope: None },
            // Core tools. They act only on the agent's own session, but they still pass the gate.
            Grant { capability: "core:pin".into(), tier: Tier::ReadOnly, scope: None },
            Grant { capability: "core:recall".into(), tier: Tier::ReadOnly, scope: None },
            Grant { capability: "agent:spawn".into(), tier: Tier::Reversible, scope: None },
            // Stage 4. The verifier is read-only, checks run only the commands in check_commands,
            // and a proposed eval case does nothing until the owner accepts it.
            Grant { capability: "agent:verify".into(), tier: Tier::Reversible, scope: None },
            Grant { capability: "exec:check".into(), tier: Tier::Reversible, scope: None },
            Grant { capability: "eval:propose".into(), tier: Tier::Reversible, scope: None },
        ],
        session_budget: Default::default(),
        global_budget: Default::default(),
        model: ModelConfig::default(),
        system_prompt: None,
        compaction: Default::default(),
        subagents: Default::default(),
        verification: VerificationConfig { enabled: true, ..Default::default() },
        check_commands: vec![],
        delegate: Default::default(),
        upgrades: Default::default(),
        extra_plugins: vec![],
        exclude_installed: vec![],
        home: PathBuf::new(),
    };
    std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
    println!("wrote {}", path.display());
    println!("Check model.price_in_per_mtok and price_out_per_mtok: the spending caps use them.");
    println!("Using an OpenAI-compatible server instead? Set model.provider to \"openai\" and model.base_url (see the README).");
    Ok(())
}

struct Opened {
    cfg: Config,
    store: Arc<Store>,
    audit: Arc<AuditLog>,
    home: PathBuf,
}

fn open(home: &Path) -> Result<Opened> {
    std::fs::create_dir_all(home)?;
    let home = home.canonicalize()?;
    let cfg = Config::load(&home.join("config.json"))?;
    Ok(Opened {
        store: Arc::new(Store::open(&home.join("sessions.db"))?),
        audit: Arc::new(AuditLog::open(&home.join("audit.db"))?),
        cfg,
        home,
    })
}

fn cmd_run(home: &Path, task: &str) -> Result<()> {
    let o = open(home)?;
    let (_event, sid) = o.store.enqueue_event("cli", task, "owner")?;
    if !o.store.claim_session(sid)? {
        bail!("session {sid} was taken by a running daemon");
    }
    eprintln!("session {sid} started");
    drive(&o, sid)
}

fn cmd_resume(home: &Path, sid: i64) -> Result<()> {
    let o = open(home)?;
    o.store.clear_interrupt(sid)?;
    if !o.store.claim_session(sid)? {
        bail!("session {sid} cannot be resumed here: it is running, completed, or does not exist");
    }
    eprintln!("resuming session {sid}");
    drive(&o, sid)
}

fn drive(o: &Opened, sid: i64) -> Result<()> {
    let provider: Box<dyn ModelProvider> = provider::from_config(&o.cfg.model, &o.home)?;
    let mut host = PluginHost::start_for(&o.cfg)?;
    // The agent's own stores can never be covered by a grant, even if the home
    // directory sits inside the workspace.
    let gate = Gate::new(&o.cfg.workspace, &o.cfg.grants, &[o.home.clone()]);
    // With the delegate on, owner-written rules answer first; anything they do not cover
    // is asked in this terminal as before.
    let approver: Box<dyn Approver> = if o.cfg.delegate.enabled {
        Box::new(
            DelegatingApprover::new(Delegate::new(&o.home, &o.cfg.workspace), Arc::new(TerminalApprover)).with_learning(
                Learning { store: Arc::clone(&o.store), audit: Arc::clone(&o.audit), cfg: o.cfg.delegate.clone() },
            ),
        )
    } else {
        Box::new(TerminalApprover)
    };
    let mut runner = Runner {
        cfg: &o.cfg,
        store: &o.store,
        audit: &o.audit,
        provider: provider.as_ref(),
        approver: approver.as_ref(),
        host: &mut host,
        gate: &gate,
        shutdown: None,
    };
    match runner.run_session(sid)? {
        Outcome::Completed { summary } => {
            println!("{summary}");
            Ok(())
        }
        Outcome::Suspended { handoff, .. } => {
            eprintln!("\n{handoff}");
            std::process::exit(2);
        }
        Outcome::Interrupted => {
            eprintln!("session {sid} interrupted; resume with `agent resume {sid}`");
            std::process::exit(3);
        }
        Outcome::Paused => unreachable!("only the daemon sets a shutdown flag"),
    }
}

fn cmd_daemon(home: &Path) -> Result<()> {
    let o = open(home)?;
    let _lock = DaemonLock::acquire(&o.home)?;
    let provider: Arc<dyn ModelProvider> = Arc::from(provider::from_config(&o.cfg.model, &o.home)?);
    let store = o.store;
    let audit = o.audit;
    // Approvals are asked through the queue so several sessions can wait at once.
    let owner: Arc<dyn Approver> = Arc::new(DbApprover::new(
        Arc::clone(&store),
        Duration::from_secs(o.cfg.approval_timeout_secs),
        Duration::from_millis(500),
    ));
    let approver: Arc<dyn Approver> = if o.cfg.delegate.enabled {
        Arc::new(
            DelegatingApprover::new(Delegate::new(&o.home, &o.cfg.workspace), owner).with_learning(Learning {
                store: Arc::clone(&store),
                audit: Arc::clone(&audit),
                cfg: o.cfg.delegate.clone(),
            }),
        )
    } else {
        owner
    };
    let max = o.cfg.max_concurrent_sessions;
    let daemon = Daemon {
        cfg: Arc::new(o.cfg),
        store,
        audit,
        provider,
        approver,
        home: o.home,
    };
    eprintln!("daemon started (up to {max} sessions at once). `agent stop` to stop, `agent approvals` to see waiting approvals.");
    daemon.run(Arc::new(AtomicBool::new(false)), DaemonOpts { verbose: true, ..Default::default() })?;
    eprintln!("daemon stopped");
    Ok(())
}

fn cmd_eval(home: &Path, rest: &[String]) -> Result<()> {
    use agent_core::eval;
    let o = open(home)?;
    let mut cfg = o.cfg.clone();
    cfg.home = o.home.clone();
    let sub = rest.first().map(|s| s.as_str()).unwrap_or("");
    let id = || -> Result<&String> { rest.get(1).context("needs a case id") };
    match sub {
        "run" => {
            let live = rest.iter().any(|a| a == "--live");
            let provider: Option<Box<dyn ModelProvider>> = if live {
                Some(provider::from_config(&cfg.model, &o.home)?)
            } else {
                None
            };
            let run = eval::run_all(&cfg, provider.as_deref())?;
            for c in &run.cases {
                println!("{:<8} {}  ({} calls)", c.status, c.id, c.steps);
                for k in c.checks.iter().filter(|k| !k.ok) {
                    println!("           failed: {} {}", k.check, k.detail);
                }
                if !c.note.is_empty() {
                    println!("           {}", c.note);
                }
            }
            let path = eval::save_run(&o.home, &run)?;
            println!("{} ({}), saved to {}", eval::summary_json(&run), run.mode, path.display());
            if !run.failed().is_empty() {
                std::process::exit(1);
            }
            Ok(())
        }
        "baseline" => {
            let run = eval::set_baseline(&o.home)?;
            println!("baseline set from run {} ({}): {}", run.run_id, run.mode, eval::summary_json(&run));
            if !run.failed().is_empty() {
                println!("note: {} case(s) fail in this baseline; they will not block comparisons", run.failed().len());
            }
            Ok(())
        }
        "compare" => {
            let base = eval::load_baseline(&o.home)?;
            let cur = eval::latest_run(&o.home)?;
            let regs = eval::compare(&base, &cur)?;
            if regs.is_empty() {
                println!("no regressions against the baseline ({} case(s) compared)", base.cases.iter().filter(|c| c.status == "pass").count());
                return Ok(());
            }
            for r in &regs {
                println!("REGRESSION {}: {}", r.id, r.reason);
            }
            std::process::exit(4);
        }
        "list" => {
            for c in eval::load_cases(&o.home)? {
                println!("case      {}  {}", c.id, clip(&c.task.replace('\n', " "), 60));
            }
            for c in eval::list_proposed(&o.home)? {
                println!("PROPOSED  {}  {}", c.id, clip(&c.task.replace('\n', " "), 60));
            }
            Ok(())
        }
        "show" => {
            let id = id()?;
            let c = eval::list_proposed(&o.home)?.into_iter().find(|c| &c.id == id).context("no such proposal")?;
            println!("{}", serde_json::to_string_pretty(&c)?);
            Ok(())
        }
        "accept" => {
            eval::accept(&o.home, id()?)?;
            println!("case {} is now part of the suite; run `agent eval run` and re-baseline when ready", id()?);
            Ok(())
        }
        "reject" => {
            eval::reject(&o.home, id()?)?;
            println!("proposal {} deleted", id()?);
            Ok(())
        }
        _ => bail!("usage: agent eval run [--live] | baseline | compare | list | show <id> | accept <id> | reject <id>"),
    }
}

fn cmd_delegate(home: &Path, rest: &[String]) -> Result<()> {
    let o = open(home)?;
    let sub = rest.first().map(|s| s.as_str()).unwrap_or("rules");
    let id = || -> Result<&str> { rest.get(1).map(|s| s.as_str()).context("needs an id") };
    match sub {
        "rules" => {
            if !o.cfg.delegate.enabled {
                println!("(the delegate is off: set delegate.enabled in config.json)");
            }
            let rules = delegate::load_rules(&o.home)?;
            if rules.is_empty() {
                println!("no rules; every approval goes to you");
            }
            for r in rules {
                let args: Vec<String> = r.args.iter().map(|(k, m)| format!("{k}={}", clip(&serde_json::to_string(m).unwrap_or_default(), 80))).collect();
                println!("{}  {:?}  {} ({})  {}{}", r.id, r.effect, r.tool, r.capability.as_deref().unwrap_or("any capability"), args.join(" "),
                    r.expires_at.map(|t| format!("  expires {t}")).unwrap_or_default());
            }
            Ok(())
        }
        "suggest" => {
            // Looks for actions you have approved over and over. Writes proposals only; changes no decision.
            let history = delegate::Past::from_log(&o.store.approval_history()?);
            let existing = delegate::load_rules(&o.home)?;
            let props = delegate::suggest(&history, &existing, o.cfg.delegate.suggest_after, &o.cfg.workspace);
            if props.is_empty() {
                println!("nothing to suggest yet (needs {} identical approvals and no refusal)", o.cfg.delegate.suggest_after);
            }
            for p in props {
                let new = delegate::write_proposal(&o.home, &p)?;
                println!("{} proposal {}: {} approvals", if new { "wrote" } else { "already proposed:" }, p.rule.id, p.owner_approvals);
            }
            Ok(())
        }
        "proposed" => {
            let list = delegate::list_proposed(&o.home)?;
            if list.is_empty() {
                println!("no proposals");
            }
            for p in list {
                println!("{}  {}  after {} approvals  (agent delegate show {})", p.rule.id, p.rule.tool, p.owner_approvals, p.rule.id);
            }
            Ok(())
        }
        "show" => {
            let id = id()?;
            let p = delegate::list_proposed(&o.home)?.into_iter().find(|p| p.rule.id == id).context("no such proposal")?;
            println!("{}", serde_json::to_string_pretty(&p)?);
            Ok(())
        }
        "accept" => {
            delegate::accept(&o.home, id()?)?;
            println!("rule is now live. `agent delegate revoke {}` removes it at any time.", id()?);
            Ok(())
        }
        "reject" => {
            delegate::reject(&o.home, id()?)?;
            println!("proposal removed");
            Ok(())
        }
        "revoke" => {
            delegate::revoke(&o.home, id()?)?;
            println!("rule revoked; it stops applying on the next request");
            Ok(())
        }
        "log" => {
            // Every decision the delegate made or passed on, with the rule that justified it.
            for r in o.audit.rows()?.into_iter().filter(|r| r.entry.decision.starts_with("delegate_")) {
                println!("#{} session {} {}  {}  {}", r.seq, r.entry.session_id, r.entry.decision, r.entry.tool, clip(&r.entry.reason, 90));
            }
            Ok(())
        }
        other => bail!("unknown delegate command '{other}'"),
    }
}

/// Runs the owner's baseline suite against the live configuration and reports regressions.
fn verify_with_eval(cfg: &Config) -> Result<Vec<Regression>> {
    let base = agent_core::eval::load_baseline(&cfg.home)?;
    let cur = agent_core::eval::run_all(cfg, None)?;
    agent_core::eval::compare(&base, &cur)
}

fn print_upgrade(r: &agent_core::store::UpgradeRow) {
    println!("#{}  {}  [{}]  snapshot {}", r.id, r.name, r.status, &r.hash[..12.min(r.hash.len())]);
    if let Some(stages) = r.report["stages"].as_array() {
        for s in stages {
            println!("  {:<18} {}", s["name"].as_str().unwrap_or("?"), s["status"].as_str().unwrap_or("?"));
            for f in s["findings"].as_array().into_iter().flatten() {
                println!("      - {}", f.as_str().unwrap_or(""));
            }
        }
    }
    if let Some(note) = r.report["auto_note"].as_str().filter(|n| !n.is_empty()) {
        println!("  auto-approval does not apply: {note}");
    }
}

fn cmd_upgrade(home: &Path, rest: &[String]) -> Result<()> {
    let o = open(home)?;
    let sub = rest.first().map(|s| s.as_str()).unwrap_or("list");
    let id = || -> Result<i64> { rest.get(1).context("needs an upgrade number")?.parse().context("the upgrade number must be a number") };
    let name = || -> Result<&str> { rest.get(1).map(|s| s.as_str()).context("needs a plugin name") };
    match sub {
        "list" => {
            let rows = o.store.list_upgrades()?;
            if rows.is_empty() {
                println!("no upgrades proposed");
            }
            for r in rows {
                println!("#{:<4} {:<24} {}", r.id, r.name, r.status);
            }
            Ok(())
        }
        "show" => {
            print_upgrade(&o.store.get_upgrade(id()?)?);
            Ok(())
        }
        "run" => {
            if !agent_core::sandbox::available() {
                bail!("bubblewrap (bwrap) is not installed; plugins written by the agent are never run without the sandbox");
            }
            let status = upgrade::run_pipeline(&o.cfg, &o.store, &o.audit, id()?, &verify_with_eval)?;
            print_upgrade(&o.store.get_upgrade(id()?)?);
            println!("\nresult: {status}");
            if status == "ready_for_review" {
                println!("review it above, then `agent upgrade approve {}` or `agent upgrade reject {}`", id()?, id()?);
            }
            Ok(())
        }
        "approve" => {
            let status = upgrade::approve(&o.cfg, &o.store, &o.audit, id()?, "owner", &verify_with_eval)?;
            println!("{status}");
            if status == "rolled_back" {
                println!("the suite failed after the new version went live, so it was rolled back; see `agent upgrade show {}`", id()?);
            }
            Ok(())
        }
        "reject" => {
            upgrade::reject(&o.store, &o.audit, id()?)?;
            println!("rejected");
            Ok(())
        }
        "rollback" => {
            let to = rest.get(2).map(|v| v.parse::<u32>()).transpose().context("the version must be a number")?;
            println!("{}", upgrade::rollback(&o.cfg, &o.store, &o.audit, name()?, to)?);
            Ok(())
        }
        "history" => {
            let n = name()?;
            let active = upgrade::active_version(&o.home, n);
            for v in upgrade::versions(&o.home, n) {
                println!(
                    "v{}{}  approved by {}  upgrade #{}  {}",
                    v.version,
                    if Some(v.version) == active { " (active)" } else { "" },
                    v.approved_by, v.upgrade_id, v.capabilities.join(",")
                );
            }
            Ok(())
        }
        other => bail!("unknown upgrade command '{other}'"),
    }
}

/// Shows whether the configured provider and model can drive this agent, without needing a session.
fn cmd_model_check(home: &Path) -> Result<()> {
    let cfg = Config::load(&home.join("config.json"))?;
    let m = &cfg.model;
    let key_var = m.api_key_env.clone().unwrap_or_else(|| if m.provider == "anthropic" { "ANTHROPIC_API_KEY".into() } else { "OPENAI_API_KEY".into() });
    let key_state = if key_var.is_empty() { "none (by config)".to_string() } else if std::env::var(&key_var).map(|k| !k.trim().is_empty()).unwrap_or(false) { format!("{key_var} is set") } else { format!("{key_var} is NOT set") };
    println!("provider {}  model {}  base_url {}  key: {}", m.provider, m.model, m.base_url.clone().unwrap_or_else(|| "(default)".into()), key_state);
    std::fs::create_dir_all(&cfg.home)?;
    let provider = match provider::from_config(m, &cfg.home) {
        Ok(p) => p,
        Err(e) => {
            println!("  FAIL setup                    {e:#}");
            println!("       -> {}", agent_core::modelcheck::hint(&format!("{e:#}")));
            bail!("this provider and model cannot drive the agent yet (see above)");
        }
    };
    let steps = agent_core::modelcheck::self_check(provider.as_ref());
    let mut failed = false;
    for s in &steps {
        println!("  {} {:<24} {}", if s.ok { "ok  " } else { "FAIL" }, s.name, s.detail);
        if !s.ok && !s.detail.starts_with("skipped") {
            println!("       -> {}", agent_core::modelcheck::hint(&s.detail));
        }
        failed |= !s.ok;
    }
    if failed {
        bail!("this provider and model cannot drive the agent yet (see above)");
    }
    println!("all steps passed: this provider and model can drive the agent");
    Ok(())
}

/// `agent mcp inspect <server>`: what an MCP server says about its tools, and the hash to pin.
fn cmd_mcp(home: &Path, rest: &[String]) -> Result<()> {
    if rest.first().map(|s| s.as_str()) != Some("inspect") {
        bail!("usage: agent mcp inspect <server name from the config>");
    }
    let name = rest.get(1).context("needs a server name")?;
    let cfg = Config::load(&home.join("config.json"))?;
    let plugin = cfg.plugins.iter().find(|p| &p.name == name && p.mcp.is_some()).with_context(|| format!("no MCP server named '{name}' in the config"))?;
    let report = agent_core::plugin::PluginHost::inspect_mcp(plugin, &cfg.workspace)?;
    println!("server '{name}' advertises {} tool(s)\n", report.tools.len());
    for (original, t) in &report.tools {
        let granted = cfg.grants.iter().filter(|g| g.capability == t.capability).map(|g| g.tier.as_str()).max().map(|t| format!("granted as {t}")).unwrap_or_else(|| "NOT granted: hidden and denied".into());
        println!("  {} (server's name: {original})", t.name);
        println!("      capability {}  [{granted}]{}", t.capability, if t.scope_args.is_empty() { String::new() } else { format!("  path arguments: {}", t.scope_args.join(", ")) });
        println!("      {}", t.description.lines().next().unwrap_or("").chars().take(110).collect::<String>());
    }
    println!("\nRead the descriptions: they are text the model will see, written by whoever runs the server.");
    println!("To refuse any later change to them, add this to the server's \"mcp\" section:\n\n    \"pin\": \"{}\"", report.hash);
    Ok(())
}
