use crate::audit::AuditLog;
use crate::config::Config;
use crate::gate::Gate;
use crate::plugin::PluginHost;
use crate::provider::ModelProvider;
use crate::runner::{Approver, Outcome, Runner};
use crate::source::EventSourceHost;
use crate::store::Store;
use anyhow::{bail, Result};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Sessions in these states are done as far as the daemon is concerned.
/// A paused session goes back to "queued", so it is not counted here.
const FINISHED: [&str; 4] = ["completed", "suspended", "failed", "interrupted"];

pub struct DaemonOpts {
    /// How often the daemon looks for new events and free workers.
    pub tick: Duration,
    /// Return once this many sessions have finished and nothing is running.
    /// None means run until shutdown. Mostly for tests and one-off batch runs.
    pub stop_after_finished: Option<u64>,
    /// Print one line per session start and finish to stderr.
    pub verbose: bool,
}

impl Default for DaemonOpts {
    fn default() -> Self {
        Self { tick: Duration::from_millis(500), stop_after_finished: None, verbose: false }
    }
}

pub struct Daemon {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub audit: Arc<AuditLog>,
    pub provider: Arc<dyn ModelProvider>,
    pub approver: Arc<dyn Approver>,
    pub home: PathBuf,
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Daemon {
    /// The daemon loop. Each event becomes its own session with its own plugin
    /// processes, so one runaway task cannot touch another. At most
    /// `max_concurrent_sessions` run at once.
    pub fn run(&self, shutdown: Arc<AtomicBool>, opts: DaemonOpts) -> Result<()> {
        let stop_file = self.home.join("stop");
        let _ = std::fs::remove_file(&stop_file);

        // Sessions still marked running were left by a process that died. Their
        // unfinished tool calls are repaired (never re-run) when they resume.
        let recovered = self.store.recover_running()?;
        if recovered > 0 && opts.verbose {
            eprintln!("recovered {recovered} session(s) left running by a crash");
        }

        // The config file is watched while running. When you edit it, new sessions use the new
        // settings (plugins, MCP servers, grants, budgets), and event sources are started, stopped or
        // restarted to match, with no daemon restart. Sessions already running keep the settings they
        // began with, apart from installed plugins, which they pick up between turns.
        let mut cfg = Arc::clone(&self.cfg);
        let config_path = self.home.join("config.json");
        let mut stamp = config_stamp(&config_path);
        let mut sources = EventSourceHost::start(&cfg.sources, &cfg.workspace)?;
        let active = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        loop {
            if stop_file.exists() {
                let _ = std::fs::remove_file(&stop_file);
                shutdown.store(true, Ordering::SeqCst);
            }
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            let now_stamp = config_stamp(&config_path);
            if now_stamp != stamp {
                stamp = now_stamp;
                match Config::load(&config_path) {
                    Ok(new) => {
                        for note in sources.reload(&new.sources, &new.workspace) {
                            if opts.verbose {
                                eprintln!("config reloaded: {note}");
                            }
                        }
                        if opts.verbose {
                            eprintln!("config reloaded: new sessions will use it");
                        }
                        cfg = Arc::new(new);
                    }
                    // A half-written or invalid file must not stop the daemon: keep what works.
                    Err(e) => {
                        if opts.verbose {
                            eprintln!("config changed but cannot be used, keeping the previous one: {e:#}");
                        }
                    }
                }
            }
            let cap = cfg.max_concurrent_sessions.max(1);

            sources.drain(&self.store, 32)?;
            handles.retain(|h: &std::thread::JoinHandle<()>| !h.is_finished());

            while active.load(Ordering::SeqCst) < cap {
                let Some(sid) = self.store.claim_next()? else { break };
                active.fetch_add(1, Ordering::SeqCst);
                handles.push(self.spawn_worker(sid, Arc::clone(&cfg), Arc::clone(&active), Arc::clone(&shutdown), opts.verbose));
            }

            if let Some(n) = opts.stop_after_finished {
                if active.load(Ordering::SeqCst) == 0 && self.store.count_sessions(&FINISHED)? >= n {
                    break;
                }
            }
            std::thread::sleep(opts.tick);
        }

        // Tell running sessions to pause, then wait for them. They go back to
        // the queue and pick up where they left off on the next start.
        shutdown.store(true, Ordering::SeqCst);
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }

    fn spawn_worker(
        &self,
        sid: i64,
        cfg: Arc<Config>,
        active: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        verbose: bool,
    ) -> std::thread::JoinHandle<()> {
        let store = Arc::clone(&self.store);
        let audit = Arc::clone(&self.audit);
        let provider = Arc::clone(&self.provider);
        let approver = Arc::clone(&self.approver);
        let home = self.home.clone();
        std::thread::spawn(move || {
            let _guard = ActiveGuard(active);
            if verbose {
                eprintln!("session {sid}: started");
            }
            let outcome: Result<Outcome> = (|| {
                let mut host = PluginHost::start_for(&cfg)?;
                let gate = Gate::new(&cfg.workspace, &cfg.grants, &[home.clone()]);
                let mut runner = Runner {
                    cfg: &cfg,
                    store: &store,
                    audit: &audit,
                    provider: provider.as_ref(),
                    approver: approver.as_ref(),
                    host: &mut host,
                    gate: &gate,
                    shutdown: Some(&shutdown),
                };
                runner.run_session(sid)
            })();
            match outcome {
                Ok(o) => {
                    if verbose {
                        eprintln!("session {sid}: {}", describe(&o));
                    }
                }
                Err(e) => {
                    let _ = store.append_log(sid, "note", json!({ "text": format!("worker error: {e:#}") }));
                    let _ = store.set_status(sid, "failed");
                    if verbose {
                        eprintln!("session {sid}: failed: {e:#}");
                    }
                }
            }
        })
    }
}

fn describe(o: &Outcome) -> String {
    match o {
        Outcome::Completed { .. } => "completed".into(),
        Outcome::Suspended { reason, .. } => format!("suspended ({reason})"),
        Outcome::Interrupted => "interrupted".into(),
        Outcome::Paused => "paused for shutdown".into(),
    }
}

/// Only one daemon may run per home directory, because crash recovery assumes any
/// session marked running belongs to a dead process. The lock is a pid file that
/// is ignored when its process is gone (Linux: checks /proc).
pub struct DaemonLock {
    path: PathBuf,
}

impl DaemonLock {
    pub fn acquire(home: &Path) -> Result<Self> {
        let path = home.join("daemon.pid");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                if Path::new(&format!("/proc/{pid}")).exists() {
                    bail!("a daemon is already running (pid {pid})");
                }
            }
            let _ = std::fs::remove_file(&path);
        }
        std::fs::write(&path, std::process::id().to_string())?;
        Ok(Self { path })
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Size and modification time of the config file, to notice an edit cheaply.
fn config_stamp(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}
