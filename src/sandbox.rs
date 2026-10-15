//! OS sandbox for plugins, using bubblewrap. A sandboxed plugin sees: system directories
//! read-only, a private /tmp and /proc, the workspace, and whatever the owner listed. It has no
//! network unless granted, its own process space, and it cannot see the agent's home directory
//! (session log, audit log, delegate rules). If bwrap is missing the plugin does not start.
use crate::config::SandboxConfig;
use anyhow::{bail, Result};
use std::path::Path;

const SEARCH: [&str; 3] = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

pub fn find_bwrap(sb: &SandboxConfig) -> Result<String> {
    if let Some(p) = &sb.program {
        if Path::new(p).exists() {
            return Ok(p.clone());
        }
        bail!("sandbox program '{p}' does not exist");
    }
    SEARCH
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
        .ok_or_else(|| anyhow::anyhow!("bubblewrap (bwrap) is not installed"))
}

pub fn available() -> bool {
    find_bwrap(&SandboxConfig::default()).is_ok()
}

/// The program and arguments that run `command args` inside the sandbox.
pub fn wrap(sb: &SandboxConfig, workspace: &Path, command: &str, args: &[String]) -> Result<(String, Vec<String>)> {
    let bwrap = find_bwrap(sb).map_err(|e| anyhow::anyhow!("sandbox required but unavailable, so the plugin was not started: {e}"))?;
    let ws = workspace.to_string_lossy().to_string();
    let mut a: Vec<String> = vec!["--unshare-all".into()];
    if sb.network {
        a.push("--share-net".into());
    }
    for x in ["--die-with-parent", "--new-session"] {
        a.push(x.into());
    }
    for d in ["/usr"] {
        a.extend(["--ro-bind".into(), d.into(), d.into()]);
    }
    for (link, target) in [("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib"), ("/lib64", "usr/lib64")] {
        a.extend(["--symlink".into(), target.into(), link.into()]);
    }
    a.extend(["--ro-bind-try".into(), "/etc/ld.so.cache".into(), "/etc/ld.so.cache".into()]);
    a.extend(["--proc".into(), "/proc".into(), "--dev".into(), "/dev".into(), "--tmpfs".into(), "/tmp".into()]);
    a.extend([if sb.workspace_readonly { "--ro-bind" } else { "--bind" }.into(), ws.clone(), ws.clone()]);
    // Hidden paths come right after the workspace, so they cover a home directory that sits inside
    // it. Only the paths the owner (or the core) lists below are made visible again.
    for h in &sb.hide {
        if h.starts_with(workspace) {
            a.extend(["--tmpfs".into(), h.to_string_lossy().to_string()]);
        }
    }
    for p in &sb.ro_binds {
        a.extend(["--ro-bind".into(), p.clone(), p.clone()]);
    }
    for p in &sb.rw_binds {
        a.extend(["--bind".into(), p.clone(), p.clone()]);
    }
    // The program itself must be visible. Anything under /usr already is.
    let cmd_path = Path::new(command);
    if cmd_path.is_absolute() && !cmd_path.starts_with("/usr") && !cmd_path.starts_with("/bin") {
        a.extend(["--ro-bind".into(), command.into(), command.into()]);
    }
    a.extend(["--chdir".into(), ws, "--clearenv".into(), "--setenv".into(), "PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()]);
    a.push("--".into());
    a.push(command.into());
    a.extend(args.iter().cloned());
    Ok((bwrap, a))
}
