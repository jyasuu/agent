//! The pluggable agent, through stage 5 (loop, daemon, compaction, sub-agents, verifier, evals, delegate).
//! The core: session store, audit log, permission gate, plugin host,
//! model provider contract, and the session runner.
pub mod audit;
pub mod compact;
pub mod config;
pub mod daemon;
pub mod delegate;
pub mod eval;
pub mod gate;
pub mod hooks;
pub mod modelcheck;
pub mod plugin;
pub mod provider;
pub mod runner;
pub mod sandbox;
pub mod source;
pub mod store;
pub mod upgrade;
