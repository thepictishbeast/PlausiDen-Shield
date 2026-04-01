//! Safe command execution layer.
//!
//! All system commands go through this module. No shell string concatenation.
//! Every command uses explicit argument arrays via `tokio::process::Command`.

pub mod command;
