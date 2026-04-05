//! Parameterized command execution — the ONLY way Shield runs system commands.
//!
//! Security invariant: user input is NEVER interpolated into shell strings.
//! All arguments are passed as explicit array elements to `Command::new()`.
#![allow(dead_code)]

use anyhow::{Context, Result};
use std::process::Output;
use tokio::process::Command;

/// Result of a command execution.
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl From<Output> for CommandResult {
    fn from(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code(),
        }
    }
}

/// Execute a command with explicit arguments. No shell interpretation.
///
/// # Arguments
///
/// * `program` - The binary to execute (e.g., "ufw", "systemctl").
/// * `args` - Argument array. Each element is one argument.
///
/// # Security
///
/// This function uses `Command::new()` which does NOT invoke a shell.
/// Arguments are passed directly to the process via `execvp()`.
/// Shell metacharacters in arguments have no special meaning.
pub async fn exec(program: &str, args: &[&str]) -> Result<CommandResult> {
    tracing::debug!(
        program = program,
        args = ?args,
        "Executing command"
    );

    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("Failed to execute: {} {}", program, args.join(" ")))?;

    let result = CommandResult::from(output);

    if !result.success {
        tracing::warn!(
            program = program,
            exit_code = result.exit_code,
            stderr = %result.stderr.trim(),
            "Command failed"
        );
    }

    Ok(result)
}

/// Execute a command with sudo. Same security model as `exec()`.
pub async fn exec_sudo(program: &str, args: &[&str]) -> Result<CommandResult> {
    let mut sudo_args = vec![program];
    sudo_args.extend_from_slice(args);
    exec("sudo", &sudo_args).await
}

/// Execute a command and return stdout lines, filtering empty lines.
pub async fn exec_lines(program: &str, args: &[&str]) -> Result<Vec<String>> {
    let result = exec(program, args).await?;
    Ok(result
        .stdout
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.is_empty())
        .collect())
}
