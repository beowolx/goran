//! WHOIS lookup functionality using system's whois command.

use anyhow::{bail, Context, Result};
use std::process::{Command, Output, Stdio};
use std::str;

/// Checks if the 'whois' command is available on the system.
///
/// # Returns
/// `true` if the command exists and runs successfully, `false` otherwise.
pub fn check_whois_command() -> Result<bool> {
  Command::new("whois")
    .arg("--version")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .map(|status| status.success())
    .or_else(|e| {
      if e.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
      } else {
        Err(e).context("Failed to run 'whois --version' command check")
      }
    })
}

/// Executes the 'whois' command for the given target.
///
/// # Arguments
/// * `target` - IP address or domain to query
///
/// # Returns
/// Raw WHOIS command output as a String
///
/// # Errors
/// - Command execution failure
/// - Non-zero exit status
/// - UTF-8 decoding errors
/// - Empty output
pub fn fetch_whois_info(target: &str) -> Result<String> {
  let output: Output = Command::new("whois")
    .arg(target)
    .output()
    .with_context(|| {
      format!("Failed to execute whois command for target: {target}")
    })?;

  if !output.status.success() {
    let stderr = str::from_utf8(&output.stderr)
      .unwrap_or("Failed to read stderr")
      .trim();
    bail!(
      "whois command failed with status: {status}. Stderr: {stderr}",
      status = output.status,
      stderr = stderr
    );
  }

  let stdout = str::from_utf8(&output.stdout)
    .with_context(|| {
      format!("Failed to decode whois output as UTF-8 for target: {target}")
    })?
    .trim()
    .to_string();

  if stdout.is_empty() {
    bail!("whois command returned empty output for target: {target}");
  }

  Ok(stdout)
}
