//! Fetches and parses WHOIS information for domain names.
//!
//! This module provides functionality to execute the system's `whois` command
//! and parse its output into a structured `Info` object. It handles variations
//! in WHOIS output formats on a best-effort basis using regular expressions.

use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::{Command, Stdio};

// --- Regex for parsing WHOIS output ---
// These regexes attempt to capture common fields found in WHOIS records.
// Due to the lack of a standardized format, they are best-effort matches.

static RE_DOMAIN_NAME: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:Domain Name|domain):\s*(.*)").unwrap());
static RE_REGISTRAR: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Registrar|registrar|Sponsoring Registrar):\s*(.*)").unwrap()
});
static RE_CREATION_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Creation Date|Registered on|created):\s*(.*)").unwrap()
});
static RE_UPDATED_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Updated Date|Changed|last-updated):\s*(.*)").unwrap()
});
static RE_EXPIRY_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(
    r"^(?:Registry Expiry Date|Expiry Date|Expires On|paid-till):\s*(.*)",
  )
  .unwrap()
});
static RE_NAME_SERVER: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Name Server|nserver|Name Servers):\s*(.*)").unwrap()
});
static RE_DOMAIN_STATUS: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:Domain Status|status):\s*(.*)").unwrap());
static RE_REGISTRANT_ORG: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Registrant Organization|org):\s*(.*)").unwrap()
});
static RE_REGISTRANT_COUNTRY: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:Registrant Country|country):\s*(.*)").unwrap());

// Regex to identify lines indicating redacted information.
static RE_REDACTED: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"(?i)REDACTED FOR PRIVACY").unwrap());
// Regex to identify common comment or non-data lines to ignore.
static RE_IGNORE_PREFIXES: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:%|>>>|NOTE:|Registrar URL:)").unwrap());

/// Parsed WHOIS information for a domain.
///
/// Fields are optional as they may not be present or parseable in the raw output.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Info {
  /// The registered domain name, usually normalized to lowercase.
  pub domain_name: Option<String>,
  /// The sponsoring registrar.
  pub registrar: Option<String>,
  /// The date the domain was registered. Format varies.
  pub creation_date: Option<String>,
  /// The date the domain record was last updated. Format varies.
  pub updated_date: Option<String>,
  /// The date the domain registration expires. Format varies.
  pub expiry_date: Option<String>,
  /// A list of name servers associated with the domain, normalized to lowercase.
  #[serde(default)]
  pub name_servers: Vec<String>,
  /// A list of statuses reported for the domain (e.g., "clientTransferProhibited").
  #[serde(default)]
  pub domain_status: Vec<String>,
  /// The organization associated with the registrant. May be redacted.
  pub registrant_organization: Option<String>,
  /// The country associated with the registrant. May be redacted.
  pub registrant_country: Option<String>,
}

impl Info {
  /// Checks if any significant fields have been successfully parsed.
  ///
  /// This is used to determine if the WHOIS output likely contained useful
  /// domain information, rather than just boilerplate or an error message.
  fn is_meaningfully_parsed(&self) -> bool {
    self.domain_name.is_some()
      || self.registrar.is_some()
      || self.creation_date.is_some()
      || self.expiry_date.is_some()
      || !self.name_servers.is_empty()
      || self.registrant_organization.is_some()
      || self.registrant_country.is_some()
  }
}

/// Parses a single line of WHOIS output and updates the `Info` struct.
///
/// Uses the pre-compiled regexes to extract relevant data. Collects potentially
/// multi-valued fields (name servers, domain status) into temporary hash sets
/// to handle duplicates before final assignment.
fn parse_line(
  line: &str,
  info: &mut Info,
  name_servers: &mut HashSet<String>,
  domain_status: &mut HashSet<String>,
) {
  if let Some(caps) = RE_DOMAIN_NAME.captures(line) {
    if info.domain_name.is_none() {
      info.domain_name = caps.get(1).map(|m| m.as_str().trim().to_lowercase());
    }
  } else if let Some(caps) = RE_REGISTRAR.captures(line) {
    if info.registrar.is_none() {
      info.registrar = caps.get(1).map(|m| m.as_str().trim().to_string());
    }
  } else if let Some(caps) = RE_CREATION_DATE.captures(line) {
    if info.creation_date.is_none() {
      info.creation_date = caps.get(1).map(|m| m.as_str().trim().to_string());
    }
  } else if let Some(caps) = RE_UPDATED_DATE.captures(line) {
    if info.updated_date.is_none() {
      info.updated_date = caps.get(1).map(|m| m.as_str().trim().to_string());
    }
  } else if let Some(caps) = RE_EXPIRY_DATE.captures(line) {
    if info.expiry_date.is_none() {
      info.expiry_date = caps.get(1).map(|m| m.as_str().trim().to_string());
    }
  } else if let Some(caps) = RE_NAME_SERVER.captures(line) {
    if let Some(matched_value) = caps.get(1) {
      // Handle multiple name servers potentially listed on the same line.
      matched_value.as_str().split_whitespace().for_each(|ns| {
        if !ns.is_empty() {
          name_servers.insert(ns.to_lowercase());
        }
      });
    }
  } else if let Some(caps) = RE_DOMAIN_STATUS.captures(line) {
    if let Some(matched_value) = caps.get(1) {
      // Often includes a URL after the status, which we trim off.
      let status_part = matched_value
        .as_str()
        .split(" https://")
        .next()
        .unwrap_or_else(|| matched_value.as_str())
        .trim();
      if !status_part.is_empty() {
        domain_status.insert(status_part.to_string());
      }
    }
  } else if let Some(caps) = RE_REGISTRANT_ORG.captures(line) {
    if info.registrant_organization.is_none() {
      if let Some(val) = caps.get(1).map(|m| m.as_str().trim()) {
        // Avoid storing explicitly redacted values.
        if !RE_REDACTED.is_match(val) {
          info.registrant_organization = Some(val.to_string());
        }
      }
    }
  } else if let Some(caps) = RE_REGISTRANT_COUNTRY.captures(line) {
    if info.registrant_country.is_none() {
      if let Some(val) = caps.get(1).map(|m| m.as_str().trim()) {
        // Avoid storing explicitly redacted values.
        if !RE_REDACTED.is_match(val) {
          info.registrant_country = Some(val.to_string());
        }
      }
    }
  }
  // Lines not matching any regex are implicitly ignored.
}

/// Parses the raw multiline output from the 'whois' command.
///
/// Iterates through each line, skipping empty lines, comments, and redacted lines.
/// Uses the `parse_line` helper function for individual line processing.
/// Collects and sorts multi-value fields (name servers, status) at the end.
fn parse_whois_output(raw_output: &str) -> Info {
  let mut info = Info::default();
  let mut name_servers = HashSet::new();
  let mut domain_status = HashSet::new();

  for line in raw_output.lines() {
    let line = line.trim();
    // Skip lines that are empty, marked as comments/notes, or clearly redacted.
    if line.is_empty()
      || RE_IGNORE_PREFIXES.is_match(line)
      || RE_REDACTED.is_match(line)
    {
      continue;
    }

    parse_line(line, &mut info, &mut name_servers, &mut domain_status);
  }

  info.name_servers = name_servers.into_iter().collect();
  info.name_servers.sort_unstable();
  info.domain_status = domain_status.into_iter().collect();
  info.domain_status.sort_unstable();

  info
}

/// Checks if the 'whois' command is available and executable in the system's PATH.
///
/// Attempts to run `whois --version`. Note that not all `whois` implementations
/// support the `--version` flag, but it's a common convention. Success is based
/// on the exit status.
///
/// # Errors
///
/// Returns an error if the command cannot be found (`ErrorKind::NotFound`) or
/// if there's another issue executing the command (e.g., permissions).
/// The error message provides guidance on installing `whois` if it's not found.
pub fn check_whois_command() -> Result<bool> {
  Command::new("whois")
    .arg("--version")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .map(|status| status.success())
    .map_err(|e| {
      if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!("'whois' command not found in PATH. Please install it.")
      } else {
        anyhow::Error::new(e).context("Failed to execute 'whois --version'")
      }
    })
}

/// Executes the 'whois' command for a given target (domain or IP) and parses the output.
///
/// # Arguments
///
/// * `target` - The domain name or IP address to query.
///
/// # Returns
///
/// A `Result` containing the parsed `Info` structure on success.
///
/// # Errors
///
/// Returns an error if:
/// - The `whois` command fails to execute.
/// - The `whois` command exits with a non-zero status code.
/// - The command produces empty output (both stdout and stderr).
/// - The output could not be parsed into a meaningful `Info` structure
///   (checked using `is_meaningfully_parsed`). The error message will indicate
///   a potential format issue.
/// - The output contains non-UTF8 characters (though `from_utf8_lossy` mitigates this).
pub fn fetch_whois_info(target: &str) -> Result<Info> {
  let output =
    Command::new("whois")
      .arg(target)
      .output()
      .with_context(|| {
        format!("Failed to execute whois command for target: '{target}'")
      })?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
      "whois command for '{}' failed with status: {}. Stderr: {}",
      target,
      output.status,
      stderr.trim()
    );
  }

  let stdout = String::from_utf8_lossy(&output.stdout);

  if stdout.trim().is_empty() {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
      bail!("whois command for '{target}' returned empty stdout and stderr.");
    }
    bail!(
      "whois command for '{target}' returned empty stdout. Stderr: {stderr}"
    );
  }

  let parsed_info = parse_whois_output(&stdout);

  if !parsed_info.is_meaningfully_parsed() {
    bail!("Failed to parse any key fields from WHOIS output for target: '{target}'. Output might be in an unexpected format or lack common fields.");
  }

  Ok(parsed_info)
}
