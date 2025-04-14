#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client;
use serde::Serialize;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;

mod geo;
mod whois;

#[derive(Parser, Debug, Clone)]
#[command(
  name = "miru",
  author = "Luis Cardoso <luis@luiscardoso.dev>",
  version = "0.1.0"
)]
#[command(
  about = "Query IPs/domains for Geolocation, WHOIS, DNS, SSL, and VirusTotal info.",
  long_about = "A command-line utility to gather various information about an IP address or domain name, including Geolocation, WHOIS records, DNS details, SSL certificate information, and VirusTotal reputation scores."
)]
struct Cli {
  /// The IP address or domain name to analyze.
  target: String,

  /// Enable `VirusTotal` reputation check.
  /// Requires `VT_API_KEY` environment variable or `--vt-api-key` flag.
  #[arg(long)]
  vt: bool,

  /// `VirusTotal` API key.
  /// Overrides the `VT_API_KEY` environment variable if both are set.
  #[arg(long = "vt-api-key", requires = "vt", value_name = "API_KEY")]
  vt_api_key_flag: Option<String>,

  /// Output results in JSON format instead of human-readable text.
  #[arg(long)]
  json: bool,

  /// Skip the WHOIS lookup step.
  #[arg(long)]
  no_whois: bool,

  /// Skip the DNS lookup step.
  #[arg(long)]
  no_dns: bool,

  /// Skip the SSL certificate check step.
  #[arg(long)]
  no_ssl: bool,
}

/// Holds the results from the different analysis steps.
#[derive(Debug, Serialize, Default)]
struct AnalysisResults {
  target: String,
  geo_info: Option<geo::Info>,
  whois_info: Option<whois::Info>,
  skipped_steps: Vec<String>,
  errors: Vec<String>,
}

/// Fetches Geolocation information.
async fn fetch_geo_step(
  target: &str,
  client: &Client,
) -> Result<geo::Info, String> {
  geo::fetch_geo_info(target, client)
    .await
    .map_err(|e| format!("Geolocation lookup failed: {e}"))
}

/// Fetches WHOIS information if applicable.
fn fetch_whois_step(
  target: &str,
  cli: &Cli,
  whois_available: bool,
) -> Result<Option<whois::Info>, String> {
  let is_ip_address = IpAddr::from_str(target).is_ok();
  if cli.no_whois {
    return Ok(None);
  }
  if is_ip_address {
    return Ok(None);
  }
  if !whois_available {
    return Err(
      "WHOIS lookup skipped: 'whois' command not found or not executable."
        .to_string(),
    );
  }

  match whois::fetch_whois_info(target) {
    Ok(info) => Ok(Some(info)),
    Err(e) => Err(format!("WHOIS lookup failed: {e}")),
  }
}

fn fetch_dns_step(cli: &Cli) -> Result<Option<()>, String> {
  if cli.no_dns {
    Ok(None)
  } else {
    Err("DNS lookup feature not yet implemented.".to_string())
  }
}

fn fetch_ssl_step(cli: &Cli) -> Result<Option<()>, String> {
  if cli.no_ssl {
    Ok(None)
  } else {
    Err("SSL certificate check feature not yet implemented.".to_string())
  }
}

fn fetch_vt_step(
  cli: &Cli,
  api_key: Option<&str>,
) -> Result<Option<()>, String> {
  if !cli.vt {
    Ok(None)
  } else if api_key.is_none() {
    Err("VirusTotal check requires an API key (VT_API_KEY env var or --vt-api-key flag), but none was provided.".to_string())
  } else {
    Err("VirusTotal check feature not yet implemented.".to_string())
  }
}

fn print_human_readable(results: &AnalysisResults) {
  println!("--- Analysis Results for: {} ---", results.target);

  println!("\n[+] Geolocation:");
  match &results.geo_info {
    Some(info) => {
      println!("    IP: {}", info.query);
      println!("    Country: {}", info.country.as_deref().unwrap_or("N/A"));
      println!("    City: {}", info.city.as_deref().unwrap_or("N/A"));
      println!(
        "    Region: {}",
        info.region_name.as_deref().unwrap_or("N/A")
      );
      println!("    ISP: {}", info.isp.as_deref().unwrap_or("N/A"));
    }
    None => {
      println!("    Not available (lookup failed or skipped).");
    }
  }

  println!("\n[+] WHOIS Information:");
  match &results.whois_info {
    Some(info) => {
      println!(
        "    Domain Name: {}",
        info.domain_name.as_deref().unwrap_or("N/A")
      );
      println!(
        "    Registrar: {}",
        info.registrar.as_deref().unwrap_or("N/A")
      );
      println!(
        "    Created: {}",
        info.creation_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "    Updated: {}",
        info.updated_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "    Expires: {}",
        info.expiry_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "    Status: {}",
        if info.domain_status.is_empty() {
          "N/A".to_string()
        } else {
          info.domain_status.join(", ")
        }
      );
      println!(
        "    Name Servers: {}",
        if info.name_servers.is_empty() {
          "N/A".to_string()
        } else {
          info.name_servers.join(", ")
        }
      );
      println!(
        "    Registrant Org: {}",
        info
          .registrant_organization
          .as_deref()
          .unwrap_or("N/A (or Redacted)")
      );
      println!(
        "    Registrant Country: {}",
        info
          .registrant_country
          .as_deref()
          .unwrap_or("N/A (or Redacted)")
      );
    }
    None => {
      println!(
        "    Not available (lookup failed, skipped, or not applicable)."
      );
    }
  }

  println!("\n[+] DNS Information:");
  println!("    Feature not yet implemented.");

  println!("\n[+] SSL Certificate Information:");
  println!("    Feature not yet implemented.");

  println!("\n[+] VirusTotal Reputation:");
  println!("    Feature not yet implemented.");

  if !results.skipped_steps.is_empty() {
    println!("\n--- Skipped Steps ---");
    for step in &results.skipped_steps {
      println!("  - {step}");
    }
  }

  if !results.errors.is_empty() {
    println!("\n--- Errors Encountered ---");
    for error in &results.errors {
      eprintln!("  [!] {error}");
    }
  }
}

/// Prints the results in JSON format.
fn print_json(results: &AnalysisResults) -> Result<()> {
  serde_json::to_string_pretty(results)
    .map(|json_string| println!("{json_string}"))
    .context("Failed to serialize results to JSON")
}

#[tokio::main]
async fn main() -> Result<()> {
  let cli = Cli::parse();
  let http_client = Client::builder()
    .user_agent(format!("miru_cli/{}", env!("CARGO_PKG_VERSION")))
    .build()?;

  let mut results = AnalysisResults {
    target: cli.target.clone(),
    ..Default::default()
  };

  let whois_available = match whois::check_whois_command() {
    Ok(available) => available,
    Err(e) => {
      results.errors.push(format!(
        "Error checking for 'whois' command: {e}. WHOIS lookups will be skipped."
      ));
      false
    }
  };

  let final_vt_api_key = if cli.vt {
    cli
      .vt_api_key_flag
      .clone()
      .or_else(|| env::var("VT_API_KEY").ok().filter(|key| !key.is_empty()))
  } else {
    None
  };

  if !cli.json {
    println!("Fetching Geolocation info...");
  }
  match fetch_geo_step(&cli.target, &http_client).await {
    Ok(info) => results.geo_info = Some(info),
    Err(e) => results.errors.push(e),
  }

  if !cli.json {
    println!("Fetching WHOIS info (if applicable)...");
  }
  match fetch_whois_step(&cli.target, &cli, whois_available) {
    Ok(Some(info)) => results.whois_info = Some(info),
    Ok(None) => {
      let is_ip = IpAddr::from_str(&cli.target).is_ok();
      if cli.no_whois {
        results
          .skipped_steps
          .push("WHOIS (skipped by --no-whois flag)".to_string());
      } else if is_ip {
        results
          .skipped_steps
          .push("WHOIS (skipped for IP address target)".to_string());
      } else {
        results
          .skipped_steps
          .push("WHOIS (skipped for unknown reason)".to_string());
      }
    }
    Err(e) => results.errors.push(e),
  }

  if !cli.json && !cli.no_dns {
    println!("Checking DNS info (not implemented)...");
  }
  match fetch_dns_step(&cli) {
    Ok(None) => results
      .skipped_steps
      .push("DNS (skipped by --no-dns flag)".to_string()),
    Err(e) => results.errors.push(e),
    Ok(Some(())) => todo!(),
  }

  if !cli.json && !cli.no_ssl {
    println!("Checking SSL info (not implemented)...");
  }
  match fetch_ssl_step(&cli) {
    Ok(None) => results
      .skipped_steps
      .push("SSL (skipped by --no-ssl flag)".to_string()),
    Err(e) => results.errors.push(e),
    Ok(Some(())) => todo!(),
  }

  if !cli.json && cli.vt {
    println!("Checking VirusTotal info (not implemented)...");
  }
  match fetch_vt_step(&cli, final_vt_api_key.as_deref()) {
    Ok(None) => {
      if !cli.vt {
        results
          .skipped_steps
          .push("VirusTotal (skipped by --no-vt flag)".to_string());
      }
    }
    Err(e) => results.errors.push(e),
    Ok(Some(())) => todo!(),
  }

  if cli.json {
    print_json(&results)?;
  } else {
    print_human_readable(&results);
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_args(args: &[&str]) -> Vec<String> {
    std::iter::once("miru".to_string())
      .chain(args.iter().map(std::string::ToString::to_string))
      .collect()
  }

  #[test]
  fn test_basic_target() {
    let args = make_args(&["example.com"]);
    let cli = Cli::try_parse_from(args).expect("Should parse basic target");
    assert_eq!(cli.target, "example.com");
    assert!(!cli.vt);
    assert!(cli.vt_api_key_flag.is_none());
    assert!(!cli.json);
    assert!(!cli.no_whois);
    assert!(!cli.no_dns);
    assert!(!cli.no_ssl);
  }

  #[test]
  fn test_vt_flag() {
    let args = make_args(&["example.com", "--vt"]);
    let cli = Cli::try_parse_from(args).expect("Should parse --vt flag");
    assert!(cli.vt);
  }

  #[test]
  fn test_vt_with_api_key() {
    let args = make_args(&["example.com", "--vt", "--vt-api-key", "mykey123"]);
    let cli =
      Cli::try_parse_from(args).expect("Should parse --vt with API key flag");
    assert!(cli.vt);
    assert_eq!(cli.vt_api_key_flag, Some("mykey123".to_string()));
  }

  #[test]
  fn test_vt_api_key_requires_vt_flag() {
    let args = make_args(&["example.com", "--vt-api-key", "mykey123"]);
    let result = Cli::try_parse_from(args);
    assert!(
      result.is_err(),
      "Parsing should fail if --vt-api-key is used without --vt"
    );
    // Updated error message check for clap 4+ (more flexible)
    assert!(
      result.unwrap_err().to_string().contains("--vt"),
      "Error message should mention '--vt' requirement"
    );
  }

  #[test]
  fn test_json_flag() {
    let args = make_args(&["example.com", "--json"]);
    let cli = Cli::try_parse_from(args).expect("Should parse --json flag");
    assert!(cli.json);
  }

  #[test]
  fn test_no_flags() {
    let args = make_args(&["1.1.1.1", "--no-whois", "--no-dns", "--no-ssl"]);
    let cli = Cli::try_parse_from(args).expect("Should parse --no-* flags");
    assert!(cli.no_whois);
    assert!(cli.no_dns);
    assert!(cli.no_ssl);
    assert!(!cli.json);
  }

  #[test]
  fn test_combination_flags() {
    let args = make_args(&["rust-lang.org", "--json", "--no-ssl", "--vt"]);
    let cli =
      Cli::try_parse_from(args).expect("Should parse combination of flags");
    assert_eq!(cli.target, "rust-lang.org");
    assert!(cli.json);
    assert!(cli.no_ssl);
    assert!(cli.vt);
    assert!(!cli.no_whois);
    assert!(!cli.no_dns);
    assert!(cli.vt_api_key_flag.is_none());
  }

  #[test]
  fn test_missing_target_arg_fails() {
    let args = make_args(&[]);
    let result = Cli::try_parse_from(args);
    assert!(
      result.is_err(),
      "Parsing should fail if target argument is missing"
    );
    assert!(
      matches!(
        result.unwrap_err().kind(),
        clap::error::ErrorKind::MissingRequiredArgument
      ),
      "Error kind should be MissingRequiredArgument"
    );
  }

  #[test]
  fn test_ip_as_target() {
    let args = make_args(&["8.8.8.8"]);
    let cli =
      Cli::try_parse_from(args).expect("Should parse IP address as target");
    assert_eq!(cli.target, "8.8.8.8");
  }

  #[test]
  fn test_vt_api_key_from_env() {
    std::env::set_var("VT_API_KEY", "envkey123");
    let args = make_args(&["example.com", "--vt"]);
    let cli = Cli::try_parse_from(args).expect("Should parse with env var key");
    assert!(cli.vt);
    assert!(cli.vt_api_key_flag.is_none());
    std::env::remove_var("VT_API_KEY");
  }

  #[test]
  fn test_vt_api_key_flag_overrides_env() {
    std::env::set_var("VT_API_KEY", "envkey_should_be_ignored");
    let args =
      make_args(&["example.com", "--vt", "--vt-api-key", "flagkey_wins"]);
    let cli = Cli::try_parse_from(args)
      .expect("Flag key should override env var parsing");
    assert!(cli.vt);
    assert_eq!(cli.vt_api_key_flag, Some("flagkey_wins".to_string()));
    std::env::remove_var("VT_API_KEY");
  }

  #[test]
  fn test_vt_api_key_requires_vt_flag_even_with_env() {
    std::env::set_var("VT_API_KEY", "envkey123");
    let args_no_vt = make_args(&["example.com"]);
    let cli_no_vt = Cli::try_parse_from(args_no_vt)
      .expect("Parsing should succeed without --vt");
    assert!(!cli_no_vt.vt);
    assert!(
      cli_no_vt.vt_api_key_flag.is_none(),
      "API key flag should be None because --vt flag was missing"
    );
    let final_key_scenario1 = if cli_no_vt.vt {
      cli_no_vt
        .vt_api_key_flag
        .or_else(|| env::var("VT_API_KEY").ok().filter(|k| !k.is_empty()))
    } else {
      None
    };
    assert!(
      final_key_scenario1.is_none(),
      "Final key should be None when --vt is off"
    );
    std::env::remove_var("VT_API_KEY");

    let args_flag_only = make_args(&["example.com", "--vt-api-key", "flagkey"]);
    let result_flag_only = Cli::try_parse_from(args_flag_only);
    assert!(
      result_flag_only.is_err(),
      "Using --vt-api-key flag requires --vt flag, regardless of env var"
    );
    assert!(result_flag_only.unwrap_err().to_string().contains("--vt"));
  }
}
