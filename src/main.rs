#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use clap::Parser;
use std::env;

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

fn main() {
  let cli = Cli::parse();

  let final_vt_api_key = if cli.vt {
    cli
      .vt_api_key_flag
      .or_else(|| env::var("VT_API_KEY").ok().filter(|key| !key.is_empty()))
  } else {
    None
  };

  println!("Parsed arguments:");
  println!("  Target: {}", cli.target);
  println!("  VirusTotal Check: {}", cli.vt);
  if let Some(key) = &final_vt_api_key {
    println!("  VirusTotal API Key: Provided (len: {})", key.len());
  } else if cli.vt {
    println!("  VirusTotal API Key: Not provided via --vt-api-key flag or VT_API_KEY env var.");
  }
  println!("  JSON Output: {}", cli.json);
  println!("  Skip WHOIS: {}", cli.no_whois);
  println!("  Skip DNS: {}", cli.no_dns);
  println!("  Skip SSL: {}", cli.no_ssl);
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
        result.err().unwrap().kind(),
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

    let args = make_args(&["example.com"]);
    let cli =
      Cli::try_parse_from(args).expect("Parsing should succeed without --vt");

    assert!(!cli.vt);
    assert!(
      cli.vt_api_key_flag.is_none(),
      "API key flag should be None because --vt flag was missing"
    );

    std::env::remove_var("VT_API_KEY");

    let args_flag = make_args(&["example.com", "--vt-api-key", "flagkey"]);
    let result_flag = Cli::try_parse_from(args_flag);
    assert!(
      result_flag.is_err(),
      "Using --vt-api-key flag requires --vt flag, regardless of env var"
    );
    assert!(result_flag.unwrap_err().to_string().contains("--vt"));
  }
}
