use clap::Parser;

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
pub struct Cli {
  /// The IP address or domain name to analyze.
  pub target: String,

  /// Enable `VirusTotal` reputation check.
  /// Requires `VT_API_KEY` environment variable or `--vt-api-key` flag.
  #[arg(long)]
  pub vt: bool,

  /// `VirusTotal` API key.
  /// Overrides the `VT_API_KEY` environment variable if both are set.
  #[arg(long = "vt-api-key", requires = "vt", value_name = "API_KEY")]
  pub vt_api_key_flag: Option<String>,

  /// Output results in JSON format instead of human-readable text.
  #[arg(long)]
  pub json: bool,

  /// Skip the WHOIS lookup step.
  #[arg(long)]
  pub no_whois: bool,

  /// Skip the DNS lookup step.
  #[arg(long)]
  pub no_dns: bool,

  /// Skip the SSL certificate check step.
  #[arg(long)]
  pub no_ssl: bool,

  /// Ask Gemini to write a full narrative report and a final verdict.
  #[arg(long)]
  pub llm_report: bool,

  /// Gemini API key (overrides the `GEMINI_API_KEY` env-var).   
  #[arg(long = "llm-api-key", requires = "llm_report", value_name = "API_KEY")]
  pub llm_api_key_flag: Option<String>,

  /// Persist any api-key flags that are present into the user config file.
  #[arg(long)]
  pub save_keys: bool,

  /// Print the current merged configuration and exit.
  #[arg(long)]
  pub config_show: bool,
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;

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
    env::set_var("VT_API_KEY", "envkey123");
    let args = make_args(&["example.com", "--vt"]);
    let cli = Cli::try_parse_from(args).expect("Should parse with env var key");
    assert!(cli.vt);
    assert!(cli.vt_api_key_flag.is_none());
    env::remove_var("VT_API_KEY");
  }

  #[test]
  fn test_vt_api_key_flag_overrides_env() {
    env::set_var("VT_API_KEY", "envkey_should_be_ignored");
    let args =
      make_args(&["example.com", "--vt", "--vt-api-key", "flagkey_wins"]);
    let cli = Cli::try_parse_from(args)
      .expect("Flag key should override env var parsing");
    assert!(cli.vt);
    assert_eq!(cli.vt_api_key_flag, Some("flagkey_wins".to_string()));
    env::remove_var("VT_API_KEY");
  }

  #[test]
  fn test_vt_api_key_requires_vt_flag_even_with_env() {
    env::set_var("VT_API_KEY", "envkey123");
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
    env::remove_var("VT_API_KEY");

    let args_flag_only = make_args(&["example.com", "--vt-api-key", "flagkey"]);
    let result_flag_only = Cli::try_parse_from(args_flag_only);
    assert!(
      result_flag_only.is_err(),
      "Using --vt-api-key flag requires --vt flag, regardless of env var"
    );
    assert!(result_flag_only.unwrap_err().to_string().contains("--vt"));
  }
}
