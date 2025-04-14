use crate::cli::Cli;
use crate::results::{self, Analysis};
use crate::steps;
use crate::whois;
use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;

pub struct App {
  cli: Cli,
  client: Client,
  results: Analysis,
  whois_available: bool,
  vt_api_key: Option<String>,
}

impl App {
  pub fn new() -> Result<Self> {
    let cli = Cli::parse();
    let client = Client::builder()
      .user_agent(format!("miru_cli/{}", env!("CARGO_PKG_VERSION")))
      .build()?;

    let mut initial_results = Analysis {
      target: cli.target.clone(),
      ..Default::default()
    };

    let whois_available = match whois::check_whois_command() {
      Ok(available) => available,
      Err(e) => {
        initial_results.errors.push(format!(
          "Error checking for 'whois' command: {e}. WHOIS lookups will be skipped."
        ));
        false
      }
    };

    let vt_api_key = if cli.vt {
      cli
        .vt_api_key_flag
        .clone()
        .or_else(|| env::var("VT_API_KEY").ok().filter(|key| !key.is_empty()))
    } else {
      None
    };

    Ok(Self {
      cli,
      client,
      results: initial_results,
      whois_available,
      vt_api_key,
    })
  }

  pub async fn run(&mut self) -> Result<()> {
    self.run_geo_lookup().await;
    self.run_whois_lookup();
    self.run_dns_lookup();
    self.run_ssl_lookup();
    self.run_vt_lookup();
    self.print_results()
  }

  async fn run_geo_lookup(&mut self) {
    if !self.cli.json {
      println!("Fetching Geolocation info...");
    }
    match steps::fetch_geo_step(&self.cli.target, &self.client).await {
      Ok(info) => self.results.geo_info = Some(info),
      Err(e) => self.results.errors.push(e),
    }
  }

  fn run_whois_lookup(&mut self) {
    if !self.cli.json && !self.cli.no_whois {
      println!("Fetching WHOIS info (if applicable)...");
    }
    match steps::fetch_whois_step(
      &self.cli.target,
      &self.cli,
      self.whois_available,
    ) {
      Ok(Some(info)) => self.results.whois_info = Some(info),
      Ok(None) => {
        let reason = if self.cli.no_whois {
          "skipped by --no-whois flag"
        } else if IpAddr::from_str(&self.cli.target).is_ok() {
          "skipped for IP address target"
        } else if !self.whois_available {
          "skipped: 'whois' command unavailable"
        } else {
          "skipped (reason unclear)"
        };
        self.results.skipped_steps.push(format!("WHOIS ({reason})"));
      }
      Err(e) => self.results.errors.push(e),
    }
  }

  fn run_dns_lookup(&mut self) {
    if !self.cli.json && !self.cli.no_dns {
      println!("Checking DNS info (not implemented)...");
    }
    match steps::fetch_dns_step(&self.cli) {
      Ok(None) => {
        if self.cli.no_dns {
          self
            .results
            .skipped_steps
            .push("DNS (skipped by --no-dns flag)".to_string());
        }
      }
      Err(e) => self.results.errors.push(e),
      Ok(Some(())) => todo!("Handle DNS results when implemented"),
    }
  }

  fn run_ssl_lookup(&mut self) {
    if !self.cli.json && !self.cli.no_ssl {
      println!("Checking SSL info (not implemented)...");
    }
    match steps::fetch_ssl_step(&self.cli) {
      Ok(None) => {
        if self.cli.no_ssl {
          self
            .results
            .skipped_steps
            .push("SSL (skipped by --no-ssl flag)".to_string());
        }
      }
      Err(e) => self.results.errors.push(e),
      Ok(Some(())) => todo!("Handle SSL results when implemented"),
    }
  }

  fn run_vt_lookup(&mut self) {
    if !self.cli.json && self.cli.vt {
      println!("Checking VirusTotal info (not implemented)...");
    }
    match steps::fetch_vt_step(&self.cli, self.vt_api_key.as_deref()) {
      Ok(None) => {
        // Skipped because VT wasn't enabled (`--vt` flag missing)
      }
      Err(e) => self.results.errors.push(e),
      Ok(Some(())) => todo!("Handle VT results when implemented"),
    }
  }

  fn print_results(&self) -> Result<()> {
    if self.cli.json {
      results::print_json(&self.results)
    } else {
      results::print_human_readable(&self.results);
      Ok(())
    }
  }
}
