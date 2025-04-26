use crate::cli::Cli;
use crate::results::{self, Analysis};
use crate::steps;
use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use std::env;

/// Strip URL schemes (`http://`, `https://`) and any path/query, leaving only host or IP.
fn normalize_target(input: &str) -> String {
  let mut s = input.trim();
  if let Some(stripped) = s.strip_prefix("http://") {
    s = stripped;
  } else if let Some(stripped) = s.strip_prefix("https://") {
    s = stripped;
  }
  if let Some(idx) = s.find('/') {
    s = &s[..idx];
  }
  s.to_string()
}

pub struct App {
  cli: Cli,
  client: Client,
  results: Analysis,
  vt_api_key: Option<String>,
}

impl App {
  pub fn new() -> Result<Self> {
    let mut cli = Cli::parse();
    cli.target = normalize_target(&cli.target);

    let client = Client::builder()
      .user_agent(format!("miru_cli/{}", env!("CARGO_PKG_VERSION")))
      .build()?;

    let initial_results = Analysis {
      target: cli.target.clone(),
      ..Default::default()
    };

    let vt_api_key = if cli.vt {
      cli
        .vt_api_key_flag
        .clone()
        .or_else(|| env::var("VT_API_KEY").ok().filter(|k| !k.is_empty()))
    } else {
      None
    };

    Ok(Self {
      cli,
      client,
      results: initial_results,
      vt_api_key,
    })
  }

  pub async fn run(&mut self) -> Result<()> {
    self.run_geo_lookup().await;
    self.run_whois_lookup().await;
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

  async fn run_whois_lookup(&mut self) {
    if !self.cli.json && !self.cli.no_whois {
      println!("Fetching WHOIS info...");
    }
    match steps::fetch_whois_step(&self.cli.target, &self.cli).await {
      Ok(Some(info)) => self.results.whois_info = Some(info),
      Ok(None) => {
        let reason = if self.cli.no_whois {
          "skipped by --no-whois flag"
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
      Ok(None) => { /* skipped – VT flag not enabled */ }
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
