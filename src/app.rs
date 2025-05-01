use crate::cli::Cli;
use crate::results::{self, Analysis};
use crate::steps;
use anyhow::Result;
use clap::Parser;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
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

fn new_spinner(msg: &str) -> ProgressBar {
  let pb = ProgressBar::new_spinner();
  pb.set_style(
    ProgressStyle::with_template("{spinner} {msg}")
      .expect("valid spinner template")
      .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
  );
  pb.enable_steady_tick(std::time::Duration::from_millis(80));
  pb.set_message(msg.to_owned());
  pb
}

fn spinner(enabled: bool, label: &str) -> Option<ProgressBar> {
  if enabled {
    Some(new_spinner(label))
  } else {
    None
  }
}

pub struct App {
  cli: Cli,
  client: Client,
  results: Analysis,
  vt_api_key: Option<String>,
  llm_api_key: Option<String>,
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

    let llm_api_key = if cli.llm_report {
      cli.llm_api_key_flag.clone().or_else(|| {
        std::env::var("GEMINI_API_KEY")
          .ok()
          .filter(|k| !k.is_empty())
      })
    } else {
      None
    };

    Ok(Self {
      cli,
      client,
      results: initial_results,
      vt_api_key,
      llm_api_key,
    })
  }

  pub async fn run(&mut self) -> Result<()> {
    self.run_geo_lookup().await;
    self.run_whois_lookup().await;
    self.run_dns_lookup().await;
    self.run_ssl_lookup().await;
    self.run_vt_lookup().await;
    if self.cli.llm_report {
      self.run_llm_report().await
    } else {
      self.print_results()
    }
  }

  async fn run_llm_report(&mut self) -> Result<()> {
    let pb = spinner(!self.cli.json, "🤖  Gemini LLM Report");

    let res = async {
      let key = self
        .llm_api_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!(
          "Gemini report requested, but no API key supplied (--llm-api-key or GEMINI_API_KEY)"
        ))?;

      crate::providers::llm::generate_report(&self.results, key, &self.client).await
    }
    .await;

    match res {
      Ok(report) => {
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} Gemini LLM", style("✅").green()));
        }
        println!("\n{report}\n");
      }
      Err(err) => {
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} Gemini LLM", style("❌").red()));
        }
        self.results.errors.push(err.to_string());
      }
    }
    Ok(())
  }

  async fn run_geo_lookup(&mut self) {
    let pb = spinner(!self.cli.json, "🌐  Geolocation");
    match steps::fetch_geo_step(&self.cli.target, &self.client).await {
      Ok(info) => {
        self.results.geo_info = Some(info);
        if let Some(pb) = pb {
          pb.finish_with_message(format!(
            "{} Geolocation",
            style("✅").green()
          ));
        }
      }
      Err(e) => {
        self.results.errors.push(e);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} Geolocation", style("❌").red()));
        }
      }
    }
  }

  async fn run_whois_lookup(&mut self) {
    let pb = spinner(!self.cli.json && !self.cli.no_whois, "📜  WHOIS");
    match steps::fetch_whois_step(&self.cli.target, &self.cli).await {
      Ok(Some(info)) => {
        self.results.whois_info = Some(info);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} WHOIS", style("✅").green()));
        }
      }
      Ok(None) => {
        // Either skipped or IP address
        if self.cli.no_whois {
          self
            .results
            .skipped_steps
            .push("WHOIS (skipped by --no-whois flag)".into());
        }
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} WHOIS", style("⚠️").yellow()));
        }
      }
      Err(e) => {
        self.results.errors.push(e);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} WHOIS", style("❌").red()));
        }
      }
    }
  }

  async fn run_dns_lookup(&mut self) {
    let pb = spinner(!self.cli.json && !self.cli.no_dns, "🧭  DNS");
    match steps::fetch_dns_step(&self.cli.target, &self.cli).await {
      Ok(Some(info)) => {
        self.results.dns_info = Some(info);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} DNS", style("✅").green()));
        }
      }
      Ok(None) => {
        if self.cli.no_dns {
          self
            .results
            .skipped_steps
            .push("DNS (skipped by --no-dns flag)".into());
        }
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} DNS", style("⚠️").yellow()));
        }
      }
      Err(e) => {
        self.results.errors.push(e);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} DNS", style("❌").red()));
        }
      }
    }
  }

  async fn run_ssl_lookup(&mut self) {
    let pb = spinner(!self.cli.json && !self.cli.no_ssl, "🔒  SSL");
    match steps::fetch_ssl_step(&self.cli.target, &self.cli).await {
      Ok(Some(info)) => {
        self.results.ssl_info = Some(info);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} SSL", style("✅").green()));
        }
      }
      Ok(None) => {
        if self.cli.no_ssl {
          self
            .results
            .skipped_steps
            .push("SSL (skipped by --no-ssl flag)".into());
        }
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} SSL", style("⚠️").yellow()));
        }
      }
      Err(e) => {
        self.results.errors.push(e);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} SSL", style("❌").red()));
        }
      }
    }
  }

  async fn run_vt_lookup(&mut self) {
    let pb = spinner(!self.cli.json && self.cli.vt, "🕵️  VirusTotal");
    match steps::fetch_vt_step(
      &self.cli.target,
      &self.cli,
      &self.client,
      self.vt_api_key.as_deref(),
    )
    .await
    {
      Ok(Some(info)) => {
        self.results.vt_info = Some(info);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} VirusTotal", style("✅").green()));
        }
      }
      Ok(None) => {
        // VT disabled, no spinner created if json or flag off
      }
      Err(e) => {
        self.results.errors.push(e);
        if let Some(pb) = pb {
          pb.finish_with_message(format!("{} VirusTotal", style("❌").red()));
        }
      }
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
