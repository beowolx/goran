use crate::providers::{dns, geo, ssl, vt, whois};
use anyhow::{Context, Result};
use console::{style, Style};
use serde::Serialize;

#[derive(Debug, Serialize, Default)]
pub struct Analysis {
  pub target: String,

  #[serde(skip_serializing_if = "Option::is_none")]
  pub geo_info: Option<geo::Info>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub whois_info: Option<whois::Info>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub dns_info: Option<dns::Info>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub ssl_info: Option<ssl::Info>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub vt_info: Option<vt::Info>,

  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub skipped_steps: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub errors: Vec<String>,
}

/// Helper: coloured keys so the summary is easy to scan.
fn key(s: &str) -> console::StyledObject<&str> {
  style(s).bold().cyan()
}

/// Helper: print a section header ("🌐 Geolocation") once.
fn header(title: &str, emoji: &str) {
  println!(
    "\n{} {}",
    style(emoji).bold(),
    Style::new().bold().underlined().apply_to(title)
  );
}

fn print_geo_info(geo: Option<&geo::Info>) {
  header("Geolocation", "🌐");
  match geo {
    Some(i) => {
      println!("  {} {}", key("IP:"), i.query);
      println!(
        "  {} {}",
        key("Country:"),
        i.country.as_deref().unwrap_or("N/A")
      );
      println!("  {} {}", key("City:"), i.city.as_deref().unwrap_or("N/A"));
      println!(
        "  {} {}",
        key("Region:"),
        i.region_name.as_deref().unwrap_or("N/A")
      );
      println!("  {} {}", key("ISP:"), i.isp.as_deref().unwrap_or("N/A"));
    }
    None => println!("  {}", style("Not available").dim()),
  }
}

fn print_whois_info(whois: Option<&whois::Info>) {
  header("WHOIS", "📜");
  match whois {
    Some(i) => {
      println!(
        "  {} {}",
        key("Domain Name:"),
        i.domain_name.as_deref().unwrap_or("N/A")
      );
      println!(
        "  {} {}",
        key("Registrar:"),
        i.registrar.as_deref().unwrap_or("N/A")
      );
      println!(
        "  {} {}",
        key("Created:"),
        i.creation_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "  {} {}",
        key("Updated:"),
        i.updated_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "  {} {}",
        key("Expires:"),
        i.expiry_date.as_deref().unwrap_or("N/A")
      );
      println!(
        "  {} {}",
        key("Status:"),
        if i.domain_status.is_empty() {
          "N/A".into()
        } else {
          i.domain_status.join(", ")
        }
      );
      println!(
        "  {} {}",
        key("Name Servers:"),
        if i.name_servers.is_empty() {
          "N/A".into()
        } else {
          i.name_servers.join(", ")
        }
      );
      println!(
        "  {} {}",
        key("Registrant Org:"),
        i.registrant_organization
          .as_deref()
          .unwrap_or("N/A (or Redacted)")
      );
      println!(
        "  {} {}",
        key("Registrant Country:"),
        i.registrant_country
          .as_deref()
          .unwrap_or("N/A (or Redacted)")
      );
    }
    None => println!("  {}", style("Not available").dim()),
  }
}

fn print_dns_info(dns: Option<&dns::Info>) {
  header("DNS", "🧭");
  match dns {
    Some(i) => {
      println!("  {} {:?}", key("A:"), i.a);
      println!("  {} {:?}", key("AAAA:"), i.aaaa);
      println!("  {} {:?}", key("MX:"), i.mx);
      println!("  {} {:?}", key("NS:"), i.ns);
    }
    None => println!("  {}", style("Not available").dim()),
  }
}

fn print_ssl_info(ssl: Option<&ssl::Info>) {
  header("SSL Certificate", "🔒");
  match ssl {
    Some(i) => {
      println!("  {} {}", key("Issuer:"), i.issuer);
      println!("  {} {}", key("Subject:"), i.subject);
      println!("  {} {}", key("Valid From:"), i.not_before);
      println!("  {} {}", key("Valid Until:"), i.not_after);
      let dns_names_str = if i.dns_names.is_empty() {
        "N/A".to_string()
      } else {
        i.dns_names.join(", ")
      };
      println!("  {} {}", key("DNS Names:"), dns_names_str);
      println!("  {} {}", key("TLS Version:"), i.tls_version);
    }
    None => println!("  {}", style("Not available").dim()),
  }
}

fn print_vt_info(vt: Option<&vt::Info>) {
  header("VirusTotal Reputation", "🕵️");
  match vt {
    Some(i) => {
      let s = &i.stats;
      let total = s.malicious + s.harmless + s.suspicious + s.undetected;
      println!(
        "  {} {}/{} engines {}  (suspicious: {}, harmless: {}, undetected: {})",
        key("Malicious:"),
        s.malicious,
        total,
        if s.malicious == 0 {
          style("✅").green()
        } else {
          style("⚠️").yellow()
        },
        s.suspicious,
        s.harmless,
        s.undetected
      );
      if let Some(rep) = i.reputation {
        println!("  {} {}", key("Overall score:"), rep);
      }
      if !i.categories.is_empty() {
        println!("  {} {}", key("Categories:"), i.categories.join(", "));
      }
    }
    None => println!("  {}", style("Not available").dim()),
  }
}

pub fn print_human_readable(results: &Analysis) {
  println!(
    "{} {}",
    style("•").magenta(),
    Style::new()
      .bold()
      .magenta()
      .apply_to(format!("Analysis Results for: {}", &results.target))
  );

  print_geo_info(results.geo_info.as_ref());
  print_whois_info(results.whois_info.as_ref());
  print_dns_info(results.dns_info.as_ref());
  print_ssl_info(results.ssl_info.as_ref());
  print_vt_info(results.vt_info.as_ref());

  if !results.skipped_steps.is_empty() {
    header("Skipped Steps", "⚠");
    for s in &results.skipped_steps {
      println!("  {}", style(s).yellow());
    }
  }

  if !results.errors.is_empty() {
    header("Errors Encountered", "❌");
    for e in &results.errors {
      eprintln!("  {}", style(e).red().bold());
    }
  }
}

pub fn print_json(results: &Analysis) -> Result<()> {
  serde_json::to_string_pretty(results)
    .map(|s| println!("{s}"))
    .context("Failed to serialize results to JSON")
}
