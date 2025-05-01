use crate::providers::{dns, geo, whois};
use anyhow::{Context, Result};
use serde::Serialize;

/// Holds the results from the different analysis steps.
#[derive(Debug, Serialize, Default)]
pub struct Analysis {
  pub target: String,
  pub geo_info: Option<geo::Info>,
  pub whois_info: Option<whois::Info>,
  pub dns_info: Option<dns::Info>,
  //  placeholders for SSL, VT results when implemented
  // pub ssl_info: Option<ssl::Info>,
  // pub vt_info: Option<vt::Info>,
  pub skipped_steps: Vec<String>,
  pub errors: Vec<String>,
}

fn print_geo_info(geo_info: Option<&geo::Info>) {
  println!("\n[+] Geolocation:");
  match geo_info {
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
}

fn print_whois_info(whois_info: Option<&whois::Info>) {
  println!("\n[+] WHOIS Information:");
  match whois_info {
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
}

fn print_dns_info(dns_info: Option<&dns::Info>) {
  println!("\n[+] DNS Information:");
  match dns_info {
    Some(info) => {
      println!("    A: {:?}", info.a);
      println!("    AAAA: {:?}", info.aaaa);
      println!("    MX: {:?}", info.mx);
      println!("    NS: {:?}", info.ns);
    }
    None => println!("    Not available (lookup failed or skipped)."),
  }
}

pub fn print_human_readable(results: &Analysis) {
  println!("--- Analysis Results for: {} ---", results.target);

  print_geo_info(results.geo_info.as_ref());
  print_whois_info(results.whois_info.as_ref());
  print_dns_info(results.dns_info.as_ref());

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

pub fn print_json(results: &Analysis) -> Result<()> {
  serde_json::to_string_pretty(results)
    .map(|json_string| println!("{json_string}"))
    .context("Failed to serialize results to JSON")
}
