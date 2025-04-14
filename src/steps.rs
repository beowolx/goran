use crate::{
  cli::Cli,
  providers::{geo, whois},
};
use anyhow::Result;
use reqwest::Client;
use std::net::IpAddr;
use std::str::FromStr;

/// Fetches Geolocation information.
pub async fn fetch_geo_step(
  target: &str,
  client: &Client,
) -> Result<geo::Info, String> {
  geo::fetch_geo_info(target, client)
    .await
    .map_err(|e| format!("Geolocation lookup failed: {e}"))
}

/// Fetches WHOIS information if applicable.
pub fn fetch_whois_step(
  target: &str,
  cli: &Cli,
  whois_available: bool,
) -> Result<Option<whois::Info>, String> {
  let is_ip_address = IpAddr::from_str(target).is_ok();

  // Early returns for skipped conditions
  if cli.no_whois {
    return Ok(None);
  }
  if is_ip_address {
    return Ok(None);
  }
  if !whois_available {
    return Ok(None);
  }

  match whois::fetch_whois_info(target) {
    Ok(info) => Ok(Some(info)),
    Err(e) => Err(format!("WHOIS lookup failed: {e}")),
  }
}

pub fn fetch_dns_step(cli: &Cli) -> Result<Option<()>, String> {
  if cli.no_dns {
    Ok(None)
  } else {
    Err("DNS lookup feature not yet implemented.".to_string())
  }
}

pub fn fetch_ssl_step(cli: &Cli) -> Result<Option<()>, String> {
  if cli.no_ssl {
    Ok(None)
  } else {
    Err("SSL certificate check feature not yet implemented.".to_string())
  }
}

pub fn fetch_vt_step(
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
