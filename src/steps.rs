use crate::{
  cli::Cli,
  providers::{dns, geo, rdap, whois},
};
use anyhow::Result;
use reqwest::Client;
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

/// Attempt an RDAP lookup, progressively stripping left-most labels until
/// either a response is obtained or we run out of labels (max 10 hops).
async fn rdap_recursive_lookup(target: &str) -> Option<whois::Info> {
  let mut candidate = target.trim_end_matches('.').to_lowercase();
  let mut hops = 0;

  loop {
    if hops > 10 {
      break;
    }
    if let Ok(info) = rdap::fetch_rdap_info(&candidate).await {
      return Some(info);
    }

    if let Some(idx) = candidate.find('.') {
      candidate = candidate[idx + 1..].to_string();
      hops += 1;
      continue;
    }
    break;
  }
  None
}

/// Fetches WHOIS (or RDAP) information if applicable.
pub async fn fetch_whois_step(
  target: &str,
  cli: &Cli,
) -> Result<Option<whois::Info>, String> {
  if cli.no_whois || std::net::IpAddr::from_str(target).is_ok() {
    return Ok(None);
  }

  match whois::fetch_whois_info(target).await {
    Ok(info) => Ok(Some(info)),
    Err(err) => {
      // fallback: try RDAP on the original target, then with label‑stripping
      (rdap_recursive_lookup(target).await).map_or_else(
        || Err(format!("WHOIS/RDAP lookup failed: {err}")),
        |info| Ok(Some(info)),
      )
    }
  }
}

pub async fn fetch_dns_step(
  target: &str,
  cli: &Cli,
) -> Result<Option<dns::Info>, String> {
  if cli.no_dns {
    return Ok(None);
  }
  dns::lookup(target)
    .await
    .map(Some)
    .map_err(|e| format!("DNS lookup failed: {e}"))
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
