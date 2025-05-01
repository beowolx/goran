use anyhow::{anyhow, Result};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct LastAnalysisStats {
  pub harmless: u32,
  pub malicious: u32,
  pub suspicious: u32,
  pub undetected: u32,
  pub timeout: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Attributes {
  #[serde(rename = "last_analysis_stats")]
  pub stats: LastAnalysisStats,
  /// Overall VT reputation score (-100…100, >0 means "good")
  pub reputation: Option<i32>,
  /// VT crowdsourced categories
  pub categories: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct ApiResponse {
  data: Data,
}

#[derive(Debug, Deserialize, Clone)]
struct Data {
  attributes: Attributes,
}

#[derive(Debug, Serialize, Clone)]
pub struct Info {
  pub stats: LastAnalysisStats,
  pub reputation: Option<i32>,
  pub categories: Vec<String>,
}

/// Fetches information about a target (IP address or domain) from the `VirusTotal` API.
///
/// This function determines if the target is an IP or domain, constructs the appropriate
/// `VirusTotal` API endpoint, sends a GET request with the provided API key, and parses
/// the response to extract relevant information.
///
/// # Arguments
///
/// * `target` - The IP address or domain name to query `VirusTotal` for.
/// * `api_key` - The `VirusTotal` API key.
/// * `client` - A `reqwest::Client` instance to use for the HTTP request.
///
/// # Errors
///
/// This function can return an error in several cases:
/// - If the HTTP request to the `VirusTotal` API fails (e.g., network issues).
/// - If the `VirusTotal` API returns an HTTP error status code (e.g., invalid API key, rate limits).
/// - If the response from the `VirusTotal` API is not valid JSON or cannot be deserialized into the expected structure.
pub async fn fetch_vt_info(
  target: &str,
  api_key: &str,
  client: &Client,
) -> Result<Info> {
  let endpoint = if target.parse::<IpAddr>().is_ok() {
    format!("https://www.virustotal.com/api/v3/ip_addresses/{target}")
  } else {
    format!("https://www.virustotal.com/api/v3/domains/{target}")
  };

  let resp: ApiResponse = client
    .get(endpoint)
    .header(header::ACCEPT, "application/json")
    .header("x-apikey", api_key)
    .send()
    .await?
    .error_for_status()?
    .json()
    .await
    .map_err(|e| anyhow!("Invalid VT JSON: {e}"))?;

  let attrs = resp.data.attributes;
  let categories = attrs.categories.unwrap_or_default().into_values().collect();

  Ok(Info {
    stats: attrs.stats,
    reputation: attrs.reputation,
    categories,
  })
}
