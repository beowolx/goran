//! IP geolocation service using ip-api.com.

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;

/// Geolocation data from ip-api.com
///
/// Fields are based on the `ip-api.com` JSON response structure.
/// Some fields are optional as they might not always be provided by the API.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Info {
  /// Request status ("success" or "fail")
  pub status: String,

  /// Failure message (if status is "fail")
  pub message: Option<String>,

  /// Resolved IP address
  pub query: String,

  /// Country name
  pub country: Option<String>,

  /// City name
  pub city: Option<String>,

  /// Region/State name
  pub region_name: Option<String>,

  /// Internet Service Provider
  pub isp: Option<String>,
}

/// Fetches geolocation for an IP address or domain.
///
/// # Arguments
/// * `target` - IP address or domain
/// * `http_client` - HTTP client for the request
///
/// # Errors
/// - Failed HTTP request
/// - Non-success status code
/// - Deserialization error
/// - API failure response
///
/// # Example
/// ```ignore
/// use goran::providers::geo;
/// let client = reqwest::Client::new();
/// let geo = geo::fetch_geo_info("8.8.8.8", &client).await?;
/// ```
pub async fn fetch_geo_info(
  target: &str,
  http_client: &Client,
) -> Result<Info> {
  let url = format!("http://ip-api.com/json/{target}");

  let response = http_client
    .get(&url)
    .send()
    .await
    .with_context(|| format!("Failed to send request to {url}"))?;

  if !response.status().is_success() {
    bail!(
      "Geolocation API request failed with status: {}",
      response.status()
    );
  }

  let geo_info = response
    .json::<Info>()
    .await
    .with_context(|| "Failed to deserialize Geolocation API response")?;

  if geo_info.status != "success" {
    let error_message = geo_info
      .message
      .unwrap_or_else(|| "Unknown API error".to_string());
    bail!("Geolocation API indicated failure: {error_message}");
  }

  Ok(geo_info)
}
