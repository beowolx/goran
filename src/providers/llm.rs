use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct GeminiResponse {
  candidates: Vec<Candidate>,
}
#[derive(Deserialize)]
struct Candidate {
  content: Content,
}
#[derive(Deserialize)]
struct Content {
  parts: Vec<Part>,
}
#[derive(Deserialize)]
struct Part {
  text: Option<String>,
}

/// Generates a report using the Gemini AI model based on the provided analysis findings.
///
/// This function takes the analysis results, serializes them, combines them with a base prompt,
/// sends the combined text to the Gemini API, and returns the generated report text.
///
/// # Arguments
///
/// * `analysis` - A reference to the `Analysis` struct containing the findings to report on.
/// * `api_key` - The API key for accessing the Gemini API.
/// * `client` - A `reqwest::Client` instance to use for the HTTP request.
///
/// # Errors
///
/// This function can return an error in several cases:
/// - If the `analysis` data cannot be serialized to JSON.
/// - If the base prompt file (`src/config/prompt.txt`) cannot be read.
/// - If the HTTP request to the Gemini API fails (e.g., network issues).
/// - If the Gemini API returns an HTTP error status code.
/// - If the response from the Gemini API is not valid JSON or cannot be deserialized.
pub async fn generate_report(
  analysis: &crate::results::Analysis,
  api_key: &str,
  client: &Client,
) -> Result<String> {
  let summary_json = serde_json::to_value(analysis)?;

  let base_prompt_template = fs::read_to_string("src/config/prompt.txt")
    .context("Failed to read prompt file")?;
  let instruction = base_prompt_template
    .replace("__JSON_DATA_PLACEHOLDER__", &summary_json.to_string());

  let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    );
  let body = serde_json::json!({
      "contents": [{
          "parts": [{ "text": instruction }],
          "role": "user"
      }]
  });

  let resp = client
    .post(&url)
    .json(&body)
    .send()
    .await
    .context("Failed to call Gemini")?
    .error_for_status()
    .context("Gemini returned HTTP error")?;

  let resp_json: GeminiResponse = resp.json().await.context("Invalid JSON")?;
  let answer = resp_json
    .candidates
    .first()
    .and_then(|c| c.content.parts.first())
    .and_then(|p| p.text.as_ref())
    .cloned()
    .unwrap_or_else(|| "Gemini returned an empty response.".to_string());

  Ok(answer)
}
