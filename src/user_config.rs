use serde::{Deserialize, Serialize};

const APP_NAME: &str = "miru";
const FILE_NAME: Option<&str> = None;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct UserConfig {
  pub vt_api_key: Option<String>,
  pub gemini_api_key: Option<String>,
}

/// Read ~/.config/rs.miru/default-config.toml (or OS equivalent).
pub fn load() -> UserConfig {
  confy::load(APP_NAME, FILE_NAME).unwrap_or_default()
}

pub fn store(cfg: &UserConfig) -> anyhow::Result<()> {
  confy::store(APP_NAME, FILE_NAME, cfg).map_err(Into::into)
}
