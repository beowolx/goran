use crate::providers::whois::Info;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RdapResponse {
  #[serde(default)]
  ldh_name: Option<String>,
  #[serde(default)]
  nameservers: Vec<NameServer>,
  #[serde(default)]
  status: Vec<String>,
  #[serde(default)]
  events: Vec<Event>,
  #[serde(default)]
  entities: Vec<Entity>,
  #[serde(default)]
  links: Vec<Link>,
  #[serde(flatten)]
  _extra: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NameServer {
  ldh_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
  event_action: String,
  event_date: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entity {
  #[serde(default)]
  roles: Vec<String>,
  handle: Option<String>,
  #[serde(rename = "vcardArray")]
  vcard_array: Option<Value>,
  #[serde(flatten)]
  _extra: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct Link {
  rel: String,
  href: String,
}

fn entity_by_role<'a>(
  entities: &'a [Entity],
  role: &str,
) -> Option<&'a Entity> {
  entities
    .iter()
    .find(|e| e.roles.iter().any(|r| r.eq_ignore_ascii_case(role)))
}

fn vcard_text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
  v.get(1)?
    .as_array()?
    .iter()
    .filter_map(|prop| prop.as_array())
    .find(|prop| {
      prop
        .first()
        .and_then(|v| v.as_str())
        .map_or(false, |s| s == key)
        && prop
          .get(2)
          .and_then(|v| v.as_str())
          .map_or(false, |s| s == "text")
    })
    .and_then(|prop| prop.get(3)?.as_str())
}

fn org_country(v: &Value) -> (Option<String>, Option<String>) {
  let mut org = None;
  let mut country = None;

  for prop in v.get(1).and_then(Value::as_array).into_iter().flatten() {
    let p = match prop.as_array() {
      Some(p) if p.len() >= 4 => p,
      _ => continue,
    };

    let key = p[0].as_str().unwrap_or_default();
    let val = &p[3];

    match key {
      "org" if org.is_none() => org = val.as_str().map(ToOwned::to_owned),
      "country-name" if country.is_none() => {
        country = val.as_str().map(ToOwned::to_owned);
      }
      "adr" if country.is_none() => match val {
        Value::Array(a) => {
          country = a
            .iter()
            .rev()
            .filter_map(Value::as_str)
            .find(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        }
        Value::String(s) => {
          country = s
            .split(&[',', '\n'][..])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .last()
            .map(ToOwned::to_owned);
        }
        _ => {}
      },
      _ => {}
    }

    if org.is_some() && country.is_some() {
      break;
    }
  }

  (org, country)
}

/// Fetches RDAP information for a domain.
///
/// # Arguments
///
/// * `target` - The domain to query
/// * `client` - The HTTP client to use for requests
///
/// # Returns
///
/// Domain information parsed from RDAP response
///
/// # Errors
///
/// Returns an error if:
/// * RDAP request to registry fails
/// * Registry RDAP returns non-2xx status
/// * Failed to deserialize registry RDAP JSON
pub async fn fetch_rdap_info(
  target: impl AsRef<str> + Send,
  client: &Client,
) -> Result<Info> {
  // 1) Registry (rdap.org) query
  let registry: RdapResponse = client
    .get(format!("https://rdap.org/domain/{}", target.as_ref()))
    .send()
    .await
    .context("RDAP request to registry failed")?
    .error_for_status()
    .context("Registry RDAP returned non-2xx status")?
    .json()
    .await
    .context("Failed to deserialize registry RDAP JSON")?;

  // 2) Cheap registrar name
  let registrar_name = entity_by_role(&registry.entities, "registrar")
    .and_then(|e| {
      e.vcard_array
        .as_ref()
        .and_then(|v| vcard_text(v, "fn"))
        .or(e.handle.as_deref())
    })
    .map(ToOwned::to_owned);

  // 3) Do we need a second hop?
  let registrant_missing = entity_by_role(&registry.entities, "registrant")
    .and_then(|e| e.vcard_array.as_ref())
    .and_then(|v| vcard_text(v, "fn"))
    .map_or(true, |s| s.trim().is_empty());

  let effective = if registrant_missing {
    let related_url = registry
      .links
      .iter()
      .find(|l| l.rel.eq_ignore_ascii_case("related"))
      .map(|l| l.href.as_str());

    if let Some(url) = related_url {
      match client.get(url).send().await {
        Ok(response) => match response.error_for_status() {
          Ok(response) => (response.json::<RdapResponse>().await)
            .map_or(registry, |rdap| rdap),
          Err(_) => registry,
        },
        Err(_) => registry,
      }
    } else {
      registry
    }
  } else {
    registry
  };

  // 4) Map into neutral Info
  let mut info = Info {
    registrar: registrar_name,
    domain_name: effective.ldh_name.map(|n| n.to_lowercase()),
    domain_status: effective.status.clone(),
    ..Info::default()
  };

  info.name_servers = effective
    .nameservers
    .iter()
    .map(|ns| ns.ldh_name.to_lowercase())
    .collect();

  for ev in &effective.events {
    match ev.event_action.as_str() {
      "registration" if info.creation_date.is_none() => {
        info.creation_date = Some(ev.event_date.clone());
      }
      "last changed" | "last updated" if info.updated_date.is_none() => {
        info.updated_date = Some(ev.event_date.clone());
      }
      "expiration" if info.expiry_date.is_none() => {
        info.expiry_date = Some(ev.event_date.clone());
      }
      _ => {}
    }
  }

  if let Some(registrant) = entity_by_role(&effective.entities, "registrant") {
    if let Some(vcard) = &registrant.vcard_array {
      let (org, country) = org_country(vcard);
      info.registrant_organization = org;
      info.registrant_country = country;
    }
  }

  Ok(info)
}
