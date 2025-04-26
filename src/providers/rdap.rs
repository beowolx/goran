use crate::providers::whois::Info;

use anyhow::{anyhow, Result};
use icann_rdap_client::prelude::*;
use icann_rdap_common::{
  prelude::Domain,
  response::{ObjectCommonFields, RdapResponse},
};
use serde_json::Value;
use std::str::FromStr;

fn find_entity_by_role<'a>(
  entities: &'a [icann_rdap_common::response::Entity],
  role: &str,
) -> Option<&'a icann_rdap_common::response::Entity> {
  entities
    .iter()
    .find(|e| e.roles().iter().any(|r| r.eq_ignore_ascii_case(role)))
}

fn vcard_text<'a>(v: &'a [Value], key: &str) -> Option<&'a str> {
  v.get(1)?
    .as_array()?
    .iter()
    .filter_map(|p| p.as_array())
    .find(|p| match (p.first(), p.get(2)) {
      (Some(k), Some(t)) => {
        k.as_str() == Some(key) && t.as_str() == Some("text")
      }
      _ => false,
    })
    .and_then(|p| p.get(3)?.as_str())
}

fn org_country(vcard: &[Value]) -> (Option<String>, Option<String>) {
  let mut org = None;
  let mut country = None;

  for p in vcard.get(1).and_then(Value::as_array).into_iter().flatten() {
    let arr = match p.as_array() {
      Some(a) if a.len() >= 4 => a,
      _ => continue,
    };

    match arr[0].as_str().unwrap_or_default() {
      "org" if org.is_none() => org = arr[3].as_str().map(str::to_owned),
      "country-name" if country.is_none() => {
        country = arr[3].as_str().map(str::to_owned);
      }
      "adr" if country.is_none() => match &arr[3] {
        Value::Array(a) => {
          country = a
            .iter()
            .rev()
            .filter_map(Value::as_str)
            .find(|s| !s.is_empty())
            .map(str::to_owned);
        }
        Value::String(s) => {
          country = s
            .split(&[',', '\n'][..])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .last()
            .map(str::to_owned);
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

/// Fetches RDAP information for the given domain or IP address.
///
/// # Errors
///
/// Returns an error if:
/// - The `target` is not a valid domain name or IP address.
/// - There is an issue creating the RDAP client.
/// - The RDAP request fails due to network issues or server errors.
/// - The RDAP response is not the expected domain information.
pub async fn fetch_rdap_info(target: &str) -> Result<Info> {
  // 1) build + send RDAP query via icann-rdap-client
  let query = QueryType::from_str(target)?;
  let client = create_client(&ClientConfig::default())?;
  let store = MemoryBootstrapStore::new();

  let resp = rdap_bootstrapped_request(&query, &client, &store, |_| {}).await?;

  // 2) ensure we really got a Domain object
  let domain: &Domain = match &resp.rdap {
    RdapResponse::Domain(d) => d,
    _ => return Err(anyhow!("RDAP response for {target} was not a domain")),
  };

  // 3) skeleton Info
  let mut info = Info {
    domain_name: domain.ldh_name().map(str::to_lowercase),
    domain_status: domain.status().clone(),
    ..Info::default()
  };

  // registrar
  info.registrar = domain
    .entities()
    .iter()
    .find(|e| {
      e.roles()
        .iter()
        .any(|r| r.eq_ignore_ascii_case("registrar"))
    })
    .and_then(|e| {
      e.vcard_array
        .as_ref()
        .and_then(|v| vcard_text(v, "fn"))
        .or_else(|| e.handle())
    })
    .map(str::to_owned);

  // nameservers
  info.name_servers = domain
    .nameservers()
    .iter()
    .filter_map(|ns| ns.ldh_name.as_deref())
    .map(str::to_lowercase)
    .collect();

  // events
  for ev in domain.events() {
    let action = ev.event_action().unwrap_or_default();
    let date = ev.event_date().unwrap_or_default();
    match action {
      "registration" if info.creation_date.is_none() => {
        info.creation_date = Some(date.to_owned());
      }
      "last changed" | "last updated" if info.updated_date.is_none() => {
        info.updated_date = Some(date.to_owned());
      }
      "expiration" if info.expiry_date.is_none() => {
        info.expiry_date = Some(date.to_owned());
      }
      _ => {}
    }
  }

  // registrant org / country (registry-level)
  if let Some(ent) = find_entity_by_role(domain.entities(), "registrant") {
    if let Some(v) = ent.vcard_array.as_ref() {
      let (org, country) = org_country(v);
      info.registrant_organization = org;
      info.registrant_country = country;
    }
  }

  // 4) fallback: follow registrar's "related" link if still blank
  if info.registrant_organization.is_none() || info.registrant_country.is_none()
  {
    if let Some(url) = domain
      .links()
      .iter()
      .find(|l| l.rel().map_or(false, |r| r.eq_ignore_ascii_case("related")))
      .and_then(|l| l.href())
    {
      let alt_resp = rdap_url_request(url, &client).await?;
      let alt: Domain = match alt_resp.rdap {
        RdapResponse::Domain(d) => *d,
        _ => {
          return Err(anyhow!(
            "RDAP response for related link {url} was not a domain"
          ))
        }
      };

      if let Some(ent) = find_entity_by_role(alt.entities(), "registrant") {
        if let Some(v) = ent.vcard_array.as_ref() {
          let (org, country) = org_country(v);

          if info.registrant_organization.is_none() {
            info.registrant_organization = org;
          }
          if info.registrant_country.is_none() {
            info.registrant_country = country;
          }
        }
      }
    }
  }

  Ok(info)
}
