use std::{
  collections::{HashMap, HashSet},
  sync::LazyLock,
};

use futures::stream::{FuturesUnordered, StreamExt};
use memchr::memchr;
use regex::Regex;
use thiserror::Error;
use whois_rust::{WhoIs, WhoIsLookupOptions, WhoIsServerValue};

static DEFAULT_SERVERS_JSON: &str = include_str!("../config/servers.json");

const IGNORE_PREFIXES: [&str; 4] = ["%", ">>>", "NOTE:", "Registrar URL:"];

static RE_REDACTED: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"(?i)REDACTED\s+FOR\s+PRIVACY").unwrap());

/// AFNIC (.fr) contact-block helpers
static RE_HOLDER_C: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"(?i)^(holder-c|registrant-c):\s*(.+)$").unwrap()
});
static RE_NICHDL: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"(?i)^nic-hdl:\s*(.+)$").unwrap());
static RE_CB_CONTACT: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"(?i)^\s*contact:\s*(.+)$").unwrap());
static RE_CB_COUNTRY: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"(?i)^\s*country:\s*(.+)$").unwrap());

/// Referral header
static RE_REFERRAL: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(
        r"(?i)(ReferralServer|Registrar WHOIS Server|Whois Server):\s*(?:r?whois://)?([^\s\r\n]+)",
    )
    .unwrap()
});

static WHOIS_CLIENT: LazyLock<WhoIs> = LazyLock::new(|| {
  WhoIs::from_string(DEFAULT_SERVERS_JSON).expect("init whois client")
});

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct Info {
  pub domain_name: Option<String>,
  pub registrar: Option<String>,
  pub creation_date: Option<String>,
  pub updated_date: Option<String>,
  pub expiry_date: Option<String>,
  #[serde(default)]
  pub name_servers: Vec<String>,
  #[serde(default)]
  pub domain_status: Vec<String>,
  pub registrant_organization: Option<String>,
  pub registrant_country: Option<String>,
}

impl Info {
  pub fn merge_missing(&mut self, other: Self) {
    macro_rules! maybe {
      ($field:ident) => {
        if self.$field.is_none() {
          self.$field = other.$field;
        }
      };
    }
    maybe!(domain_name);
    maybe!(registrar);
    maybe!(creation_date);
    maybe!(updated_date);
    maybe!(expiry_date);
    maybe!(registrant_organization);
    maybe!(registrant_country);

    if self.name_servers.is_empty() {
      self.name_servers = other.name_servers;
    }
    if self.domain_status.is_empty() {
      self.domain_status = other.domain_status;
    }
  }

  #[inline]
  #[must_use]
  pub fn ok(&self) -> bool {
    self.domain_name.is_some()
      || self.registrar.is_some()
      || self.creation_date.is_some()
      || self.expiry_date.is_some()
      || !self.name_servers.is_empty()
      || self.registrant_organization.is_some()
      || self.registrant_country.is_some()
  }
}

#[derive(Debug, Error)]
pub enum Error {
  #[error("whois operation failed: {0}")]
  WhoIs(#[from] whois_rust::WhoIsError),
  #[error("WHOIS response contained no useful fields")]
  NoUsefulFields,
}

#[derive(Default)]
struct ParseCtx {
  info: Info,
  ns: HashSet<String>,
  status: HashSet<String>,
  contacts: HashMap<String, (Option<String>, Option<String>)>,
  current_hdl: Option<String>,
  holder_hdl: Option<String>,
}

impl ParseCtx {
  fn process_line(&mut self, line: &str) {
    let trimmed = line.trim();
    if trimmed.is_empty()
      || ignored_prefix(trimmed)
      || RE_REDACTED.is_match(trimmed)
    {
      return;
    }

    if self.handle_afnic_contact_block(trimmed) {
      return;
    }

    if let Some(idx) = memchr(b':', trimmed.as_bytes()) {
      let (raw_key, raw_val) = trimmed.split_at(idx);
      let key_lc = raw_key.trim().to_ascii_lowercase();
      let val = raw_val[1..].trim(); // skip ':'

      match key_lc.as_str() {
        "domain name" | "domain" => {
          self
            .info
            .domain_name
            .get_or_insert_with(|| val.to_ascii_lowercase());
        }
        "registrar" | "sponsoring registrar" => {
          self.info.registrar.get_or_insert(val.to_string());
        }
        "creation date" | "registered on" | "created" => {
          self.info.creation_date.get_or_insert(val.to_string());
        }
        "updated date" | "changed" | "last-updated" => {
          self.info.updated_date.get_or_insert(val.to_string());
        }
        "registry expiry date" | "expiry date" | "expires on" | "paid-till" => {
          self.info.expiry_date.get_or_insert(val.to_string());
        }
        "name server" | "name servers" | "nserver" => {
          val.split_whitespace().for_each(|s| {
            self.ns.insert(s.to_ascii_lowercase());
          });
        }
        "domain status" | "status" => {
          let s = val
            .split_once(" https://")
            .map_or(val, |(left, _)| left)
            .trim();
          if !s.is_empty() {
            self.status.insert(s.to_string());
          }
        }
        "registrant organization" | "registrant name" | "org" => {
          self
            .info
            .registrant_organization
            .get_or_insert(val.to_string());
        }
        "registrant country" | "country" => {
          self.info.registrant_country.get_or_insert(val.to_string());
        }
        _ => {}
      }
    }
  }

  /// Handle the irregular "contact-block" used by AFNIC (.fr).
  fn handle_afnic_contact_block(&mut self, trimmed: &str) -> bool {
    if let Some(c) = RE_NICHDL.captures(trimmed) {
      let hdl = c[1].to_string();
      self.current_hdl = Some(hdl.clone());
      self.contacts.entry(hdl).or_insert((None, None));
      return true;
    }

    if let Some(hdl) = &self.current_hdl {
      if trimmed.is_empty() {
        self.current_hdl = None;
        return true;
      }
      if let Some(c) = RE_CB_CONTACT.captures(trimmed) {
        self.contacts.entry(hdl.clone()).and_modify(|v| {
          v.0.get_or_insert(c[1].trim().to_string());
        });
        return true;
      }
      if let Some(c) = RE_CB_COUNTRY.captures(trimmed) {
        self.contacts.entry(hdl.clone()).and_modify(|v| {
          v.1.get_or_insert(c[1].trim().to_string());
        });
        return true;
      }
    }

    if self.holder_hdl.is_none() {
      if let Some(c) = RE_HOLDER_C.captures(trimmed) {
        self.holder_hdl = Some(c[2].to_string());
        return true;
      }
    }
    false
  }

  fn finalize(mut self) -> Info {
    // Merge contact-block data
    if let Some(hdl) = self.holder_hdl {
      if let Some((org, ctry)) = self.contacts.remove(&hdl) {
        if self.info.registrant_organization.is_none() {
          self.info.registrant_organization = org;
        }
        if self.info.registrant_country.is_none() {
          self.info.registrant_country = ctry;
        }
      }
    }

    self.info.name_servers = self.ns.into_iter().collect();
    self.info.name_servers.sort_unstable();

    self.info.domain_status = self.status.into_iter().collect();
    self.info.domain_status.sort_unstable();

    self.info
  }
}

/// Fast check for ignorable line prefixes (case-insensitive)
#[inline]
fn ignored_prefix(line: &str) -> bool {
  IGNORE_PREFIXES
    .iter()
    .any(|p| line.len() >= p.len() && line[..p.len()].eq_ignore_ascii_case(p))
}

#[must_use]
pub fn parse(raw: &str) -> Info {
  let mut ctx = ParseCtx::default();
  for line in raw.lines() {
    ctx.process_line(line);
  }
  ctx.finalize()
}

/// Extract referral hosts from a WHOIS record.
fn referrals(raw: &str) -> Vec<String> {
  RE_REFERRAL
    .captures_iter(raw)
    .map(|c| c[2].trim().to_string())
    .collect()
}

async fn primary_fetch(
  whois: &WhoIs,
  domain: &str,
) -> Result<(Info, Vec<String>), Error> {
  let mut opts = WhoIsLookupOptions::from_string(domain)?;
  opts.follow = 1;
  let raw = whois.lookup_async(opts).await?;
  Ok((parse(&raw), referrals(&raw)))
}

/// Fetch WHOIS (possibly following referrals) for a domain.
///
/// # Errors
///
/// Returns an error if parsing WHOIS servers fails, lookup fails,
/// or if the response contains no relevant information.
pub async fn fetch_whois_info(target: &str) -> Result<Info, Error> {
  const MAX_REFERRALS: usize = 5;
  const MAX_FALLBACKS: usize = 10;

  let whois = &*WHOIS_CLIENT;
  let mut domain = target.trim_end_matches('.').to_ascii_lowercase();
  let mut attempts = 0;

  loop {
    // 1) initial query
    let (mut info, refs) = primary_fetch(whois, &domain).await?;

    // 2) if key registrant fields are missing, probe referrals concurrently
    if (info.registrant_organization.is_none()
      || info.registrant_country.is_none())
      && !refs.is_empty()
    {
      let mut visited = HashSet::with_capacity(refs.len());
      let mut tasks = FuturesUnordered::new();

      for h in refs.into_iter().take(MAX_REFERRALS) {
        if visited.insert(h.clone()) {
          let mut o = WhoIsLookupOptions::from_string(&domain)?;
          o.server = WhoIsServerValue::from_string(&h).ok();
          o.follow = 0;
          let w = whois.clone();
          tasks.push(
            async move { w.lookup_async(o).await.ok().map(|s| parse(&s)) },
          );
        }
      }

      while let Some(Some(extra)) = tasks.next().await {
        info.merge_missing(extra);
        if info.registrant_organization.is_some()
          && info.registrant_country.is_some()
        {
          break;
        }
      }
    }

    if info.ok() {
      return Ok(info);
    }

    // Strip the left-most label and try again (up to MAX_FALLBACKS)
    if attempts < MAX_FALLBACKS {
      if let Some(idx) = domain.find('.') {
        domain = domain[idx + 1..].to_string();
        attempts += 1;
        continue;
      }
    }

    return Err(Error::NoUsefulFields);
  }
}
