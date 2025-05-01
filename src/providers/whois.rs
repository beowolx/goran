use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use whois_rust::{WhoIs, WhoIsLookupOptions, WhoIsServerValue};

static DEFAULT_SERVERS_JSON: &str = include_str!("../config/servers.json");

static RE_DOMAIN_NAME: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:Domain Name|domain):\s*(.+)$").unwrap());
static RE_REGISTRAR: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Registrar|Sponsoring Registrar):\s*(.+)$").unwrap()
});
static RE_CREATION_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Creation Date|Registered on|created):\s*(.+)$").unwrap()
});
static RE_UPDATED_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Updated Date|Changed|last-updated):\s*(.+)$").unwrap()
});
static RE_EXPIRY_DATE: Lazy<Regex> = Lazy::new(|| {
  Regex::new(
    r"^(?:Registry Expiry Date|Expiry Date|Expires On|paid-till):\s*(.+)$",
  )
  .unwrap()
});
static RE_NAME_SERVER: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Name Server|nserver|Name Servers):\s*(.+)$").unwrap()
});
static RE_DOMAIN_STATUS: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:Domain Status|status):\s*(.+)$").unwrap());

static RE_REGISTRANT_ORG: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Registrant (?:Organization|Name)|org):\s*(.+)$").unwrap()
});
static RE_REGISTRANT_COUNTRY: Lazy<Regex> = Lazy::new(|| {
  Regex::new(r"^(?:Registrant Country|country):\s*(.+)$").unwrap()
});

/// AFNIC contact-block helpers
static RE_HOLDER_C: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:holder-c|registrant-c):\s*(.+)$").unwrap());
static RE_NICHDL: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^nic-hdl:\s*(.+)$").unwrap());
static RE_CB_CONTACT: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^\s*contact:\s*(.+)$").unwrap());
static RE_CB_COUNTRY: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^\s*country:\s*(.+)$").unwrap());

static RE_REDACTED: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"(?i)REDACTED FOR PRIVACY").unwrap());
static RE_IGNORE_PREFIXES: Lazy<Regex> =
  Lazy::new(|| Regex::new(r"^(?:%|>>>|NOTE:|Registrar URL:)").unwrap());

/// referral header
static RE_REFERRAL: Lazy<Regex> = Lazy::new(|| {
  Regex::new(
        r"(?:ReferralServer|Registrar WHOIS Server|Whois Server):[^\S\n]*(?:r?whois://)?([^\s\r\n]+)",
    )
    .unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    if self.domain_name.is_none() {
      self.domain_name = other.domain_name;
    }
    if self.registrar.is_none() {
      self.registrar = other.registrar;
    }
    if self.creation_date.is_none() {
      self.creation_date = other.creation_date;
    }
    if self.updated_date.is_none() {
      self.updated_date = other.updated_date;
    }
    if self.expiry_date.is_none() {
      self.expiry_date = other.expiry_date;
    }
    if self.name_servers.is_empty() {
      self.name_servers = other.name_servers;
    }
    if self.domain_status.is_empty() {
      self.domain_status = other.domain_status;
    }
    if self.registrant_organization.is_none() {
      self.registrant_organization = other.registrant_organization;
    }
    if self.registrant_country.is_none() {
      self.registrant_country = other.registrant_country;
    }
  }

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

/// Internal parsing state.
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
      || RE_IGNORE_PREFIXES.is_match(trimmed)
      || RE_REDACTED.is_match(trimmed)
    {
      return;
    }

    if self.handle_afnic_contact_block(trimmed) {
      return;
    }

    if self.maybe_set(&RE_DOMAIN_NAME, trimmed, |ctx, v| {
      ctx.info.domain_name = Some(v.to_lowercase());
    }) || self.maybe_set(&RE_REGISTRAR, trimmed, |ctx, v| {
      ctx.info.registrar = Some(v);
    }) || self.maybe_set(&RE_CREATION_DATE, trimmed, |ctx, v| {
      ctx.info.creation_date = Some(v);
    }) || self.maybe_set(&RE_UPDATED_DATE, trimmed, |ctx, v| {
      ctx.info.updated_date = Some(v);
    }) || self.maybe_set(&RE_EXPIRY_DATE, trimmed, |ctx, v| {
      ctx.info.expiry_date = Some(v);
    }) {
      return;
    }

    if let Some(c) = RE_NAME_SERVER.captures(trimmed) {
      c[1].split_whitespace().for_each(|s| {
        if !s.is_empty() {
          self.ns.insert(s.to_lowercase());
        }
      });
      return;
    }

    if let Some(c) = RE_DOMAIN_STATUS.captures(trimmed) {
      let s = c[1]
        .split_once(" https://")
        .map_or(&c[1], |(s, _)| s)
        .trim()
        .to_string();
      if !s.is_empty() {
        self.status.insert(s);
      }
      return;
    }

    let _ = self.maybe_set(&RE_REGISTRANT_ORG, trimmed, |ctx, v| {
      ctx.info.registrant_organization = Some(v);
    });
    let _ = self.maybe_set(&RE_REGISTRANT_COUNTRY, trimmed, |ctx, v| {
      ctx.info.registrant_country = Some(v);
    });
  }

  fn maybe_set<F>(&mut self, re: &Regex, line: &str, mut f: F) -> bool
  where
    F: FnMut(&mut Self, String),
  {
    re.captures(line).map_or(false, |caps| {
      f(self, caps[1].trim().to_string());
      true
    })
  }

  fn handle_afnic_contact_block(&mut self, trimmed: &str) -> bool {
    if let Some(caps) = RE_NICHDL.captures(trimmed) {
      self.current_hdl = Some(caps[1].to_string());
      self
        .contacts
        .entry(caps[1].to_string())
        .or_insert((None, None));
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
        self.holder_hdl = Some(c[1].to_string());
        return true;
      }
    }

    false
  }

  fn finalize(mut self) -> Info {
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

fn parse_whois(raw: &str) -> Info {
  let mut ctx = ParseCtx::default();
  raw.lines().for_each(|line| ctx.process_line(line));
  ctx.finalize()
}

/// Extract referral hosts from a WHOIS response.
fn referrals(raw: &str) -> Vec<String> {
  RE_REFERRAL
    .captures_iter(raw)
    .map(|caps| caps[1].trim_matches([' ', '\r', '\n'].as_ref()).to_string())
    .collect()
}

async fn fetch_single(whois: &WhoIs, domain: &str) -> Result<Info> {
  let mut opts = WhoIsLookupOptions::from_string(domain)?;
  opts.follow = 1;

  let raw = whois.lookup_async(opts.clone()).await?;
  let mut info = parse_whois(&raw);

  let mut q: VecDeque<String> = referrals(&raw).into();
  let mut visited = HashSet::new();

  while (info.registrant_organization.is_none()
    || info.registrant_country.is_none())
    && !q.is_empty()
    && visited.len() < 5
  {
    let h = q.pop_front().unwrap();
    if !visited.insert(h.clone()) {
      continue;
    }
    if let Ok(server) = WhoIsServerValue::from_string(&h) {
      let mut o = opts.clone();
      o.server = Some(server);
      o.follow = 0;
      if let Ok(r) = whois.lookup_async(o).await {
        let extra = parse_whois(&r);
        info.merge_missing(extra);
        for n in referrals(&r) {
          if !visited.contains(&n) {
            q.push_back(n);
          }
        }
      }
    }
  }

  if !info.ok() {
    bail!("WHOIS response contained no useful fields");
  }
  Ok(info)
}

/// Fetch WHOIS (possibly following referrals) for a domain.
///
/// # Errors
///
/// Returns an error if parsing WHOIS servers fails, lookup fails,
/// or if the response contains no relevant information.
pub async fn fetch_whois_info(target: &str) -> Result<Info> {
  let whois = WhoIs::from_string(DEFAULT_SERVERS_JSON)?;

  let mut candidate = target.trim_end_matches('.').to_lowercase();
  let mut attempts = 0;

  loop {
    match fetch_single(&whois, &candidate).await {
      Ok(i) => return Ok(i),
      Err(e) if attempts < 10 => {
        if let Some(idx) = candidate.find('.') {
          candidate = candidate[idx + 1..].to_string();
          attempts += 1;
          continue;
        }
        return Err(e);
      }
      Err(e) => return Err(e),
    }
  }
}
