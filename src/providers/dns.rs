use anyhow::Result;
use serde::Serialize;
use std::net::IpAddr;

use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

#[derive(Debug, Serialize)]
pub struct Info {
  pub a: Vec<IpAddr>,
  pub aaaa: Vec<IpAddr>,
  pub mx: Vec<String>,
  pub ns: Vec<String>,
}

/// Performs A, AAAA, MX, and NS DNS lookups for the given target domain.
///
/// # Arguments
///
/// * `target` - The domain name or hostname to perform DNS lookups for.
///
/// # Returns
///
/// A `Result` containing an `Info` struct with the resolved records on success,
/// or an `anyhow::Error` if any of the lookups fail.
///
/// # Errors
///
/// Returns an error if the DNS resolver cannot be built or if any of the underlying
/// DNS lookups (A, AAAA, MX, NS) fail.
pub async fn lookup(target: &str) -> Result<Info> {
  let resolver: TokioResolver = Resolver::builder_tokio()?.build();

  // A + AAAA
  let ips = resolver.lookup_ip(target).await?;
  let (mut a, mut aaaa) = (Vec::new(), Vec::new());
  for ip in ips {
    if ip.is_ipv4() {
      a.push(ip);
    } else {
      aaaa.push(ip);
    }
  }

  // MX
  let mx = resolver
    .mx_lookup(target)
    .await
    .map(|ans| ans.iter().map(|rec| rec.exchange().to_utf8()).collect())
    .unwrap_or_default();

  // NS
  let ns = resolver
    .lookup(target, RecordType::NS)
    .await
    .map(|ans| {
      ans
        .iter()
        .filter_map(|r| match r {
          RData::NS(name) => Some(name.to_string()),
          _ => None,
        })
        .collect()
    })
    .unwrap_or_default();

  Ok(Info { a, aaaa, mx, ns })
}
