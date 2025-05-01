use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rustls::{
  pki_types::{IpAddr as RustlsIpAddr, ServerName},
  ClientConfig, ProtocolVersion, RootCertStore,
};
use rustls_native_certs::load_native_certs;
use serde::Serialize;
use std::{
  net::{IpAddr, ToSocketAddrs},
  str::FromStr,
  sync::Arc,
  time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use x509_parser::{extensions::GeneralName, prelude::*};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Clone)]
pub struct Info {
  pub issuer: String,
  pub subject: String,
  pub not_before: String,
  pub not_after: String,
  pub dns_names: Vec<String>,
  pub tls_version: String,
}

/// Fetches SSL/TLS certificate information for a given target host or IP address.
///
/// This function performs the following steps:
/// 1. Establishes a TCP connection to `<target>:443`.
/// 2. Performs a TLS handshake (v1.2 or v1.3) using the operating system's
///    native root certificate store to validate the server certificate.
/// 3. Parses the server's end-entity certificate to extract relevant details.
/// 4. Extracts the negotiated TLS protocol version.
///
/// # Arguments
///
/// * `target` - A string slice representing the hostname (e.g., "example.com")
///              or IP address (e.g., "1.1.1.1") to connect to.
///
/// # Returns
///
/// A `Result` containing an `Info` struct with the certificate details on success,
/// or an `anyhow::Error` on failure.
///
/// # Errors
///
/// This function can return an error in several cases, including but not limited to:
/// - DNS resolution failure for the target host.
/// - TCP connection failure or timeout.
/// - TLS handshake failure or timeout.
/// - The server provides no certificates or an empty certificate chain.
/// - Failure to parse the server's certificate.
/// - Invalid certificate validity timestamps.
/// - Issues loading the native certificate store (though some errors might be suppressed).
pub async fn fetch_ssl_info(target: &str) -> Result<Info> {
  let mut root_store = RootCertStore::empty();
  for cert in load_native_certs().expect("could not load platform certs") {
    if let Err(e) = root_store.add(cert) {
      eprintln!("Warning: Failed to add native certificate: {e}");
    }
  }

  let tls_config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();
  let connector = TlsConnector::from(Arc::new(tls_config));

  let addr = format!("{target}:443")
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| anyhow::anyhow!("could not resolve `{target}`"))?;
  let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
    .await
    .context("TCP connect timed out")??;

  let server_name = match IpAddr::from_str(target) {
    Ok(ip) => ServerName::IpAddress(RustlsIpAddr::from(ip)),
    Err(_) => ServerName::try_from(target.to_string())?,
  };
  let tls_stream = timeout(
    HANDSHAKE_TIMEOUT,
    connector.connect(server_name.to_owned(), tcp),
  )
  .await
  .context("TLS handshake timed out")??;
  let session = &tls_stream.get_ref().1;

  let tls_version = session
    .protocol_version()
    .map_or("unknown", |v| match v {
      ProtocolVersion::TLSv1_3 => "TLS 1.3",
      ProtocolVersion::TLSv1_2 => "TLS 1.2",
      _ => "unknown",
    })
    .to_string();

  let chain = session
    .peer_certificates()
    .ok_or_else(|| anyhow::anyhow!("server returned no certificates"))?;
  let end_entity = chain
    .first()
    .ok_or_else(|| anyhow::anyhow!("certificate chain is empty"))?
    .as_ref();

  let (_, cert) = X509Certificate::from_der(end_entity)
    .context("parsing end-entity certificate")?;

  let issuer = cert
    .issuer()
    .iter_common_name()
    .next()
    .and_then(|cn| cn.as_str().ok())
    .map_or_else(|| cert.issuer().to_string(), std::borrow::ToOwned::to_owned);

  let subject = cert
    .subject()
    .iter_common_name()
    .next()
    .and_then(|cn| cn.as_str().ok())
    .map_or_else(
      || cert.subject().to_string(),
      std::borrow::ToOwned::to_owned,
    );

  let not_before: DateTime<Utc> =
    DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
      .ok_or_else(|| anyhow::anyhow!("invalid not_before timestamp"))?;
  let not_after: DateTime<Utc> =
    DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
      .ok_or_else(|| anyhow::anyhow!("invalid not_after timestamp"))?;

  let dns_names = cert
    .subject_alternative_name()
    .ok()
    .flatten()
    .map(|ext| {
      ext
        .value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
          GeneralName::DNSName(n) => Some((*n).to_owned()),
          _ => None,
        })
        .collect()
    })
    .unwrap_or_default();

  Ok(Info {
    issuer,
    subject,
    not_before: not_before.to_rfc2822(),
    not_after: not_after.to_rfc2822(),
    dns_names,
    tls_version,
  })
}
