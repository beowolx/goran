use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rustls::{
  pki_types::{IpAddr as RustlsIpAddr, ServerName},
  ClientConfig, ProtocolVersion, RootCertStore,
};
use serde::Serialize;
use std::{
  net::{IpAddr, ToSocketAddrs},
  str::FromStr,
  sync::{Arc, OnceLock},
  time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use x509_parser::{extensions::GeneralName, prelude::*};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

static TLS_CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();

/// Build or return the cached `TlsConnector`.
fn tls_connector() -> &'static TlsConnector {
  TLS_CONNECTOR.get_or_init(|| {
    // Build the root store from the embedded Mozilla bundle.
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = ClientConfig::builder()
      .with_root_certificates(root_store)
      .with_no_client_auth();

    TlsConnector::from(Arc::new(tls_config))
  })
}

#[derive(Debug, Serialize, Clone)]
pub struct Info {
  pub issuer: String,
  pub subject: String,
  pub not_before: String,
  pub not_after: String,
  pub dns_names: Vec<String>,
  pub tls_version: String,
}

/// Fetches SSL/TLS certificate information for a given host or IP address.
///
/// This function attempts to establish a TLS connection to the target on port 443.
/// It performs a TCP connect, followed by a TLS handshake using a cached `TlsConnector`
/// configured with Mozilla's root certificates.
///
/// If successful, it parses the server's end-entity certificate to extract details
/// like issuer, subject, validity period, Subject Alternative Names (SANs), and the
/// negotiated TLS protocol version.
///
/// # Arguments
///
/// * `target` - A string slice representing the hostname or IP address to connect to.
///
/// # Returns
///
/// A `Result` containing an `Info` struct with the certificate details and TLS version,
/// or an `anyhow::Error` if any step fails.
///
/// # Errors
///
/// This function can fail in several ways:
///
/// *   **DNS Resolution:** If the `target` cannot be resolved to a socket address.
/// *   **TCP Connection:** If the TCP connection to `target:443` fails or times out (`CONNECT_TIMEOUT`).
/// *   **TLS Handshake:** If the TLS handshake fails or times out (`HANDSHAKE_TIMEOUT`).
/// *   **Invalid Server Name:** If the `target` is not a valid DNS name or IP address for Server Name Indication (SNI).
/// *   **Missing Certificates:** If the server does not provide any certificates during the handshake.
/// *   **Certificate Parsing:** If the server's end-entity certificate cannot be parsed (e.g., invalid DER format).
/// *   **Invalid Timestamps:** If the certificate's `notBefore` or `notAfter` fields contain invalid timestamp values.
/// *   **Underlying IO errors:** Propagated errors from the network operations.
pub async fn fetch_ssl_info(target: &str) -> Result<Info> {
  // 1. TCP connect
  let addr = format!("{target}:443")
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| anyhow::anyhow!("could not resolve `{target}`"))?;

  let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
    .await
    .context("TCP connect timed out")??;

  // 2. TLS handshake
  let server_name = match IpAddr::from_str(target) {
    Ok(ip) => ServerName::IpAddress(RustlsIpAddr::from(ip)),
    Err(_) => ServerName::try_from(target.to_string())?,
  };

  let tls_stream = timeout(
    HANDSHAKE_TIMEOUT,
    tls_connector().connect(server_name.clone(), tcp),
  )
  .await
  .context("TLS handshake timed out")??;

  let session = &tls_stream.get_ref().1;

  // 3. Protocol version
  let tls_version = session
    .protocol_version()
    .map_or("unknown", |v| match v {
      ProtocolVersion::TLSv1_3 => "TLS 1.3",
      ProtocolVersion::TLSv1_2 => "TLS 1.2",
      _ => "unknown",
    })
    .to_string();

  // 4. Certificate parsing
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
    .map_or_else(|| cert.issuer().to_string(), str::to_owned);

  let subject = cert
    .subject()
    .iter_common_name()
    .next()
    .and_then(|cn| cn.as_str().ok())
    .map_or_else(|| cert.subject().to_string(), str::to_owned);

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
