#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::Result;
use miru::run;

#[tokio::main]
async fn main() -> Result<()> {
  // Install the default crypto provider for rustls
  let _ = rustls::crypto::ring::default_provider().install_default();

  run().await
}
