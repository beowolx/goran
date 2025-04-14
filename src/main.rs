#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::Result;

mod app;
mod cli;
mod geo;
mod results;
mod steps;
mod whois;

#[tokio::main]
async fn main() -> Result<()> {
  let mut app = app::App::new()?;

  app.run().await
}
