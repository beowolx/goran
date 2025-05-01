#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::Result;

mod app;
mod cli;
pub mod providers;
mod results;
mod steps;
mod user_config;

/// Runs the main application logic.
///
/// This function parses command-line arguments, initializes the application state,
/// executes the requested analysis steps (like Geolocation, WHOIS), and prints
/// the results.
///
/// # Errors
///
/// Returns an error if initialization fails (e.g., building the HTTP client) or
/// if printing the final results in JSON format fails.
pub async fn run() -> Result<()> {
  let mut app = app::App::new()?;

  app.run().await
}
