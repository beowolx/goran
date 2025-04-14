#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::Result;

// Declare library modules
mod app;
mod cli;
pub mod providers; // Make the providers module public
mod results;
mod steps;
// pub mod geo; // Removed
// pub mod whois; // Removed

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
  // Initialize the application state (App::new uses cli::Cli internally)
  let mut app = app::App::new()?;

  // Run the analysis (App::run calls steps, uses results internally)
  app.run().await
}
