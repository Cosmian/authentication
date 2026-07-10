//! Auth Authentication Server binary entry point.
//!
//! Loads server parameters from a TOML configuration file and starts the server.
//!
//! # Usage
//!
//! ```text
//! # Using the default config file (./auth_verifier.toml in the working directory):
//! auth_verifier
//!
//! # Specifying a custom config file path:
//! auth_verifier /path/to/my-config.toml
//! ```

use auth_verifier::{ServerParams, start_auth_verifier};
use cosmian_logger::info;
use std::{path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cosmian_logger::log_init(None);

    // The first positional argument is the config file path.
    // Default: auth_verifier.toml in the current working directory.
    let config_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("auth_verifier.toml"));

    info!(
        "Loading Auth Authentication Server configuration from: {}",
        config_path.display()
    );

    let config_content = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "Failed to read configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let server_params: ServerParams = toml::from_str(&config_content).map_err(|e| {
        format!(
            "Failed to parse configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    info!("Configuration loaded successfully");

    start_auth_verifier(Arc::new(server_params), None)
        .await
        .map_err(|e| format!("Authentication server error: {e}").into())
}
