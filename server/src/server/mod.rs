mod auth_verifier;
mod dev_seed;
pub use auth_verifier::start_auth_verifier;

pub mod endpoints;

pub mod parameters;

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}
