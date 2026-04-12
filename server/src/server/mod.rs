mod auth_server;
pub use auth_server::start_auth_server;

pub mod endpoints;

pub mod parameters;

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
}
