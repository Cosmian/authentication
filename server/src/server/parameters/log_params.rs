/// Console logging configuration.
///
/// Controls the verbosity of stdout logs. The `level` field sets the
/// default log filter applied at startup. It can be overridden at
/// runtime by setting the `RUST_LOG` environment variable.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LogConfig {
    /// The minimum log level emitted to stdout.
    ///
    /// Accepted values (in increasing verbosity):
    /// `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`.
    ///
    /// The string is passed directly as the `RUST_LOG` directive, so
    /// target-qualified filters like `"info,auth_verifier=debug"` are
    /// also supported.
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}
