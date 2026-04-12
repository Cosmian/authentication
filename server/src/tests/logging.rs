use cosmian_logger::{TracingConfig, tracing_init};
use std::sync::Once;

/// Initialize tracing/logging once for the entire test process.
/// Prevents panics like: "Tracing already initialized or crashed" when tests
/// or multiple crates call `cosmian_logger::log_init` concurrently.
static INIT_LOGGING: Once = Once::new();

pub fn init_test_logging(rust_log: Option<&str>) {
    INIT_LOGGING.call_once(|| {
        log_test(rust_log.or(option_env!("RUST_LOG")));
    });
}

fn log_test(rust_log: Option<&str>) {
    let config = TracingConfig {
        service_name: String::new(),
        no_log_to_stdout: false,
        log_to_file: None,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: false,
        rust_log: rust_log
            .or(option_env!("RUST_LOG"))
            .map(std::borrow::ToOwned::to_owned),
        with_ansi_colors: true,
        otlp: None,
    };
    tracing_init(&config);
}
