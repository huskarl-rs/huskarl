pub mod api;
pub mod browser;
pub mod client_error;
pub mod config;
pub mod expectations;
pub mod flow;
pub mod report;
pub mod runner;

pub const CONFORMANCE_SUITE_BASE: &str = "https://localhost.emobix.co.uk:8443";

pub fn client_id() -> String {
    std::env::var("CONFORMANCE_CLIENT_ID").unwrap_or_else(|_| "client".to_string())
}

pub fn assert_no_failures(failures: Vec<String>) {
    if !failures.is_empty() {
        panic!(
            "{} module(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
