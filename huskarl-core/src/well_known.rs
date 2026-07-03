//! Well-known URI path transformations.
//!
//! Two rules exist for deriving a well-known document URL from an identifier:
//! RFC 8414 §3.1 (and RFC 9728 §3.1, which specifies the same rule) *insert*
//! the well-known path between the host and the path and/or query components,
//! while the legacy `OpenID` Connect Discovery 1.0 §4 rule *appends* it after
//! the path.

use http::Uri;

/// Rebuilds `url` with the path produced by `build` from the current path.
/// Any terminating `/` is removed from the path first (RFC 8414 §3.1,
/// RFC 9728 §3.1); a query component is preserved.
fn with_transformed_path(url: Uri, build: impl FnOnce(&str) -> String) -> Result<Uri, http::Error> {
    let path = url.path();
    let cleaned_path = path.strip_suffix('/').unwrap_or(path);
    let mut new_path_and_query = build(cleaned_path);
    if let Some(query) = url.query() {
        new_path_and_query = format!("{new_path_and_query}?{query}");
    }
    let mut parts = url.into_parts();
    parts.path_and_query = Some(new_path_and_query.try_into()?);
    Ok(Uri::from_parts(parts)?)
}

/// Inserts `well_known_path` between the host and the path and/or query
/// components (RFC 8414 §3.1, RFC 9728 §3.1):
/// `https://example.com/x` → `https://example.com/.well-known/…/x`.
pub(crate) fn insert_well_known_path(url: Uri, well_known_path: &str) -> Result<Uri, http::Error> {
    with_transformed_path(url, |path| format!("{well_known_path}{path}"))
}

/// Appends `well_known_path` after the existing path (the legacy `OpenID`
/// Connect Discovery 1.0 §4 rule):
/// `https://example.com/x` → `https://example.com/x/.well-known/…`.
pub(crate) fn append_well_known_path(url: Uri, well_known_path: &str) -> Result<Uri, http::Error> {
    with_transformed_path(url, |path| format!("{path}{well_known_path}"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::no_path("https://example.com", "https://example.com/.well-known/x")]
    #[case::path_goes_after("https://example.com/a", "https://example.com/.well-known/x/a")]
    #[case::trailing_slash("https://example.com/a/", "https://example.com/.well-known/x/a")]
    #[case::query_preserved("https://example.com/a?q=1", "https://example.com/.well-known/x/a?q=1")]
    fn insert_puts_well_known_before_the_path(#[case] url: &str, #[case] expected: &str) {
        let url: Uri = url.parse().unwrap();
        assert_eq!(
            insert_well_known_path(url, "/.well-known/x")
                .unwrap()
                .to_string(),
            expected
        );
    }

    #[rstest]
    #[case::no_path("https://example.com", "https://example.com/.well-known/x")]
    #[case::path_goes_before("https://example.com/a", "https://example.com/a/.well-known/x")]
    #[case::trailing_slash("https://example.com/a/", "https://example.com/a/.well-known/x")]
    fn append_puts_well_known_after_the_path(#[case] url: &str, #[case] expected: &str) {
        let url: Uri = url.parse().unwrap();
        assert_eq!(
            append_well_known_path(url, "/.well-known/x")
                .unwrap()
                .to_string(),
            expected
        );
    }
}
