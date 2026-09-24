//! RFC 3986 §6.2.2/§6.2.3 normalization for server-side `DPoP` binding.

use http::Uri;

pub(super) fn htu_matches(htu: &str, request: &Uri) -> bool {
    // RFC 9449 §4.2 forbids query and fragment components in the claim.
    // Check before parsing: `http::Uri` can discard a fragment.
    if htu.contains(['?', '#']) {
        return false;
    }
    let Some(proof) = normalize(htu) else {
        return false;
    };
    normalize(&request.to_string()).is_some_and(|request| proof == request)
}

fn normalize(value: &str) -> Option<String> {
    // Query and fragment are outside the DPoP target comparison. Claims
    // containing them have already been rejected by `htu_matches`.
    let target = value.split(['?', '#']).next()?;
    let uri = fluent_uri::Uri::parse(target).ok()?;
    let authority = uri.authority()?;
    if authority.host().is_empty() {
        return None;
    }
    // RFC 3986 permits arbitrary digit strings as ports; HTTP ports must
    // fit in u16. Do not let normalization hide an invalid port.
    authority.port_to_u16().ok()?;

    let normalized = uri.normalize();
    let empty_path = normalized.path().is_empty();
    let mut target = normalized.into_string();
    // fluent-uri handles syntax and default ports, but deliberately leaves
    // empty-path equivalence to the application (upstream issue #27).
    if empty_path {
        target.push('/');
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_targets_match_in_both_directions() {
        for (a, b) in [
            (
                "HTTPS://EXAMPLE.COM/resource",
                "https://example.com/resource",
            ),
            ("https://example.com:443/a", "https://example.com/a"),
            ("http://example.com:80", "http://example.com/"),
            ("http://example.com:/", "http://example.com/"),
            ("https://example.com", "https://example.com/"),
            (
                "https://example.com/%7e%61%2D%5f",
                "https://example.com/~a-_",
            ),
            ("https://example.com/%2f%3a", "https://example.com/%2F%3A"),
            ("https://example.com/a/./b/../c", "https://example.com/a/c"),
            ("https://example.com/a/%2e%2e/c", "https://example.com/c"),
            ("https://example.com/../../a", "https://example.com/a"),
            ("https://example.com/a/.", "https://example.com/a/"),
            ("https://example.com/a/b/..", "https://example.com/a/"),
            ("https://example.com/a//../b", "https://example.com/a/b"),
            ("https://[2001:DB8::1]:443/a", "https://[2001:db8::1]/a"),
            (
                "https://[2001:db8:0:0:0:0:0:1]/a",
                "https://[2001:db8::1]/a",
            ),
        ] {
            assert!(htu_matches(a, &b.parse().unwrap()), "{a} != {b}");
            assert!(htu_matches(b, &a.parse().unwrap()), "{b} != {a}");
        }
        assert!(htu_matches(
            "https://%65XAMPLE.com/a",
            &"https://example.com/a".parse().unwrap()
        ));
        assert!(htu_matches(
            "https://example.com/a",
            &"https://example.com/a?query=ignored".parse().unwrap()
        ));
    }

    #[test]
    fn distinct_or_invalid_targets_do_not_match() {
        let request = "https://example.com/a/b".parse().unwrap();
        for proof in [
            "http://example.com/a/b",
            "https://other.example/a/b",
            "https://example.com:8443/a/b",
            "https://example.com:99999/a/b",
            "https://example.com:bad/a/b",
            "https://example.com/A/b",
            "https://example.com/a%2Fb",
            "https://example.com/a//b",
            "https://example.com/a/b/",
            "https://example.com/a/b?query",
            "https://example.com/a/b#fragment",
            "https://example.com/a/b?",
            "https://example.com/a/b#",
            "https://user@example.com/a/b",
            "https://example.com/a/%",
            "https://example.com/a/%GG",
            "/a/b",
            "example.com:443",
            "garbage",
            "https:///a/b",
        ] {
            assert!(!htu_matches(proof, &request), "accepted {proof}");
        }
        assert!(!htu_matches(
            "https://example.com/%252F",
            &"https://example.com/%2F".parse().unwrap()
        ));
    }
}
