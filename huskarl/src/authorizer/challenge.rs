//! `WWW-Authenticate` challenge parsing (RFC 7235 §2.1 / RFC 9110 §11).

use http::{HeaderMap, header::WWW_AUTHENTICATE};

use crate::core::OAuthErrorCode;

/// A parsed `WWW-Authenticate` challenge (RFC 7235 §2.1).
///
/// Obtain challenges with [`parse_challenges`]. Use [`is_scheme`](Self::is_scheme)
/// and [`param`](Self::param) for case-insensitive comparisons.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The authentication scheme, e.g. `Bearer` or `DPoP`.
    pub scheme: String,
    /// The scheme's mutually exclusive auth parameters or `token68` value.
    pub payload: ChallengePayload,
}

/// What follows a challenge's scheme — the grammar's
/// `token68 / #auth-param` alternation, which is mutually exclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengePayload {
    /// Auth parameters in wire order.
    ///
    /// Quoted strings are unquoted and quoted pairs are unescaped. A bare
    /// scheme is represented by an empty list. Duplicate names are preserved.
    Params(Vec<(String, String)>),
    /// The `token68` payload for schemes that use one (e.g. `Basic`,
    /// `Negotiate`).
    Token68(String),
}

impl Challenge {
    fn new(scheme: String) -> Self {
        Self {
            scheme,
            payload: ChallengePayload::Params(Vec::new()),
        }
    }

    // Called only while the parser is building the `Params` variant.
    fn push_param(&mut self, name: String, value: String) {
        debug_assert!(matches!(self.payload, ChallengePayload::Params(_)));
        if let ChallengePayload::Params(params) = &mut self.payload {
            params.push((name, value));
        }
    }

    /// Returns whether the authentication scheme matches case-insensitively.
    #[must_use]
    pub fn is_scheme(&self, scheme: &str) -> bool {
        self.scheme.eq_ignore_ascii_case(scheme)
    }

    /// Returns the auth parameters, or an empty slice for a `token68` challenge.
    #[must_use]
    pub fn params(&self) -> &[(String, String)] {
        match &self.payload {
            ChallengePayload::Params(params) => params,
            ChallengePayload::Token68(_) => &[],
        }
    }

    /// Returns the `token68` payload, if present.
    #[must_use]
    pub fn token68(&self) -> Option<&str> {
        match &self.payload {
            ChallengePayload::Params(_) => None,
            ChallengePayload::Token68(token68) => Some(token68),
        }
    }

    /// Returns the first parameter whose name matches case-insensitively.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns the challenge's typed `error` code, if present.
    ///
    /// Unknown extension codes are preserved as [`OAuthErrorCode::Other`]. Use
    /// [`param`](Self::param) to read the original wire value.
    #[must_use]
    pub fn error(&self) -> Option<OAuthErrorCode> {
        self.param("error").map(OAuthErrorCode::from)
    }
}

/// Parses all challenges from every `WWW-Authenticate` header value.
///
/// Invalid header values and malformed segments are skipped where possible, so
/// an empty result does not prove that the server sent no challenge.
#[must_use]
pub fn parse_challenges(headers: &HeaderMap) -> Vec<Challenge> {
    let mut out = Vec::new();
    for value in headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        parse_challenge_list(value, &mut out);
    }
    out
}

/// Returns true if any challenge carries the given `error` code.
pub(crate) fn challenge_has_error(headers: &HeaderMap, code: &OAuthErrorCode) -> bool {
    parse_challenges(headers)
        .iter()
        .any(|challenge| challenge.error().as_ref() == Some(code))
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// RFC 7235 §2.1 `token68` characters, excluding the trailing `=` padding.
fn is_token68_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
}

struct Cursor<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.s.get(self.pos + offset).copied()
    }

    fn bump(&mut self) {
        self.pos += 1;
    }

    fn at_end(&self) -> bool {
        self.pos >= self.s.len()
    }

    /// RFC 9110 OWS/BWS: spaces and horizontal tabs.
    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump();
        }
    }

    /// Skips OWS and commas — the legacy `#rule` list syntax permits empty
    /// elements (`, ,`).
    fn skip_list_separators(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b',')) {
            self.bump();
        }
    }

    fn lex_while(&mut self, pred: fn(u8) -> bool) -> Option<String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if pred(c) {
                self.bump();
            } else {
                break;
            }
        }
        // Header values that survive `to_str` are visible ASCII, so this
        // cannot allocate replacement characters.
        (self.pos > start).then(|| String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }

    fn lex_token(&mut self) -> Option<String> {
        self.lex_while(is_tchar)
    }

    /// Lexes a quoted-string (RFC 9110 §5.6.4), unescaping quoted-pairs.
    /// The caller has already seen the opening `"`. Returns `None` for an
    /// unterminated string (cursor is left at end of input).
    fn lex_quoted_string(&mut self) -> Option<String> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.bump();
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return None,
                Some(b'"') => {
                    self.bump();
                    return Some(String::from_utf8_lossy(&out).into_owned());
                }
                Some(b'\\') => {
                    self.bump();
                    let escaped = self.peek()?;
                    out.push(escaped);
                    self.bump();
                }
                Some(c) => {
                    out.push(c);
                    self.bump();
                }
            }
        }
    }

    /// Error recovery: advances to the next comma (or end of input). Only
    /// called from outside a quoted string, so a bare comma is a real
    /// delimiter.
    fn skip_to_comma(&mut self) {
        while let Some(c) = self.peek() {
            if c == b',' {
                break;
            }
            self.bump();
        }
    }

    /// A `token =` at the cursor begins an auth-param; `token ==` or a bare
    /// token does not (token68 padding / a new scheme).
    fn at_param_equals(&self) -> bool {
        self.peek() == Some(b'=') && self.peek_at(1) != Some(b'=')
    }

    /// Non-consuming lookahead: does the input continue with `, token =` —
    /// another auth-param of the current challenge — rather than a new
    /// challenge or the end of the list?
    fn continues_with_param(&self) -> bool {
        let mut probe = Cursor {
            s: self.s,
            pos: self.pos,
        };
        probe.skip_ows();
        if probe.peek() != Some(b',') {
            return false;
        }
        probe.skip_list_separators();
        probe.lex_token().is_some() && {
            probe.skip_ows();
            probe.at_param_equals()
        }
    }

    /// Parses an auth-param value: token or quoted-string.
    fn lex_param_value(&mut self) -> Option<String> {
        match self.peek() {
            Some(b'"') => self.lex_quoted_string(),
            Some(c) if is_tchar(c) => self.lex_token(),
            _ => None,
        }
    }
}

/// Parses one header value's challenge list into `out`.
fn parse_challenge_list(value: &str, out: &mut Vec<Challenge>) {
    let mut cur = Cursor {
        s: value.as_bytes(),
        pos: 0,
    };

    // A scheme token already consumed by the params-vs-new-challenge
    // lookahead below.
    let mut pending_scheme: Option<String> = None;

    loop {
        let scheme = if let Some(scheme) = pending_scheme.take() {
            scheme
        } else {
            cur.skip_list_separators();
            if cur.at_end() {
                return;
            }
            let Some(token) = cur.lex_token() else {
                // Junk where a scheme should be; drop the segment.
                cur.skip_to_comma();
                continue;
            };
            token
        };
        let mut challenge = Challenge::new(scheme);

        // challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
        cur.skip_ows();
        if matches!(cur.peek(), None | Some(b',')) {
            out.push(challenge);
            continue;
        }

        // The first word after the scheme is either a token68 or the first
        // parameter's name. Lex the union of both charsets, then decide by
        // what follows.
        let Some(word) = cur.lex_while(|c| is_tchar(c) || is_token68_char(c)) else {
            // e.g. a stray `=` or quote; drop the rest of the segment.
            cur.skip_to_comma();
            out.push(challenge);
            continue;
        };
        cur.skip_ows();

        if cur.at_param_equals() {
            cur.bump(); // `=`
            cur.skip_ows();
            match cur.lex_param_value() {
                Some(value) => {
                    challenge.push_param(word, value);
                    parse_remaining_params(&mut cur, &mut challenge, &mut pending_scheme);
                }
                // `word=` with no value is ambiguous: token68 with one pad
                // char (`Basic dGVzdA=`) or a malformed empty-valued
                // auth-param (`Bearer error=, realm="foo"`). A `, token =`
                // continuation reads as the latter — otherwise treating it
                // as token68 would promote the following parameter names to
                // ghost challenge schemes.
                None if cur.continues_with_param() => {
                    challenge.push_param(word, String::new());
                    parse_remaining_params(&mut cur, &mut challenge, &mut pending_scheme);
                }
                None => challenge.payload = ChallengePayload::Token68(word + "="),
            }
        } else if cur.peek() == Some(b'=') {
            // Multiple `=`: token68 padding.
            let mut token68 = word;
            while cur.peek() == Some(b'=') {
                token68.push('=');
                cur.bump();
            }
            challenge.payload = ChallengePayload::Token68(token68);
        } else {
            // Bare word: token68 without padding.
            challenge.payload = ChallengePayload::Token68(word);
        }

        // Resynchronize on anything unparsed before the next challenge.
        cur.skip_ows();
        if !matches!(cur.peek(), None | Some(b',')) && pending_scheme.is_none() {
            cur.skip_to_comma();
        }
        out.push(challenge);
    }
}

/// Parses `, name = value` continuations after a challenge's first
/// parameter. On encountering a bare token (no `=`), records it as the next
/// challenge's scheme in `pending_scheme` and stops.
fn parse_remaining_params(
    cur: &mut Cursor,
    challenge: &mut Challenge,
    pending_scheme: &mut Option<String>,
) {
    loop {
        cur.skip_ows();
        match cur.peek() {
            None => return,
            Some(b',') => {
                cur.skip_list_separators();
                if cur.at_end() {
                    return;
                }
                let Some(token) = cur.lex_token() else {
                    cur.skip_to_comma();
                    continue;
                };
                cur.skip_ows();
                if cur.at_param_equals() {
                    cur.bump(); // `=`
                    cur.skip_ows();
                    match cur.lex_param_value() {
                        Some(value) => challenge.push_param(token, value),
                        // `name=` with the value simply absent: record it
                        // faithfully with an empty value (token68 is not
                        // possible in this position).
                        None if matches!(cur.peek(), None | Some(b',')) => {
                            challenge.push_param(token, String::new());
                        }
                        // Unparseable value (e.g. an unterminated quote
                        // consumed the rest); drop the parameter.
                        None => cur.skip_to_comma(),
                    }
                } else {
                    *pending_scheme = Some(token);
                    return;
                }
            }
            // Junk directly after a parameter value; drop up to the next
            // delimiter and let the loop decide what follows it.
            Some(_) => cur.skip_to_comma(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(WWW_AUTHENTICATE, value.parse().unwrap());
        }
        headers
    }

    fn challenge(scheme: &str, params: &[(&str, &str)]) -> Challenge {
        Challenge {
            scheme: scheme.to_owned(),
            payload: ChallengePayload::Params(
                params
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
            ),
        }
    }

    // RFC 7235 §4.1's worked example: parameter/scheme disambiguation and a
    // quoted-pair inside a quoted-string.
    #[test]
    fn rfc7235_example() {
        let headers = headers(&[
            r#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple""#,
        ]);

        assert_eq!(
            parse_challenges(&headers),
            [
                challenge(
                    "Newauth",
                    &[
                        ("realm", "apps"),
                        ("type", "1"),
                        ("title", r#"Login to "apps""#),
                    ],
                ),
                challenge("Basic", &[("realm", "simple")]),
            ]
        );
    }

    #[test]
    fn bearer_and_dpop_challenges() {
        let headers = headers(&[
            r#"Bearer realm="example", error="invalid_token", error_description="The access token expired""#,
            r#"DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof""#,
        ]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 2);
        assert!(challenges[0].is_scheme("bearer"));
        assert_eq!(challenges[0].error(), Some(OAuthErrorCode::InvalidToken));
        assert_eq!(
            challenges[0].param("ERROR_DESCRIPTION"),
            Some("The access token expired")
        );
        assert!(challenges[1].is_scheme("DPoP"));
        assert_eq!(challenges[1].error(), Some(OAuthErrorCode::UseDPoPNonce));
    }

    // Standard resource-server error codes should parse to typed variants.
    #[test]
    fn every_resource_server_code_arrives_typed() {
        for (wire, expected) in [
            ("invalid_request", OAuthErrorCode::InvalidRequest),
            ("invalid_token", OAuthErrorCode::InvalidToken),
            ("insufficient_scope", OAuthErrorCode::InsufficientScope),
            ("invalid_dpop_proof", OAuthErrorCode::InvalidDPoPProof),
            ("use_dpop_nonce", OAuthErrorCode::UseDPoPNonce),
            (
                "insufficient_user_authentication",
                OAuthErrorCode::InsufficientUserAuthentication,
            ),
        ] {
            let headers = headers(&[&format!(r#"Bearer error="{wire}""#)]);
            let challenges = parse_challenges(&headers);
            assert_eq!(challenges[0].error(), Some(expected), "{wire}");
            // The original wire spelling remains available.
            assert_eq!(challenges[0].param("error"), Some(wire), "{wire}");
        }
    }

    // Preserve extension codes that are not yet in the registry.
    #[test]
    fn an_unknown_challenge_code_is_preserved_verbatim() {
        let headers = headers(&[r#"Bearer error="something_bespoke""#]);
        let challenges = parse_challenges(&headers);
        assert_eq!(
            challenges[0].error(),
            Some(OAuthErrorCode::from("something_bespoke"))
        );
    }

    // The motivating bug for the parser: `error=` inside a quoted value must
    // not register as a challenge error code.
    #[test]
    fn error_inside_quoted_value_is_not_a_code() {
        let headers = headers(&[
            r#"Bearer error="invalid_request", error_description="try again, error=invalid_token happens sometimes""#,
        ]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].error(), Some(OAuthErrorCode::InvalidRequest));
    }

    #[test]
    fn error_inside_error_uri_is_not_a_code() {
        let headers = headers(&[
            r#"Bearer error="invalid_request", error_uri="https://as.example.com/doc?error=invalid_token""#,
        ]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].error(), Some(OAuthErrorCode::InvalidRequest));
    }

    #[test]
    fn token68_with_padding() {
        let headers = headers(&["Basic dGVzdDoxMjM=, Bearer error=invalid_token"]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "Basic");
        assert_eq!(challenges[0].token68(), Some("dGVzdDoxMjM="));
        assert!(challenges[0].params().is_empty());
        assert_eq!(challenges[1].error(), Some(OAuthErrorCode::InvalidToken));
    }

    #[test]
    fn token68_double_padding_and_slash() {
        let headers = headers(&["Negotiate a/b+c==, Bearer error=x"]);

        let challenges = parse_challenges(&headers);
        assert_eq!(
            challenges[0].payload,
            ChallengePayload::Token68("a/b+c==".to_owned())
        );
        assert_eq!(challenges[1].error(), Some(OAuthErrorCode::from("x")));
    }

    #[test]
    fn scheme_only_challenges() {
        let headers = headers(&[r#"Negotiate, Bearer realm="api""#]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0], challenge("Negotiate", &[]));
        assert_eq!(challenges[1].param("realm"), Some("api"));
    }

    #[test]
    fn unquoted_params_and_loose_whitespace() {
        let headers = headers(&["Bearer  error = invalid_token ,scope=read"]);

        let challenges = parse_challenges(&headers);
        assert_eq!(
            challenges,
            [challenge(
                "Bearer",
                &[("error", "invalid_token"), ("scope", "read")],
            )]
        );
    }

    #[test]
    fn empty_list_elements_are_tolerated() {
        let headers = headers(&[", , Bearer error=\"invalid_token\", , DPoP error=use_dpop_nonce"]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].error(), Some(OAuthErrorCode::InvalidToken));
        assert_eq!(challenges[1].error(), Some(OAuthErrorCode::UseDPoPNonce));
    }

    #[test]
    fn unterminated_quote_drops_segment_without_error_codes() {
        let headers = headers(&[r#"Bearer error="unterminated"#]);

        // The malformed segment is dropped without inventing an error code.
        assert!(
            parse_challenges(&headers)
                .iter()
                .all(|challenge| challenge.error().is_none())
        );
    }

    // An empty unquoted value in first position is grammar-invalid and
    // shaped like token68 padding; the `, token =` continuation must tip the
    // reading toward "malformed param" so the following parameters are not
    // promoted to ghost challenge schemes.
    #[test]
    fn empty_param_value_does_not_eat_following_params() {
        let headers = headers(&[r#"Bearer error=, realm="foo""#]);

        assert_eq!(
            parse_challenges(&headers),
            [challenge("Bearer", &[("error", ""), ("realm", "foo")])]
        );
    }

    #[test]
    fn empty_param_value_in_continuation_position() {
        let headers = headers(&["Bearer a=1, b=, c=2"]);

        assert_eq!(
            parse_challenges(&headers),
            [challenge("Bearer", &[("a", "1"), ("b", ""), ("c", "2")])]
        );
    }

    #[test]
    fn empty_quoted_value() {
        let headers = headers(&[r#"Bearer realm="""#]);

        assert_eq!(parse_challenges(&headers)[0].param("realm"), Some(""));
    }

    #[test]
    fn no_challenges() {
        assert!(parse_challenges(&headers(&[])).is_empty());
        assert!(parse_challenges(&headers(&["  ,  "])).is_empty());
    }

    #[test]
    fn first_param_lookahead_does_not_eat_next_scheme() {
        // After `realm="x"` the bare `DPoP` token must start a new
        // challenge, not be mistaken for a parameter.
        let headers = headers(&[r#"Bearer realm="x", DPoP, Basic realm="y""#]);

        let challenges = parse_challenges(&headers);
        assert_eq!(challenges.len(), 3);
        assert_eq!(challenges[1], challenge("DPoP", &[]));
        assert_eq!(challenges[2].param("realm"), Some("y"));
    }

    // Defence-in-depth: real header values that survive `HeaderValue::to_str`
    // are visible ASCII, so non-ASCII never reaches the lexer via
    // `parse_challenges`. Drive `parse_challenge_list` directly to confirm
    // multibyte UTF-8 in a quoted-string round-trips intact, rather than being
    // decoded byte-by-byte into mojibake.
    #[test]
    fn non_ascii_quoted_value_round_trips() {
        let value = "über café — naïve 🦀";
        let mut out = Vec::new();
        parse_challenge_list(&format!(r#"Bearer error_description="{value}""#), &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].param("error_description"), Some(value));
    }
}
