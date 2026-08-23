# The error model

This page explains why huskarl separates failure details, retryability, OAuth
verdicts, and application recovery. For API contracts, see
[`Error`](crate::error::Error).

## Classification is not recovery

Nearly every fallible operation returns the one concrete
[`Error`](crate::error::Error). It is not generic, so it embeds in your own error
enum and keeps one shape across every layer it crosses.

An `Error` carries two classification facts in addition to its cause:

- [`RetryAdvice`](crate::error::RetryAdvice): whether retrying this operation
  may help, and the minimum delay when one is known.
- [`verdict`](crate::error::Error::verdict): the OAuth error an authorization
  server named, if one judged the request.

Neither fact chooses an application recovery action. Retrying, changing the
request, starting interactive authorization, or stopping depends on resources
held by the caller, such as a refresh token, reusable credentials, or a retry
budget. Lower layers cannot see those alternatives, so they should not choose
among them.

Consequently, [`RetryAdvice::No`](crate::error::RetryAdvice::No) means only that
retrying the same operation is not expected to help. A higher layer may still
have another operation available.

Some operations still return dedicated error enums when their variants are the
operation's expected control flow. Device-flow polling is one example: pending,
denied, and expired are outcomes a caller must handle distinctly rather than
diagnostic classifications.

## Retry advice is scoped

Retry advice applies to the operation that failed. It does not authorize
replaying a larger flow. In particular, retrying an idempotent metadata fetch is
different from replaying a request that may consume an authorization code or
rotate a refresh token.

An optional delay preserves information available only at the failure site,
such as `Retry-After` or a backend cooldown. It is a lower bound, not a complete
retry policy. Callers still need deadlines, attempt limits, jitter, and a total
retry budget.

## Verdicts require a judgement

RFC 6749 §5.2 puts error codes on ordinary 4xx rejection responses. A `429`
already says the peer is throttling requests, and a code arriving on a 5xx may
be a gateway echoing something rather than an authorization server deciding
anything. Acting on either body as a credential verdict is how throttling or an
outage becomes a forced re-authentication.

For that reason, only a response whose status permits the body to express a
request judgement produces a verdict. An OAuth code found in a `429` or 5xx body
remains diagnostic text but does not become a typed verdict. This prevents
callers from discarding credentials or starting authorization based on a
throttle response or an error echoed by a proxy.

The absence of a verdict does not identify the failed component. That detail
belongs to the cause and source chain; retryability belongs to `RetryAdvice`.

## Transparency

`Error` has no message of its own and is not a distinct layer in a source chain:
its `Display` renders the failure it wraps, and its `source` is that failure's
own source.

Reporters such as `snafu::Report`, `anyhow`, and `eyre` walk `source` and render each
layer independently, knowing nothing about huskarl. A layer that borrowed its
child's message would print it twice. Transparency preserves one distinct
message per layer without requiring a huskarl-specific reporter.

[`chain`](crate::error::Error::chain) yields the distinct messages, for
rendering. [`cause`](crate::error::Error::cause) is the one typed hop to the
erased backend failure, for callers that need to recover their own concrete type.

## Propagating without dropping

A wrapping layer normally knows more context but no new classification fact. It
must therefore preserve the inner classification. Reconstructing an error from
only the fields a wrapper currently knows risks losing a verdict, retry delay,
or future classification member.

[`Classification`](crate::error::propagation::Classification) makes that one
value rather than a set of fields to copy. [`Origin`](crate::error::propagation::Origin)
then makes the distinction explicit per error variant:

- `Propagates` wraps an existing `Error` and carries its classification intact.
- `Establishes` represents a new failure and supplies a new classification.

`#[derive(Classify)]` can infer propagation from a variant containing `Error`.
Leaf variants declare the classification they establish:

```text
#[derive(Debug, snafu::Snafu, huskarl_macros::Classify)]
pub(crate) enum ClientSecretError {
    #[classify(no)]
    BuildingBasicHeader { source: http::header::InvalidHeaderValue },
    FetchingSecret { source: Error },   // propagates; nothing to declare
}
```

`#[classify(with = path)]` handles decisions that depend on a runtime value,
such as an I/O error kind, protocol response, or `Error` nested behind another
public error type. The derive passes references to that variant's fields, in
declaration order, so the handler cannot receive another variant. Its handler returns `Origin`, explicitly choosing
`Establishes` or `Propagates`; rebuilding an equal classification is not
propagation.

### The backstop

Derive-time inspection cannot detect an `Error` hidden behind a type alias or
another cause enum. The `strict-propagation` feature therefore checks at runtime
that a newly established classification does not cover an existing classified
error in the source chain.

That check can inspect only the chain exposed by `std::error::Error::source`.
A transparent wrapper may delegate `source()` past its contained `Error`, making
the classified hop genuinely unobservable. Every such internal wrapper must
therefore return `Origin::Propagates` explicitly and have a test that preserves
the complete classification.

The workspace enables this check in tests. It is optional for dependents because
their own public error abstractions may legitimately contain a huskarl error
without participating in huskarl's internal propagation convention.

## HTTP responses

[`FailedResponse`](crate::http::FailedResponse) keeps status classification,
`Retry-After`, and OAuth verdict handling together. It cannot be built from a
2xx response, and
[`into_error`](crate::http::FailedResponse::into_error) applies the transient
status rule, retry delay, and judged-versus-echoed distinction in one step.
Keeping these decisions together prevents different endpoint implementations
from interpreting the same response differently.
