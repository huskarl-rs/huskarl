//! Sources of grant parameters for from-scratch token exchanges.
//!
//! A [`TokenCache`](crate::cache::TokenCache) drives repeated exchanges over
//! its lifetime, but a grant is an honest single-exchange value. The seam
//! between the two is a [`GrantParametersSource`]: the cache asks it for
//! parameters each time it needs to obtain a token from scratch.
//!
//! Parameters that are intrinsically reusable implement
//! [`GrantParametersSource`] directly, so they can be handed to the cache
//! builder as-is (e.g. [`ClientCredentialsGrantParameters`]). The other
//! sources are:
//!
//! - [`single_use`] — single-use credentials (an authorization or device code)
//!   that must be consumed once and never replayed; the wrapper provides the
//!   take-once state a bare value cannot.
//! - [`from_fn`] — a closure re-invoked per exchange, producing a freshly-minted
//!   value each time (e.g. a JWT-bearer assertion re-signed with a current
//!   `exp`).
//! - [`reusable`] — wraps any custom value with reusable (clone-each-time)
//!   semantics, for parameter types that do not implement the trait themselves.
//!
//! [`ClientCredentialsGrantParameters`]: crate::grant::client_credentials::ClientCredentialsGrantParameters

use std::sync::{Mutex, PoisonError};

use crate::core::{
    Error,
    platform::{MaybeSendBoxFuture, MaybeSendFuture, MaybeSendSync},
};

/// The single way a cache obtains parameters for a from-scratch exchange.
///
/// This is dyn-capable: a cache stores it as
/// `Box<dyn GrantParametersSource<P>>`. Intrinsically reusable parameter types
/// implement it directly; otherwise use [`single_use`], [`from_fn`], or
/// [`reusable`], or implement it on your own type (e.g. a client that fetches
/// assertions from a sidecar).
pub trait GrantParametersSource<P>: MaybeSendSync {
    /// Yields parameters for one fresh exchange.
    ///
    /// `Ok(Some(params))` proceeds to the exchange. `Ok(None)` means nothing is
    /// left to try — a single-use source already consumed, or none configured —
    /// and the cache reports that no token source remains. `Err` means
    /// producing the parameters failed (e.g. signing an assertion), and is
    /// treated as a fresh-exchange failure.
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<P>, Error>>;

    /// Whether a failure on this source can be retried later without re-running
    /// an interactive flow.
    ///
    /// `true` for reusable and dynamic sources (a later call may succeed);
    /// `false` for single-use sources, whose credentials are spent. The cache
    /// uses this to classify errors: a retryable source keeps the underlying
    /// error's classification, otherwise the failure is a reauth signal.
    fn retryable(&self) -> bool {
        true
    }

    /// Best-effort: whether a subsequent [`acquire`](Self::acquire) could still
    /// yield parameters. Backs
    /// [`GrantTokenSource::has_grant_parameters`](crate::cache::GrantTokenSource::has_grant_parameters).
    fn available(&self) -> bool {
        true
    }

    /// Whether a rejection of the *credential* (`invalid_grant`) means this
    /// source is exhausted.
    ///
    /// `true` for a fixed value — the same value will only be rejected again,
    /// so the cache stops reusing it and reports re-authorization is required,
    /// mirroring how a refresh token is discarded on `invalid_grant`. `false`
    /// for a dynamic source ([`from_fn`]), whose next value may succeed (e.g. a
    /// freshly re-signed assertion).
    ///
    /// Only the credential-fatal `invalid_grant` triggers this. A request-shape
    /// rejection (a code whose [`parameters_at_fault`](crate::core::OAuthErrorCode::parameters_at_fault):
    /// `invalid_scope`, `invalid_target`, `invalid_resource`) leaves the
    /// credential intact and never spends the source.
    ///
    /// Defaults to `false` so a custom source is never disabled unless it opts
    /// in.
    fn discard_after_rejection(&self) -> bool {
        false
    }
}

/// Wraps a value with reusable semantics: cloned for every exchange.
///
/// Most reusable parameter types implement [`GrantParametersSource`] directly
/// and need no wrapper; use this only for a value whose type does not.
pub struct Reusable<P>(pub P);

impl<P: Clone + MaybeSendSync> GrantParametersSource<P> for Reusable<P> {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<P>, Error>> {
        let params = self.0.clone();
        Box::pin(async move { Ok(Some(params)) })
    }

    fn discard_after_rejection(&self) -> bool {
        true
    }
}

/// Reusable fixed parameters, cloned for each from-scratch exchange.
///
/// For a value whose type already implements [`GrantParametersSource`] (such as
/// [`ClientCredentialsGrantParameters`](crate::grant::client_credentials::ClientCredentialsGrantParameters)),
/// pass it directly instead of wrapping it here.
pub fn reusable<P>(params: P) -> Reusable<P> {
    Reusable(params)
}

/// Single-use fixed parameters: consumed by the first exchange attempt and
/// never replayed. Build with [`single_use`].
pub struct SingleUse<P>(Mutex<Option<P>>);

impl<P: MaybeSendSync> GrantParametersSource<P> for SingleUse<P> {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<P>, Error>> {
        // Single-use parameters (e.g. an authorization code) are consumed by
        // this one attempt, succeed or fail; replaying them is futile and
        // hazardous (RFC 6749 §4.1.2).
        let params = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        Box::pin(async move { Ok(params) })
    }

    fn retryable(&self) -> bool {
        false
    }

    fn available(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

/// Single-use fixed parameters, consumed by the first exchange attempt and
/// never replayed.
///
/// Use for grants whose parameters carry a single-use credential — an
/// authorization code (RFC 6749 §4.1.2) or a device code.
pub fn single_use<P>(params: P) -> SingleUse<P> {
    SingleUse(Mutex::new(Some(params)))
}

/// A dynamic source that re-invokes a closure for every from-scratch exchange,
/// producing freshly-minted parameters each time. Build with [`from_fn`].
pub struct FromFn<F>(pub F);

impl<P, F, Fut> GrantParametersSource<P> for FromFn<F>
where
    F: Fn() -> Fut + MaybeSendSync,
    Fut: MaybeSendFuture<Output = Result<P, Error>> + 'static,
    P: MaybeSendSync,
{
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<P>, Error>> {
        let fut = (self.0)();
        Box::pin(async move { fut.await.map(Some) })
    }

    // retryable() defaults to true: a dynamic source can always try again,
    // minting a fresh value on the next call.
}

/// A dynamic parameter source that mints a fresh value for each exchange.
///
/// The closure is invoked once per from-scratch exchange (after any
/// refresh-token attempt), so each gets freshly-produced parameters — e.g. a
/// JWT-bearer assertion re-signed with a current `iat`/`exp`/`jti`:
///
/// ```rust,no_run
/// use huskarl::{cache::from_fn, grant::jwt_bearer::JwtBearerGrantParameters};
/// # #[derive(Clone)]
/// # struct Signer;
/// # async fn mint_assertion(_signer: &Signer) -> Result<String, huskarl::core::Error> {
/// #     Ok(String::new())
/// # }
/// # fn example(signer: Signer) {
/// // Pass the result to a cache builder's `.grant_parameters(...)`.
/// let source = from_fn(move || {
///     let signer = signer.clone();
///     async move {
///         let assertion = mint_assertion(&signer).await?;
///         Ok::<_, huskarl::core::Error>(
///             JwtBearerGrantParameters::builder()
///                 .assertion(assertion)
///                 .build(),
///         )
///     }
/// });
/// # let _ = source;
/// # }
/// ```
pub fn from_fn<F>(f: F) -> FromFn<F> {
    FromFn(f)
}

/// The default source when no parameters are configured: a cache that can only
/// serve and refresh a primed token. [`acquire`](GrantParametersSource::acquire)
/// always yields `None`.
pub struct NoSource;

impl<P: MaybeSendSync> GrantParametersSource<P> for NoSource {
    fn acquire(&self) -> MaybeSendBoxFuture<'_, Result<Option<P>, Error>> {
        Box::pin(async { Ok(None) })
    }

    fn retryable(&self) -> bool {
        false
    }

    fn available(&self) -> bool {
        false
    }
}
