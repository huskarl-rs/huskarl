#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Google Cloud cryptographic integrations for `huskarl`.
//!
//! - [`kms`] — Cloud KMS signers, verifiers, and AEAD ciphers (asymmetric JWS,
//!   symmetric HMAC and AES), with version pinning and rotation support.
//! - [`secretmanager`] — a `huskarl` secret provider backed by Secret Manager.
//!
//! Each integration is gated by a Cargo feature with the same name.
//!
//! # Documentation
//!
//! - **Solve a task:** [sign JWS and serve
//!   JWKS](crate::_docs::guide::asymmetric_signing) from an asymmetric key,
//!   [encrypt and sign](crate::_docs::guide::symmetric_crypto) with symmetric
//!   keys, [keep keys fresh](crate::_docs::guide::refreshing_keys) under
//!   rotation, or [read secrets](crate::_docs::guide::secret_manager) from
//!   Secret Manager.
//! - **Understand the design:** read how
//!   [versions and rotation](crate::_docs::explanation::versions_and_rotation)
//!   work, how keys derive a [`kid`](crate::_docs::explanation::key_ids), and
//!   the [error model](crate::_docs::explanation::error_handling).
//! - **Look up the API:** use the crate modules and item pages in this reference.
//!
//! Related how-to guides and explanation live in `huskarl-core`, which defines
//! the traits this crate implements:
//!
//! - [Providing secrets](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/providing_secrets/index.html)
//! - [Configuring JWT verification](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/guide/configuring_jwt_verification/index.html)
//! - [Composing crypto strategies](https://docs.rs/huskarl-core/latest/huskarl_core/_docs/explanation/crypto_strategies/index.html)
//!   — how the multi-key, refreshable, and retrying wrappers stack on these keys.

#[cfg(any(doc, docsrs))]
pub mod _docs;

pub mod kid;
#[cfg(feature = "kms")]
pub mod kms;
#[cfg(feature = "secretmanager")]
pub mod secretmanager;

#[cfg(any(feature = "kms", feature = "secretmanager"))]
mod retry;
