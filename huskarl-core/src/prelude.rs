//! Anonymous trait imports that make the crate's method syntax work.
//!
//! This prelude is **trait-only, by design**: it holds exactly the traits
//! whose methods users call on values they already hold, imported anonymously
//! (`as _`) so a glob import adds **zero names** to your namespace — it can
//! never collide with your code, and it is always safe to grow. Types are
//! named at their use sites, so they are imported explicitly instead; traits
//! you *implement* (rather than call) are excluded too.
//!
//! Downstream crates re-export this from their own preludes (e.g.
//! `huskarl::prelude`), so importing the outermost prelude is enough.

pub use crate::{
    crypto::cipher::{AeadDecryptor as _, AeadEncryptor as _, AeadEncryptorSelector as _},
    crypto::seal::{AeadSealer as _, AeadUnsealer as _},
    crypto::signer::{
        AsymmetricJwsSigner as _, AsymmetricJwsSignerSelector as _, JwsSigner as _,
        JwsSignerSelector as _,
    },
    crypto::verifier::{JwsVerifier as _, JwsVerifierFactory as _, JwsVerifierPlatform as _},
    dpop::{AuthorizationServerDPoP as _, ResourceServerDPoP as _},
    secrets::Secret as _,
};
