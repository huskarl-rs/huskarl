//! Anonymous trait imports that make the crate's method syntax work.
//!
//! This prelude imports traits anonymously (`as _`) to enable method calls
//! without introducing trait names. Imported traits can still make calls
//! ambiguous if their methods overlap. Import types and traits used in `impl`
//! blocks explicitly.
//!
//! Downstream crates re-export this from their own preludes (e.g.
//! `huskarl::prelude`), so importing the outermost prelude is enough.

pub use crate::{
    crypto::{
        cipher::{AeadDecryptor as _, AeadEncryptor as _, AeadEncryptorSelector as _},
        seal::{AeadSealer as _, AeadUnsealer as _},
        signer::{
            AsymmetricJwsSigner as _, AsymmetricJwsSignerSelector as _, JwsSigner as _,
            JwsSignerSelector as _,
        },
        verifier::{JwsVerifier as _, JwsVerifierFactory as _, JwsVerifierPlatform as _},
    },
    dpop::{AuthorizationServerDPoP as _, ResourceServerDPoP as _},
    secrets::Secret as _,
};
