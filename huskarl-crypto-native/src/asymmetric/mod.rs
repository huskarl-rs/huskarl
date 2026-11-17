//! Asymmetric cryptography algorithms for signing and verifying.

pub mod signer;
pub mod verifier;

/// The supported RSA signing schemes, shared by signing and verification keys.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::EnumString, strum::VariantNames, strum::IntoStaticStr,
)]
#[strum(serialize_all = "UPPERCASE")]
enum RsaAlgorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
}
