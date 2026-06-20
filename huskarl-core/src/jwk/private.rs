//! Validated private-key types with guaranteed private material.

use super::*;

/// An RSA private key with guaranteed private material.
///
/// Obtained via [`RsaKey::private_key()`]. The private exponent `d` is
/// guaranteed present; CRT parameters remain optional.
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct RsaPrivateKey {
    /// The public key components.
    pub public: RsaPublicKey,
    /// The private exponent (guaranteed present).
    pub d: Vec<u8>,
    /// First prime factor (CRT parameter, RFC 7518 §6.3.2).
    pub p: Option<Vec<u8>>,
    /// Second prime factor (CRT parameter).
    pub q: Option<Vec<u8>>,
    /// First factor CRT exponent.
    pub dp: Option<Vec<u8>>,
    /// Second factor CRT exponent.
    pub dq: Option<Vec<u8>>,
    /// First CRT coefficient.
    pub qi: Option<Vec<u8>>,
    /// Additional prime factors for multi-prime RSA (RFC 7518 §6.3.2.7).
    pub oth: Option<Vec<OtherPrimeInfo>>,
}

impl std::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qi.zeroize();
        if let Some(oth) = &mut self.oth {
            for info in oth.iter_mut() {
                info.zeroize();
            }
        }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An EC private key with guaranteed private material.
///
/// Obtained via [`EcKey::private_key()`].
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct EcPrivateKey {
    /// The public key components.
    pub public: EcPublicKey,
    /// The private key value (guaranteed present).
    pub d: Vec<u8>,
}

impl std::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for EcPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An OKP private key with guaranteed private material.
///
/// Obtained via [`OkpKey::private_key()`].
#[non_exhaustive]
#[derive(PartialEq, Clone)]
pub struct OkpPrivateKey {
    /// The public key components.
    pub public: OkpPublicKey,
    /// The private key value (guaranteed present).
    pub d: Vec<u8>,
}

impl std::fmt::Debug for OkpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkpPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Zeroize for OkpPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for OkpPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A validated private key with guaranteed private material.
///
/// Obtained via [`Key::private_key()`] or [`Jwk::private_key()`]. Each variant
/// guarantees that the private exponent / key parameter `d` is present.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum PrivateKey {
    /// An RSA private key.
    Rsa(RsaPrivateKey),
    /// An Elliptic Curve private key.
    Ec(EcPrivateKey),
    /// An Octet Key Pair private key.
    Okp(OkpPrivateKey),
}

impl PrivateKey {
    /// Returns the public key, stripping all private material.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(rsa) => PublicKey::Rsa(rsa.public.clone()),
            PrivateKey::Ec(ec) => PublicKey::Ec(ec.public.clone()),
            PrivateKey::Okp(okp) => PublicKey::Okp(okp.public.clone()),
        }
    }
}

// --- From: variant → PrivateKey enum ---

impl From<RsaPrivateKey> for PrivateKey {
    fn from(value: RsaPrivateKey) -> Self {
        Self::Rsa(value)
    }
}

impl From<EcPrivateKey> for PrivateKey {
    fn from(value: EcPrivateKey) -> Self {
        Self::Ec(value)
    }
}

impl From<OkpPrivateKey> for PrivateKey {
    fn from(value: OkpPrivateKey) -> Self {
        Self::Okp(value)
    }
}

// --- From: private → serde type (infallible widening) ---

impl From<RsaPrivateKey> for RsaKey {
    fn from(mut key: RsaPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                RsaPublicKey {
                    n: vec![],
                    e: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
            p: key.p.take(),
            q: key.q.take(),
            dp: key.dp.take(),
            dq: key.dq.take(),
            qi: key.qi.take(),
            oth: key.oth.take(),
        }
    }
}

impl From<EcPrivateKey> for EcKey {
    fn from(mut key: EcPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                EcPublicKey {
                    crv: String::new(),
                    x: vec![],
                    y: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
        }
    }
}

impl From<OkpPrivateKey> for OkpKey {
    fn from(mut key: OkpPrivateKey) -> Self {
        Self {
            public: std::mem::replace(
                &mut key.public,
                OkpPublicKey {
                    crv: String::new(),
                    x: vec![],
                },
            ),
            d: Some(std::mem::take(&mut key.d)),
        }
    }
}

impl From<PrivateKey> for Key {
    fn from(value: PrivateKey) -> Self {
        match value {
            PrivateKey::Rsa(rsa) => Key::Rsa(rsa.into()),
            PrivateKey::Ec(ec) => Key::Ec(ec.into()),
            PrivateKey::Okp(okp) => Key::Okp(okp.into()),
        }
    }
}

// --- From: private → public (strip private material) ---

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(mut key: RsaPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            RsaPublicKey {
                n: vec![],
                e: vec![],
            },
        )
    }
}

impl From<EcPrivateKey> for EcPublicKey {
    fn from(mut key: EcPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            EcPublicKey {
                crv: String::new(),
                x: vec![],
                y: vec![],
            },
        )
    }
}

impl From<OkpPrivateKey> for OkpPublicKey {
    fn from(mut key: OkpPrivateKey) -> Self {
        std::mem::replace(
            &mut key.public,
            OkpPublicKey {
                crv: String::new(),
                x: vec![],
            },
        )
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value.public_key()
    }
}

// --- private_key() methods on serde types ---

impl RsaKey {
    /// Returns a validated [`RsaPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<RsaPrivateKey> {
        Some(RsaPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
            p: self.p.clone(),
            q: self.q.clone(),
            dp: self.dp.clone(),
            dq: self.dq.clone(),
            qi: self.qi.clone(),
            oth: self.oth.clone(),
        })
    }
}

impl EcKey {
    /// Returns a validated [`EcPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<EcPrivateKey> {
        Some(EcPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
        })
    }
}

impl OkpKey {
    /// Returns a validated [`OkpPrivateKey`] if private material is present.
    #[must_use]
    pub fn private_key(&self) -> Option<OkpPrivateKey> {
        Some(OkpPrivateKey {
            public: self.public.clone(),
            d: self.d.clone()?,
        })
    }
}
