//! Fuzzes the v1 sealed-bundle parser
//! (`[0x01 || nonce_len:u8 || tag_len:u8 || nonce || ciphertext || tag]`).
//! The passthrough decryptor accepts everything so the fuzzer exercises the
//! header parsing and slicing arithmetic instead of stopping at the AEAD
//! tag check on every input.
#![no_main]

use huskarl_core::crypto::KeyMatchStrength;
use huskarl_core::crypto::cipher::{
    AeadDecryptor, AeadUnsealer, AeadV1Unsealer, CipherMatch, DecryptError,
};
use huskarl_core::platform::MaybeSendBoxFuture;
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct PassthroughDecryptor;

impl AeadDecryptor for PassthroughDecryptor {
    fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        Some(KeyMatchStrength::ByAlgorithm)
    }

    fn decrypt<'a>(
        &'a self,
        _cipher_match: Option<&'a CipherMatch<'a>>,
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
        aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async move {
            // Read every byte of every slice the unsealer carved out of the
            // bundle, so any mis-sliced range is actually dereferenced.
            let sum = nonce
                .iter()
                .chain(ciphertext)
                .chain(tag)
                .chain(aad)
                .fold(0u8, |acc, b| acc.wrapping_add(*b));
            Ok(vec![sum])
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let unsealer = AeadV1Unsealer::new(PassthroughDecryptor);
    // Peel off up to 8 leading bytes as AAD so that path isn't always empty.
    let (aad, bundle) = data.split_at(data.len().min(8));
    let _ = futures_executor::block_on(unsealer.unseal(None, bundle, aad));
});
