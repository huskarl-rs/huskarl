# Key versions and rotation

Cloud KMS keys and Secret Manager secrets are *versioned*: a `CryptoKey` or
secret provides a stable name while its individual versions change over time.
This crate turns those versions into `huskarl` signers, verifiers, and ciphers.
The rules below explain which versions each type uses during rotation.

## Versions are resolved once, then pinned

Every key type here resolves its version(s) **at build time** and then pins the
result. A built
[`SigningKey`](crate::kms::asymmetric::signer::SigningKey) or
[`CipherKey`](crate::kms::symmetric::cipher::CipherKey) keeps using exactly the
version(s) it resolved, no matter what happens in KMS afterwards. They do not
poll or refresh themselves — `try_refresh` is a no-op.

To pick up a newly rotated version you **rebuild** the key. You rarely do this
by hand: the `huskarl-core` refresh wrappers rebuild on a schedule for you — see
the [self-refreshing keys guide](crate::_docs::guide::refreshing_keys).

## One version to write, all versions to read

The asymmetry that makes rotation safe:

- **Signing and encryption pin a single version.** A signer emits one
  signature; an encryptor emits one ciphertext. There is exactly one *current*
  version, chosen by the [`VersionStrategy`](crate::kms::VersionStrategy).
- **Verification and decryption span every enabled version.** A verifier must
  accept signatures made by any not-yet-retired key; a decryptor must read
  ciphertext produced by any of them. So these load *all* enabled versions and
  route by `kid`/algorithm (see [key IDs](crate::_docs::explanation::key_ids)).

[`CipherKey`](crate::kms::symmetric::cipher::CipherKey) and the HMAC
[`VerifyingKey`](crate::kms::symmetric::signer::VerifyingKey) /
[`SigningKey`](crate::kms::symmetric::signer::SigningKey) pairing combine both
sides: encrypt/sign with one, decrypt/verify with all.

## Why the strategy is critical for encryption

Because reading tolerates any enabled version but writing commits to one, the
*choice* of which version to write with is where rotation races live. That
choice is the [`VersionStrategy`](crate::kms::VersionStrategy):

- [`Latest`](crate::kms::VersionStrategy::Latest) starts writing with a new
  version as soon as an encryptor reloads. Consumers that have not yet loaded
  that version cannot decrypt its ciphertext. Signing has a similar propagation
  window when verifiers cache their keys, although clients can often retry after
  the verifier refreshes.
- [`ByLabel`](crate::kms::VersionStrategy::ByLabel) writes with whichever
  version a label on the `CryptoKey` points at. You promote the label only
  *after* every consumer has loaded the new version as a decryptor — so the
  encryptor can never outrun the decryptors.
- [`MinAge`](crate::kms::VersionStrategy::MinAge) writes with the newest version
  that meets a configured minimum age, skipping versions younger than the
  propagation window. It is a coarser, time-based alternative to `ByLabel`.
- [`Specific`](crate::kms::VersionStrategy::Specific) pins a version ID
  outright — no automatic movement at all.

## The safe rotation order

For encryption keys the ordering is always:

1. **Add** the new version.
2. **Wait** for every consumer to load it as a decryptor (they will on their
   next refresh).
3. **Promote** it for encryption — flip the `ByLabel` label, or let `MinAge`
   age it in.

Encryption should be the *last* operation to switch. Signing can often tolerate
a shorter coordination window because a failed verification can be retried
after the verifier refreshes. If every signature must verify immediately,
stage signing-key promotion in the same way.

## Secret Manager follows the same shape

Multi-version secrets work the same way.
[`SecretVersions`](crate::secretmanager::SecretVersions) exposes a **primary**
version, resolved through a caller-controlled alias, together with **all**
enabled versions. It validates that the primary appears in the enabled set.
Write with the primary and build a decryptor from all enabled versions. Promote
the primary by repointing the alias, again only after every consumer has loaded
the new version. See the
[Secret Manager guide](crate::_docs::guide::secret_manager).
