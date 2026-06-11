# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Removed

- `#[try_builder]` and its `#[try_setter(Trait::method)]` field attribute.
  Superseded by bon's native fallible `with` closures —
  `#[builder(with = |value: impl Trait| -> Result<_, huskarl_core::Error> { … })]` —
  which became expressible once the converter traits returned the concrete
  `huskarl_core::Error` instead of a per-impl associated error type.

### Changed

- `#[from_metadata]` no longer routes converted fields through hidden
  `{field}_internal` setters. Metadata values now go through the public
  setter; when that setter is a fallible `with` closure, the generated
  `builder_from_metadata` unwraps the `Result` — metadata fields already have
  the target type, so the conversion must be an infallible identity case.

## [0.1.0] - 2026-03-24

- Initial implementation.
