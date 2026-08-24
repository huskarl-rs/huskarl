# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.4.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-macros-v0.3.1...huskarl-macros-v0.4.0) - 2026-08-24

### Added

- *(macros)* add Classify derive ([#285](https://github.com/huskarl-rs/huskarl/pull/285))
- [**breaking**] Make builder_from_metadata/etc. return Result instead of Option ([#282](https://github.com/huskarl-rs/huskarl/pull/282))

### Other

- [**breaking**] Update dependencies and update crate descriptions. ([#304](https://github.com/huskarl-rs/huskarl/pull/304))
- explain classified errors and recovery ([#297](https://github.com/huskarl-rs/huskarl/pull/297))
- *(core)* [**breaking**] migrate internal errors to classifications ([#288](https://github.com/huskarl-rs/huskarl/pull/288))

## [0.3.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-macros-v0.3.0...huskarl-macros-v0.3.1) - 2026-07-08

### Added

- *(macros)* Handle metadata fields that are keywords ([#160](https://github.com/huskarl-rs/huskarl/pull/160))

### Other

- Pay down the usability-review docs debt ([#179](https://github.com/huskarl-rs/huskarl/pull/179))
- Docs update ([#92](https://github.com/huskarl-rs/huskarl/pull/92))

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
