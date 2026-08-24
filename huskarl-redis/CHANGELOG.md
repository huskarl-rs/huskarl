# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-redis-v0.2.0...huskarl-redis-v0.3.0) - 2026-08-24

### Added

- *(client)* [**breaking**] Support signed JARM authorization responses ([#259](https://github.com/huskarl-rs/huskarl/pull/259))

### Fixed

- Improve the panic story of the crate. ([#275](https://github.com/huskarl-rs/huskarl/pull/275))

### Other

- [**breaking**] Update dependencies and update crate descriptions. ([#304](https://github.com/huskarl-rs/huskarl/pull/304))
- Improve some documentation ([#302](https://github.com/huskarl-rs/huskarl/pull/302))
- Improve docs discovery ([#300](https://github.com/huskarl-rs/huskarl/pull/300))
- *(adapters)* propagate classified backend errors ([#289](https://github.com/huskarl-rs/huskarl/pull/289))

## [0.2.0](https://github.com/huskarl-rs/huskarl/compare/huskarl-redis-v0.1.1...huskarl-redis-v0.2.0) - 2026-07-19

### Added

- *(redis)* [**breaking**] Make key prefix mandatory to avoid accidental cross-context reuse. ([#242](https://github.com/huskarl-rs/huskarl/pull/242))

## [0.1.1](https://github.com/huskarl-rs/huskarl/compare/huskarl-redis-v0.1.0...huskarl-redis-v0.1.1) - 2026-07-16

### Other

- *(huskarl-resource-server)* release v0.9.1 ([#216](https://github.com/huskarl-rs/huskarl/pull/216))

## [0.1.0](https://github.com/huskarl-rs/huskarl/releases/tag/huskarl-redis-v0.1.0) - 2026-07-10

### Added

- *(redis)* Add redis cache/set existence check in redis. ([#217](https://github.com/huskarl-rs/huskarl/pull/217))
