# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] - 2026-06-30

### Changes

 - Add max_response_bytes builder parameter (defaults to 1024 x 1024).

## [0.7.0] - 2026-06-15

### Changes

 - Bump huskarl-core to 0.7.0-pre.0 and adopt its dyn-trait design.
 - The `mtls` builder parameter defaults to `NoMtls` (plain TLS); it no longer
   needs to be set explicitly.
 - The `follow_redirects` parameter is not present on wasm.

# [0.6.0] - 2026-05-25

### Changes

 - Update to huskarl-core 0.6.

## [0.5.0] - 2026-05-06

### Changes

 - Update to huskarl-core 0.5.

## [0.4.1] - 2026-05-05

### Changes

 - Add the ability to set whether the client follows redirects (defaults to false).

## [0.4.0] - 2026-04-28

### Changes

- Update to huskarl-core 0.4.

## [0.3.0] - 2026-04-28

### Changes

- Update to huskarl-core 0.3.

## [0.2.0] - 2026-04-06

### Changes

- Breaking: update to huskarl-core 0.2.

## [0.1.0] - 2026-03-24

- Initial implementation.
