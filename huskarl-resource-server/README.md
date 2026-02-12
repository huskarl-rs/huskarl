<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

# `OAuth2` library for resource servers.

This library handles concerns of interest to `OAuth2` resource servers. The primary need
in this case is validating provided access tokens, and checking whether the authorization
matches the necessary level.

Currently this crate helps to handle the first of these; validating access tokens. It
then provides the context from those access tokens which let the server implement the
rest of the authorization checking.

<!-- cargo-reedme: end -->
