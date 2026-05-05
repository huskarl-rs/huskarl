//! `OAuth2` grant type implementations.
//!
//! Choose the grant type that fits your use case:
//!
//! | Grant | Use case |
//! |-------|----------|
//! | [`authorization_code`] | User-facing apps — the user logs in via a browser |
//! | [`client_credentials`] | Machine-to-machine — the client acts on its own behalf |
//! | [`device_authorization`] | Devices with limited input (TVs, CLIs) |
//! | [`token_exchange`] | Exchange an existing token for a new one (impersonation, delegation) |
//! | [`refresh`] | Renew an access token using a refresh token |

pub mod authorization_code;
pub mod client_credentials;
pub mod core;
pub mod device_authorization;
pub mod refresh;
pub mod token_exchange;
