# huskarl

This crate implements authentication functionality using `OAuth2` specifications,
adhering to modern security practices (e.g. requirements for FAPI 2.0 support).

## Why use this?

This crate fills in the rest of the owl that many authentication implementations don't
implement. For example, it provides secure approaches to getting secret data (e.g.
keys) into your configuration. It recognises that in many cases, authentication is
a process, and encodes the process in a secure way. A good example of this is the
authorization code grant, which can require calls to the pushed authorization
request endpoint, then authorization endpoint, followed by the token endpoint;
while maintaining various security requirements, and acting in line with server
metadata discovery.

The crate is also based on the idea that modern security (e.g. FAPI 2.0) is not
"just for banking organizations"; these are actually good modern practices for a
secure system, and the features deserve to be available to anybody writing code
in rust. Systems should be secure by default, and flexible by design.
