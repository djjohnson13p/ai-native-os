# Credential Broker Fixtures

Synthetic fixtures for `docs/79-v0.1-credential-broker-and-secret-mediation.md`.

They exercise opaque credential handles, scoped use requests, exportability, delegation, revocation, and fail-closed behavior.

No file in this directory may contain real passwords, API tokens, private keys, refresh tokens, session cookies, or production connection strings.

The intended safety property is:

> Providers receive permission to perform one bounded credential-backed operation, not ambient possession of the user's long-lived secret whenever the ecosystem permits mediation.
