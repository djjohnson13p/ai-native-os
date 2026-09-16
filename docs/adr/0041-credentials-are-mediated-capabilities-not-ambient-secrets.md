# ADR 0041 — Credentials Are Mediated Capabilities, Not Ambient Secrets

- Status: **Proposed / controlling for v0.1 credential-broker spike**
- Date: 2026-09-15

## Context

AIOS providers will need authenticated access to services such as email, databases, repositories, package registries, cloud APIs, peer devices, and organization systems.

Copying long-lived credentials into provider environment variables, config files, prompts, Task records, or remote requests would undermine the no-ambient-authority architecture and make provider compromise far more damaging.

## Decision

AIOS represents credentials through opaque `credential://` handles and a trusted Credential Broker.

Providers receive the ability to perform a narrowly authorized credential-backed operation rather than raw long-lived secret material whenever technically possible.

Preferred order:

```text
BROKERED_OPERATION
→ DELEGATED_SHORT_LIVED
→ LOCAL_INJECTION_RESTRICTED
→ EXPORT_WITH_APPROVAL (exceptional)
```

Credential use is authorized independently through the current Task/Authority Coordinator and is bound to the current provider principal/Execution Binding/service/scope.

Non-exportable credentials remain inside their secure storage boundary even when execution moves to peer/remote compute.

## Consequences

### Positive

- provider compromise exposes less reusable authority;
- secrets are absent from semantic IR/provenance by design;
- remote placement cannot silently export device-local credentials;
- credential rotation/revocation can occur without changing Task/object identity;
- external broad credentials can still be constrained by narrower AIOS runtime authority.

### Costs

- Credential Broker becomes trusted infrastructure;
- some legacy tools require awkward local injection adapters;
- not every external provider supports ideal token exchange/scoping;
- service-specific mediation logic may be required.

## Security impact

Credential possession does not replace deterministic authorization.

A valid handle plus a valid external secret is insufficient without a current matching Authority Grant.

The broker fails closed on scope, service, provider, Task, exportability, lifecycle, or secure-store mismatch.

## Compatibility impact

Legacy applications that require raw secrets may run only through an explicitly bounded local injection/habitat profile appropriate to the credential's exportability.

## Related

- `docs/56-cryptographic-identity-trust-and-credential-fabric.md`
- `docs/79-v0.1-credential-broker-and-secret-mediation.md`
- `specs/credential-handle.schema.json`
- `specs/credential-use-request.schema.json`
- `specs/credential-use-result.schema.json`
- ADR 0006
- ADR 0026
- ADR 0039

## Principle

> **Authorize use, not possession.**
