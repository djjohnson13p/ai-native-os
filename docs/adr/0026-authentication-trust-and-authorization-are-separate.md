# ADR 0026 — Authentication, Trust, and Authorization Are Separate

- Status: **Proposed**
- Date: 2026-09-15

## Context

AIOS connects user devices, services, providers, cloud infrastructure, package publishers, and organization systems.

Traditional systems often accidentally treat network locality, account login, device pairing, certificate validity, or package signatures as broad trust/permission.

That would violate the project's no-ambient-authority model.

## Decision

AIOS will treat these as distinct layers:

```text
Identity       who/what is this?
Authentication can it prove that identity?
Trust evidence what policy-relevant evidence exists about it?
Authorization is this principal allowed to do this action now?
Credential use which narrowly mediated secret/key capability is needed?
```

Stable device/service/publisher identity SHOULD be independent of IP address, process/container identity, storage location, or cloud resource name.

Successful authentication MUST NOT itself grant access beyond deterministic policy.

## Credential rule

Long-lived credential material SHOULD remain behind trusted credential handles. Providers/workloads receive use authority to a handle rather than raw secrets whenever practical.

## Signature rule

A valid software/package signature proves origin/integrity under a key. It does not prove safety, quality, semantic conformance, or entitlement to runtime authority.

## Consequences

### Positive

- Personal Compute Fabric can survive changing routes/IPs;
- peer discovery is not equivalent to trust;
- package publisher identity does not bypass sandboxing;
- credentials can be revoked/rotated without changing semantic principals;
- authorization remains task-scoped and explainable.

### Costs

- more explicit identity/key lifecycle records;
- pairing/federation/recovery need deterministic workflows;
- providers must integrate with mediated credential APIs rather than assume environment secrets.

## Related

- `docs/19-principal-and-authority-model.md`
- `docs/21-trust-boundaries.md`
- `docs/56-cryptographic-identity-trust-and-credential-fabric.md`
- `specs/trust-identity.schema.json`
- `specs/credential-handle.schema.json`
