# ADR 0040 — Execution Bindings Are Immutable Attempt Receipts

- Status: **Proposed / controlling for v0.1 provider-supervisor spike**
- Date: 2026-09-15

## Context

AIOS separates provider-independent semantic program identity from concrete provider, resource, grant, placement, and sandbox state.

If a runtime mutates an Execution Binding in place when retrying, substituting a provider, refreshing grants, or changing placement, provenance can no longer answer what a specific attempt actually intended to execute.

Mutable bindings also create confused-deputy and stale-authority risks.

## Decision

For v0.1, an Execution Binding is an immutable attempt-specific record.

Once an attempt begins, its binding's provider, input/output refs, authority-grant refs, execution profile, placement, and attempt identity are not rewritten.

For Stage-1 provider admission, the binding also records the selected conformance evidence ID, the effective provider trust-source ID, and exact non-null capability-contract, manifest, and build hashes. The v0.1 Stage-1 schema requires these facts so a schema-valid new receipt cannot omit identities that launch checks. The trusted store verifies the trust source existed and was effective when the enabled provider was bound; launch compares the receipt and immutable store marker with the source effective at check time. Refreshing conformance evidence or changing effective trust requires a new attempt and binding.

A material runtime change requires:

```text
finish/invalidate prior attempt
→ create a new attempt
→ create a new Execution Binding
→ perform any required fresh authority/resource checks
```

The same validated semantic node/program hash may be referenced by every attempt.

## Consequences

### Positive

- exact attempt reconstruction;
- clean provider substitution/retry history;
- no stale grant accidentally follows a new provider/binding;
- crash recovery can reconcile each attempt independently;
- semantic identity remains stable across runtime changes;
- provenance is easier to audit.

### Costs

- more durable attempt/binding records;
- retries require explicit new-record creation;
- control-plane code must distinguish semantic node state from current/latest attempt state.

## Security impact

Provider/workload identity and grants remain tied to the exact attempt they were evaluated for.

A new provider cannot inherit an old provider's binding/grant merely because it implements the same semantic capability.

## Compatibility impact

This affects only pre-v1 runtime contracts. It does not alter AIOS IR semantic identity.

Earlier unpinned or nullable-identity receipts are historical data for unstamped stores; they are not rewritten or newly admitted under the Stage-1 binding schema. The schema, fixture, persistence guard, and launch check are tightened together because the Stage-1 spike exposed a mismatch between schema validity and launch eligibility. The runtime-only binding change does not alter AIOS IR or its semantic hash.

## Related

- `docs/78-v0.1-execution-binding-and-provider-supervisor.md`
- `specs/execution-binding.schema.json`
- `specs/provider-invocation-request.schema.json`
- `specs/provider-invocation-result.schema.json`
- ADR 0020
- ADR 0039

## Principle

> **Retry changes runtime history, not semantic meaning; never rewrite the old receipt to describe the new attempt.**
