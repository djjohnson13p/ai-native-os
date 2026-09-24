# ADR 0038 — Semantic Registry and Provider Registry Are Separate Authorities

- Status: **Accepted for the v0.1 / Phase-I substrate**
- Date: 2026-09-15

## Context

AIOS needs both stable semantic meaning and replaceable implementations. If provider manifests define capability meaning, provider substitution is illusory and a package update can silently rewrite Task semantics. If semantic validation loads/executes provider code, the trusted semantic boundary becomes a supply-chain execution path.

## Decision

AIOS maintains two distinct registries:

1. **Semantic Registry** — immutable Type/Capability Contracts + Registry Snapshots that define exact semantic meaning.
2. **Provider Registry** — implementation/package/runtime/conformance/trust/enablement metadata for providers claiming those semantic contracts.

A provider registration references semantic families/exact tested contract evidence but cannot redefine the contract.

Registry Snapshot admission/activation is separate from Provider registration/enablement.

An additive `0014` semantic repair fence separates historical admission projections from prospective executable authority. Repair of a missing `0012` guard advances an append-only generation; a snapshot can be used again only after the owner-bound local writer strictly re-verifies persisted content and records a fresh decision/source receipt for that generation. This does not undo QUARANTINED/REVOKED terminal state, restore old bindings, or rehabilitate an activation scope whose revision history may have been rolled back. A terminal marker remains authoritative even if the admission projection was forged. An append-only activation identity ledger retains deleted and renamed scope identities for repair containment. If activation guards were already absent before this ledger bootstrapped, the store globally quarantines activation because missing identities cannot be reconstructed. When a legacy admission guard was already absent before the terminal ledger existed, old admission history is unprovable and cannot be re-attested. Issue #3 will supply policy-engine integration; Stage 1 records the local writer decision without claiming external policy authentication.

Provider conformance is separate from publisher trust, runtime health, and Task authorization.

The semantic validator never executes/loads provider code.

Detailed lifecycle semantics are in `docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md`.

## Consequences

### Positive

- provider/package updates cannot silently change semantic meaning;
- semantic validation remains small/offline/deterministic;
- multiple providers can compete behind one contract;
- historical Task validation remains attributable to exact Registry Snapshot;
- provider trust/conformance/revocation can evolve independently.

### Costs

- two registries/lifecycle models must be maintained;
- provider eligibility needs compatibility/conformance checks against exact resolved contracts;
- distribution/catalog UX must avoid presenting installability as semantic trust.

## Security impact

Registration, signatures, conformance, and enablement do not grant Task authority. Concrete execution still requires current deterministic policy/grants and sandbox/resource binding.

## Related

- ADR 0013
- ADR 0030
- ADR 0034
- `docs/28-capability-contracts-and-conformance.md`
- `docs/31-semantic-registry-snapshots.md`
- `docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md`
- GitHub Issue #2
