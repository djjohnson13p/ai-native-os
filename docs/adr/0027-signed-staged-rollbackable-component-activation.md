# ADR 0027 — Signed, Staged, Rollbackable Component Activation

- Status: **Proposed**
- Date: 2026-09-15

## Context

The long-term AIOS ecosystem depends on continuously adding/updating capability providers, Domain Packs, Views, Skills, model runtimes/assets, compatibility adapters, policy bundles, compiled targets, and system extensions.

A simple download-and-run model would let ecosystem growth become an uncontrolled trust boundary.

## Decision

Distributed AIOS components will use immutable content identity, publisher signatures, explicit manifests, and staged activation.

Activation pipeline:

```text
acquire -> digest verify -> signature/publisher verify -> strict manifest parse
-> compatibility/dependency check -> authority/effect diff -> conformance/security gates
-> inactive staging -> policy/approval -> atomic activation -> health gate/rollback
```

An update is treated as a new component version, not as an implicitly trusted mutation of the existing version.

## Authority-diff rule

An update that broadens authority/effect/network/credential requirements requires explicit policy evaluation and any required approval.

A publisher signature MUST NOT allow silent permission expansion.

## Semantic-diff rule

Changes to provided semantic capability/type versions, effect classes, determinism, verification, or minimum isolation are explicit compatibility changes.

## Rollback rule

The system SHOULD retain a known-good previous version/activation pointer when practical.

Irreversible state migrations require explicit backup/migration policy before activation.

## Consequences

### Positive

- ecosystem growth remains auditable;
- component mirrors/catalogs need not be roots of trust;
- updates cannot silently broaden authority;
- package/provider versions remain attributable in provenance;
- rollback/reproducibility are compatible with offline/peer distribution.

### Costs

- package metadata/signing infrastructure;
- activation/conformance machinery;
- storage overhead for staged/previous versions;
- more complicated state migration handling.

## Related

- `docs/57-component-distribution-supply-chain-and-update-trust.md`
- `specs/component-package.schema.json`
- `docs/adr/0017-compiled-targets-do-not-carry-authority.md`
