# 71 — Issue #17 Validator Spike Readiness Checklist

## Purpose

This is the short preflight status for the first serious Codex implementation assignment.

It distinguishes **architecture questions that are closed** from **mechanical implementation work that belongs inside the spike**.

## Status

**Issue #17 is SPIKE_READY.**

That means architecture/contracts/fixtures were sufficiently constrained to begin implementation.
As of 2026-09-19, the Issue #17 implementation, generated hashes, fixture automation,
property tests, and resource-limit tests are present on the dedicated implementation branch.

## Closed decisions / repository migrations

- [x] AIOS IR is provider/runtime independent.
- [x] Task ID is outside semantic IR.
- [x] `program_id` is a logical label, not exact semantic identity.
- [x] v0.1 semantic hash field inclusion/exclusion is defined (ADR 0029 / docs 66).
- [x] node/set ordering and safe-default normalization are defined.
- [x] canonical JSON/hash profile is defined (JCS + domain-separated SHA-256 bootstrap).
- [x] semantic refs are exactly `<id>@<major>` (ADR 0030 / docs 67).
- [x] immutable Registry Snapshot resolves one exact active contract per `(ID, major)`.
- [x] no network/catalog/SemVer solver is used during validation.
- [x] authority resource selectors are symbolic, not host paths/runtime handles.
- [x] verifier role/kind behavior is explicit.
- [x] duplicate semantic authority requests are rejected.
- [x] optional-input behavior is defined.
- [x] egress/cache/fallback edge rules are defined (ADR 0031 / docs 68).
- [x] semantic effect vocabulary is unified (ADR 0032).
- [x] required-vs-allowed effect/authority model is decided (ADR 0033 / docs 69).
- [x] `capability-contract.schema.json` structurally requires `required_effect_classes`, `allowed_effect_classes`, `required_authority_classes`, and `allowed_authority_classes`.
- [x] bootstrap capability fixtures use the canonical uppercase effect vocabulary and explicit lower/upper bounds.
- [x] bootstrap registry fixture explicitly includes fallback/test capabilities (`artifact.copy.compat`, `text.uppercase`) instead of relying on an implicit private test registry.
- [x] validator reason-code registry covers current negative fixtures, including `IR_EGRESS_NOT_ALLOWED`.
- [x] provider-conformance reason-code registry exists separately from validator/runtime reason codes.
- [x] valid/invalid semantic fixtures cover policy-controlled data egress, missing required authority, capability egress mismatch, and invalid probabilistic content-addressed caching.
- [x] minimal Rust workspace/trusted boundary is documented (docs 60).
- [x] test/fuzz/resource-limit matrix exists (docs 61).
- [x] first-session runbook exists (docs 62).
- [x] Stage-0 closure audit/maturity index exists (docs 81 + `specs/contract-maturity.json`).
- [x] root agent/contribution/PR rules exist.

## Mechanical work intentionally inside Issue #17

These are implementation tasks, not open architecture questions:

- [x] create Rust workspace/crates/CLI;
- [x] implement capability/type/Registry Snapshot structural loaders against the now-aligned schemas;
- [x] implement semantic contract consistency checks;
- [x] generate real contract hashes and Registry Snapshot identity to replace fixture placeholders;
- [x] implement strict duplicate-key parser/resource limits;
- [x] implement graph/type/capability/effect/fallback passes;
- [x] implement required-vs-allowed authority/effect checks;
- [x] implement policy-egress semantic consistency (including `data.egress` destination-class matching) without performing authorization;
- [x] implement effect summary;
- [x] implement semantic-view normalization/JCS/hash;
- [x] automate repository positive/negative/version/hash/edge fixtures;
- [x] add property/fuzz smoke targets;
- [x] run official RFC 8785 test-vector and round-trip canonicalization tests;
- [x] reconcile the implementation-discovered JCS exact-integer boundary through an explicit ADR/profile/schema/fixture/test update.

## Pre-spike audit checks

Before coding, verify the checked-out branch contains:

```text
AGENTS.md
docs/30-aios-ir-reference-validator-plan.md
docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md
docs/61-validator-test-fuzz-and-resource-limit-matrix.md
docs/62-first-codex-session-runbook.md
docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md
docs/67-v0.1-semantic-reference-and-version-resolution.md
docs/68-aios-ir-v0.1-edge-case-semantics.md
docs/69-v0.1-capability-effect-and-authority-contract-profile.md
docs/70-validator-and-registry-reason-code-catalog.md
docs/81-stage0-architecture-closure-audit.md
```

and:

```text
specs/aios-ir.schema.json
specs/capability-contract.schema.json
specs/type-contract.schema.json
specs/registry-snapshot.schema.json
specs/ir-validation-result.schema.json
specs/validator-output.schema.json
specs/effect-summary.schema.json
specs/validator-reason-codes.json
specs/provider-conformance-reason-codes.json
specs/contract-maturity.json
```

with fixtures:

```text
examples/aios-ir/demonstration-a.ir.json
examples/aios-ir/valid-cases.json
examples/aios-ir/invalid-cases.json
examples/aios-ir/invalid-semantic-cases.json
examples/aios-ir/canonicalization-cases.json
examples/aios-ir/version-resolution-cases.json
examples/aios-ir/edge-case-cases.json
examples/aios-ir/capability-contracts.json
examples/aios-ir/type-contracts.json
examples/aios-ir/registry-snapshot.json
examples/aios-ir/provider-conformance-cases.json
```

## Stop conditions remain active

`SPIKE_READY` does not mean "code around contradictions."

Stop/propose an architecture change if implementation finds, for example:

- accepted ADR and schema cannot both be satisfied;
- two valid fixture expectations conflict;
- hash profile produces non-deterministic output across conforming implementations;
- required effect/authority semantics cannot be represented without broadening trusted authority;
- a dependency forces network/provider/model execution in trusted validation;
- registry resolution cannot be made immutable/reproducible as specified;
- JCS/numeric/Unicode/duplicate-key behavior of the selected Rust stack differs from the controlling canonicalization/parser contract.

## Explicitly deferred from Issue #17

- Task daemon/SQLite persistence;
- Cedar policy authorization;
- provider process execution;
- Credential Broker;
- model planner/router;
- Varlink/WIT production provider runtime;
- Resource Broker;
- GUI;
- peer/network/cloud/storage fabrics;
- package manager/component activation;
- Universal App Broker;
- Skill compilation/MLIR;
- custom AIOS source language.

## Merge gate

The spike is successful only if a hostile candidate program can pass through:

```text
bytes
→ strict parser/limits
→ structural schema
→ immutable registry
→ graph/references
→ types/capabilities
→ required/allowed effects + authority + egress + fallback
→ effect summary
→ normalized semantic view
→ canonical semantic hash
```

with deterministic machine diagnostics and no execution/authority side effects.

## After #17

Do not jump directly to an AI planner.

Follow:

- `docs/82-stage1-core-substrate-codex-runbook.md`
- `docs/86-stage1-deterministic-spine-acceptance-tests.md`

The next milestone is a complete deterministic Task/Artifact/Provenance/Registry/Authority/Provider execution/recovery spine with no AI model.

## Principle

> **The repository is ready to implement the semantic boundary, not ready to implement the whole operating system.**
