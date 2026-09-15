# 71 — Issue #17 Validator Spike Readiness Checklist

## Purpose

This is the short preflight status for the first serious Codex implementation assignment.

It distinguishes **architecture questions that are closed** from **mechanical implementation/contract migration that belongs inside the spike**.

## Status

**Issue #17 is SPIKE_READY.**

That means architecture is sufficiently constrained to begin implementation. It does **not** mean all code/schemas/hashes already exist.

## Closed decisions

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
- [x] bootstrap validator/registry reason-code catalog exists (docs 70 + machine registry).
- [x] minimal Rust workspace/trusted boundary is documented (docs 60).
- [x] test/fuzz/resource-limit matrix exists (docs 61).
- [x] first-session runbook exists (docs 62).
- [x] root agent/contribution/PR rules exist.

## Mechanical work intentionally inside Issue #17

These are implementation tasks, not open architecture questions:

- [ ] create Rust workspace/crates/CLI;
- [ ] add `required_effect_classes` / `required_authority_classes` to the structural capability-contract schema and bootstrap fixtures under ADR 0033;
- [ ] implement semantic contract consistency checks;
- [ ] generate real contract hashes and registry snapshot identity to replace fixture placeholders;
- [ ] implement strict duplicate-key parser/resource limits;
- [ ] implement graph/type/capability/effect/fallback passes;
- [ ] implement effect summary;
- [ ] implement semantic-view normalization/JCS/hash;
- [ ] automate repository positive/negative/version/hash/edge fixtures;
- [ ] add property/fuzz smoke targets;
- [ ] reconcile any actual implementation-discovered contradiction through explicit ADR/schema/fixture update.

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
```

## Stop conditions remain active

`SPIKE_READY` does not mean "code around contradictions."

Stop/propose an architecture change if implementation finds, for example:

- accepted ADR and schema cannot both be satisfied;
- two valid fixture expectations conflict;
- hash profile produces non-deterministic output across conforming implementations;
- required effect/authority semantics cannot be represented without broadening trusted authority;
- a dependency forces network/provider/model execution in trusted validation;
- registry resolution cannot be made immutable/reproducible as specified.

## Explicitly deferred from Issue #17

- Task daemon/SQLite persistence;
- Cedar policy authorization;
- provider process execution;
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
→ effects/authority/egress/fallback
→ effect summary
→ normalized semantic view
→ canonical semantic hash
```

with deterministic machine diagnostics and no execution/authority side effects.

## Principle

> **The repository is ready to implement the semantic boundary, not ready to implement the whole operating system.**
