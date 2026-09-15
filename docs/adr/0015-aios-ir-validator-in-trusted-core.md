# ADR 0015 — AIOS IR Validator Is Part of the Trusted Core

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

The planner, model adapters, providers, and legacy habitats are intentionally treated as fallible or potentially untrusted. AIOS IR is the boundary that turns proposed work into something eligible for deterministic policy evaluation and execution.

If the validator itself relies on model judgment, executes provider code during validation, or silently repairs unsafe programs, the boundary collapses.

## Decision

The AIOS IR parser/normalizer/semantic validator will be part of the trusted control-plane core.

For the v0.1 implementation it should:

- be implemented in Rust unless a benchmark/ADR justifies otherwise;
- perform parsing, schema checks, graph checks, type/capability validation, effect/authority consistency checks, bounded-failure checks, and canonical hashing without invoking an AI model;
- operate against immutable/read-only registry snapshots;
- never execute provider code while validating;
- emit stable machine-readable reason codes;
- impose resource/depth/size limits on untrusted IR;
- be fuzzable and covered by adversarial fixtures;
- fail closed on unknown semantic versions or security-relevant fields.

A planner may use validator errors to propose a repaired program, but repair is a new untrusted proposal that must be validated again.

## Consequences

### Positive

- model/provider compromise cannot redefine executable semantics;
- validator behavior is reproducible and testable;
- Codex can implement a bounded security-critical component with explicit fixtures;
- IR becomes a meaningful security boundary rather than documentation.

### Negative

- the trusted core grows;
- registry/versioning logic must be implemented carefully;
- validator updates require security-sensitive review;
- accepting richer language features becomes intentionally slower because each feature expands the trusted semantic surface.

## Acceptance criteria

- all current valid/invalid IR fixtures produce expected outcomes;
- no validation path requires network/model/provider execution;
- malformed/deep/large documents fail within configured limits;
- semantic hash is stable for canonical-equivalent input;
- fuzzing can be added without invoking external providers;
- planner repair loops cannot bypass the same validator.

## Related

- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `specs/aios-ir.schema.json`
- `examples/aios-ir/`
- R-IR-003
- Issue #16
