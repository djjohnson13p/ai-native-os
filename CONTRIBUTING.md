# Contributing

The project is currently transitioning from architecture hardening toward bounded v0.1 implementation.

Contributions should preserve the architecture constitution while turning individual contracts into small testable components.

## Start with the issue and repository instructions

Before changing code/contracts:

1. read root `AGENTS.md`;
2. read the GitHub issue/workstream;
3. read the smallest relevant architecture/ADR/schema/fixture set;
4. identify the current roadmap stage and dependencies;
5. do not infer missing architecture from implementation convenience.

## High-value contribution types

Current priorities include:

- architecture/security review;
- threat-model critiques;
- semantic contract/fixture refinement;
- conformance/adversarial-test design;
- small bounded implementation spikes tied to open issues;
- compatibility/resource/network/storage research that preserves current stage boundaries;
- documentation that reduces ambiguity for implementation/review.

Large implementation efforts should not outrun the stage gates in `docs/53-system-of-everything-staged-roadmap.md`.

## Architecture changes

Major changes should be proposed as ADRs under `docs/adr/` with:

- context;
- decision;
- alternatives considered;
- consequences;
- security/privacy impact;
- compatibility/migration impact.

If changing a semantic/security contract, update the relevant:

- design document/ADR;
- schema;
- positive fixtures;
- negative/adversarial fixtures;
- acceptance tests/reason codes.

Do not silently change authority semantics through a schema/code-only edit.

## Invariants

Every substantial PR should state whether it:

- preserves all invariants in `docs/15-system-invariants.md`;
- intentionally refines an invariant; or
- proposes changing an invariant through an explicit architecture decision.

## Implementation discipline

Prefer the smallest component that proves a reusable abstraction.

Do not solve a local problem by introducing:

- ambient user authority;
- unrestricted filesystem/network/secret access;
- provider/model/vendor semantic lock-in;
- arbitrary shell/eval escape hatches;
- hidden cloud dependency;
- application-specific point-to-point integration when a semantic capability/object boundary is required.

## AI-generated contributions

AI/Codex-generated code is welcome under the same review bar as human-authored code.

Agent output must not be treated as authoritative merely because it compiles or passes a happy-path demo.

Security-sensitive AI-generated changes require explicit negative/adversarial tests and architecture review.

## Fixtures and data

Use synthetic test data only.

Never commit:

- passwords/tokens/private keys;
- personal documents/data;
- production service responses containing private data;
- real capability grants/credential material.

## Definition of done

A contribution is not done until it documents:

- issue addressed;
- architecture/contracts followed;
- invariants preserved/changed;
- tests/checks run and results;
- known limitations/non-goals;
- migration/compatibility impact if any;
- follow-up issue/ADR required if the implementation exposed an architecture gap.

## Choose the current implementation work

Issue #17's deterministic validator is complete. Start with the active issue
and gate recorded in [Issue #38](https://github.com/djjohnson13p/ai-native-os/issues/38),
then follow `docs/82-stage1-core-substrate-codex-runbook.md` in stage order.
The following documents remain useful background for the completed validator:

- `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`
- `docs/62-first-codex-session-runbook.md`

The project should prove deterministic semantic validation before allowing model-generated plans to drive real execution.
