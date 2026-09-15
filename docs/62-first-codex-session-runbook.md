# 62 — First Codex Session Runbook

## Purpose

When Codex/Work capacity becomes available, the first serious implementation session should start from a bounded, high-signal task rather than the full AIOS vision.

The recommended first assignment remains GitHub Issue #17:

> Implement the deterministic AIOS IR validator, normalizer, static effect summary, and semantic hash boundary.

This runbook is designed so the first session spends its effort on engineering/testing rather than rediscovering architecture.

## Why Issue #17 goes first

It proves the most important distinction in the project:

```text
AI/model proposes program
        ↓
trusted deterministic system decides whether the program has valid meaning
        ↓
policy/runtime may later decide whether/how it executes
```

If this boundary is weak, every later agent/capability/cloud/GUI feature inherits ambiguity.

If it is strong, later model/planner experimentation is much safer.

## Preflight

Before changing files, Codex should:

1. read root `AGENTS.md`;
2. read Issue #17 and its comments;
3. inspect repository status/tree;
4. read the required architecture files listed below;
5. inspect all validator schemas/fixtures;
6. identify whether a Rust workspace already exists;
7. report any direct contradiction among docs/schemas/fixtures before implementing;
8. do not resolve architecture contradictions silently.

## Required reading

### Constitution / acceptance

```text
docs/15-system-invariants.md
docs/16-requirements.md
docs/17-v0.1-acceptance-tests.md
docs/59-pre-codex-foundation-closure-plan.md
```

### AIOS IR semantics

```text
docs/25-aios-ir-semantics.md
docs/26-aios-ir-validation-and-lowering.md
docs/28-capability-contracts-and-conformance.md
docs/29-semantic-type-system.md
docs/30-aios-ir-reference-validator-plan.md
docs/31-semantic-registry-snapshots.md
docs/39-static-effect-and-authority-analysis.md
docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md
docs/61-validator-test-fuzz-and-resource-limit-matrix.md
```

### ADRs

At minimum:

```text
docs/adr/0011-own-ai-native-ir-before-new-general-purpose-language.md
docs/adr/0012-structural-aios-ir-json-bootstrap.md
docs/adr/0013-separate-semantic-capability-contracts-from-providers.md
docs/adr/0014-exact-semantic-types-explicit-conversions-v0-1.md
docs/adr/0015-aios-ir-validator-in-trusted-core.md
docs/adr/0016-bootstrap-languages-are-not-semantic-abi.md
```

### Contracts / fixtures

```text
specs/aios-ir.schema.json
specs/capability-contract.schema.json
specs/type-contract.schema.json
specs/registry-snapshot.schema.json
specs/ir-validation-result.schema.json
specs/effect-summary.schema.json
examples/aios-ir/
```

## Recommended branch

```text
codex/issue-17-ir-validator
```

If project branch naming conventions change before the session, follow current repository policy rather than this example.

## Exact assignment prompt

A suitable first prompt is:

> Implement GitHub Issue #17 in this repository. Read and obey `AGENTS.md` first, then Issue #17 and the architecture/contracts/fixtures it references. Build the smallest Rust workspace/library + CLI necessary to parse, structurally and semantically validate, normalize/canonicalize, derive static effect summaries, and compute a tagged semantic hash for AIOS IR v0.1 against an immutable semantic registry snapshot. Do not implement a model planner, provider execution, network access, Cedar authorization, task daemon, GUI, cloud integration, or arbitrary shell/code execution. Treat malformed/hostile input as normal input and never panic. Reject duplicate JSON keys. Preserve stable machine-readable reason codes. Run all applicable fixture/unit/property/limit tests. If a repository contract is contradictory or unimplementable, stop at that boundary, document the exact conflict, and propose a contract/ADR change rather than silently changing semantics. Finish by opening a PR that states invariants preserved, tests run, known limitations, and any architecture follow-up.

## Implementation sequence

Recommended order inside the session:

### Step 1 — workspace bootstrap

Create only the minimum workspace needed by `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`.

Do not scaffold the future full daemon/UI/provider ecosystem.

### Step 2 — strict parser + limits

Prove:

- malformed JSON rejection;
- duplicate-key rejection;
- size/depth limits;
- typed deserialization;
- no panic.

### Step 3 — immutable semantic registry loader

Load fixture type/capability contracts without network/provider code.

Reject duplicate/conflicting contract identity.

### Step 4 — graph/reference/type/capability passes

Implement validation passes in deterministic order with stable diagnostics.

### Step 5 — effect/authority/egress consistency

Derive effect summary and reject semantic contradictions.

Do **not** grant authority.

### Step 6 — canonicalization + semantic hash

Only after full semantic validity.

Prove equivalence and difference cases.

### Step 7 — CLI

Expose validator library through simple development CLI.

CLI must not create alternate semantic logic.

### Step 8 — tests/fuzz smoke

Run architecture fixtures plus unit/property/resource-limit tests in `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`.

### Step 9 — documentation reconciliation

If implementation clarified an ambiguity, update docs/fixtures through an explicit rationale—not silent code behavior.

### Step 10 — PR

PR should reference Issue #17 and remain narrowly scoped.

## Stop conditions

Codex should pause/report rather than invent behavior when it encounters:

- two contracts assigning different meaning to the same field;
- ambiguity over whether a field participates in semantic hashing;
- a fixture contradicting an accepted/proposed controlling ADR;
- inability to detect duplicate keys safely with selected parse path;
- dependency whose behavior would violate no-network/no-provider validation boundary;
- need to add authority semantics not specified in the issue;
- need to execute provider code to validate semantic meaning;
- need to add a broad generic JSON escape hatch for security-relevant fields;
- a proposed optimization that removes verification/effect semantics.

## Explicit non-goals for first session

Do not implement:

- planner/model routing;
- OpenAI/Anthropic/Gemini/etc adapters;
- Cedar policy engine;
- provider supervisor/runtime;
- Varlink provider IPC;
- SQLite task store;
- GUI/TUI shell beyond CLI output;
- network/cloud/peer execution;
- package manager;
- legacy application broker;
- Skill compiler/MLIR lowering;
- custom AIOS source language.

Those have separate dependency gates.

## Expected deliverables

At minimum:

```text
Cargo workspace/lockfile
trusted validator library
immutable fixture registry loader
strict parser/limits
graph/type/capability/effect validation
canonicalizer/hash
structured reason codes/results
aios-ir development CLI
unit + architecture-fixture tests
property/fuzz smoke harness or clearly staged fuzz target
README/developer instructions for running validator tests
PR linked to Issue #17
```

## PR checklist

The PR description should answer:

```text
Issue:
Architecture docs followed:
Invariants preserved:
Schemas/contracts changed? why?:
Reason codes added/changed:
Tests run:
Network/model/provider execution during validation? (must be no):
Known limitations:
Follow-up issues/ADRs needed:
```

## Review order

When the PR exists, review should occur in this order:

1. architecture/semantic correctness;
2. security boundary correctness;
3. fixture/reason-code completeness;
4. canonicalization/hash determinism;
5. parser/resource-limit robustness;
6. code quality/performance;
7. ergonomics/CLI polish.

Do not approve a prettier/faster implementation that weakens the semantic/security boundary.

## After Issue #17

If the validator is successful, the next implementation sequence is:

```text
Task persistence
→ Artifact store
→ Provenance
→ semantic/provider registry
→ deterministic authority/policy
→ one deterministic Execution Binding/provider fixture
```

Still without requiring an AI planner.

## Principle

> **The first Codex task should prove that AIOS can safely reject an AI-generated program before we ask AIOS to execute one.**
