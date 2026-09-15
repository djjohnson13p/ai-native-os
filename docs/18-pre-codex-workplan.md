# 18 — Pre-Codex Work Plan and Implementation Dependency Graph

This plan distinguishes work that should be resolved through architecture/research before substantial coding from work that becomes a bounded implementation task once Codex/Work is available.

The goal is to arrive at implementation with **fewer ambiguous decisions**, not with more speculative code.

## Track A — Architecture hardening (chat-friendly)

These can be advanced substantially through design review, research, schemas, examples, and ADRs before implementation begins.

### A1 — Core vocabulary and invariants

Status: initial draft complete.

Relevant files:

- `docs/14-terminology.md`
- `docs/15-system-invariants.md`
- `docs/16-requirements.md`

### A2 — Contract schemas

Status: substantial first drafts exist.

Current contracts include:

- AIOS semantic IR;
- semantic capability contract;
- semantic type contract;
- execution binding;
- Skill manifest;
- task plan and persisted task record;
- provider/capability manifest;
- hardware profile;
- artifact handle;
- capability token;
- policy decision;
- provenance event;
- execution/sandbox profile;
- model request/result;
- legacy compatibility profile.

Before/while implementation begins:

- keep positive and negative examples synchronized;
- finalize schema versioning convention;
- identify fields that are architecture vs prototype implementation detail;
- ensure no contract assumes one model vendor;
- add automated schema/semantic fixture validation.

### A3 — Threat-model expansion

Status: initial principal/trust-boundary work complete; implementation tests still required.

Relevant work:

- trust boundaries;
- principal/authority model;
- capability-token semantics;
- secret mediation;
- external data egress flow;
- legacy habitat boundaries;
- skill supply-chain model;
- model/provider compromise cases;
- adversarial IR fixtures.

### A4 — Research decisions

Resolve or narrow:

- Linux base / image/update/rollback strategy (#14);
- service boundaries / IPC / languages (#15);
- AIOS IR/language path (#16);
- Cedar authorization spike;
- Varlink/service-boundary spike;
- sandbox/container/VM primitives;
- first Windows compatibility integration;
- first local-model runtime;
- optional remote-model adapter shape;
- prototype database/provenance storage.

### A5 — UX specification

Initial task-first object/shell model exists.

Continue wire-level/user-flow descriptions for:

- task submission;
- artifact attachment/reference;
- clarification;
- approvals;
- running task inspection;
- plan/IR/provenance detail;
- final artifact handling;
- traditional app launch.

No polished desktop design is required before v0.1.

### A6 — AI-native execution semantics

Status: first formal pass complete; ready for validator spike.

Relevant files:

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/27-skill-compilation-and-adaptive-optimization.md`
- `docs/28-capability-contracts-and-conformance.md`
- `docs/29-semantic-type-system.md`
- `docs/30-aios-ir-reference-validator-plan.md`
- `specs/aios-ir.schema.json`
- `specs/capability-contract.schema.json`
- `specs/type-contract.schema.json`
- `specs/execution-binding.schema.json`
- `specs/skill-manifest.schema.json`
- `examples/aios-ir/`

This track is central to ensuring the project does not become merely "AI generates Python/Rust commands for a conventional desktop."

## Track B — Implementation-ready issues

Current issue set:

| Issue | Workstream | Primary dependency |
| --- | --- | --- |
| #1 | persisted task model/state machine | task contracts |
| #2 | capability registry/conformance | semantic capability/type contracts |
| #3 | deterministic policy/task authority | principal/token semantics |
| #4 | artifact/data handle store | artifact contract |
| #5 | provenance service | task + artifact IDs |
| #6 | hardware profiler/resource broker | hardware contract |
| #7 | model runtime adapters | resource + egress policy |
| #8 | typed planner/orchestrator | #1 #2 #3 #17 |
| #9 | deterministic demo providers | #2 #4 |
| #10 | Universal App Broker fixture | #3 #5 + compatibility research |
| #11 | adversarial/recovery harness | all core boundaries |
| #12 | skill compilation proof | successful #8/#9 path + Skill/IR contracts |
| #13 | task-first shell | #1 #5 #8 |
| #14 | Linux base/update research | architecture |
| #15 | service/IPC/language research | architecture |
| #16 | define AIOS IR / custom-language decision criteria | architecture |
| #17 | deterministic AIOS IR validator/normalizer/hash | #16 semantic draft |

## Recommended implementation order

### Phase 0 — semantic boundary spike

1. Close/narrow #14 and #15 enough to create the development environment.
2. Keep #16 open as the language/IR research umbrella while treating current v0.1 semantics as the first experiment.
3. Implement #17 deterministic AIOS IR validator/normalizer/hash CLI/library.
4. Run IR1–IR8 fixture gates without a model planner.

At the end of Phase 0 we should have a machine-verifiable answer to: **what does an AI-native program mean, and can untrusted generated programs be rejected deterministically?**

This is intentionally before a full planner.

### Phase I — deterministic substrate

5. Implement #1 task model.
6. Implement #4 artifact handle/store.
7. Implement #5 provenance service.
8. Implement #2 semantic capability/type registry plus provider conformance boundary.
9. Implement #3 policy/authority.
10. Bind one tiny validated AIOS IR fixture to a deterministic provider through an execution binding.

At the end of Phase I, we should be able to create a task, attach an artifact, validate semantic IR, authorize a deterministic capability, bind/execute a tiny fixture, and inspect provenance **without any AI planner at all**.

That is intentional: it proves the operating substrate before introducing probabilistic reasoning.

### Phase II — orchestration and adaptive execution

11. Implement #6 hardware/resource broker skeleton.
12. Implement #7 model runtime interface.
13. Implement #8 planner/orchestrator as a producer of proposals that must lower to valid AIOS IR.
14. Implement #9 deterministic Demonstration A providers.

At the end of Phase II, Demonstration A should work through the task-first orchestration path while preserving the semantic IR/policy boundary.

### Phase III — transition strategy and user interaction

15. Implement #13 task-first shell.
16. Implement #10 Universal App Broker proof.
17. Implement #12 Skill compilation/reuse proof.

### Phase IV — hardening

18. Expand and automate #11 adversarial/recovery harness.
19. Run full `docs/17-v0.1-acceptance-tests.md` gate, including IR1–IR8.
20. Benchmark fresh planning vs IR reuse vs compiled Skill execution.
21. Update architecture docs to reflect what was actually built.
22. Use results to decide whether a human-facing/custom AI-oriented language is justified beyond structural AIOS IR.

## Codex issue sizing rule

An implementation issue is ready for Codex only when it specifies:

1. purpose;
2. architecture contracts it must obey;
3. files/modules it may reasonably create or modify;
4. inputs/outputs;
5. security boundary;
6. acceptance tests;
7. explicit non-goals;
8. dependencies that are already merged or mocked.

If an issue still contains a major architecture question, resolve the question before asking Codex to infer the answer from implementation convenience.

## Special rule for AI-generated implementation

Because AI will contribute heavily to this project, generated code must not be allowed to redefine semantic or security contracts accidentally.

Codex/agents should be instructed to:

- treat ADRs/invariants/contracts as constraints;
- propose contract changes explicitly rather than silently working around them;
- add tests for validator/policy boundaries;
- avoid arbitrary shell/eval escape hatches in core runtime paths;
- keep provider-specific code behind provider contracts;
- preserve reason codes and semantic hashes when refactoring.

## What we should avoid before implementation

Do not spend pre-implementation time on:

- branding/logo work;
- a custom kernel;
- a new general-purpose language/compiler before IR evidence;
- a full installer image;
- broad desktop theming;
- dozens of legacy compatibility targets;
- training a foundation model;
- building equivalents of Word/Photoshop/Unreal as monolithic applications;
- performance micro-optimization before contracts exist;
- committing to mobile hardware support before the control-plane abstractions are proven.

## Definition of "ready for the first serious Codex session"

We are ready when:

- AIOS IR semantics and fixtures are sufficient for #17;
- core contracts have example fixtures;
- the principal/authority model is precise;
- v0.1 service boundaries are selected/narrowed;
- the prototype Linux environment is selected/narrowed;
- the task/artifact/provenance data model is settled enough for migrations;
- the first implementation issues have acceptance tests and clear dependencies;
- no foundational issue requires Codex to decide what the OS fundamentally means.

The ideal first Codex work should feel constrained and test-driven rather than creatively architectural.
