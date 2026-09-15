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

Status: first drafts exist.

Current contracts:

- task plan
- capability manifest
- hardware profile
- artifact handle
- capability token
- provenance event

Before implementation:

- create positive and negative examples;
- define schema versioning convention;
- identify fields that are architecture vs prototype implementation detail;
- ensure no contract assumes one model vendor.

### A3 — Threat-model expansion

Before implementation:

- trust-boundary diagram;
- principal model;
- capability-token semantics;
- secret mediation;
- external data egress flow;
- legacy habitat boundaries;
- skill supply-chain model;
- model/provider compromise cases.

### A4 — Research decisions

Resolve or narrow:

- Linux base / image/update/rollback strategy (#14);
- service boundaries / IPC / languages (#15);
- sandbox/container/VM primitives;
- first Windows compatibility integration;
- first local-model runtime;
- optional remote-model adapter shape;
- prototype database/provenance storage.

### A5 — UX specification

Create wire-level/user-flow descriptions for:

- task submission;
- artifact attachment/reference;
- clarification;
- approvals;
- running task inspection;
- plan/provenance detail;
- final artifact handling;
- traditional app launch.

No polished desktop design is required before v0.1.

## Track B — Implementation-ready issues

Current issue set:

| Issue | Workstream | Primary dependency |
| --- | --- | --- |
| #1 | persisted task model/state machine | contracts |
| #2 | capability registry/conformance | capability schema |
| #3 | deterministic policy/task authority | principal/token semantics |
| #4 | artifact/data handle store | artifact contract |
| #5 | provenance service | task + artifact IDs |
| #6 | hardware profiler/resource broker | hardware contract |
| #7 | model runtime adapters | resource + egress policy |
| #8 | typed planner/orchestrator | #1 #2 #3 |
| #9 | deterministic demo providers | #2 #4 |
| #10 | Universal App Broker fixture | #3 #5 + compatibility research |
| #11 | adversarial/recovery harness | all core boundaries |
| #12 | skill compilation proof | successful #8/#9 path |
| #13 | task-first shell | #1 #5 #8 |
| #14 | Linux base/update research | architecture |
| #15 | service/IPC/language research | architecture |

## Recommended implementation order

### Phase I — contracts and deterministic substrate

1. Close research decisions #14 and #15 with ADRs.
2. Implement #1 task model.
3. Implement #4 artifact handle/store.
4. Implement #5 provenance service.
5. Implement #2 capability registry.
6. Implement #3 policy/authority.

At the end of Phase I, we should be able to create a task, attach an artifact, authorize a deterministic capability, execute a tiny fixture, and inspect provenance **without any AI planner at all**.

That is intentional: it proves the operating substrate before introducing probabilistic reasoning.

### Phase II — orchestration and adaptive execution

7. Implement #6 hardware/resource broker skeleton.
8. Implement #7 model runtime interface.
9. Implement #8 planner/orchestrator.
10. Implement #9 deterministic Demonstration A providers.

At the end of Phase II, Demonstration A should work through the task-first orchestration path.

### Phase III — transition strategy and user interaction

11. Implement #13 task-first shell.
12. Implement #10 Universal App Broker proof.
13. Implement #12 skill compilation proof.

### Phase IV — hardening

14. Expand and automate #11 adversarial/recovery harness.
15. Run full `docs/17-v0.1-acceptance-tests.md` gate.
16. Update architecture docs to reflect what was actually built.

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

If an issue still contains a major architecture question, we should resolve the question before asking Codex to infer the answer from implementation convenience.

## What we should avoid before implementation

Do not spend pre-implementation time on:

- branding/logo work;
- a custom kernel;
- a full installer image;
- broad desktop theming;
- dozens of legacy compatibility targets;
- training a foundation model;
- building equivalents of Word/Photoshop/Unreal as monolithic applications;
- performance micro-optimization before contracts exist;
- committing to mobile hardware support before the control-plane abstractions are proven.

## Definition of "ready for the first serious Codex session"

We are ready when:

- contracts have example fixtures;
- the principal/authority model is precise;
- v0.1 service boundaries are selected;
- the prototype Linux environment is selected;
- the task/artifact/provenance data model is settled enough for migrations;
- the first implementation issues have acceptance tests and clear dependencies;
- no foundational issue requires Codex to decide what the OS fundamentally means.
