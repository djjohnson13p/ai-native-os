# 81 — Stage-0 Architecture Closure Audit

## Purpose

This document answers one question:

> **How far can the project responsibly move from architecture into implementation without asking Codex to invent foundational semantics?**

It is a snapshot of pre-implementation closure, not a claim that the architecture is final or that software exists.

## Executive status

**Stage 0 is close enough to begin bounded trusted-core implementation.**

The first implementation task remains Issue #17. The immediate Phase-I contracts following it are now also sufficiently specified for bounded spikes.

This does **not** mean broad AIOS implementation should begin in parallel. The safe implementation sequence remains dependency-driven.

## What is now sufficiently settled

### Semantic computation

Closed enough for spike:

- AIOS IR v0.1 structure;
- exact semantic type/capability major selectors;
- immutable semantic registry snapshots;
- deterministic graph/type/capability/effect validation;
- bounded retries/fallback/replan;
- verification barriers;
- semantic-hash inclusion/exclusion;
- JCS/domain-separated SHA-256 bootstrap;
- provider/runtime/grant separation;
- stable validator reason-code families;
- adversarial/fuzz/resource-limit plan.

Status: **SPIKE_READY**.

### Task lifecycle

Closed enough for spike:

- stable Task identity;
- explicit states/transitions;
- optimistic compare-and-swap revision;
- idempotent transition IDs;
- deterministic transition guards;
- terminal-state rules;
- execution-attempt separation;
- `OUTCOME_UNKNOWN` handling;
- Task/provenance transactional coupling;
- restart recovery flow.

Status: **SPIKE_READY after #17**.

### Artifact/data substrate

Closed enough for spike:

- Artifact identity separate from paths/storage;
- immutable published content instances;
- blob hash vs Artifact ID;
- user import/copy-in bootstrap;
- output allocations;
- staged/finalized publication;
- publication idempotency;
- lineage;
- crash/orphan reconciliation;
- large-data streaming direction;
- export as separate capability.

Status: **SPIKE_READY after Task persistence foundation**.

### Provenance

Closed enough for spike:

- per-Task append stream;
- sequence ordering;
- canonical hash chain;
- Task-state atomicity;
- correction by append, not history rewrite;
- material-event threshold;
- privacy/minimization rule;
- verification/export/checkpoint direction.

Status: **SPIKE_READY**.

### Semantic/provider registry

Closed enough for spike:

- semantic meaning separate from provider registrations;
- immutable Registry Snapshot identity;
- provider registration/conformance evidence;
- activation lifecycle;
- semantic selectors vs exact full contract versions;
- provider availability cannot redefine meaning.

Status: **SPIKE_READY**.

### Authority/policy

Closed enough for spike:

- no ambient AI authority;
- runtime authority request must derive from validated semantic request;
- concrete resource resolution;
- deterministic default-deny policy;
- structured trusted approval;
- deny precedence;
- exact provider/binding/resource scoping;
- opaque token handle + server-side grant record;
- point-of-use validation;
- revocation/usage/expiry;
- policy snapshot attribution;
- network-connect vs data-egress separation;
- compensation/irreversible-effect authority distinction.

Status: **SPIKE_READY**.

### Credential mediation

Closed enough for spike:

- opaque credential handles;
- secret material outside IR/provenance;
- brokered operation preferred;
- short-lived delegation next;
- restricted local injection only when unavoidable;
- explicit exportability classes;
- point-of-use authority + handle checks;
- rotation/revocation;
- provider/binding/service scope;
- fail-closed secure-store behavior.

Status: **SPIKE_READY as a bounded security subsystem; concrete OS/service adapters later**.

### Provider execution

Closed enough for spike:

- immutable Execution Binding;
- provider/workload principal;
- allowlisted runtime environment;
- no shell-as-provider-ABI;
- typed invocation/result boundary;
- point-of-use grants;
- output allocation publication;
- stable supervisor result classes;
- provider exit status vs semantic result distinction;
- timeout/cancellation;
- retry via new attempts/bindings;
- crash-reconciliation behavior.

Status: **SPIKE_READY after Authority/Artifact/Registry exist**.

### Crash recovery

Closed enough for local trusted-core spike:

- persist intent before protected/observable effect;
- durable evidence before completion claim;
- idempotent local Task/Artifact transitions;
- explicit outcome certainty;
- no blind retry of `OUTCOME_UNKNOWN`;
- recovery epoch/assessment;
- one-shot grant consumption durability;
- stale approval/input/binding revalidation;
- Artifact staging/orphan/published reconciliation.

Status: **SPIKE_READY**.

## Interfaces intentionally shaped but not implementation-ready as full systems

These subsystems are represented enough that core code should not accidentally erase their future requirements, but broad implementation is deliberately deferred:

- adaptive Presentation/View Fabric;
- Resource Broker / Personal Compute Fabric;
- Network Fabric;
- cloud/edge/self-hosted services;
- storage replica/sync/namespace fabric;
- Universal Object Graph;
- Domain Packs / Universal Software Fabric;
- component distribution/update marketplace;
- legacy compatibility at broad scale;
- collaboration/multi-user organization control plane.

They remain **DRAFT**, not forgotten.

## Highest remaining pre-Codex risks

The architecture is no longer blocked by broad conceptual questions, but the following should remain explicit review targets:

### 1. Contract cross-consistency

The first real implementation may expose small contradictions between prose, JSON Schema, fixtures, reason-code registries, and SQLite layout.

Mitigation:

- source hierarchy/change-bundle rules;
- Codex stop conditions;
- architecture PR before silently changing semantics.

### 2. Canonicalization/parser reality

JCS, duplicate-key detection, depth limits, Unicode/numeric handling, and exact contract hashing must work in real Rust libraries as specified.

Mitigation:

- Issue #17 first;
- property/fuzz tests;
- no provider/model/network dependency.

### 3. SQLite/filesystem crash behavior

Artifact publication spans filesystem + metadata, so implementation details may reveal durability edge cases.

Mitigation:

- staged publication/orphan recovery;
- simulate crash points;
- never equate bytes with published Artifact.

### 4. Policy backend mapping

Cedar is attractive but remains a proposed implementation backend, not architecture identity.

Mitigation:

- Authority Coordinator contracts are engine-neutral;
- spike typed principal/action/resource/context mapping;
- replace backend if spike fails without changing semantic authority model.

### 5. Provider isolation/runtime ABI

Varlink/WIT/process boundaries are still prototype choices.

Mitigation:

- begin with one local deterministic fixture provider;
- use execution profile/no-ambient authority;
- preserve typed provider invocation contract above transport.

### 6. Project scope

The System-of-Everything mission can create pressure to implement future layers before the trusted substrate works.

Mitigation:

- Stage roadmap/exit gates;
- contract maturity index;
- Codex issue sizing;
- no broad feature work until prior gate proves itself.

## Deliberate non-closure

The following are intentionally **not** decisions we need to finalize before coding the core:

- final project/product name;
- final desktop/mobile GUI toolkit;
- final remote RPC transport;
- final public cloud provider strategy;
- final package marketplace;
- final custom source language syntax/compiler;
- custom kernel;
- full CAD/EDA/office/CRM feature model;
- universal distributed storage protocol;
- safety-critical control architecture;
- final commercial/open-source ecosystem model.

Freezing these prematurely would create more risk than leaving them as explicit later decisions.

## Implementation gate

The project may begin Issue #17 when Codex/Work is available.

After #17 merges successfully, do **not** jump directly to AI planning.

Proceed:

```text
#17 Validator
  ↓
#1 Task Manager
  ↓
#4 Artifact Store
  ↓
#5 Provenance integration/hardening
  ↓
#2 Semantic/Provider Registry runtime
  ↓
#3 Authority Coordinator
  ↓
Credential Broker minimum local boundary
  ↓
Provider Supervisor + one deterministic fixture provider
  ↓
end-to-end deterministic Task without AI
```

Only after this deterministic spine works should Resource/Model/Planner work become the main focus.

## What a successful deterministic spine proves

Before adding a model planner, AIOS should be able to prove:

1. a Task has durable identity/state;
2. input becomes a typed Artifact;
3. an AIOS IR program can be validated deterministically;
4. a semantic capability resolves independently from provider identity;
5. a provider is selected/registered/conforming;
6. requested protected resources are authorized narrowly;
7. provider receives only explicit handles/grants/interfaces;
8. output is staged, validated, published immutably;
9. provenance explains the full attempt;
10. crash/restart can reconcile without duplicating or inventing effects.

That is the minimum trustworthy operating substrate on which AI autonomy should be added.

## Contract maturity source

`specs/contract-maturity.json` is the machine-readable snapshot associated with this audit.

No current contract is `STABLE`; `SPIKE_READY` means only that bounded prototype implementation can rely on it under the change-control rules in `docs/65-contract-maturity-and-architecture-change-control.md`.

## Recommendation at this point

Continue small architecture cross-checks in chat, but **do not continue expanding the conceptual surface area indefinitely**.

The highest-value next step after the review/red-team packet is implementation evidence from Issue #17.

A new architecture document should now generally satisfy one of these tests:

- it closes a concrete Stage-0 trusted-boundary ambiguity;
- it defines a machine contract/negative fixture needed by an already-sequenced implementation issue;
- it records a discovered contradiction/decision;
- it prepares an adversarial review of the existing architecture.

Otherwise defer it until implementation teaches us something.

## Principle

> **Stage 0 is complete enough when the next unknowns are best answered by executable tests rather than more speculative architecture.**
