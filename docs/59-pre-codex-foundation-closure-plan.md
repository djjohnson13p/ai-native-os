# 59 — Pre-Codex Foundation Closure Plan

Historical pre-implementation plan. Issue #17 is closed after PR #36 merged
on 2026-09-20. For current work, use Issue #38, the active issue/PR, and
`docs/82-stage1-core-substrate-codex-runbook.md`.

## Purpose

The architecture has intentionally expanded to cover the long-term System-of-Everything destination. Before implementation accelerates, the project needs a closure discipline: decide which architecture questions must be settled now, which only need a stable interface, and which are deliberately deferred.

This document is the gate between broad architectural exploration and the first serious implementation phase.

## Three decision classes

### Class A — must be sufficiently settled before trusted-core implementation

These affect security, identity, persistence, or semantic compatibility directly:

- AIOS IR structural/semantic rules;
- semantic type/capability contracts;
- validator diagnostics/canonical identity;
- Task state/revision model;
- Artifact identity/content hashes;
- provenance linkage;
- principal/authority semantics;
- credential-handle boundary;
- provider registration/conformance boundary;
- execution binding;
- local persistence transaction/recovery model;
- effect/authority analysis;
- no-ambient-network/no-ambient-secret rules;
- component identity/version attribution.

Implementation may reveal refinements, but Codex should not invent these meanings opportunistically.

### Class B — interface must be stable enough now; full implementation can wait

These are strategically important but not required to execute Demonstration A locally:

- Resource Broker placement contract;
- Presentation/View contract;
- Network service/transfer contract;
- peer trust/device identity;
- Storage Replica/Namespace Projection contract;
- Universal Object Graph identity/source-of-truth model;
- Domain Pack manifests;
- cloud/remote service descriptors;
- package/distribution manifests;
- compatibility habitat contracts.

The goal is to prevent v0.1 code from assuming these concerns do not exist.

### Class C — deliberately deferred until evidence exists

- new kernel;
- custom driver architecture;
- production distributed consensus;
- universal mesh networking;
- real-time multi-writer sync for all object types;
- public package marketplace;
- production multi-cloud control plane;
- complete office/CRM/CAD/EDA suites;
- custom general-purpose source language/compiler;
- safety-critical physical control;
- global entity-resolution system.

## Current implementation entry order

The first coding sequence remains:

```text
#17 AIOS IR validator/canonicalizer
        ↓
Task + Artifact + Provenance persistence
        ↓
semantic registry / provider conformance
        ↓
policy/authority coordinator
        ↓
one deterministic provider execution binding
        ↓
hardware/resource broker skeleton
        ↓
model/planner proposal path
        ↓
flagship Demonstration A
```

## First-session rule

The first serious Codex session SHOULD NOT begin by implementing the GUI, cloud, peer networking, package manager, or Universal Object Graph.

It should implement the smallest trusted semantic boundary with the strongest existing fixtures: Issue #17.

## Contract freeze levels

Pre-v1 contracts are not frozen globally. Instead use levels:

```text
DRAFT       architecture can change freely with rationale
SPIKE-READY bounded implementation may rely on current shape
PROTOTYPE   implementation exists; breaking changes require migration/tests
STABLE      compatibility commitment for third parties
```

Before Codex implementation, contracts used by the assigned issue should be marked at least `SPIKE-READY` in issue/documentation context.

## Architecture-change rule during implementation

If Codex/Work discovers that a contract cannot be implemented cleanly:

1. stop at the contract boundary;
2. document the concrete incompatibility;
3. propose an ADR/schema change;
4. update fixtures/acceptance tests;
5. only then continue implementation.

Implementation convenience must not silently redefine the system.

## Definition of Stage-0 closure

Stage 0 is sufficiently closed for implementation when:

- #17 has no unresolved semantic ambiguity that would require compiler-language invention;
- local Task/Artifact/Provenance persistence contracts are coherent;
- authority policy can deterministically allow/deny fixture actions;
- one provider can be bound without ambient filesystem/network/credential access;
- recovery semantics for crash-before/after-output are specified;
- package/provider version is attributable in provenance;
- future presentation/network/cloud/storage/object layers have explicit interfaces that do not leak into semantic identity;
- the current implementation issue can be completed without selecting permanent solutions for deferred Class-C problems.

## What architecture work should continue in chat

High-value pre-implementation work still suitable for chat includes:

- negative/adversarial fixture expansion;
- reason-code normalization;
- contract cross-consistency audits;
- example end-to-end state transitions;
- Cedar policy examples/spike plan;
- storage/credential/package trust threat cases;
- first provider/validator fuzz/property requirements;
- licensing/governance decisions;
- Codex prompt/runbook creation.

## Principle

> **Explore the whole destination, freeze only the boundaries needed for the next experiment, and never make Codex guess the constitution of the system.**
