# 83 — Pre-Implementation Architecture Red-Team / Astra Review Packet

## Purpose

Before implementation expands beyond the first validator/deterministic-core spikes, the architecture should receive an **independent adversarial review** whose job is to attack assumptions rather than continue the same design momentum.

This packet is intended for a high-capability review model/session (referred to in project planning as **Astra**) or an expert human architecture/security review.

The reviewer should not be asked to redesign the whole platform from scratch. The job is:

> **Find where the current architecture fails its own goals, where two contracts contradict each other, where an attacker or failure can cross a boundary we think is closed, and where the System-of-Everything ambition creates an unworkable assumption.**

## Review posture

Assume:

- model/planner output can be malicious or badly wrong;
- provider packages can be malicious;
- legacy apps can be hostile;
- input documents can contain prompt injection/malicious data;
- cloud/peer services can lie/fail/disappear;
- a normal user can make mistakes;
- processes and devices crash at the worst possible point;
- old hardware is constrained;
- third-party contributors misunderstand contracts;
- an optimizer/Skill compiler can accidentally weaken security;
- schemas evolve and old Tasks remain in history;
- policy/approval UI can be socially engineered;
- project scope can itself become a failure mode.

Do **not** assume a fully privileged local root/kernel attacker can be defeated by a userspace v0.1 design. Where that threat changes claims, identify the claim boundary rather than pretending it is solved.

## Required reading priority

### Constitution / scope

```text
README.md
AGENTS.md
docs/00-charter.md
docs/01-design-principles.md
docs/15-system-invariants.md
docs/16-requirements.md
docs/53-system-of-everything-staged-roadmap.md
docs/54-unified-platform-fabric-architecture.md
docs/59-pre-codex-foundation-closure-plan.md
docs/81-stage0-architecture-closure-audit.md
```

### Trusted semantic core

```text
docs/25-aios-ir-semantics.md
docs/26-aios-ir-validation-and-lowering.md
docs/28-capability-contracts-and-conformance.md
docs/29-semantic-type-system.md
docs/31-semantic-registry-snapshots.md
docs/39-static-effect-and-authority-analysis.md
docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md
docs/67-v0.1-semantic-reference-and-version-resolution.md
docs/68-aios-ir-v0.1-edge-case-semantics.md
docs/69-v0.1-capability-effect-and-authority-contract-profile.md
docs/70-validator-and-registry-reason-code-catalog.md
docs/71-validator-spike-readiness-checklist.md
docs/72-v0.1-semantic-contract-and-registry-hash-profile.md
```

### Durable execution/security spine

```text
docs/73-v0.1-provenance-journal-and-hash-chain.md
docs/74-v0.1-task-manager-transition-and-cas-contract.md
docs/75-v0.1-artifact-store-content-identity-and-publication.md
docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md
docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md
docs/78-v0.1-execution-binding-and-provider-supervisor.md
docs/79-v0.1-credential-broker-and-secret-mediation.md
docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md
docs/82-stage1-core-substrate-codex-runbook.md
```

### Future fabric interfaces

Review enough to detect core assumptions that would block them:

```text
docs/40-universal-software-fabric.md
docs/42-universal-object-graph-and-data-federation.md
docs/45-cross-domain-transactions-and-compensation.md
docs/48-resource-placement-and-personal-compute-fabric.md
docs/49-identity-resolution-and-object-reconciliation.md
docs/50-adaptive-presentation-and-device-ui.md
docs/51-network-fabric-and-service-connectivity.md
docs/52-cloud-edge-and-service-fabric.md
docs/55-storage-sync-and-replica-fabric.md
docs/56-cryptographic-identity-trust-and-credential-fabric.md
docs/57-component-distribution-supply-chain-and-update-trust.md
docs/58-files-namespaces-and-semantic-projection.md
```

## Primary attack questions

### A — Is AIOS IR actually a sound trust boundary?

Try to break:

- duplicate-key/parser discrepancies;
- Unicode/numeric canonicalization ambiguity;
- hash semantic-view omission that allows behavior to change without hash change;
- metadata smuggling into execution behavior;
- graph explosion/resource denial-of-service;
- fallback/replan recursion;
- type/version selector ambiguity;
- registry snapshot mutable-history attacks;
- verifier bypass through alternate data-flow path;
- execution-class downgrade/upgrade confusion;
- authority/effect declarations narrower than actual behavior;
- provider-specific semantics leaking into supposedly provider-neutral IR.

Question:

> Can two honest implementations produce different executable meaning or semantic hashes from the same accepted IR + registry snapshot?

If yes, treat as high severity.

### B — Can authority be confused or widened?

Attack:

- semantic request -> concrete resource resolution;
- provider/workload identity substitution;
- stale approval after replan/rebinding/destination change;
- wrong-Task grant reuse;
- one-shot use race;
- revocation race;
- Task cancellation vs in-flight protected operations;
- capability contract allows effect but IR asks narrower scope;
- `network.connect` vs `data.egress` confusion;
- approval UI spoofing;
- policy snapshot mismatch;
- Cedar/builtin engine mapping divergence;
- compensation authority;
- confused-deputy through trusted system-service principal.

Question:

> Is every protected action the intersection of semantic intent, concrete binding, principal, resource, current policy, approval, and current grant at point of use?

Find any path where one piece can substitute for another.

### C — Can secrets escape?

Attack Credential Broker assumptions:

- environment inheritance;
- child process inheritance;
- crash dumps/core dumps;
- stdout/stderr/logs;
- provider result fields;
- temporary files;
- `/proc`/debugger access;
- peer/remote placement;
- token exchange that accidentally returns broader token;
- browser/session/cookie integration later;
- legacy apps requiring secret material;
- malicious provider asking trusted broker to perform overly general cryptographic/API operation.

Question:

> Does `BROKERED_OPERATION` ever become a generic oracle that grants more power than exposing the secret would have?

### D — Can crash recovery duplicate or invent effects?

Attack every crash boundary in docs 73–80.

Look for:

- Task state/provenance divergence;
- Artifact blob/metadata ordering holes;
- grant consumption race;
- provider result vs output publication mismatch;
- duplicate retry after lost response;
- external idempotency misuse;
- `OUTCOME_UNKNOWN` accidentally converted into retryable failure;
- concurrency races during recovery;
- time/clock rollback impacting expiry;
- restart with changed policy/provider/registry;
- old Task reopening under new semantics.

Question:

> Can a crash cause an irreversible action to execute twice or make a partial result appear complete?

### E — Can a provider escape the semantic contract?

Attack:

- provider manifest lies;
- conformance suite insufficient;
- native process syscalls broader than declared effect set;
- sandbox profile mismatch;
- generic filesystem/network availability;
- dynamic libraries/plugins loaded after registration;
- provider update after conformance evidence;
- subprocess spawning;
- IPC/session-bus access;
- GPU/device drivers as covert ambient surface;
- Wasm host imports broader than capability contract.

Question:

> What is the actual enforcement mechanism that makes provider behavior a subset of its declared semantic/effect contract rather than a convention?

### F — Can optimization/Skills weaken meaning?

Attack:

- verifier removal/reordering;
- stale cache across changed inputs/contract snapshot;
- compiled target using old authority;
- deterministic claim compiled from historically probabilistic behavior;
- hidden egress introduced by optimized provider;
- Skill parameter accidentally contains private data;
- semantic hash/canonicalization not covering optimization-relevant field;
- invalidation rules incomplete.

Question:

> Can repeated work become cheaper without making it less correct, less private, or more authorized?

### G — Does the future architecture actually compose?

Attack the System-of-Everything assumptions:

- semantic object ontology explosion;
- capability granularity mismatch;
- incompatible domain semantics;
- cross-domain transaction inconsistency;
- identity-resolution false merges;
- representation conversion loss;
- performance overhead of universal handles/brokers;
- specialized expert workflows that resist Task decomposition;
- local/offline constraints;
- huge CAD/media/model data movement;
- real-time/low-latency workloads;
- hardware driver/vendor ecosystems;
- multi-user/org ownership boundaries.

Question:

> Which domains require intentionally specialized deterministic subsystems rather than being forced into a universal abstraction?

The answer may be “many.” That is acceptable if the common semantic/policy boundary still composes them.

### H — Is the GUI/security model believable?

Attack:

- trusted approval surface spoofing;
- phone vs workstation detail mismatch;
- accessibility path bypassing security facts;
- remote display confidentiality;
- direct-manipulation edits not reflected in Task/object provenance;
- user fatigue from too many approvals;
- AI-generated explanations that hide consequential structured facts;
- traditional app escape hatch bypassing controls.

### I — Network/peer/cloud threats

Attack:

- LAN discovery treated as trust;
- peer identity key theft;
- stale peer resource advertisements;
- relay/cloud endpoint substitution;
- service identity resolution poisoning;
- data residency/cost controls;
- cloud outage/retry;
- split-brain/offline mutation conflicts;
- remote model prompt retention;
- untrusted remote provider claiming local semantics.

### J — Supply chain threats

Attack:

- signed malicious provider;
- compromised publisher key;
- package rollback/downgrade;
- dependency confusion;
- registry/catalog takeover;
- conformance evidence from different binary than installed package;
- update broadens authority silently;
- semantic contract package changes beneath same ID/version;
- model weights as executable/supply-chain content.

### K — Scope/engineering viability

Attack the project plan itself:

- too many abstraction layers before useful product;
- contracts that require maintenance disproportionate to benefit;
- components that should be reused rather than reinvented;
- premature distributed/cloud abstractions;
- lack of performance budget;
- likely contributor onboarding failure;
- test/conformance burden;
- licensing barriers to “best of all software” goal;
- bootstrap circular dependencies.

Question:

> What is the smallest path that proves the architecture is superior to “Linux desktop + agent framework” before the project exhausts itself?

## Required finding format

For every finding return:

```text
ID
Severity: FATAL | MAJOR | MODERATE | LOCAL | NOTE
Confidence: HIGH | MEDIUM | LOW
Area
Claim/invariant threatened
Concrete attack/failure scenario
Why current safeguards do or do not stop it
Minimal architecture fix
Files/contracts/ADRs affected
Can implementation proceed before fix? YES/NO/ONLY-#17
Regression test/fixture that should exist
```

Definitions:

### `FATAL`

The central architecture cannot plausibly satisfy a foundational goal without major redesign.

### `MAJOR`

A trusted/security/semantic boundary can fail materially; fix before the affected implementation stage.

### `MODERATE`

Architecture is viable but an important edge case/interface needs correction.

### `LOCAL`

Bounded contract/fixture/implementation detail.

### `NOTE`

Tradeoff, clarification, or future consideration without current blocker.

## Required summary outputs

The review must finish with:

1. top 10 risks by severity;
2. explicit list of **Stage-0 blockers before Issue #17**;
3. explicit list of **Stage-1 blockers after #17 but before provider execution**;
4. invariants that are too vague/unprovable;
5. contracts with hidden ambiguity;
6. places the project is over-engineering too early;
7. places it is under-specifying security/recovery;
8. one proposed simplification that preserves the long-term vision;
9. one scenario that best falsifies the architecture if it fails;
10. recommendation: proceed, proceed-with-specific-fixes, or architecture-rethink — with reasons.

## Reviewer restrictions

Do not:

- rate aesthetics/branding;
- assume one AI vendor must be used;
- solve every finding by “put it in the cloud”;
- solve every finding by “write a new kernel/language”;
- weaken local-first/privacy requirements merely for convenience;
- recommend unrestricted shell/computer-use as the core runtime;
- treat model alignment as OS authorization;
- treat signatures as runtime trust;
- demand production-grade distributed infrastructure before the local proof;
- redesign components that are already sound merely to make the review look novel.

## High-value falsification experiments after review

The review should prefer tests we can run, such as:

```text
1. differential canonicalization across two implementations
2. fuzz invalid IR/registry until parser/validator disagreement
3. simulated Task/provenance SQLite failures at every transaction boundary
4. Artifact publication crash injection at every stage
5. grant revoke/use race
6. malicious provider attempts unrelated file/network/credential access
7. provider update changes runtime behavior while keeping semantic claim
8. stale approval after replan/rebinding
9. external operation lost-response/idempotency recovery
10. compiled Skill verification/effect-broadening differential test
```

## Suggested review prompt

> Red-team this repository as an adversarial systems/security/compiler architect. The goal is not to continue the design or compliment it. Identify contradictions, trust-boundary failures, semantic ambiguity, crash/recovery holes, capability/provider escape routes, authority/credential confused-deputy problems, and project-scope assumptions that could make the architecture fail. Treat models, providers, legacy software, input data, peers, cloud services, and package publishers as potentially hostile. Use the repository invariants/requirements as claims to falsify. Produce concrete attack/failure scenarios and minimal fixes, classify severity, state whether Issue #17/Stage 1 can proceed, and propose regression tests. Do not invent missing evidence or silently change the architecture.

## Principle

> **The next model's job is not to agree with this architecture; it is to earn our confidence by trying hard to break it before implementation makes the mistakes expensive.**
