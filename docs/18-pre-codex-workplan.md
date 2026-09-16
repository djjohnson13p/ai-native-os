# 18 — Pre-Codex Work Plan and Implementation Dependency Graph

## Purpose

This file is now the compact dependency map between architecture work and implementation.

The project has deliberately explored a very large long-term destination while keeping the first build narrow. Stage-0 architecture is now **closed enough for bounded trusted-core implementation**; additional broad conceptual expansion should be deferred unless it closes a concrete contradiction or security/recovery gap.

Primary status sources:

- `docs/53-system-of-everything-staged-roadmap.md`
- `docs/59-pre-codex-foundation-closure-plan.md`
- `docs/81-stage0-architecture-closure-audit.md`
- `specs/contract-maturity.json`

## Current architecture state

### SPIKE_READY trusted-core workstreams

```text
AIOS IR validator/canonicalizer/effect analysis      #17
Task Manager / CAS transitions                       #1
Artifact Store / immutable publication               #4
Provenance journal/hash chain                        #5
Semantic Registry + Provider Registry                #2
Authority Coordinator                                #3
Credential Broker minimum boundary                   #28 subset
Provider Supervisor + one deterministic provider     #30
Crash/recovery/outcome certainty                      #11 subset
```

`SPIKE_READY` means a bounded implementation may rely on the current contract under change-control rules. It does not mean public/stable compatibility is frozen.

### DRAFT interface-shaped future fabrics

```text
Resource / Personal Compute Fabric        #20
Presentation Fabric                        #22
Network Fabric                             #23
Cloud/Edge/Remote Service Fabric           #24
Identity resolution / Object federation    #25
Storage/Replica/Namespace Fabric           #27
Component distribution / supply chain      #29
Universal Software/Object Fabric           #19/#21
```

These interfaces exist so the trusted core does not accidentally make them impossible. Their broad implementations are not Stage-1 dependencies.

## First serious Codex task

**Issue #17 remains first.**

The exact runbook is `docs/62-first-codex-session-runbook.md`.

The validator must prove:

```text
untrusted bytes
→ strict parse/limits
→ structural schema
→ immutable semantic Registry Snapshot
→ graph/reference validation
→ exact semantic type/capability validation
→ effect/authority/egress/fallback consistency
→ static effect summary
→ normalized semantic view
→ canonical semantic hash
```

with:

- stable machine reason codes;
- no model judgment;
- no provider execution;
- no network/catalog lookup;
- no policy grant;
- no arbitrary shell/code execution.

Implementation stop conditions are documented in docs 62/71/AGENTS.md.

## Stage-1 deterministic implementation sequence

After #17 merges successfully, follow `docs/82-stage1-core-substrate-codex-runbook.md`:

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
minimal Credential Broker (#28 subset)
  ↓
#30 Provider Supervisor + artifact.hash@1 fixture provider
  ↓
Stage-1 integrated deterministic spine gate
```

The Stage-1 test gate is `docs/86-stage1-deterministic-spine-acceptance-tests.md`.

At the end of Stage 1, AIOS must execute/recover one typed deterministic capability end-to-end **without any AI model**.

## Why the planner waits

The planner/model layer is intentionally downstream of the trusted deterministic substrate.

The correct direction is:

```text
model/planner proposes
        ↓
trusted validator accepts/rejects meaning
        ↓
trusted authority/resource/provider systems bind execution
        ↓
trusted runtime executes under bounded authority
```

not:

```text
model says what to run
→ host executes it
```

## Phase 2 — adaptive orchestration

After the deterministic spine passes its gate:

```text
#6 hardware profiler / local Resource Broker skeleton
→ #7 model runtime interface
→ #8 typed planner/orchestrator (proposal producer only)
→ #9 Demonstration A deterministic providers
→ local/alternate-provider placement proof
→ #12 repeated Skill/reuse proof
```

The planner must lower to the already-trusted semantic boundary rather than bypass it.

## Phase 3 — user interaction / transition

Then:

```text
#13 Task-first shell
→ #22 adaptive compact/desktop View projection
→ #10 Universal App Broker compatibility proof
→ narrow namespace/file projection needed for user/legacy interoperability
```

A polished universal desktop is not required before these proofs.

## Phase 4 — v0.1 hardening

Run:

- full `docs/17-v0.1-acceptance-tests.md`;
- Stage-1 regression suite from docs86;
- #11 adversarial/crash/recovery tests;
- planner vs IR/Skill reuse benchmarks from docs32;
- architecture reconciliation against what was actually implemented.

Do not claim v0.1 complete because a demo works if the trusted/adversarial gates fail.

## Later dependency order

After v0.1 substrate/UI proof:

```text
Personal Compute + Network + peer Storage
→ Tier-0 Universal Object Graph / first cross-domain Domain Pack
→ productivity/business capability coverage
→ creative/developer capability coverage
→ engineering (CAD/EDA/CAE/CAM/scientific) fabric
→ cloud/org/collaboration scale
→ physical/ambient capability fabric
→ continuous AIOS language/toolchain maturation
```

See docs53 for stage exit gates.

## Current issue map

| Issue | Workstream | Timing/dependency |
| --- | --- | --- |
| #1 | persisted Task Manager/state | Stage 1 after #17 |
| #2 | semantic/provider registry + conformance | Stage 1 after Task/Artifact/Provenance base |
| #3 | deterministic authority/policy | Stage 1 after registry; before protected provider execution |
| #4 | Artifact Store/lineage | Stage 1 after Task base |
| #5 | provenance | Stage 1; integrated with Task/Artifact commits |
| #6 | hardware profiler/Resource Broker | Phase 2 |
| #7 | model runtime adapters | Phase 2 after trusted spine |
| #8 | typed planner/orchestrator | Phase 2 after #17/#1/#2/#3 |
| #9 | Demonstration A providers | Phase 2 |
| #10 | Universal App Broker | Phase 3 transition proof |
| #11 | adversarial/recovery harness | cross-cutting; Stage-1 and v0.1 hardening |
| #12 | Skill compilation/reuse | after successful planner/provider path |
| #13 | Task-first shell | Phase 3 |
| #14 | Linux base/update/rollback | architecture + implementation environment experiment |
| #15 | service/IPC/language | architecture + bounded transport experiment |
| #16 | AIOS IR/custom-language criteria | architecture umbrella; do not build general language yet |
| #17 | deterministic AIOS IR validator | **FIRST CODEX SPIKE** |
| #18 | WIT/Wasm + MLIR experiments | after/alongside semantic validator evidence |
| #19 | Universal Software Fabric / Domain Packs | architecture now; implementation after core/object stage |
| #20 | Resource/Personal Compute Fabric | Phase 2 local skeleton; peer expansion later |
| #21 | cross-domain transactions/compensation | before consequential multi-domain mutation |
| #22 | adaptive Presentation/View contracts | interface now; implementation Phase 3 |
| #23 | Network Fabric | post-core peer stage |
| #24 | cloud/edge/self-hosted services | after Network/Resource foundations |
| #25 | identity resolution / merge/split | before broad federated Object deployment |
| #26 | staged System-of-Everything roadmap | ongoing governance/meta |
| #27 | Storage/Replica/Namespace Fabric | local Artifact first; distributed later |
| #28 | crypto identity/peer trust/credentials | credential subset Stage 1; peer identity later |
| #29 | component distribution/supply chain | attribution now; package ecosystem later |
| #30 | local deterministic Provider Supervisor | Stage 1 after #1/#2/#3/#4/#5/#17 |

## Contract/change discipline

Every Codex issue must state:

1. roadmap stage;
2. architecture sources/contracts;
3. allowed files/modules;
4. inputs/outputs;
5. trusted/untrusted boundary;
6. acceptance tests;
7. explicit non-goals;
8. already-merged/mocked dependencies.

If implementation finds a direct source contradiction:

```text
stop at boundary
→ document exact conflict
→ propose ADR/schema/fixture/test change
→ reconcile contract bundle
→ continue only after decision
```

Do not let code silently become the architecture.

## Remaining useful chat-only work

High-value work before/alongside the first implementation is now limited mainly to:

- cross-contract consistency audits;
- adversarial fixture/reason-code cleanup;
- implementation prompt/runbook refinement;
- independent red-team review prep;
- licensing/governance decision preparation.

The independent review packet is:

- `docs/83-pre-implementation-red-team-and-astra-review-packet.md`

The license/governance framework is:

- `docs/84-open-source-license-and-governance-decision-framework.md`

## Work we should not continue speculating about before evidence

Do not spend additional pre-implementation cycles designing:

- a custom kernel;
- full custom source language/compiler;
- polished multi-device GUI;
- production mesh networking;
- distributed filesystem/consensus;
- production multi-cloud platform;
- public package marketplace;
- complete office/CRM/CAD/EDA feature suites;
- foundation governance bureaucracy;
- detailed performance micro-optimization.

Those questions are better answered after the trusted spine produces measurements/failures.

## Definition of ready

The project is ready for the first serious Codex session when Issue #17 can be implemented without asking Codex to decide what AIOS fundamentally means.

**That condition is now met at the architecture level.**

The remaining uncertainty belongs primarily to implementation evidence: parser/library behavior, fuzzing, crash injection, filesystem/SQLite durability, sandbox enforcement, and actual performance.

## Principle

> **The architecture has done its job when the next important questions require executable tests rather than another diagram.**
