# 64 — Architecture Requirements Traceability Matrix

## Purpose

The project now has broad architecture requirements spanning the v0.1 trusted core and later platform fabrics. This matrix prevents two opposite failures:

1. treating every long-term requirement as a v0.1 implementation dependency; or
2. implementing v0.1 in a way that makes later required fabrics incompatible.

This document maps requirement families to their current roadmap scope, primary source contracts, GitHub workstreams, and expected evidence.

The base requirement catalog is `docs/16-requirements.md`.

The implementation-sensitive trusted-core requirement addendum is `docs/85-v0.1-trusted-core-requirements-addendum.md` and is normative for Stage-1 implementation.

## Scope legend

```text
CORE-v0.1
  Required by the first trusted prototype/release gate or by its direct deterministic substrate.

INTERFACE
  The boundary/identity rule must be preserved by early implementation, but full subsystem implementation is later.

LATER-STAGE
  Required before the corresponding fabric/domain claims support; not on the v0.1 critical path.

CROSS-CUTTING
  Applies whenever the relevant behavior appears, regardless of roadmap stage.
```

A requirement can be both `INTERFACE` and `CROSS-CUTTING`.

## Traceability overview

| Requirement family | IDs | Current scope | Primary architecture/contracts | Primary issues/workstreams | Evidence / gate |
| --- | --- | --- | --- | --- | --- |
| Task / intent | R-TASK-001..005 | CORE-v0.1 | docs 03, 24, 34, 35, 74; Task schemas | #1, #8 | persisted lifecycle/CAS/idempotency/recovery tests |
| AIOS IR | R-IR-001..012 | CORE-v0.1 | docs 25, 26, 30, 31, 39, 60, 61, 66–72; IR schemas/fixtures | #16, **#17** | validator positive/negative/hash/effect/fuzz gates |
| Semantic contracts | R-CONTRACT-001..007 | CORE-v0.1 | docs 28, 29, 31, 69, 72; capability/type/registry schemas | #2, #17 | registry + semantic fixture validation |
| Capability system | R-CAP-001..006 | CORE-v0.1 / INTERFACE | docs 04, 28, 37, 38, 76 | #2, #9 | two-provider semantic substitution/conformance |
| Security/authority | R-SEC-001..007 + R-AUTH-001..008 | CORE-v0.1 / CROSS-CUTTING | docs 08, 19, 21, 39, 77, 85; authority/policy/grant contracts | #3, #11 | deterministic allow/deny/approval/grant + adversarial tests |
| Artifact/data | R-DATA-001..005 + R-ART-001..005 | CORE-v0.1 | docs 20, 35, 75, 85; Artifact allocation/publication schemas | #4, #5 | content identity/staging/publication/lineage/crash tests |
| Credential mediation | R-ID-003..006 + R-CRED-001..006 | CORE-v0.1 boundary / CROSS-CUTTING | docs 56, 79, 85; credential handle/use contracts | #28 | brokered operation/exportability/secret non-leakage fixtures |
| Provider execution | R-EXEC-001..009 | CORE-v0.1 | docs 78, 80, 82, 85; binding/invocation/profile contracts | **#30** | bounded offline deterministic provider + malicious-provider tests |
| Persistence integrity | R-PERSIST-001..006 | CORE-v0.1 / CROSS-CUTTING | docs 35, 73–80, 85; `persistence-v0.1.sql` | #1/#4/#5/#3/#30 | transaction/idempotency/owner-fencing/privacy/crash-injection tests |
| Recovery certainty | R-REC-001..011 | CORE-v0.1 / CROSS-CUTTING | docs 24, 74, 80, 85, 86; recovery contracts | #11 + all core issues | crash/response-loss/private-entry/per-subject unknown-outcome tests |
| Semantic Objects | R-OBJ-001..006 | INTERFACE → Stage 5 | docs 42, 44, 49; object/relationship/identity schemas | #19, #25 | first federated objects + merge/split tests |
| Domain Packs | R-DOM-001..003 | INTERFACE → Stage 5+ | docs 40, 41, 43, 46; domain-pack schema | #19 | cross-domain workflow/conformance |
| Cross-domain effects | R-XDOM-001..005 | INTERFACE → Stage 5+ | docs 45, 47; effect/provenance/task state | #21 | compensation/unknown-outcome/commit-barrier fixtures |
| Models/agents | R-AI-001..005 | Phase II | docs 05, 22; model request/result | #7, #8, #11 | planner proposals validated; local/remote routing |
| Resource adaptation | R-RES-001..007 | R-RES-001..004 CORE/Phase II; rest INTERFACE | docs 06, 10, 48; hardware/resource/placement | #6, #20 | placement eligibility/reason-code fixtures |
| Presentation | R-PRES-001..005 | INTERFACE → Stage 3 | docs 20, 23, 50; display/view contracts | #13, #22 | same Task on compact/desktop + trusted approval UI |
| Network | R-NET-001..006 | INTERFACE → Stage 4 | docs 51; network service/transfer contracts | #23, #28 | peer transfer with explicit grant/provenance |
| Cloud/edge | R-CLOUD-001..005 | INTERFACE → Stage 9 | docs 52; remote-service/placement | #24 | local/peer/self-hosted/public substitution + outage |
| Storage/replica/namespace | R-STOR-001..007 | identity boundary CORE; distributed behavior Stage 4+ | docs 55, 58; replica/projection | #4, #27 | local Artifact identity then peer/cloud replica tests |
| Identity/trust | R-ID-001..002/007 | local/workload boundary CORE; distributed Stage 4+ | docs 19, 21, 56; trust-identity | #3, #28 | auth≠authz, workload identity, peer revocation |
| Component distribution | R-PKG-001..008 | version attribution INTERFACE/CORE; activation Stage 6+ | docs 57; component-package schema | #29 | authority-diff + staged activation/rollback |
| Legacy compatibility | R-COMPAT-001..005 | v0.1 Demo B / later expansion | docs 07 + compatibility research/profile | #10 | package classification + contained known app launch |
| Provenance/recovery | R-PROV-001..006 + R-REC-* | CORE-v0.1 / CROSS-CUTTING | docs 22, 24, 35, 73, 80; provenance/recovery schemas | #1, #5, #11 | restart/provider-failure/action attribution/reconciliation |
| Learning/Skills | R-SKILL-001..007 | v0.1 proof / later optimization | docs 09, 27, 32, 36; skill/compiled target | #12, #18 | M0–M4 benchmark + no inherited authority |
| Base system | R-BASE-001..004 | CORE-v0.1 | docs 10 + Linux/update research; ADR 0001/0002/0008 | #14 | reproducible dev base + AI-independent recovery design |
| UX | R-UX-001..004 | Stage 3 / v0.1 user demo | docs 20, 23, 50 | #13, #22 | Task-first shell + inspectability |
| Open-source architecture | R-OSS-001..004 | CROSS-CUTTING / pre-public release | CONTRIBUTING, SECURITY, ADRs, specs, docs84 | #26, #29 + governance work | public contracts/conformance/license boundaries |

## Phase-0 / Issue #17 direct requirement map

Issue #17 is the first implementation spike. The following requirements are direct merge gates or controlling constraints.

| Requirement | Validator responsibility | Primary evidence |
| --- | --- | --- |
| R-IR-001 | program can be represented/validated without provider/model/device identity | semantic IR schema + forbidden-binding fixtures |
| R-IR-002 | reject embedded grants/tokens/secrets/approval bypass | adversarial IR fixtures |
| R-IR-003 | full deterministic structural/semantic validation | library/CLI tests; no model/provider/network |
| R-IR-004 | named typed ports/references resolve | graph/reference fixture suite |
| R-IR-005 | execution class resolves/validates against capability contract | registry-aware semantic fixtures |
| R-IR-006 | retry/fallback/replan budgets are machine-bounded | failure-policy fixtures |
| R-IR-007 | authority classes + egress declarations are explicit/consistent | effect/authority/egress fixtures |
| R-IR-008 | verification gates are represented and retained in normalized program/effect summary | Demonstration A + mutation tests |
| R-IR-009 | canonical semantic identity independent of serialization/runtime binding | equivalence/difference hash tests; R17-02 exact decimal/exponent integer corpus in `review-repair-cases.json` |
| R-IR-010 | concrete provider/grant/sandbox/hardware state is outside semantic IR | schema + negative fixtures |
| R-IR-011 | validator/normalizer does not widen effects/authority or weaken verification | normalization property/regression tests |
| R-IR-012 | stable reason-code families | diagnostics tests |
| R-CONTRACT-001 | capability meaning comes from semantic contract, not provider declaration | semantic registry fixture |
| R-CONTRACT-002 | contract ports/types are named/checked | port/type fixture tests |
| R-CONTRACT-004 | IR authority requests cannot exceed capability contract class | authority semantic tests |
| R-CONTRACT-005 | types are semantic IDs, not host-language classes | type-contract fixtures |
| R-CONTRACT-006 | no implicit semantic casts in v0.1 | mismatch fixtures |
| R-CONTRACT-007 | successful validation identifies registry snapshot | validation-result fixture/tests; R17-01 structural admission corpus and R17-04 tolerance authoring tests |
| R-SEC-006 | prompt/script-like data cannot grant authority through program content | adversarial fixture policy boundary |
| R-SEC-007 | validator correctness is deterministic | no-model/no-provider boundary tests |
| R-DATA-001 | semantic program uses handles/references rather than unrestricted host paths where applicable | IR/schema examples |
| R-PROV-006 | validator/runtime identity is versionable/attributable for future persistence | validation-result/version metadata |

The detailed test matrix is `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`.

## Stage-1 trusted deterministic substrate map

After #17, Stage 1 proceeds in the sequence from `docs/82-stage1-core-substrate-codex-runbook.md`.

| Workstream | Requirements | Issue(s) | Minimum Stage-1 evidence |
| --- | --- | --- | --- |
| Task Manager | R-TASK-001..005, R-PERSIST-001/002, R-REC-005/008/009 | #1 | create/CAS transitions/idempotency/restart recovery |
| Artifact Store | R-DATA-001..005, R-ART-001..005, R-PERSIST-003, R-STOR-001/006 | #4 | local immutable content identity, staging/publication/crash recovery |
| Provenance | R-PROV-001..006, R-PERSIST-002/004, R-REC-008 | #5 | append/hash-chain/material action attribution |
| Semantic/provider registry | R-CONTRACT-001..007, R-CAP-001..003/006 | #2 | immutable snapshot + multiple provider records/conformance |
| Authority Coordinator | R-SEC-001..007, R-AUTH-001..008 | #3 | concrete deterministic allow/deny/approval/scoped grants |
| Credential Broker minimum | R-CRED-001..006, R-ID-003..006 | #28 | brokered synthetic secret use; no source-secret propagation |
| Provider Supervisor | R-EXEC-001..009, R-CAP-004/005 | **#30** | one isolated deterministic provider under immutable binding |
| Crash/recovery | R-REC-001..009 | #11 + all above | deterministic crash-point reconciliation + no blind unknown retry |
| Provider/component attribution | R-PROV-002/006, R-PKG-001/002 | #2/#29 boundary/#30 | exact provider/package/build attribution; no package manager required |

The Stage-1 integrated acceptance gate is `docs/86-stage1-deterministic-spine-acceptance-tests.md`.

Stage 1 deliberately does **not** require peer networking, cloud storage, full PKI, a GUI, broad Domain Packs, a public package registry, or an AI planner.

## v0.1 acceptance crosswalk

The acceptance plan remains authoritative for the overall v0.1 release gate. The deterministic Stage-1 gate is an earlier prerequisite.

| Acceptance group | Primary requirement families |
| --- | --- |
| Issue #17 validator gate | R-IR, R-CONTRACT, R-SEC-006/007 |
| Stage-1 deterministic spine S1–S9 | R-TASK, R-ART, R-PROV, R-AUTH, R-CRED, R-EXEC, R-REC, R-PERSIST |
| Demonstration A1 Task creation | R-TASK, R-DATA |
| A2 typed planning/semantic validation | R-IR, R-CONTRACT |
| A3 least authority | R-SEC, R-AUTH, R-ID |
| A4 provider substitution | R-CAP, R-CONTRACT, R-EXEC, R-PROV |
| A5 deterministic calculations/verification | R-AI-005, R-IR-008, R-CONTRACT |
| A6 artifact production/lineage | R-DATA, R-ART, R-PROV |
| A7 provenance inspection | R-PROV, R-UX-003 |
| A8 local/remote policy routing | R-AI-002, R-RES, R-SEC-003, R-AUTH, R-NET interface |
| A9 planner failure containment | R-IR, R-SEC, R-TASK, R-EXEC |
| A10 reusable procedure | R-SKILL |
| Demo B legacy compatibility | R-COMPAT, R-SEC, R-DATA |
| Hardware/resource tests | R-RES |
| Recovery tests | R-REC, R-TASK-005, R-PROV-005, R-BASE-004 |
| Security regression fixtures | R-SEC/R-AUTH/R-CRED/R-EXEC + relevant IR/network/compatibility boundaries |

Not every later-stage requirement must have implementation evidence for v0.1. The v0.1 implementation must, however, avoid violating their core identity/security separation rules.

## Interface-preservation checks for early PRs

Before merging trusted-core code, reviewers should ask whether the change accidentally assumes any of the following:

```text
Task identity == process ID
Object identity == database row/provider record
Artifact identity == host filesystem path
Service identity == IP/hostname
Provider identity == semantic capability meaning
Authentication == authorization
Credential handle == permission
Bearer token == durable grant semantics
Package signature == trusted execution
Cloud/storage location == semantic identity
View/window == object lifetime/identity
Model output == permission
Provider process exit == semantic success
Staging bytes == published Artifact
Lost response == safe retry
```

Any `==` above is an architecture defect unless an explicit ADR narrowly justifies a special case.

## Traceability status rules

As code is implemented, each requirement should eventually be annotated/generated with evidence status such as:

```text
ARCHITECTURE_ONLY
SPIKE_READY
IMPLEMENTED_UNVERIFIED
TESTED
CONFORMANCE_GATED
STABLE
DEFERRED_BY_STAGE
```

Do not mark a requirement implemented merely because a schema or document exists.

The current machine-readable contract readiness snapshot is `specs/contract-maturity.json`.

## Change-control rule

When a requirement changes:

1. identify controlling invariant/ADR;
2. update requirement text/ID compatibility intentionally;
3. update affected schemas/contracts;
4. update acceptance/negative fixtures;
5. update this traceability map;
6. update persistence mapping if durable state changes;
7. identify migration/provider-conformance consequences;
8. reference the change in the implementing issue/PR.

Stable requirement IDs should not be silently reused for incompatible meanings after external implementations depend on them.

## Principle

> **A universal architecture remains buildable only when every ambitious requirement can be traced to a stage, a contract, an issue, and eventually a test.**
