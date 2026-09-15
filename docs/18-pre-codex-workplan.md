# 18 — Pre-Codex Work Plan and Implementation Dependency Graph

This plan distinguishes work that should be resolved through architecture/research before substantial coding from work that becomes a bounded implementation task once Codex/Work is available.

The goal is to arrive at implementation with **fewer ambiguous decisions**, not with more speculative code.

The long-term mission is intentionally universal; the near-term implementation order is intentionally narrow. See `docs/53-system-of-everything-staged-roadmap.md`, `docs/54-unified-platform-fabric-architecture.md`, and `docs/59-pre-codex-foundation-closure-plan.md`.

## Track A — Architecture hardening (chat-friendly)

These can be advanced substantially through design review, research, schemas, examples, and ADRs before implementation begins.

### A1 — Core vocabulary and invariants

Status: substantial draft complete.

Relevant files:

- `docs/14-terminology.md`
- `docs/15-system-invariants.md`
- `docs/16-requirements.md`

### A2 — Contract schemas

Status: substantial first drafts exist.

Current contracts include:

- AIOS semantic IR;
- semantic capability/type contracts;
- execution binding;
- Skill/compiled-target manifests;
- task plan/persisted task;
- provider/capability manifest;
- hardware/resource placement;
- artifact handles;
- authority/policy/provenance;
- model request/result;
- legacy compatibility;
- Universal Software Fabric Domain Packs;
- semantic object/relationship contracts;
- adaptive display/View contracts;
- identity-resolution proposals;
- network service/transfer contracts;
- remote cloud/edge service descriptors;
- storage replica/namespace projection contracts;
- trust identity/credential-handle contracts;
- signed component package/distribution contracts.

Before/while implementation begins:

- keep positive and negative examples synchronized;
- finalize schema versioning convention;
- identify fields that are architecture vs prototype implementation detail;
- ensure no contract assumes one model/cloud/UI/storage/package vendor;
- add automated schema/semantic fixture validation.

### A3 — Threat-model expansion

Status: principal/trust-boundary architecture is substantial; implementation tests still required.

Relevant work:

- trust boundaries;
- principal/authority model;
- capability-token semantics;
- secret/credential mediation;
- external data egress flow;
- network-service identity;
- storage replica/source-of-truth boundaries;
- legacy habitat boundaries;
- Skill/component supply chain;
- model/provider compromise;
- adversarial IR fixtures;
- identity-merge false-positive consequences;
- cloud/peer trust boundaries;
- trusted approval UI;
- package signature vs runtime-authority separation;
- update permission/semantic diff gates.

### A4 — Research decisions

Resolve or narrow:

- Linux base / image/update/rollback strategy (#14);
- service boundaries / IPC / languages (#15);
- AIOS IR/language path (#16);
- WIT/Wasm + MLIR experiment (#18);
- Cedar authorization spike;
- Varlink/service-boundary spike;
- sandbox/container/VM primitives;
- first Windows compatibility integration;
- first local-model runtime;
- optional remote-model adapter shape;
- prototype database/provenance storage.

### A5 — UX / Presentation Fabric

Initial task-first object/shell model exists; adaptive presentation is explicitly separated from Task/object identity.

Relevant work:

- task submission;
- artifact/object attachment;
- clarification;
- approvals;
- running task inspection;
- plan/IR/provenance detail;
- final artifact handling;
- traditional app launch;
- compact vs desktop View projection;
- remote surfaces;
- accessibility;
- specialized direct-manipulation View contracts (#22).

No polished desktop or mobile shell is required before v0.1.

### A6 — AI-native execution semantics

Status: first formal pass complete; **Issue #17 is the preferred first SPIKE-READY implementation task**.

Relevant files:

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/27-skill-compilation-and-adaptive-optimization.md`
- `docs/28-capability-contracts-and-conformance.md`
- `docs/29-semantic-type-system.md`
- `docs/30-aios-ir-reference-validator-plan.md`
- `docs/31-semantic-registry-snapshots.md`
- `docs/32-aios-ir-and-skill-benchmark-plan.md`
- `docs/33-bootstrap-language-boundary.md`
- `docs/36-aios-ir-compiler-and-lowering-boundary.md`
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`
- `docs/62-first-codex-session-runbook.md`
- `specs/aios-ir.schema.json`
- `examples/aios-ir/`

This track is central to ensuring the project does not become merely "AI generates Python/Rust commands for a conventional desktop."

### A7 — Universal Software/Object Fabric

Status: architecture scaffolding exists; implementation deferred until core substrate is proven.

Relevant work:

- Universal Software Fabric / Domain Packs (#19);
- Tier-0 semantic object model;
- object federation/source-of-truth;
- cross-domain transactions/compensation (#21);
- identity resolution / merge/split (#25);
- software coverage expansion ladder.

The early objective is to ensure today's implementation choices do not block broad future software coverage.

### A8 — Resource / Personal Compute Fabric

Status: deterministic placement model drafted.

Relevant work:

- Resource Broker / Personal Compute Fabric (#20);
- static hardware profile vs dynamic resource snapshot;
- hard eligibility before objective ranking;
- peer placement;
- data-movement cost;
- migration/rebinding classes.

Implementation belongs after/with the v0.1 resource-broker skeleton, not before the trusted semantic substrate.

### A9 — Network + Cloud/Edge Fabrics

Status: architecture/scaffolding drafted; implementation is post-core.

Relevant work:

- bounded service identity/connectivity (#23);
- cloud/edge/self-hosted remote service model (#24);
- peer transfer/provenance;
- cost/residency policy;
- offline/reconnect semantics;
- self-hosted core-service boundaries.

Network/cloud may be researched now but must not become prerequisites for local boot/recovery or the first deterministic substrate.

### A10 — Storage / Namespace / Replica Fabric

Status: first architecture/contracts/fixtures drafted; implementation after local Artifact identity is proven.

Relevant work:

- storage/replica consistency and source-of-truth (#27);
- namespace/file projection;
- backup vs sync vs archive/cache semantics;
- large Artifact/chunk/stream behavior;
- peer/cloud replica policy;
- offline queued mutation revalidation.

The Stage-1 implementation only needs a local Artifact store whose identity is not a host path. Distributed storage is explicitly deferred.

### A11 — Cryptographic identity / credential mediation

Status: first architecture/contracts/fixtures drafted.

Relevant work:

- stable user/device/service/workload/provider/publisher identity (#28);
- peer pairing/key lifecycle;
- credential handles/secret mediation;
- authentication vs authorization boundary;
- attestation as policy evidence, not authority;
- federation/recovery later.

The v0.1 core needs local/workload identities and credential-handle abstraction, not a full distributed PKI.

### A12 — Component distribution / supply chain

Status: first architecture/package contract drafted.

Relevant work:

- signed/content-addressed package identity (#29);
- authority/effect/semantic diff gates;
- staged activation/rollback;
- conformance/build/SBOM/license metadata;
- revocation/quarantine;
- mirrors/offline bundles.

The first implementation only needs fixture provider build/version attribution. A public marketplace is deliberately deferred.

### A13 — Stage-gate governance

Issue #26 tracks the staged "system of everything" roadmap.

Universal ambition is maintained by designing reusable fabrics/contracts now while deferring broad implementation until prerequisite stage gates pass.

## Track B — Current issues and workstreams

| Issue | Workstream | Primary dependency / timing |
| --- | --- | --- |
| #1 | persisted task model/state machine | core contracts |
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
| #12 | Skill compilation proof | successful #8/#9 path + Skill/IR contracts |
| #13 | task-first shell | #1 #5 #8; adaptive View work can follow |
| #14 | Linux base/update research | architecture |
| #15 | service/IPC/language research | architecture |
| #16 | AIOS IR / custom-language decision criteria | architecture umbrella |
| #17 | deterministic AIOS IR validator/normalizer/hash | **first implementation spike** |
| #18 | WIT/Wasm + MLIR lower-layer experiments | after/alongside #17; no semantic authority |
| #19 | Universal Software Fabric / Domain Packs | architecture now; implementation post-core |
| #20 | Resource Broker / Personal Compute Fabric | Phase II architecture/implementation |
| #21 | cross-domain transactions/compensation | before consequential multi-domain mutations |
| #22 | adaptive Presentation Broker / View contracts | architecture now; shell evolution after #13 |
| #23 | Network Fabric | after core; peer stage after resource substrate |
| #24 | cloud/edge/self-hosted service model | after Network/Resource basics |
| #25 | identity resolution / merge/split | before broad federated object deployment |
| #26 | staged system-of-everything roadmap | ongoing governance/meta |
| #27 | Storage/Replica/Namespace Fabric | architecture now; local Artifact first, distributed later |
| #28 | cryptographic identity/peer trust/credential lifecycle | local/workload subset in core; peer/distributed later |
| #29 | component distribution/supply-chain/update trust | attribution now; staged ecosystem activation later |

## Recommended implementation order

### Phase 0 — semantic boundary spike

1. Close/narrow #14 and #15 enough to create the development environment.
2. Keep #16 open as the language/IR research umbrella while treating current v0.1 semantics as the first experiment.
3. Follow `docs/62-first-codex-session-runbook.md` and implement #17 deterministic AIOS IR validator/normalizer/hash/effect-summary CLI/library.
4. Run `docs/61-validator-test-fuzz-and-resource-limit-matrix.md` gates without a model planner.
5. Only after validator semantics are stable, run bounded #18 lowering/ABI experiments.

At the end of Phase 0 we should have a machine-verifiable answer to: **what does an AI-native program mean, and can untrusted generated programs be rejected deterministically?**

### Phase I — deterministic substrate

6. Implement #1 task model.
7. Implement #4 local Artifact handle/store with content identity independent of path (#27 architecture boundary).
8. Implement #5 provenance service.
9. Implement #2 semantic capability/type registry plus provider conformance boundary.
10. Implement #3 policy/authority plus local credential-handle mediation subset from #28.
11. Record provider/component build/version identity compatible with #29, without building a marketplace/package manager.
12. Bind one tiny validated AIOS IR fixture to a deterministic provider through an Execution Binding.

At the end of Phase I, create/validate/authorize/bind/execute/recover a deterministic Task **without any AI planner** and without ambient filesystem/network/secret authority.

### Phase II — orchestration and adaptive execution

13. Implement #6 hardware profiler/Resource Broker skeleton guided by #20.
14. Implement #7 model runtime interface.
15. Implement #8 planner/orchestrator as proposal producer only.
16. Implement #9 deterministic Demonstration A providers.
17. Prove local vs alternate eligible placement without semantic-program rewrite.

### Phase III — task-first user experience and transition

18. Implement #13 task-first shell.
19. Use #22 to add adaptive compact/desktop View projection after the basic shell works.
20. Add basic namespace projection from #27 only as required for user/legacy file interoperability.
21. Implement #10 Universal App Broker proof.
22. Implement #12 Skill compilation/reuse proof.

### Phase IV — v0.1 hardening

23. Expand/automate #11 adversarial/recovery harness.
24. Run full `docs/17-v0.1-acceptance-tests.md` gate.
25. Benchmark fresh planning vs IR/Skill/compiled execution.
26. Update architecture to match implemented reality.

### Phase V — Personal Compute + Network + Storage Fabric

27. Expand #28 from local/workload identity to paired device identity/key lifecycle.
28. Expand #20 from local placement to trusted peer placement.
29. Implement narrow #23 peer/service identity, bounded connectivity, transfer provenance.
30. Expand #27 to peer Artifact replica/resumable transfer/source-of-truth-safe sync.
31. Demonstrate one Task placed from laptop/phone-like client to paired workstation while preserving identity/policy and replica semantics.

### Phase VI — Tier-0 Object/Software Fabric

32. Implement narrow #19 Tier-0 Domain Pack/object registry subset.
33. Implement #25 safe identity-resolution proposal/link/merge fixtures.
34. Implement #21 cross-domain effect/compensation coordinator for the first synthetic multi-domain workflow.
35. Demonstrate one Task spanning at least three former application categories without point-to-point app integration.
36. Begin #29 staged package/provider activation only when multiple independently distributed components make it necessary.

### Phase VII — cloud/edge scale

37. Implement minimal #24 remote-worker/service path on top of Network + Resource Fabrics.
38. Extend #27 storage replicas to self-hosted/public-remote classes under residency/retention policy.
39. Extend #28 identity/federation for organization/service trust where required.
40. Demonstrate local, self-hosted/peer, and public-remote candidates for the same semantic node.
41. Preserve offline/local control-plane understanding through remote outage.

Broad productivity/business/creative/engineering Domain Pack expansion follows the stage gates in `docs/53-system-of-everything-staged-roadmap.md` rather than entering the v0.1 critical path.

## Codex issue sizing rule

An implementation issue is ready for Codex only when it specifies:

1. purpose;
2. current roadmap stage;
3. architecture contracts it must obey;
4. files/modules it may reasonably create or modify;
5. inputs/outputs;
6. security boundary;
7. acceptance tests;
8. explicit non-goals;
9. dependencies that are already merged or mocked.

If an issue still contains a major architecture question, resolve it before asking Codex to infer the answer from implementation convenience.

## Special rule for AI-generated implementation

Because AI will contribute heavily to this project, generated code must not be allowed to redefine semantic or security contracts accidentally.

Codex/agents should be instructed to:

- read root `AGENTS.md`;
- treat ADRs/invariants/contracts as constraints;
- propose contract changes explicitly rather than silently working around them;
- add tests for validator/policy boundaries;
- avoid arbitrary shell/eval escape hatches in core runtime paths;
- keep provider-specific code behind provider contracts;
- preserve reason codes and semantic hashes when refactoring;
- preserve stage boundaries instead of implementing future layers as shortcuts.

## What we should avoid before implementation

Do not spend pre-implementation time on:

- branding/logo work;
- a custom kernel;
- a new general-purpose language/compiler before IR evidence;
- a full installer image;
- polished multi-device GUI shells;
- production mesh networking;
- distributed filesystem implementation;
- public package marketplace;
- production multi-cloud orchestration;
- broad Domain Pack feature parity;
- dozens of legacy compatibility targets;
- training a foundation model;
- building equivalents of Word/Photoshop/Unreal as monolithic applications;
- performance micro-optimization before contracts exist.

## Definition of "ready for the first serious Codex session"

For Issue #17, the repository now has:

- AIOS IR semantics/fixtures;
- controlling invariants/requirements/acceptance plan;
- registry/effect contracts;
- explicit Rust workspace/trusted boundary plan;
- parser/semantic/hash/fuzz/resource-limit test matrix;
- root agent instructions;
- first-session runbook;
- bounded non-goals/stop conditions.

That makes #17 the preferred first serious implementation session, while the preflight rule still requires stopping on any actual contradiction discovered in the source-of-truth contracts.

The ideal first Codex work should feel constrained and test-driven rather than creatively architectural.
