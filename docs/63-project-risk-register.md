# 63 — Project Risk Register

## Purpose

The AIOS mission is intentionally larger than a conventional operating-system project. A written risk register keeps ambition from turning into hidden assumptions.

This is not a prediction that each risk will occur. It is a list of failure modes the architecture and roadmap should actively test against.

Risk levels are qualitative and should be revisited as implementation evidence appears.

## R1 — Scope explosion prevents a working core

**Risk:** Critical

The project attempts OS, language, GUI, cloud, networking, storage, office, CRM, CAD, EDA, media, and compatibility simultaneously and never produces a coherent executable substrate.

**Mitigation:**

- `docs/53-system-of-everything-staged-roadmap.md`;
- Issue #26 stage gates;
- Issue #17 as first bounded implementation;
- anti-scope rule: current work must unlock later layers or satisfy a stage exit gate.

**Trigger for intervention:** implementation PR introduces future-stage systems merely to make the current core demo work.

## R2 — AI becomes an ambient superuser

**Risk:** Critical

A planner/model/provider inherits the user session's filesystem/network/secrets/OS authority and a prompt-injection/model failure becomes system compromise.

**Mitigation:**

- no-ambient-authority invariant;
- task-scoped grants;
- deterministic policy;
- typed Artifact/Object handles;
- network/credential mediation;
- sandboxed providers;
- adversarial tests.

**Trigger:** any trusted-core implementation needs "just run this shell command as the user" as a general execution path.

## R3 — Semantic contracts become provider-specific APIs

**Risk:** High

Capability/type/object meaning quietly mirrors the first implementation library/vendor, preventing provider substitution and long-term architecture evolution.

**Mitigation:**

- semantic capability/type/object contracts separate from providers;
- conformance tests;
- two-provider substitution tests;
- vendor-neutral identifiers;
- explicit representation/conversion contracts.

**Trigger:** semantic schema contains pandas/Excel/Salesforce/AWS/OpenAI-specific fields that are not adapter metadata.

## R4 — Premature custom language/compiler consumes the project

**Risk:** High

The project spends years recreating compiler/runtime infrastructure before proving AI-native semantics.

**Mitigation:**

- own AIOS IR first;
- bootstrap with Rust/Python/C++/Wasm/MLIR where useful;
- benchmark-driven language escalation;
- ADR 0011/0016.

**Trigger:** implementation begins custom parser/compiler/runtime features not required by validated IR evidence.

## R5 — The project recreates monolithic applications under new names

**Risk:** High

Instead of eliminating application boundaries, AIOS builds its own Word/CRM/CAD/etc silos with proprietary internal object models.

**Mitigation:**

- Domain Packs;
- Universal Object Graph;
- semantic capabilities;
- Views separated from identity/state;
- coverage ladder using bridges/open engines/providers.

**Trigger:** a domain implementation can only be used through its own UI/database and cannot expose semantic capabilities to other Tasks.

## R6 — Cross-domain automation creates irreversible damage

**Risk:** Critical

An AI Task updates CRM, billing, orders, communication, or external systems as if all API calls were reversible local functions.

**Mitigation:**

- transaction/effect classes;
- commit barriers;
- idempotency keys;
- optimistic revisions;
- compensation graphs;
- irreversible-effect gates;
- outcome-unknown recovery.

**Trigger:** retries can duplicate sends/charges/submissions or partial workflows report clean success.

## R7 — Identity resolution merges the wrong real-world entities

**Risk:** High/Critical by domain

Probabilistic similarity incorrectly merges people, companies, products, invoices, or regulated records.

**Mitigation:**

- proposal vs merge state;
- deterministic contradiction checks;
- consequence-level policy;
- approval for high-risk merges;
- reversible merge/split history;
- field source-of-truth retention.

**Trigger:** embedding/model confidence alone can commit durable identity merge.

## R8 — Storage/sync corrupts source-of-truth state

**Risk:** Critical

A newer cache/mirror/offline copy silently overwrites authoritative data, or sync deletion destroys backup/archive history.

**Mitigation:**

- explicit replica roles;
- consistency classes;
- revision/precondition checks;
- tombstones;
- sync/backup/archive separation;
- explicit failover promotion.

**Trigger:** "latest timestamp wins" is used as a generic conflict/source-of-truth policy.

## R9 — Network/cloud convenience bypasses privacy

**Risk:** Critical

Remote providers become eligible because they are fast/cheap even when task data should remain local/personal.

**Mitigation:**

- hard eligibility before scoring;
- explicit egress grants;
- trust/service identities;
- data-residency policy;
- local/offline baseline;
- transfer provenance.

**Trigger:** remote score/quality can override `local-only`/confidential rules.

## R10 — Package ecosystem becomes the main attack surface

**Risk:** High/Critical

Continuous expansion brings malicious/compromised providers, Skills, Domain Packs, models, or updates into trusted execution.

**Mitigation:**

- content-addressed packages;
- publisher signatures;
- signature != trust;
- staged/quarantined activation;
- authority/semantic diff gates;
- conformance/SBOM/build provenance;
- sandboxing;
- revocation/rollback.

**Trigger:** signed update activates with broader authority without review/policy.

## R11 — Legacy compatibility weakens the entire security model

**Risk:** High

A legacy app expects broad desktop authority and becomes an escape hatch around Artifact/object/network/secret controls.

**Mitigation:**

- compatibility habitats;
- constrained filesystem projections;
- explicit clipboard/device/network/secret grants;
- VM fallback for high-risk apps;
- compatibility never defines semantic authority.

**Trigger:** compatibility requires mounting full home directory or inheriting all user credentials by default.

## R12 — AIOS performs worse than existing app workflows

**Risk:** High

The architecture adds planning, serialization, policy, validation, data movement, and model latency until tasks are slower/more expensive than simply opening an app.

**Mitigation:**

- reason-once/Skill compilation;
- deterministic provider paths;
- local caches/data locality;
- benchmark M0–M4 modes;
- optimize after correctness boundaries;
- direct-manipulation Views for expert work.

**Trigger:** repeated stable tasks continue consuming expensive model reasoning with no measurable reuse benefit.

## R13 — Universal type/object model becomes unusably abstract

**Risk:** Medium/High

Trying to normalize every domain produces generic objects that lose specialist semantics or force awkward lowest-common-denominator interfaces.

**Mitigation:**

- minimal Tier-0 objects;
- explicit domain extensions;
- semantic conversions;
- specialized Domain Packs/Views;
- provider-specific metadata kept out of core meaning.

**Trigger:** CAD/EDA/accounting experts cannot represent essential domain invariants without opaque metadata blobs.

## R14 — GUI becomes either chat-only or desktop-clone-only

**Risk:** High

The UI either forces every task through conversation or simply recreates windows/icons/apps with a chatbot on top.

**Mitigation:**

- Presentation Broker;
- Task-first shell;
- adaptive View contracts;
- direct manipulation for CAD/EDA/media/code;
- trusted approval UI;
- voice/headless/accessibility modes.

**Trigger:** expert workflows require abandoning AIOS semantics to launch a conventional silo, or ordinary outcome tasks require manual app selection.

## R15 — Hardware heterogeneity becomes unmaintainable

**Risk:** High

Supporting old/new x86/ARM/RISC-V CPUs, GPUs/NPUs, phones/workstations, and devices explodes provider/testing combinations.

**Mitigation:**

- deterministic hardware profile;
- provider capability requirements;
- Resource Broker;
- graceful degradation;
- peer/remote placement;
- conformance suites;
- mature Linux driver ecosystem first.

**Trigger:** semantic behavior changes depending on hardware rather than only provider availability/placement.

## R16 — "Cloud-capable" becomes "cloud-required"

**Risk:** High

Convenient remote services gradually become mandatory for boot, recovery, files, identity, or ordinary local work.

**Mitigation:**

- offline baseline invariant;
- cloud as runtime provider;
- local policy/task/provenance stores;
- self-hostable paths where practical;
- remote state never sole semantic authority by default.

**Trigger:** cloud outage prevents local recovery or accessing locally available Task/Object history.

## R17 — Open-source/license boundaries block distribution

**Risk:** High

Combining kernels, codecs, geometry engines, model weights, compatibility layers, proprietary adapters, and Domain Packs creates incompatible redistribution/source obligations or trademark/patent risk.

**Mitigation:**

- explicit package/license metadata;
- modular process/component boundaries;
- independent implementation of proprietary product concepts;
- preserve attribution/source obligations;
- legal review before public distribution/claims.

**Trigger:** a core image statically/bundledly combines components without understanding their license obligations.

## R18 — Compatibility promises exceed reality

**Risk:** Medium/High

"Runs everything" becomes an expectation that all Windows/macOS/iOS/Android/proprietary/DRM apps work perfectly.

**Mitigation:**

- explicit support states;
- app/profile fixtures;
- technical/legal feasibility labels;
- VM/remote fallback;
- no unsupported marketing claims.

**Trigger:** documentation says universal/perfect compatibility without a support matrix.

## R19 — Agent-generated code causes architectural drift

**Risk:** High

Codex/other agents independently make local convenience choices that gradually violate contracts/invariants.

**Mitigation:**

- root `AGENTS.md` as map;
- issue-specific runbooks;
- ADR/schema/fixture sources of truth;
- PR invariant checklist;
- bounded issues;
- stop-on-contract-conflict rule.

**Trigger:** agent PR changes security/semantic schema because tests are difficult without an explicit architecture rationale.

## R20 — Documentation becomes larger than usable context

**Risk:** Medium

The architecture becomes so documented that developers/agents cannot identify which sources control a task.

**Mitigation:**

- short `AGENTS.md` map;
- issue-specific required-reading lists;
- ADRs for decisions;
- schemas/fixtures as executable contracts;
- stage-specific runbooks;
- archive/supersede stale docs explicitly later.

**Trigger:** every task requires reading dozens of unrelated docs or multiple docs conflict silently.

## R21 — Governance fragmentation creates incompatible AIOS dialects

**Risk:** Medium/High later

Independent Domain Packs/providers redefine shared types/capabilities, fragmenting the ecosystem into incompatible forks.

**Mitigation:**

- semantic registry governance;
- versioned public contracts;
- conformance tests;
- extension namespaces;
- compatibility/migration rules;
- decentralized implementations over common semantics.

**Trigger:** third-party providers require vendor-specific capability IDs for ordinary shared concepts.

## R22 — Trusted computing base grows too large to audit

**Risk:** High

Too many parsers/providers/UI/cloud components are treated as trusted core, making security review impractical.

**Mitigation:**

- small Rust trusted boundary initially;
- provider processes/components outside TCB;
- capability/credential mediation;
- layered sandboxing;
- minimize privileged daemon responsibilities;
- explicit trust-boundary reviews.

**Trigger:** a third-party library/provider must run privileged/in-process solely for convenience.

## Risk review cadence

Revisit this register:

- before each stage transition;
- after any serious security/recovery failure;
- before public release;
- before making compatibility/security/performance claims;
- when a major new domain fabric becomes implementation-critical.

Each risk should eventually gain concrete tests/metrics where practical.

## Principle

> **The project should fail experiments cheaply in architecture/prototypes rather than fail users expensively after universal scope is deployed.**
