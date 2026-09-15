# AI-Native Operating System — Architecture Draft v0.1

> Working title. The final project name, license, implementation languages, and governance model are intentionally not fixed yet.

This repository defines an open-source computing architecture designed **around AI from the beginning**, rather than adding an AI assistant to an application-centric desktop.

The immediate project is a narrow AI-native operating-system prototype. The long-term mission is broader:

> **Build a task-first semantic computing platform in which programming languages, applications, data, devices, networks, storage, cloud services, and domain software progressively converge behind one coherent system of meaning, authority, provenance, and interchangeable capabilities.**

The user should increasingly describe outcomes rather than choose which application silo, programming language, device, or cloud service performs each step.

## Core premise

Traditional computing is organized roughly as:

```text
hardware
→ operating system
→ applications
→ files/application databases
→ human manually coordinates the applications
```

AIOS aims toward:

```text
human / organization intent
        ↓
Task + policy + provenance
        ↓
AIOS semantic program
        ↓
semantic objects + capabilities
        ↓
validated provider/resource binding
        ↓
local · peer · cloud · legacy · native execution
```

The machine organizes itself around the requested outcome.

## Foundational goals

1. **Task-first computing** — the Task, not the application, is the primary execution/audit unit.
2. **AI-native semantics** — intent, capabilities, effects, verification, authority requests, Skills, and provenance are first-class computational concepts.
3. **Capability-oriented software** — useful application functions become semantic capabilities that can be composed across domains.
4. **Universal Object Graph** — durable semantic identity survives changes in application, database, storage location, file path, provider, and device.
5. **Universal Software Fabric** — CRM, billing, office, creative, database, CAD/EDA, development, scientific, and future domains grow as Domain Packs/capabilities rather than mandatory monolithic apps.
6. **Adaptive presentation** — the same Task/object can project appropriately to phone, desktop, multi-display workstation, voice, accessibility, or specialized expert Views.
7. **Hardware-adaptive execution** — hardware changes placement and available providers, not the conceptual OS.
8. **Personal Compute Fabric** — trusted user-owned devices can form one policy-bounded compute/storage pool.
9. **Local-first privacy** — private data does not leave the local/personal trust boundary merely because AI is involved.
10. **Deterministic enforcement** — semantic validation, policy, privilege, secret mediation, recovery, and critical base-system mechanisms do not depend on unconstrained model judgment.
11. **Model/provider independence** — no AI model, cloud, database, application vendor, or implementation language is the semantic identity of the system.
12. **Reason once, compile when stable, reuse thereafter** — repeated validated reasoning can become cheaper versioned Skills/deterministic computation without inheriting old authority.
13. **Open, inspectable ecosystem** — contracts, conformance, package identity, provenance, authority changes, and compatibility claims should be inspectable rather than implicit.

## The governing security rule

> **AI may propose what to do. Deterministic validation decides whether the proposed program has valid meaning. Deterministic policy decides what is allowed.**

A model/planner/agent/Skill/provider cannot grant itself permission by generating code, JSON, shell commands, UI actions, or persuasive text.

## Unified platform architecture

```text
Human / Organization Intent
            ↓
Task / Policy / Approval / Provenance
            ↓
AIOS Semantic Compute Fabric
(AIOS IR · semantic types/capabilities · effects · verification · Skills)
            ↓
Universal Object Graph + Universal Software Fabric
            ↓
┌─────────────────────┬─────────────────────┐
│ Presentation Fabric │ Execution Providers │
└─────────────────────┴──────────┬──────────┘
                                 ↓
          Resource / Personal Compute Fabric
          Network / Cloud / Edge Fabric
          Storage / Namespace / Replica Fabric
          Identity / Trust / Credential Fabric
          Component Distribution / Supply Chain
                                 ↓
          Compatibility + Native Provider Engines
                                 ↓
                 Deterministic Linux Base
```

Full architecture map: [`docs/54-unified-platform-fabric-architecture.md`](docs/54-unified-platform-fabric-architecture.md).

## Native object model

AIOS separates concepts that conventional desktops often collapse into an application/window/file:

```text
Task         = intent + execution lifecycle + authority + provenance
Object       = durable semantic identity of a thing
Artifact     = durable content/representation + lineage
Workspace    = optional organization/context/projection container
Conversation = interaction/communication context
Application  = legacy/provider/UI entity rather than universal owner
View         = presentation/direct-manipulation projection
```

A file path, cloud object key, database row ID, window, provider ID, or device is not automatically the semantic identity of the user's work.

## AI-native computational model

The project separates the languages used to **implement** the bootstrap system from the semantic representation describing **what the AI-native computer should do**.

Bootstrap implementation may use:

```text
Rust     → trusted control-plane core
Python   → rapid model/provider/data experimentation
C/C++    → bounded bridge to mature native ecosystems
WASM     → portable provider / compiled-Skill target candidate
Linux    → mature kernel/driver/filesystem/network substrate
```

Those are implementation mechanisms, not the semantic ABI of AIOS.

The project is defining **AIOS IR**, a provider-independent typed semantic program with first-class concepts for:

```text
capability invocation
typed data flow
deterministic vs probabilistic execution
authority requests
data egress
verification
resource/locality constraints
bounded failure/fallback
provenance
Skill compilation
```

The design rule is:

> **Own the semantics before owning the syntax.**

A human/AI-oriented general-purpose language may grow from AIOS IR later if measurements show real benefit. The project will not build a new language/compiler merely for novelty.

## Semantic capability model

AIOS invokes semantic capabilities rather than application names:

```text
AIOS IR node
    ↓
Semantic Capability Contract
    ↓
One of N conforming Provider Implementations
    ↓
Execution Binding + sandbox + current grants + placement
```

Example:

```text
cad.feature.extrude@1
```

could eventually be satisfied by:

- an AIOS-native geometry provider;
- an adapted open-source engine;
- a bridged legacy CAD application;
- a trusted peer workstation provider;
- a policy-approved remote engineering service.

Changing the eligible provider does not change the semantic operation.

## Universal Software Fabric

The long-term goal is not to ship separate AIOS clones of every existing application.

Instead, applications are decomposed into reusable semantic objects, capabilities, invariants, engines, adapters, and Views.

A CRM becomes concepts such as:

```text
Party · Organization · Contact · Lead · Opportunity · Quote · Order · Invoice · Payment
```

with capabilities such as:

```text
crm.create_opportunity
crm.merge_contacts
commerce.quote.revise
billing.issue_invoice
```

Engineering software similarly decomposes into Parts, Assemblies, Constraints, Schematics, Nets, PCB objects, simulation capabilities, renderers/solvers, and specialized direct-manipulation Views.

See:

- [`docs/40-universal-software-fabric.md`](docs/40-universal-software-fabric.md)
- [`docs/41-domain-capability-architecture.md`](docs/41-domain-capability-architecture.md)
- [`docs/43-software-coverage-expansion-strategy.md`](docs/43-software-coverage-expansion-strategy.md)

## Capability coverage grows progressively

AIOS does not need to rewrite the world's software before becoming useful.

A capability can mature through:

```text
UNAVAILABLE
→ LEGACY-LAUNCH
→ LEGACY-BRIDGED
→ EXTERNAL/REMOTE PROVIDER
→ OPEN-SOURCE ENGINE ADAPTER
→ AIOS-NATIVE PROVIDER
→ OPTIMIZED/COMPILED PROVIDER
→ MULTIPLE CONFORMING PROVIDERS
```

The user-facing semantic capability can remain stable while the implementation underneath improves.

## Universal Object Graph

The same real-world thing should retain one durable AIOS identity whenever practical even if many systems represent it.

Example:

```text
CRM customer 99881
billing customer C-31002
ERP account A00941
email contact customer@example.test
```

may be linked to one canonical semantic Party object—but probabilistic AI confidence alone cannot perform a high-consequence merge. Contradictions, source evidence, policy, revision checks, consequence level, and required approvals remain explicit.

See:

- [`docs/42-universal-object-graph-and-data-federation.md`](docs/42-universal-object-graph-and-data-federation.md)
- [`docs/44-tier0-universal-object-model.md`](docs/44-tier0-universal-object-model.md)
- [`docs/49-identity-resolution-and-object-reconciliation.md`](docs/49-identity-resolution-and-object-reconciliation.md)

## Storage, networking, cloud, and devices

These are runtime fabrics—not semantic authorities.

A Document object can survive:

- rename/move between folders;
- local/peer/cloud replicas;
- conversion to PDF/Markdown/DOCX;
- provider replacement;
- device replacement.

A Task can potentially move computation from an old laptop to a trusted workstation GPU or permitted cloud provider without changing semantic program identity.

Relevant architecture:

- [`docs/48-resource-placement-and-personal-compute-fabric.md`](docs/48-resource-placement-and-personal-compute-fabric.md)
- [`docs/50-adaptive-presentation-and-device-ui.md`](docs/50-adaptive-presentation-and-device-ui.md)
- [`docs/51-network-fabric-and-service-connectivity.md`](docs/51-network-fabric-and-service-connectivity.md)
- [`docs/52-cloud-edge-and-service-fabric.md`](docs/52-cloud-edge-and-service-fabric.md)
- [`docs/55-storage-sync-and-replica-fabric.md`](docs/55-storage-sync-and-replica-fabric.md)
- [`docs/56-cryptographic-identity-trust-and-credential-fabric.md`](docs/56-cryptographic-identity-trust-and-credential-fabric.md)
- [`docs/57-component-distribution-supply-chain-and-update-trust.md`](docs/57-component-distribution-supply-chain-and-update-trust.md)
- [`docs/58-files-namespaces-and-semantic-projection.md`](docs/58-files-namespaces-and-semantic-projection.md)

## Stage discipline

The end state is intentionally huge. The next implementation step is intentionally small.

The staged roadmap is:

```text
architecture constitution
→ trusted semantic substrate
→ adaptive orchestration
→ task-first adaptive shell
→ personal compute/network/storage
→ Tier-0 object/software fabric
→ productivity/business domains
→ creative/developer domains
→ engineering domains
→ cloud/org/edge collaboration
→ physical/ambient domains
→ continuous language/platform maturation
```

See [`docs/53-system-of-everything-staged-roadmap.md`](docs/53-system-of-everything-staged-roadmap.md).

## v0.1 target

The flagship user intent remains deliberately narrow:

> “Understand these numbers, identify the important changes, produce a chart and a concise report, and save the result.”

The eventual v0.1 prototype should:

- create a durable Task;
- import/reference the data as an Artifact;
- derive/validate typed AIOS IR;
- resolve calculation/table/chart/document capabilities;
- request only minimum authority;
- execute deterministic calculations/providers;
- invoke AI only for semantic reasoning where useful;
- independently verify consequential numeric claims;
- produce portable output artifacts;
- record inspectable provenance;
- demonstrate provider substitution;
- demonstrate repeated-work reuse/Skill optimization;
- separately launch at least one legacy application through a compatibility habitat.

The goal is to prove an architecture that is meaningfully different from a normal desktop with a chatbot attached.

## First implementation target

The preferred first serious implementation assignment is **GitHub Issue #17**:

> deterministic AIOS IR parser/validator/normalizer/static-effect-summary/semantic-hash boundary.

It intentionally requires:

- no model planner;
- no provider execution;
- no network/cloud;
- no GUI;
- no Cedar policy engine yet;
- no custom source language.

Implementation preparation:

- [`AGENTS.md`](AGENTS.md) — concise instructions/map for coding agents
- [`docs/59-pre-codex-foundation-closure-plan.md`](docs/59-pre-codex-foundation-closure-plan.md) — architecture closure classes/gates
- [`docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`](docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md) — initial implementation/module shape
- [`docs/61-validator-test-fuzz-and-resource-limit-matrix.md`](docs/61-validator-test-fuzz-and-resource-limit-matrix.md) — validator security/test matrix
- [`docs/62-first-codex-session-runbook.md`](docs/62-first-codex-session-runbook.md) — first Codex session prompt/sequence/stop conditions

## Repository guide

### Constitution / requirements

- [`docs/00-charter.md`](docs/00-charter.md)
- [`docs/01-design-principles.md`](docs/01-design-principles.md)
- [`docs/14-terminology.md`](docs/14-terminology.md)
- [`docs/15-system-invariants.md`](docs/15-system-invariants.md) — **36 current invariants**
- [`docs/16-requirements.md`](docs/16-requirements.md)
- [`docs/17-v0.1-acceptance-tests.md`](docs/17-v0.1-acceptance-tests.md)
- [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md)

### Security / state / trust

- [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md)
- [`docs/19-principal-and-authority-model.md`](docs/19-principal-and-authority-model.md)
- [`docs/21-trust-boundaries.md`](docs/21-trust-boundaries.md)
- [`docs/24-task-state-machine.md`](docs/24-task-state-machine.md)
- [`docs/35-v0.1-persistence-model.md`](docs/35-v0.1-persistence-model.md)
- [`docs/45-cross-domain-transactions-and-compensation.md`](docs/45-cross-domain-transactions-and-compensation.md)

### AIOS IR / language / compilation

- [`docs/23-ai-native-language-and-ir.md`](docs/23-ai-native-language-and-ir.md)
- [`docs/25-aios-ir-semantics.md`](docs/25-aios-ir-semantics.md)
- [`docs/26-aios-ir-validation-and-lowering.md`](docs/26-aios-ir-validation-and-lowering.md)
- [`docs/27-skill-compilation-and-adaptive-optimization.md`](docs/27-skill-compilation-and-adaptive-optimization.md)
- [`docs/28-capability-contracts-and-conformance.md`](docs/28-capability-contracts-and-conformance.md)
- [`docs/29-semantic-type-system.md`](docs/29-semantic-type-system.md)
- [`docs/30-aios-ir-reference-validator-plan.md`](docs/30-aios-ir-reference-validator-plan.md)
- [`docs/31-semantic-registry-snapshots.md`](docs/31-semantic-registry-snapshots.md)
- [`docs/32-aios-ir-and-skill-benchmark-plan.md`](docs/32-aios-ir-and-skill-benchmark-plan.md)
- [`docs/33-bootstrap-language-boundary.md`](docs/33-bootstrap-language-boundary.md)
- [`docs/36-aios-ir-compiler-and-lowering-boundary.md`](docs/36-aios-ir-compiler-and-lowering-boundary.md)
- [`docs/39-static-effect-and-authority-analysis.md`](docs/39-static-effect-and-authority-analysis.md)

### Platform fabrics

- [`docs/40-universal-software-fabric.md`](docs/40-universal-software-fabric.md)
- [`docs/41-domain-capability-architecture.md`](docs/41-domain-capability-architecture.md)
- [`docs/42-universal-object-graph-and-data-federation.md`](docs/42-universal-object-graph-and-data-federation.md)
- [`docs/43-software-coverage-expansion-strategy.md`](docs/43-software-coverage-expansion-strategy.md)
- [`docs/44-tier0-universal-object-model.md`](docs/44-tier0-universal-object-model.md)
- [`docs/46-domain-pack-lifecycle-and-governance.md`](docs/46-domain-pack-lifecycle-and-governance.md)
- [`docs/47-cross-domain-reference-workflow.md`](docs/47-cross-domain-reference-workflow.md)
- [`docs/48-resource-placement-and-personal-compute-fabric.md`](docs/48-resource-placement-and-personal-compute-fabric.md)
- [`docs/49-identity-resolution-and-object-reconciliation.md`](docs/49-identity-resolution-and-object-reconciliation.md)
- [`docs/50-adaptive-presentation-and-device-ui.md`](docs/50-adaptive-presentation-and-device-ui.md)
- [`docs/51-network-fabric-and-service-connectivity.md`](docs/51-network-fabric-and-service-connectivity.md)
- [`docs/52-cloud-edge-and-service-fabric.md`](docs/52-cloud-edge-and-service-fabric.md)
- [`docs/53-system-of-everything-staged-roadmap.md`](docs/53-system-of-everything-staged-roadmap.md)
- [`docs/54-unified-platform-fabric-architecture.md`](docs/54-unified-platform-fabric-architecture.md)
- [`docs/55-storage-sync-and-replica-fabric.md`](docs/55-storage-sync-and-replica-fabric.md)
- [`docs/56-cryptographic-identity-trust-and-credential-fabric.md`](docs/56-cryptographic-identity-trust-and-credential-fabric.md)
- [`docs/57-component-distribution-supply-chain-and-update-trust.md`](docs/57-component-distribution-supply-chain-and-update-trust.md)
- [`docs/58-files-namespaces-and-semantic-projection.md`](docs/58-files-namespaces-and-semantic-projection.md)

### Decisions / contracts / fixtures

- [`docs/adr/`](docs/adr/) — Architecture Decision Records
- [`specs/README.md`](specs/README.md) — machine-contract index/principles
- [`specs/`](specs/) — JSON Schemas + draft persistence SQL
- [`examples/aios-ir/`](examples/aios-ir/) — semantic IR/registry/validation/adversarial fixtures
- [`examples/reference-task/`](examples/reference-task/) — broader control-plane Demonstration A/B fixtures
- [`examples/domain-fabric/`](examples/domain-fabric/) — synthetic Universal Object/Domain examples
- [`examples/platform-fabric/`](examples/platform-fabric/) — presentation/network/cloud/storage/trust/package examples
- [`interfaces/wit/`](interfaces/wit/) — early Wasm Component/WIT ABI experiments

## Non-goals for v0.1

- writing a new kernel;
- replacing every existing operating system/application;
- guaranteeing universal legacy compatibility;
- building a full desktop/mobile shell;
- building production distributed storage/network/cloud infrastructure;
- launching a public package marketplace;
- training a foundation model;
- locking to one AI/cloud/vendor;
- building a new general-purpose source language/compiler before AIOS IR evidence justifies it.

## Current phase

**Stage 0 architecture constitution is nearing the point where the first trusted-core spike can begin. No implementation claim is made yet.**

The immediate engineering objective is intentionally small:

```text
untrusted candidate AIOS IR
        ↓
strict deterministic parser/validator
        ↓
semantic registry/type/capability/effect checks
        ↓
canonical semantic identity/hash
        ↓
VALID or REJECTED
```

Once that boundary works, the project can safely begin building Task persistence, Artifact/provenance stores, deterministic policy, provider binding, and eventually model-assisted orchestration on top.
