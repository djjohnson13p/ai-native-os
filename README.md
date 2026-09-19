# AI-Native Operating System — Architecture Draft v0.1

> Working title. The final project name, license, implementation languages, and governance model are intentionally not fixed yet.

This repository defines an open computing architecture designed **around AI from the beginning**, rather than adding an AI assistant to an application-centric desktop.

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
- produce portable output Artifacts;
- record inspectable provenance;
- demonstrate provider substitution;
- demonstrate repeated-work reuse/Skill optimization;
- separately launch at least one legacy application through a compatibility habitat.

The goal is to prove an architecture that is meaningfully different from a normal desktop with a chatbot attached.

## Current implementation entry point

**Stage 0 is closed enough for bounded trusted-core implementation.** The repository now includes
the Issue #17 reference implementation of the deterministic AIOS IR v0.1 trust boundary. It is a
validator and development CLI, not an execution runtime or authority system.

The first serious implementation assignment remains **GitHub Issue #17**:

> deterministic AIOS IR parser/validator/normalizer/static-effect-summary/semantic-hash boundary.

It intentionally requires:

- no model planner;
- no provider execution;
- no network/cloud;
- no GUI;
- no policy backend yet;
- no custom source language.

### Run the reference validator

Install a Rust toolchain compatible with `rust-toolchain.toml`, then run the complete trusted-core
suite from the repository root:

```text
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The CLI always requires an explicit local immutable registry bundle for commands that interpret a
program:

```text
cargo run -p aios-ir-cli -- validate examples/aios-ir/demonstration-a.ir.json --registry examples/aios-ir
cargo run -p aios-ir-cli -- normalize examples/aios-ir/demonstration-a.ir.json --registry examples/aios-ir
cargo run -p aios-ir-cli -- hash examples/aios-ir/demonstration-a.ir.json --registry examples/aios-ir
cargo run -p aios-ir-cli -- effects examples/aios-ir/demonstration-a.ir.json --registry examples/aios-ir
cargo run -p aios-ir-cli -- explain-error IR_GRAPH_CYCLE
```

All CLI responses are JSON. Exit status `0` means valid/successful, `2` means deterministic
rejection, and `1` means an operational or invocation error. Validation performs no model call,
provider execution, authority grant, or network lookup.

After #17, the project builds a deterministic operating spine before introducing AI planning:

```text
#17 validator
→ #1 Task Manager
→ #4 Artifact Store
→ #5 Provenance
→ #2 Semantic/Provider Registry
→ #3 Authority Coordinator
→ minimal Credential Broker
→ #30 Provider Supervisor + one deterministic provider
→ deterministic end-to-end Task with crash/recovery tests
→ only then Resource/Model/Planner work
```

Implementation/review preparation:

- [`AGENTS.md`](AGENTS.md) — coding-agent constitution/map
- [`docs/59-pre-codex-foundation-closure-plan.md`](docs/59-pre-codex-foundation-closure-plan.md) — architecture closure classes/gates
- [`docs/62-first-codex-session-runbook.md`](docs/62-first-codex-session-runbook.md) — exact first Codex session scope/stop conditions
- [`docs/71-validator-spike-readiness-checklist.md`](docs/71-validator-spike-readiness-checklist.md) — #17 architecture readiness
- [`docs/81-stage0-architecture-closure-audit.md`](docs/81-stage0-architecture-closure-audit.md) — Stage-0 closure assessment
- [`docs/82-stage1-core-substrate-codex-runbook.md`](docs/82-stage1-core-substrate-codex-runbook.md) — deterministic-spine implementation sequence
- [`docs/83-pre-implementation-red-team-and-astra-review-packet.md`](docs/83-pre-implementation-red-team-and-astra-review-packet.md) — independent adversarial architecture review packet
- [`specs/contract-maturity.json`](specs/contract-maturity.json) — machine-readable maturity snapshot

## Trusted-core architecture now specified

The pre-implementation contracts cover:

```text
AIOS IR validation + semantic hashing
Task CAS/idempotent state transitions
Artifact content identity + staged publication
append/hash-chain provenance
semantic registry snapshots + provider registrations
engine-neutral deterministic policy + trusted approvals + scoped grants
opaque Credential Broker / secret mediation
immutable Execution Bindings + typed Provider Supervisor invocation
crash consistency / outcome certainty / deterministic recovery
```

Important safety rules now include:

- Execution Bindings are immutable attempt receipts;
- provider retry/substitution creates a new binding/attempt;
- raw long-lived credentials do not live in IR/Task/provenance/provider manifests;
- capability contracts declare required and allowed effect/authority envelopes;
- `network.connect` and `data.egress` are distinct authority classes;
- `OUTCOME_UNKNOWN` is not ordinary retryable failure;
- Artifact staging bytes are not published output;
- response loss does not imply the operation failed or should rerun.

## Repository guide

### Constitution / requirements

- [`docs/00-charter.md`](docs/00-charter.md)
- [`docs/01-design-principles.md`](docs/01-design-principles.md)
- [`docs/14-terminology.md`](docs/14-terminology.md)
- [`docs/15-system-invariants.md`](docs/15-system-invariants.md) — **36 current invariants**
- [`docs/16-requirements.md`](docs/16-requirements.md)
- [`docs/17-v0.1-acceptance-tests.md`](docs/17-v0.1-acceptance-tests.md)
- [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md)
- [`docs/53-system-of-everything-staged-roadmap.md`](docs/53-system-of-everything-staged-roadmap.md)
- [`docs/81-stage0-architecture-closure-audit.md`](docs/81-stage0-architecture-closure-audit.md)

### Security / state / trusted execution

- [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md)
- [`docs/19-principal-and-authority-model.md`](docs/19-principal-and-authority-model.md)
- [`docs/21-trust-boundaries.md`](docs/21-trust-boundaries.md)
- [`docs/24-task-state-machine.md`](docs/24-task-state-machine.md)
- [`docs/35-v0.1-persistence-model.md`](docs/35-v0.1-persistence-model.md)
- [`docs/73-v0.1-provenance-journal-and-hash-chain.md`](docs/73-v0.1-provenance-journal-and-hash-chain.md)
- [`docs/74-v0.1-task-manager-transition-and-cas-contract.md`](docs/74-v0.1-task-manager-transition-and-cas-contract.md)
- [`docs/75-v0.1-artifact-store-content-identity-and-publication.md`](docs/75-v0.1-artifact-store-content-identity-and-publication.md)
- [`docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md`](docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md)
- [`docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`](docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md)
- [`docs/78-v0.1-execution-binding-and-provider-supervisor.md`](docs/78-v0.1-execution-binding-and-provider-supervisor.md)
- [`docs/79-v0.1-credential-broker-and-secret-mediation.md`](docs/79-v0.1-credential-broker-and-secret-mediation.md)
- [`docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md`](docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md)

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
- [`docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`](docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md)
- [`docs/68-aios-ir-v0.1-edge-case-semantics.md`](docs/68-aios-ir-v0.1-edge-case-semantics.md)
- [`docs/69-v0.1-capability-effect-and-authority-contract-profile.md`](docs/69-v0.1-capability-effect-and-authority-contract-profile.md)
- [`docs/72-v0.1-semantic-contract-and-registry-hash-profile.md`](docs/72-v0.1-semantic-contract-and-registry-hash-profile.md)

### Platform fabrics

- [`docs/40-universal-software-fabric.md`](docs/40-universal-software-fabric.md)
- [`docs/41-domain-capability-architecture.md`](docs/41-domain-capability-architecture.md)
- [`docs/42-universal-object-graph-and-data-federation.md`](docs/42-universal-object-graph-and-data-federation.md)
- [`docs/43-software-coverage-expansion-strategy.md`](docs/43-software-coverage-expansion-strategy.md)
- [`docs/44-tier0-universal-object-model.md`](docs/44-tier0-universal-object-model.md)
- [`docs/45-cross-domain-transactions-and-compensation.md`](docs/45-cross-domain-transactions-and-compensation.md)
- [`docs/46-domain-pack-lifecycle-and-governance.md`](docs/46-domain-pack-lifecycle-and-governance.md)
- [`docs/47-cross-domain-reference-workflow.md`](docs/47-cross-domain-reference-workflow.md)
- [`docs/48-resource-placement-and-personal-compute-fabric.md`](docs/48-resource-placement-and-personal-compute-fabric.md)
- [`docs/49-identity-resolution-and-object-reconciliation.md`](docs/49-identity-resolution-and-object-reconciliation.md)
- [`docs/50-adaptive-presentation-and-device-ui.md`](docs/50-adaptive-presentation-and-device-ui.md)
- [`docs/51-network-fabric-and-service-connectivity.md`](docs/51-network-fabric-and-service-connectivity.md)
- [`docs/52-cloud-edge-and-service-fabric.md`](docs/52-cloud-edge-and-service-fabric.md)
- [`docs/54-unified-platform-fabric-architecture.md`](docs/54-unified-platform-fabric-architecture.md)
- [`docs/55-storage-sync-and-replica-fabric.md`](docs/55-storage-sync-and-replica-fabric.md)
- [`docs/56-cryptographic-identity-trust-and-credential-fabric.md`](docs/56-cryptographic-identity-trust-and-credential-fabric.md)
- [`docs/57-component-distribution-supply-chain-and-update-trust.md`](docs/57-component-distribution-supply-chain-and-update-trust.md)
- [`docs/58-files-namespaces-and-semantic-projection.md`](docs/58-files-namespaces-and-semantic-projection.md)

### Decisions / contracts / fixtures / governance

- [`docs/adr/`](docs/adr/) — Architecture Decision Records
- [`specs/README.md`](specs/README.md) — machine-contract index/principles
- [`specs/contract-maturity.json`](specs/contract-maturity.json) — current maturity status
- [`specs/`](specs/) — JSON Schemas + aligned draft persistence SQL
- [`examples/`](examples/) — synthetic positive/negative/adversarial fixtures
- [`interfaces/wit/`](interfaces/wit/) — early Wasm Component/WIT ABI experiments
- [`docs/82-stage1-core-substrate-codex-runbook.md`](docs/82-stage1-core-substrate-codex-runbook.md) — post-validator deterministic-core build sequence
- [`docs/83-pre-implementation-red-team-and-astra-review-packet.md`](docs/83-pre-implementation-red-team-and-astra-review-packet.md) — independent architecture red-team packet
- [`docs/84-open-source-license-and-governance-decision-framework.md`](docs/84-open-source-license-and-governance-decision-framework.md) — license/governance decision scaffolding; no final license chosen

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

**Stage 0 architecture is closed enough that further progress now depends more on executable evidence than on adding broader conceptual architecture.**

The immediate next milestone is Issue #17. Independent adversarial review can run against `docs/83-pre-implementation-red-team-and-astra-review-packet.md` before or alongside early implementation review.

No production-readiness or working-operating-system claim is made yet.
