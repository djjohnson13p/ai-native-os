# AI-Native Operating System — Architecture Draft v0.1

> Working title. The project name, final license, implementation languages, and governance model are intentionally not fixed yet.

This repository defines an open-source operating-system architecture designed **around AI from the beginning**, rather than adding an AI assistant to an application-centric desktop.

The core premise is simple:

> People primarily care about accomplishing tasks, not choosing applications. The system should translate human intent into safe, inspectable, reusable capabilities and execute those capabilities across local hardware, compatibility environments, remote compute, and existing software.

The initial implementation should **not** begin with a new kernel. It should use a mature kernel and driver ecosystem—initially Linux—and place the novel work in the userspace architecture: intent handling, AI-native execution semantics, capability discovery, agent execution, resource brokerage, compatibility routing, policy enforcement, learning, and task-first interaction.

## Foundational goals

1. **Task-first computing** — the task, not the app, is the primary user-level unit of work.
2. **Capability-oriented software** — document editing, calculation, image manipulation, 3D rendering, communication, and other functions become discoverable capabilities.
3. **AI as an operating primitive** — intent, agents, memory, provenance, confidence, delegation, policy, and capabilities are first-class system concepts.
4. **Universal legacy compatibility as a transition strategy** — existing Windows, Linux, Android, web, and other software should run through transparent execution habitats whenever technically and legally feasible.
5. **Hardware-adaptive operation** — the system profiles available hardware and composes an appropriate local, hybrid, or remote execution plan.
6. **Local-first privacy and explicit data boundaries** — private context does not leave the device merely because an AI model is involved.
7. **Deterministic foundations** — boot, hardware detection, rollback, security policy, validation, and destructive operations remain deterministic and auditable.
8. **Model independence** — the operating system must not depend on a single AI provider or model family.
9. **Reason once, compile when stable, reuse thereafter** — repeated reasoning should become cheaper deterministic procedures when safe.
10. **Open-source by design** — architecture, interfaces, policy formats, semantic contracts, and conformance tests should be publicly inspectable.

## Architecture shorthand

The current working model is:

```text
Human intent
    ↓
Task / intent layer
    ↓
Planner proposal
    ↓
AIOS IR validation + semantic capability/type contracts
    ↓
Deterministic policy + capability/resource brokers
    ↓
Execution binding
    ↓
Deterministic providers · AI models · compiled Skills · containers · VMs · legacy software
    ↓
Deterministic Linux-based system foundation
```

AI may propose what to do. **Deterministic validation decides whether the program is well-formed; deterministic policy decides what is allowed.**

## Native object model

The current draft separates the concepts that conventional operating systems often collapse into applications/windows:

```text
Task         = intent + authorization + execution + provenance
Artifact     = durable content/data and lineage
Workspace    = optional organizational/context container
Conversation = interaction channel/history
Application  = legacy/provider/UI entity
Window/View  = presentation of an object, not its lifetime
```

## AI-native computational model

The project explicitly separates the language used to **implement** the operating environment from the language/representation used to describe **what an AI-native computer should do**.

Bootstrap implementation can use mature tools such as Rust, Python, C/C++, Linux APIs, existing compatibility projects, and WASM. Those are implementation mechanisms, not the semantic identity of the OS.

The project is defining **AIOS IR**, a provider-independent typed semantic graph with first-class concepts for:

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

AIOS IR never grants itself authority. Provider identities, capability grants, sandbox instances, and hardware placement are bound only after deterministic validation and policy evaluation.

The design principle is:

> **Own the semantics before owning the syntax.**

A new human-facing/general-purpose language may emerge later if real measurements show that it improves correctness, AI generation reliability, optimization, security, or efficiency. The project will not build one merely for novelty.

## Bootstrap language boundary

Current proposed roles:

```text
Rust     → trusted control-plane core
Python   → rapid model/provider/data experimentation
C/C++    → bounded bridge to mature native ecosystems
WASM     → portable provider / compiled-Skill target candidate
Shell    → build/dev/maintenance glue, not runtime escape hatch
```

The stable architecture lives above those choices in AIOS IR, semantic contracts, task/artifact/authority/provenance contracts, and language-neutral execution bindings.

The long-term objective is not “write the OS in Rust.” It is “use mature tooling until measurements justify owning a deeper compiler/runtime.”

## Semantic contract model

AIOS IR invokes semantic capabilities rather than executables/applications:

```text
AIOS IR node
    ↓
Semantic Capability Contract
    ↓
One of N Provider Implementations
    ↓
Runtime binding + sandbox + authority grant
```

Semantic types are also separated from physical representation, so `data.table@1` can survive a change from one dataframe/library/serialization implementation to another.

This gives the Resource/Capability Brokers room to adapt execution to available hardware without changing task meaning.

## Adaptive compilation model

Stable repeated work may progressively move from expensive reasoning to reusable validated computation:

```text
fresh intent
   ↓
model-assisted plan
   ↓
validated AIOS IR
   ↓ repeated success
parameterized Skill
   ↓
compiled deterministic subgraphs
   ↓
WASM / native / provider-pipeline / query / accelerator targets
```

Compiled targets contain computation, **not reusable authority**. Every invocation gets fresh policy evaluation and execution binding.

The benchmark plan explicitly compares fresh planning, IR reuse, Skill reuse, and compiled execution before the project claims efficiency gains.

## Repository map

### Foundation

- [`docs/00-charter.md`](docs/00-charter.md) — project charter and definition
- [`docs/01-design-principles.md`](docs/01-design-principles.md) — non-negotiable design principles
- [`docs/02-system-architecture.md`](docs/02-system-architecture.md) — layered architecture
- [`docs/03-task-intent-model.md`](docs/03-task-intent-model.md) — tasks, intents, plans, and provenance
- [`docs/04-capability-model.md`](docs/04-capability-model.md) — capability providers and composition
- [`docs/05-agent-runtime.md`](docs/05-agent-runtime.md) — agent lifecycle and execution model
- [`docs/06-resource-broker.md`](docs/06-resource-broker.md) — hardware- and cost-aware scheduling
- [`docs/07-universal-app-broker.md`](docs/07-universal-app-broker.md) — legacy software compatibility fabric
- [`docs/08-security-threat-model.md`](docs/08-security-threat-model.md) — capability security and threat model
- [`docs/09-memory-learning-privacy.md`](docs/09-memory-learning-privacy.md) — local memory and reusable learning
- [`docs/10-hardware-adaptation.md`](docs/10-hardware-adaptation.md) — installation and graceful degradation
- [`docs/11-v0.1-prototype.md`](docs/11-v0.1-prototype.md) — narrow proof-of-concept target
- [`docs/12-roadmap.md`](docs/12-roadmap.md) — staged development roadmap
- [`docs/13-open-questions.md`](docs/13-open-questions.md) — current open/narrowed/proposed decision status

### Architecture hardening

- [`docs/14-terminology.md`](docs/14-terminology.md) — canonical vocabulary and core abstractions
- [`docs/15-system-invariants.md`](docs/15-system-invariants.md) — 25 architecture invariants that implementation must preserve
- [`docs/16-requirements.md`](docs/16-requirements.md) — testable architecture requirements with stable IDs
- [`docs/17-v0.1-acceptance-tests.md`](docs/17-v0.1-acceptance-tests.md) — acceptance, IR, recovery, compatibility, and adversarial test plan
- [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md) — implementation dependency graph and Codex-readiness criteria
- [`docs/19-principal-and-authority-model.md`](docs/19-principal-and-authority-model.md) — principals, resources, grants, approval, delegation, revocation, and egress semantics
- [`docs/20-user-object-model.md`](docs/20-user-object-model.md) — task/artifact/workspace/conversation/application/view object model
- [`docs/21-trust-boundaries.md`](docs/21-trust-boundaries.md) — trusted base, providers, legacy habitats, external systems, and boundary-crossing rules
- [`docs/22-end-to-end-reference-flow.md`](docs/22-end-to-end-reference-flow.md) — complete Demonstration A flow through planning, policy, execution, verification, and learning
- [`docs/23-task-shell-ux.md`](docs/23-task-shell-ux.md) — task-first interaction, approval, progress, artifact, and compatibility-launch behavior
- [`docs/24-task-state-machine.md`](docs/24-task-state-machine.md) — deterministic persisted lifecycle, recovery, cancellation, verification, and rollback states
- [`docs/34-task-ir-lifecycle.md`](docs/34-task-ir-lifecycle.md) — relationship between durable Task identity, planner revisions, validated semantic programs, and execution bindings
- [`docs/35-v0.1-persistence-model.md`](docs/35-v0.1-persistence-model.md) — proposed SQLite control-plane durability/transaction/recovery model

### AI-native language / execution semantics

- [`docs/23-ai-native-language-and-ir.md`](docs/23-ai-native-language-and-ir.md) — why the project owns AI-native semantics before inventing a new general-purpose language
- [`docs/25-aios-ir-semantics.md`](docs/25-aios-ir-semantics.md) — formal semantic graph model
- [`docs/26-aios-ir-validation-and-lowering.md`](docs/26-aios-ir-validation-and-lowering.md) — deterministic validation, runtime binding, and lowering pipeline
- [`docs/27-skill-compilation-and-adaptive-optimization.md`](docs/27-skill-compilation-and-adaptive-optimization.md) — reason-once/compile/reuse lifecycle
- [`docs/28-capability-contracts-and-conformance.md`](docs/28-capability-contracts-and-conformance.md) — provider-independent capability semantics and provider conformance
- [`docs/29-semantic-type-system.md`](docs/29-semantic-type-system.md) — semantic types vs physical representations and explicit conversion rules
- [`docs/30-aios-ir-reference-validator-plan.md`](docs/30-aios-ir-reference-validator-plan.md) — bounded Rust validator implementation plan for the first Codex spike
- [`docs/31-semantic-registry-snapshots.md`](docs/31-semantic-registry-snapshots.md) — immutable/content-addressed semantic meaning used for reproducible validation
- [`docs/32-aios-ir-and-skill-benchmark-plan.md`](docs/32-aios-ir-and-skill-benchmark-plan.md) — M0–M4 efficiency/correctness benchmark framework
- [`docs/33-bootstrap-language-boundary.md`](docs/33-bootstrap-language-boundary.md) — existing-language bootstrap and evidence threshold for deeper custom language/runtime work
- [`docs/36-aios-ir-compiler-and-lowering-boundary.md`](docs/36-aios-ir-compiler-and-lowering-boundary.md) — how validated deterministic subgraphs may lower to efficient targets without carrying authority

### Research

- [`docs/research/01-linux-base-and-updates.md`](docs/research/01-linux-base-and-updates.md) — reference Linux, image-mode, update, and rollback evaluation
- [`docs/research/02-sandboxing-and-execution-isolation.md`](docs/research/02-sandboxing-and-execution-isolation.md) — Landlock/namespaces/container/VM isolation strategy
- [`docs/research/03-legacy-compatibility-fabric.md`](docs/research/03-legacy-compatibility-fabric.md) — Wine, Android, CPU translation, VM, and experimental macOS routing model
- [`docs/research/04-model-runtime-and-routing.md`](docs/research/04-model-runtime-and-routing.md) — provider-neutral model routing and local-runtime strategy
- [`docs/research/05-service-ipc-and-language.md`](docs/research/05-service-ipc-and-language.md) — process boundaries, Varlink/D-Bus/gRPC roles, Rust/Python split, and persistence
- [`docs/research/06-authorization-policy-engine.md`](docs/research/06-authorization-policy-engine.md) — Cedar vs OPA and the proposed authority-coordinator boundary

### Decisions and machine-readable contracts

- [`docs/adr/`](docs/adr/) — architecture decisions, including AIOS IR, semantic contracts, bootstrap-language, validator, and compiled-authority boundaries
- [`specs/README.md`](specs/README.md) — contract principles, semantic layers, registry snapshots, and versioning rules
- [`specs/`](specs/) — task, AIOS IR, validation, semantic registry/type/capability, hardware, artifact, authority, provenance, execution-binding/isolation, compiled target, Skill, model, policy, compatibility, and persistence contracts
- [`specs/persistence-v0.1.sql`](specs/persistence-v0.1.sql) — draft SQLite schema for task/program/binding/artifact/policy/provenance recovery
- [`examples/aios-ir/`](examples/aios-ir/) — Demonstration A IR, semantic registries, validation/binding/Skill examples, and positive/adversarial fixtures
- [`examples/reference-task/`](examples/reference-task/) — broader Demonstration A/B control-plane fixtures
- [`prototypes/README.md`](prototypes/README.md) — implementation boundaries for the first prototype

### Implementation backlog

GitHub Issues contain bounded v0.1 workstreams with acceptance criteria. The implementation dependency order is documented in [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md).

Issue #17 is the proposed first major semantic-boundary implementation spike: deterministic AIOS IR parsing/validation/normalization/hashing without a model planner.

## v0.1 success criterion

A user should be able to give a high-level task such as:

> “Understand these numbers, identify the important changes, produce a chart and a concise report, and save the result.”

The prototype should:

- inspect the available data;
- derive a typed planner proposal and normalize it to valid AIOS IR;
- select calculation, table, chart, and document capabilities without the user opening applications;
- request only the minimum permissions needed;
- execute locally where practical;
- verify important deterministic results;
- produce inspectable provenance showing what happened;
- save normal portable files;
- learn/reuse at least one repeated task pattern;
- measurably reduce repeated model/planning work through Skill/IR reuse;
- and transparently launch at least one legacy application through a compatibility habitat as a separate proof of the transition strategy.

That is intentionally much narrower than “build a universal operating system.” The goal of v0.1 is to prove that the architecture is meaningfully different from a conventional desktop with a chatbot attached.

## Non-goals for v0.1

- Writing a new kernel
- Reimplementing Windows, macOS, Android, or Linux
- Guaranteeing that every legacy application works
- Allowing an AI model to synthesize privileged kernel or driver code during normal boot
- Building a full desktop replacement
- Training a foundation model
- Locking the project to any AI provider
- Building a new general-purpose source language/compiler before AIOS IR evidence justifies it

## Current phase

**Architecture and pre-implementation hardening. No implementation claim is made yet.**

The immediate work is to make the semantic/contracts boundary precise enough that the first implementation tasks are constrained engineering problems rather than opportunities for implementation convenience to redefine the OS.
