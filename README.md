# AI-Native Operating System — Architecture Draft v0.1

> Working title. The project name, final license, implementation languages, and governance model are intentionally not fixed yet.

This repository defines an open-source operating-system architecture designed **around AI from the beginning**, rather than adding an AI assistant to an application-centric desktop.

The core premise is simple:

> People primarily care about accomplishing tasks, not choosing applications. The system should translate human intent into safe, inspectable, reusable capabilities and execute those capabilities across local hardware, compatibility environments, remote compute, and existing software.

The initial implementation should **not** begin with a new kernel. It should use a mature kernel and driver ecosystem—initially Linux—and place the novel work in the userspace architecture: intent handling, capability discovery, agent execution, resource brokerage, compatibility routing, policy enforcement, learning, and task-first interaction.

## Foundational goals

1. **Task-first computing** — the task, not the app, is the primary user-level unit of work.
2. **Capability-oriented software** — document editing, calculation, image manipulation, 3D rendering, communication, and other functions become discoverable capabilities.
3. **AI as an operating primitive** — intent, agents, memory, provenance, confidence, delegation, policy, and capabilities are first-class system concepts.
4. **Universal legacy compatibility as a transition strategy** — existing Windows, Linux, Android, web, and other software should run through transparent execution habitats whenever technically and legally feasible.
5. **Hardware-adaptive operation** — the system profiles available hardware and composes an appropriate local, hybrid, or remote execution plan.
6. **Local-first privacy and explicit data boundaries** — private context does not leave the device merely because an AI model is involved.
7. **Deterministic foundations** — boot, hardware detection, rollback, security policy, and destructive operations remain deterministic and auditable.
8. **Model independence** — the operating system must not depend on a single AI provider or model family.
9. **Reason once, compile when stable, reuse thereafter** — repeated reasoning should become cheaper deterministic procedures when safe.
10. **Open-source by design** — architecture, interfaces, policy formats, capability manifests, and conformance tests should be publicly inspectable.

## Architecture shorthand

The current working model is:

```text
Human intent
    ↓
Task / intent layer
    ↓
Planner + capability broker + policy engine
    ↓
Resource broker + Universal App Broker
    ↓
Deterministic providers · AI models · containers · VMs · legacy software
    ↓
Deterministic Linux-based system foundation
```

AI may propose what to do. **Deterministic policy decides what is allowed.**

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
- [`docs/13-open-questions.md`](docs/13-open-questions.md) — decisions intentionally left open

### Architecture hardening

- [`docs/14-terminology.md`](docs/14-terminology.md) — canonical vocabulary and core abstractions
- [`docs/15-system-invariants.md`](docs/15-system-invariants.md) — rules that should survive implementation changes
- [`docs/16-requirements.md`](docs/16-requirements.md) — testable architecture requirements with stable IDs
- [`docs/17-v0.1-acceptance-tests.md`](docs/17-v0.1-acceptance-tests.md) — acceptance, recovery, compatibility, and adversarial test plan
- [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md) — implementation dependency graph and Codex-readiness criteria
- [`docs/19-principal-and-authority-model.md`](docs/19-principal-and-authority-model.md) — principals, resources, grants, approval, delegation, revocation, and egress semantics
- [`docs/20-user-object-model.md`](docs/20-user-object-model.md) — task/artifact/workspace/conversation/application/view object model
- [`docs/21-trust-boundaries.md`](docs/21-trust-boundaries.md) — trusted base, providers, legacy habitats, external systems, and boundary-crossing rules
- [`docs/22-end-to-end-reference-flow.md`](docs/22-end-to-end-reference-flow.md) — complete Demonstration A flow through planning, policy, execution, verification, and learning
- [`docs/23-task-shell-ux.md`](docs/23-task-shell-ux.md) — task-first interaction, approval, progress, artifact, and compatibility-launch behavior
- [`docs/24-task-state-machine.md`](docs/24-task-state-machine.md) — deterministic persisted lifecycle, recovery, cancellation, verification, and rollback states

### Research

- [`docs/research/01-linux-base-and-updates.md`](docs/research/01-linux-base-and-updates.md) — reference Linux, image-mode, update, and rollback evaluation
- [`docs/research/02-sandboxing-and-execution-isolation.md`](docs/research/02-sandboxing-and-execution-isolation.md) — Landlock/namespaces/container/VM isolation strategy
- [`docs/research/03-legacy-compatibility-fabric.md`](docs/research/03-legacy-compatibility-fabric.md) — Wine, Android, CPU translation, VM, and experimental macOS routing model
- [`docs/research/04-model-runtime-and-routing.md`](docs/research/04-model-runtime-and-routing.md) — provider-neutral model routing and local-runtime strategy
- [`docs/research/05-service-ipc-and-language.md`](docs/research/05-service-ipc-and-language.md) — process boundaries, Varlink/D-Bus/gRPC roles, Rust/Python split, and persistence
- [`docs/research/06-authorization-policy-engine.md`](docs/research/06-authorization-policy-engine.md) — Cedar vs OPA and the proposed authority-coordinator boundary

### Decisions and machine-readable contracts

- [`docs/adr/`](docs/adr/) — accepted/proposed architecture decision records
- [`specs/README.md`](specs/README.md) — contract principles and versioning rules
- [`specs/`](specs/) — draft task, capability, hardware, artifact, authority, provenance, execution-isolation, model, policy, and compatibility contracts
- [`examples/reference-task/`](examples/reference-task/) — concrete Demonstration A/B contract fixtures for future conformance tests
- [`prototypes/README.md`](prototypes/README.md) — implementation boundaries for the first prototype

### Implementation backlog

GitHub Issues contain bounded v0.1 workstreams with acceptance criteria. The implementation dependency order is documented in [`docs/18-pre-codex-workplan.md`](docs/18-pre-codex-workplan.md).

## v0.1 success criterion

A user should be able to give a high-level task such as:

> “Understand these numbers, identify the important changes, produce a chart and a concise report, and save the result.”

The prototype should:

- inspect the available data;
- derive a typed execution plan;
- select calculation, table, chart, and document capabilities without the user opening applications;
- request only the minimum permissions needed;
- execute locally where practical;
- verify important deterministic results;
- produce inspectable provenance showing what happened;
- save normal portable files;
- learn/reuse at least one repeated task pattern;
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

## Current phase

**Architecture and pre-implementation hardening. No implementation claim is made yet.**

The immediate work is to make the contracts precise enough that implementation can be divided into bounded workstreams without allowing convenience decisions to silently redefine the system.
