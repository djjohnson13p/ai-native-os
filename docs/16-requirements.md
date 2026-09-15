# 16 — Architecture Requirements

This document converts the current vision into testable requirements. The IDs are intended to be referenced by ADRs, issues, implementation plans, conformance tests, and later release criteria.

Status values used here:

- **MUST** — required for the architecture to be considered valid;
- **SHOULD** — strong default that may be overridden by an explicit ADR;
- **MAY** — optional capability.

## Task and intent

### R-TASK-001 — Task identity

Every user-initiated or autonomous unit of work MUST have a stable task identifier independent of individual processes or providers.

### R-TASK-002 — Intent preservation

The system MUST retain the original user intent alongside normalized/structured interpretations and plan revisions.

### R-TASK-003 — Typed plan

Executable plans MUST be represented in a constrained typed form rather than unconstrained natural language.

### R-TASK-004 — Plan revision history

Material plan changes SHOULD be preserved in provenance so that users and developers can reconstruct why execution changed.

### R-TASK-005 — Long-running tasks

The task model MUST support work that survives shell/UI restarts and, eventually, device reboot.

## AIOS intermediate representation

### R-IR-001 — Provider-independent semantic program

Runnable task semantics MUST be representable without requiring a concrete provider, model vendor, executable path, process ID, or hardware device identity.

### R-IR-002 — No embedded authority

Semantic IR MUST NOT contain reusable authority grants, bearer tokens, passwords, secret values, approval bypasses, or other values that grant execution permission merely by appearing in the program.

### R-IR-003 — Deterministic validation

Before execution, AIOS IR MUST pass structural and semantic validation performed by deterministic code without requiring a model judgment for correctness.

### R-IR-004 — Explicit typed data flow

Every executable IR node MUST use named typed input/output ports and all data-flow references MUST resolve before a task becomes runnable.

### R-IR-005 — Explicit execution class

Every executable node MUST declare or resolve to an execution class sufficient for caching, verification, provenance, and skill-compilation decisions: deterministic, bounded nondeterministic, probabilistic, or opaque external.

### R-IR-006 — Bounded control behavior

AIOS IR v0.1 MUST NOT permit unbounded retry, fallback, replan, or general loop behavior. Any repeated execution behavior MUST have a finite machine-verifiable budget.

### R-IR-007 — Explicit authority and egress intent

IR nodes that require side effects MUST explicitly request the relevant authority classes, and external data egress MUST be declared as denied or policy-controlled before runtime binding.

### R-IR-008 — Verification preservation

Required verification gates MUST be represented in the semantic graph such that optimizers/compilers cannot remove them without creating a semantically different program requiring revalidation.

### R-IR-009 — Stable semantic identity

Normalized IR SHOULD have a canonical serialization/content hash so equivalent executable meaning can be identified independently of formatting and runtime provider bindings.

### R-IR-010 — Execution binding separation

Concrete provider identity, grant references, sandbox profile, hardware placement, attempt number, and other runtime bindings MUST be represented outside the semantic IR.

### R-IR-011 — Non-escalating transformation

Optimization/compilation MUST NOT broaden authority, egress, or side effects; weaken verification; or replace deterministic behavior with probabilistic behavior without semantic revalidation.

### R-IR-012 — Stable validation reason codes

The validator SHOULD emit stable machine-readable reason-code families for schema, reference, graph, type, capability, effect, authority, egress, failure-policy, and version errors.

## Semantic type and capability contracts

### R-CONTRACT-001 — Capability semantics independent of provider

The meaning of a stable semantic capability MUST be defined independently from any provider implementation.

### R-CONTRACT-002 — Named typed ports

Capability contracts MUST declare named semantic input and output ports and their type versions.

### R-CONTRACT-003 — Provider conformance

A provider claiming interchangeability SHOULD be evaluated against the same referenced conformance suite as other providers implementing that semantic capability.

### R-CONTRACT-004 — Allowed effects and authority classes

Semantic capability contracts MUST declare the effect/authority classes an implementation is permitted to require. A provider requesting undeclared authority MUST fail closed.

### R-CONTRACT-005 — Semantic types independent of representation

Semantic type identity MUST NOT be defined solely by a host-language class, library object, file extension, or one physical encoding.

### R-CONTRACT-006 — Explicit conversion

AIOS IR v0.1 SHOULD require exact compatible semantic types and represent meaningful semantic conversion through explicit capabilities rather than implicit language-style casts.

### R-CONTRACT-007 — Registry snapshot reproducibility

IR semantic validation SHOULD be reproducible against identifiable capability/type registry snapshots.

## Capability system

### R-CAP-001 — Stable capability identity

Capabilities MUST have stable semantic identifiers and explicit versions or compatibility ranges.

### R-CAP-002 — Typed interfaces

A capability MUST declare input types, output types, side effects, authority requirements, determinism characteristics, and failure modes.

### R-CAP-003 — Multiple providers

The registry MUST allow more than one provider to satisfy the same capability.

### R-CAP-004 — Provider selection

Provider selection MUST be policy-aware and SHOULD consider privacy, quality, latency, resource cost, monetary cost, energy, availability, trust, and user preference.

### R-CAP-005 — Provider isolation

Untrusted or third-party providers MUST execute under bounded authority appropriate to their capability.

### R-CAP-006 — Conformance

The project SHOULD define conformance tests for stable capabilities before claiming provider interchangeability.

## Security and authority

### R-SEC-001 — No ambient authority

AI reasoning components MUST NOT automatically inherit the logged-in user's complete permissions.

### R-SEC-002 — Task-scoped grants

Side-effecting execution MUST be authorized by deterministic grants scoped to a task, principal, action, and resource.

### R-SEC-003 — Egress control

Transfer of user data outside the local trust boundary MUST pass an explicit policy decision and MUST be recorded in provenance.

### R-SEC-004 — Secret mediation

Providers SHOULD receive handles or narrowly scoped credentials instead of raw long-lived secrets where possible.

### R-SEC-005 — Irreversible actions

High-consequence irreversible actions MUST have stricter policy than reversible task-local writes and MUST support explicit approval requirements.

### R-SEC-006 — Untrusted instructions

Data content MUST NOT be able to grant itself authority by containing instructions, prompts, scripts, metadata, or model-readable text.

### R-SEC-007 — Deterministic enforcement

Policy enforcement, sandbox setup, privilege transitions, secure storage, boot/recovery, and rollback MUST NOT depend on unconstrained model output for correctness.

## Data and artifacts

### R-DATA-001 — Typed handles

Providers SHOULD exchange references to typed data/artifacts rather than unrestricted filesystem paths whenever practical.

### R-DATA-002 — Portable artifacts

User-facing outputs SHOULD be exportable to ordinary interoperable formats.

### R-DATA-003 — Lineage

Derived artifacts MUST be linkable to their source artifacts and producing task steps.

### R-DATA-004 — Sensitivity metadata

The data layer SHOULD support sensitivity/classification labels that policy can use for egress and provider selection.

### R-DATA-005 — Integrity

Artifacts and important task inputs SHOULD have content hashes when practical so provenance can detect unexpected mutation.

## Models and agents

### R-AI-001 — Provider independence

The AI runtime interface MUST support multiple model providers and MUST NOT make one vendor's proprietary API the operating-system contract.

### R-AI-002 — Local/remote routing

The resource/model broker MUST be capable of routing appropriate work between local and remote model providers according to policy and hardware availability.

### R-AI-003 — Structured output validation

Model-generated plans and machine-actionable outputs MUST be validated against schemas or equivalent constrained interfaces before execution.

### R-AI-004 — Agent scope

Each agent MUST be associated with a task and explicit capability scope.

### R-AI-005 — Verification separation

For consequential deterministic results, the system SHOULD verify model conclusions against deterministic computation or an independent verifier where possible.

## Resource adaptation

### R-RES-001 — Hardware profile

The system MUST be able to derive a structured hardware profile containing CPU architecture, memory, accelerators, storage, relevant devices, and execution constraints.

### R-RES-002 — Graceful degradation

Unsupported or constrained local hardware SHOULD reduce local capability or change placement rather than automatically making the entire OS unusable.

### R-RES-003 — Placement rationale

Resource-placement decisions SHOULD be explainable in terms of policy and measurable constraints such as privacy, latency, memory, accelerator support, cost, or energy.

### R-RES-004 — Offline baseline

The system MUST retain a minimally useful offline operating/recovery mode without a remote AI service.

## Legacy compatibility

### R-COMPAT-001 — Package classification

The Universal App Broker MUST inspect a legacy package/application and classify the execution requirements before launch.

### R-COMPAT-002 — Habitat routing

Legacy execution SHOULD be routed through a named, inspectable habitat profile rather than ad-hoc host mutation.

### R-COMPAT-003 — Containment

Legacy habitats MUST receive explicit filesystem, network, device, IPC, clipboard, and secret boundaries appropriate to the application.

### R-COMPAT-004 — Translation composition

The architecture MUST permit OS API translation, CPU architecture translation, containers, VMs, and remote execution to be composed where needed.

### R-COMPAT-005 — Honest compatibility claims

The project MUST distinguish "transparent launch", "supported", "works with limitations", "experimental", and "unsupported" compatibility states.

## Provenance and recovery

### R-PROV-001 — Append-only event history

Task execution MUST produce an append-oriented provenance stream sufficient to reconstruct material actions.

### R-PROV-002 — Provider attribution

Provenance MUST identify the provider/model or deterministic component responsible for each material execution step.

### R-PROV-003 — Authority attribution

Provenance MUST record the grant/approval under which a side effect occurred.

### R-PROV-004 — External transfer visibility

Provenance MUST make external data transfer visible to the user and debugging tools.

### R-PROV-005 — Recovery metadata

Reversible actions SHOULD record enough information to support compensation, rollback, or restoration.

## Learning and skills

### R-SKILL-001 — Versioned skills

Reusable learned procedures MUST be versioned artifacts with provenance and declared authority requirements.

### R-SKILL-002 — Revalidation

A previously successful skill MUST still pass current policy and provider validation when executed later.

### R-SKILL-003 — Compilation threshold

Probabilistic workflows SHOULD only be compiled into deterministic procedures after explicit validation criteria are met.

### R-SKILL-004 — Privacy scrubbing

Skills intended for sharing MUST NOT include private context merely because that context appeared in the task from which the skill was learned.

### R-SKILL-005 — No inherited grants

A reusable or compiled Skill MUST NOT carry forward task-specific approvals, capability tokens, bearer credentials, or other prior execution authority.

### R-SKILL-006 — Source traceability

Compiled Skill targets SHOULD remain traceable to a source AIOS IR hash/template and validation evidence.

### R-SKILL-007 — Measurable efficiency

Claims that Skill reuse improves efficiency SHOULD be supported by measurements such as reduced model invocations/tokens, latency, memory, network, energy, or monetary cost.

## Base system

### R-BASE-001 — Mature kernel/driver ecosystem first

The initial implementation MUST use an existing mature kernel and driver ecosystem unless a future ADR demonstrates a concrete need for kernel replacement.

### R-BASE-002 — Atomic recovery path

The base system SHOULD support known-good rollback for system updates and critical configuration changes.

### R-BASE-003 — Signed system components

Privileged system components SHOULD be verifiable by cryptographic identity/signature and version metadata.

### R-BASE-004 — AI-independent recovery

Recovery tooling MUST remain usable without a functioning AI planner.

## User experience

### R-UX-001 — Task-first primary path

The primary interface MUST allow the user to request outcomes without manually selecting applications.

### R-UX-002 — Traditional application escape hatch

The user SHOULD retain the ability to explicitly launch and interact with traditional applications when desired.

### R-UX-003 — Inspectability

Users MUST be able to inspect active tasks, requested approvals, significant provider choices, data egress, failures, and results.

### R-UX-004 — Progressive disclosure

The default interface SHOULD hide unnecessary implementation detail while making deeper plan/provenance information available on demand.

## Open-source architecture

### R-OSS-001 — Open contracts

Core task, capability, policy, provenance, artifact, provider, type, and IR contracts MUST be publicly documented if the project is released as open source.

### R-OSS-002 — Conformance over branding

Third-party providers SHOULD be judged by public conformance tests and declared capabilities rather than requiring vendor-specific integration.

### R-OSS-003 — Vendor-neutral naming

Core architecture MUST avoid requiring OpenAI, Anthropic, Google, Apple, Microsoft, or another vendor's trademark or service as an identity dependency.
