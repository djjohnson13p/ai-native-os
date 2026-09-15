# 16 — Architecture Requirements

This document converts the current vision into testable requirements. The IDs are intended to be referenced by ADRs, issues, implementation plans, conformance tests, and later release criteria.

Status values used here:

- **MUST** — required for the architecture to be considered valid;
- **SHOULD** — strong default that may be overridden by an explicit ADR;
- **MAY** — optional capability.

## Requirement scope

These are **architecture requirements**, not all immediate v0.1 release gates.

Use `docs/17-v0.1-acceptance-tests.md`, `docs/53-system-of-everything-staged-roadmap.md`, and `docs/64-requirements-traceability-matrix.md` to distinguish:

```text
CORE-v0.1     required by the first trusted prototype
INTERFACE     contract/boundary must be preserved now; implementation can be later
LATER-STAGE   required before the corresponding platform fabric claims support
```

A later-stage requirement still constrains earlier architecture when violating it would create an incompatible foundation.

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

## Semantic objects and Domain Packs

### R-OBJ-001 — Provider-independent object identity

A durable semantic Object MUST be identifiable independently of the application, database, storage backend, file path, external record ID, or provider currently representing it.

### R-OBJ-002 — Explicit source-of-truth state

Federated, mirrored, derived, native, and ephemeral Object states MUST be distinguishable, and the authoritative source for mutable fields SHOULD be explicit where more than one system participates.

### R-OBJ-003 — Revision-safe mutation

Durable Object mutation SHOULD support revision/version/content preconditions so stale state cannot silently overwrite a newer authoritative revision.

### R-OBJ-004 — Relationship semantics

Cross-object relationships SHOULD use versioned semantic predicates/contracts rather than provider-specific foreign-key meaning as the platform interface.

### R-OBJ-005 — Identity merge is consequential state change

Probabilistic/entity-resolution output MAY propose that records are equivalent, but durable link/merge operations MUST pass deterministic contradiction checks, current revision checks, policy, and any consequence-appropriate approval.

### R-OBJ-006 — Merge/split history

Object merges/links/splits MUST preserve enough alias/tombstone/provenance history to reconstruct prior references and repair an incorrect merge without deleting audit history.

### R-DOM-001 — Domain Pack semantics are open/versioned

A Domain Pack MUST describe its semantic objects/extensions, capabilities, invariants, and dependencies through versioned contracts rather than requiring one application/provider implementation.

### R-DOM-002 — Views do not own domain identity

A Domain Pack MAY provide specialized Views, but the View MUST NOT become the sole owner/identity of the underlying semantic Objects or capabilities.

### R-DOM-003 — Domain correctness remains explicit

Domain Packs SHOULD express deterministic validation/invariants for consequential domain rules where possible rather than delegating correctness solely to unconstrained model reasoning.

## Cross-domain effects and transactions

### R-XDOM-001 — Transaction/effect class

Consequential side-effecting capabilities SHOULD expose semantics sufficient to distinguish atomic-local, conditional/versioned remote, idempotent external, compensatable, and irreversible external effects.

### R-XDOM-002 — Stable operation identity

External side-effect attempts MUST have stable operation identities sufficient for retry/recovery/idempotency/provenance decisions.

### R-XDOM-003 — Unknown outcome is explicit

After timeout/crash/disconnection, an operation whose external effect cannot be proven complete or absent MUST be represented as unknown rather than blindly retried.

### R-XDOM-004 — Compensation is a new authorized effect

Compensation/rollback of non-atomic external effects MUST be explicitly authorized and recorded; it MUST NOT be modeled as erasing historical evidence.

### R-XDOM-005 — Irreversible-effect gate

Irreversible external effects SHOULD execute only after required verification, revision/precondition checks, approvals, and durable provenance up to the commit boundary are satisfied.

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

### R-RES-005 — Hard eligibility before optimization

Semantic compatibility, authority/policy, isolation, conformance/correctness, and resource feasibility MUST be enforced as hard placement constraints before convenience objectives such as latency, cost, or energy are ranked.

### R-RES-006 — Placement does not change semantic identity

Moving an eligible semantic node between local CPU/GPU/NPU, trusted peer, edge, or remote provider MUST create/change runtime binding rather than silently changing the semantic-program identity.

### R-RES-007 — Data movement is placement cost

The Resource Broker SHOULD consider input/output size, replica/cache locality, transfer cost, and egress policy when ranking otherwise eligible placement candidates.

## Presentation fabric

### R-PRES-001 — Presentation is projection

Changing screen/device/View/input modality MUST NOT change Task, Object, Artifact, or semantic-program identity.

### R-PRES-002 — Adaptive View selection

The Presentation Broker SHOULD be able to select different conforming Views for compact, desktop, multi-display, voice/headless, accessibility, remote-surface, and specialized direct-manipulation contexts.

### R-PRES-003 — Trusted approval surface

Security-sensitive approval/credential/authority confirmation MUST use trusted system presentation that an untrusted provider View cannot impersonate as authoritative.

### R-PRES-004 — Specialized direct manipulation

The architecture MUST permit domain-specialized direct manipulation (for example CAD/EDA/media/code/table Views) rather than forcing every expert workflow through natural-language conversation.

### R-PRES-005 — Accessibility is contract input

Presentation contracts SHOULD represent accessibility/input/output requirements as first-class selection/conformance constraints rather than optional afterthoughts.

## Network fabric

### R-NET-001 — No ambient connectivity

Providers, models, Skills, and legacy habitats MUST NOT receive unrestricted network access merely because the host is connected.

### R-NET-002 — Service identity independent of endpoint

A stable service/peer identity MUST be representable independently of its current IP address, DNS name, relay, interface, or route.

### R-NET-003 — Discovery is not authorization

Discovering/reaching a local/peer/remote service MUST NOT itself authorize connection/use/data transfer.

### R-NET-004 — Transfer provenance

Material data transfer SHOULD record Task, source references, destination/service identity, purpose, policy/grant, and transfer outcome sufficient for user inspection/recovery.

### R-NET-005 — Inbound exposure defaults closed

Publishing/listening services SHOULD require explicit authority/policy and MUST NOT be enabled merely by installing a provider.

### R-NET-006 — Retry respects external-effect certainty

Network reconnect/retry MUST preserve operation-level idempotency/outcome rules and MUST NOT duplicate irreversible external effects solely because a transport disconnected.

## Cloud / edge / remote services

### R-CLOUD-001 — Cloud is provider/runtime state

Cloud provider names, regions, instance IDs, bucket paths, and proprietary resource identifiers MUST NOT become core semantic Task/Object identity.

### R-CLOUD-002 — Remote eligibility is policy constrained

Residency, jurisdiction, sensitivity, trust, cost ceiling, and egress policy MUST be able to make a remote candidate ineligible before objective scoring.

### R-CLOUD-003 — Remote failure remains locally inspectable

Loss of a remote provider/cloud service MUST NOT erase local knowledge of Task state, semantic program identity, policy/provenance, or already committed local artifacts.

### R-CLOUD-004 — No mandatory proprietary cloud for core recovery

Boot/recovery and locally available core capabilities MUST NOT depend on one proprietary cloud account/service unless the requested capability is inherently remote.

### R-CLOUD-005 — Provider substitution preserves semantics

Switching among conforming eligible self-hosted/edge/public remote providers MUST create a new Execution Binding/placement record rather than a semantic rewrite.

## Storage / replica / namespace fabric

### R-STOR-001 — Storage location is not semantic identity

Filesystem paths, mount points, database rows, object-store keys, replica IDs, and cloud locations MUST NOT define semantic Object identity and SHOULD NOT define Artifact identity beyond explicit representation/version semantics.

### R-STOR-002 — Replica role is explicit

Authoritative, mirror, cache, archive, export, and derived replicas MUST be distinguishable so a convenient/newer replica cannot silently become source of truth.

### R-STOR-003 — Replica promotion is explicit

Promotion/failover of a mirror/replica to authoritative state MUST use explicit policy/revision/integrity checks and provenance.

### R-STOR-004 — Sync is distinct from backup/archive/cache

The platform MUST distinguish synchronization, backup, archive, cache, and export semantics so deletion/retention behavior is not inferred incorrectly across classes.

### R-STOR-005 — Offline reconciliation is revision-safe

Queued/offline mutations MUST be revalidated against current revision/version and current authority/policy before remote/federated commit after reconnect.

### R-STOR-006 — Namespace projection does not own identity

Renaming/moving/materializing a file/path projection MUST NOT by itself create/destroy the underlying semantic Object/Artifact identity.

### R-STOR-007 — Large data need not traverse control-plane database

The architecture SHOULD support streaming/range/chunked/content-addressed handling so large engineering/media/scientific/model artifacts do not require embedding/copying entire payloads through ordinary control-plane state.

## Cryptographic identity / trust / credentials

### R-ID-001 — Authentication is separate from authorization

Successful login, device pairing, certificate/key proof, package signature, or service authentication MUST NOT independently grant broad protected-resource authority.

### R-ID-002 — Stable device/service/publisher identity

Device, service, provider, and publisher identity SHOULD survive endpoint/IP/process/cloud-resource changes through explicit stable principal identity/key lifecycle semantics.

### R-ID-003 — Credential mediation

Long-lived secrets SHOULD remain behind opaque/narrow credential handles so providers/workloads can be authorized to use a credential without receiving raw secret material whenever practical.

### R-ID-004 — Non-exportable credentials remain non-exportable

Credentials marked non-exportable or handle-only MUST NOT be serialized into remote execution/model/provider requests merely because the task migrates.

### R-ID-005 — Delegation cannot amplify authority

Delegated workload/provider authority MUST NOT exceed the source principal's current permission and MUST carry bounded scope/expiry/delegation depth.

### R-ID-006 — Revocation preserves history

Revoking/rotating a device/service/publisher credential SHOULD invalidate future/current authorization as appropriate without rewriting historical Task/Object/provenance identity.

### R-ID-007 — Attestation is evidence

Hardware/software attestation MAY influence policy but MUST NOT override ordinary authority, privacy, egress, or approval requirements.

## Component distribution / supply chain

### R-PKG-001 — Immutable package identity

Distributable providers, Domain Packs, Views, Skills, model assets/runtimes, compatibility adapters, policy/registry bundles, and system extensions SHOULD have explicit logical version plus immutable content digest.

### R-PKG-002 — Publisher signature is not runtime authority

A valid package signature MAY establish publisher/integrity evidence but MUST NOT automatically grant semantic conformance, safety status, or runtime authority.

### R-PKG-003 — Authority-diff gate

An update that broadens authority, effect, network, credential, or minimum-isolation requirements MUST be detectable and MUST pass current policy/approval before activation.

### R-PKG-004 — Semantic-diff gate

Changes to provided semantic capabilities/types, determinism/effect semantics, verification, or conformance claims MUST be versioned/evaluated explicitly rather than hidden as ordinary implementation updates.

### R-PKG-005 — Staged activation and rollback

Security-relevant components SHOULD be staged/validated before atomic activation and SHOULD retain a known-good rollback path when state-migration semantics permit.

### R-PKG-006 — Catalog/mirror is not root of trust

Package registries/catalogs/mirrors MAY distribute immutable content, but clients MUST independently verify required content identity/signature/trust/conformance metadata according to policy.

### R-PKG-007 — Supply-chain attribution

Security-sensitive components SHOULD expose publisher/version/build provenance/SBOM/license metadata sufficient to attribute what executed and assess dependencies.

### R-PKG-008 — Revocation/quarantine preserves provenance

Compromised/revoked components SHOULD be disableable/quarantinable without deleting historical evidence of Tasks that previously used them.

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

### R-PROV-006 — Runtime-version attribution

Material execution SHOULD identify relevant provider/component/semantic-registry/runtime versions or immutable identities needed to reconstruct what implementation performed the work.

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

Core task, capability, policy, provenance, artifact, provider, type, IR, and stable platform-fabric contracts MUST be publicly documented if the project is released as open source.

### R-OSS-002 — Conformance over branding

Third-party providers SHOULD be judged by public conformance tests and declared capabilities rather than requiring vendor-specific integration.

### R-OSS-003 — Vendor-neutral naming

Core architecture MUST avoid requiring OpenAI, Anthropic, Google, Apple, Microsoft, AWS, Azure, Salesforce, Adobe, Autodesk, or another vendor's trademark/service as an identity dependency.

### R-OSS-004 — License boundary visibility

Distributed components SHOULD preserve machine-readable license/attribution metadata and explicit package/process/component boundaries sufficient to avoid accidental incompatibility as the platform incorporates many open-source ecosystems.
