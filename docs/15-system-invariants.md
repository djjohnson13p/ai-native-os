# 15 — System Invariants

These invariants are intended to survive implementation-language changes, model-provider changes, UI changes, and compatibility-layer changes. They are stronger than preferences and should be treated as architecture tests.

## I1 — No ambient AI authority

No model, planner, agent, learned skill, or compatibility profile inherits the user's full authority merely because the user launched it.

Every side-effecting action must be attributable to a task and authorized through deterministic policy.

## I2 — Plans are proposals, not permissions

A planner may produce any syntactically valid plan. Execution occurs only after every step resolves to known capabilities and passes deterministic semantic validation and policy checks.

Generated shell commands, code, SQL, scripts, or UI actions do not receive privileged execution merely because a model produced them.

## I3 — The deterministic base can boot without an AI provider

A machine must be able to boot, identify hardware, expose recovery, inspect policy, update/rollback, and reach a minimally useful maintenance environment even when no AI model is available.

## I4 — User data has an explicit egress boundary

Data does not leave the local trust boundary by implication. Remote execution requires an egress decision that is visible in provenance and subject to policy.

## I5 — Every external side effect is attributable

The system must be able to identify the task, semantic program/node, principal, provider, capability, authority grant, input references, and timestamp associated with an external communication or persistent change.

## I6 — Repeated reasoning should become cheaper when safe

The system should not repeatedly spend large-model reasoning on stable deterministic work. Validated repeated plans should be eligible for reuse/compilation into versioned Skills or deterministic providers.

Optimization must not weaken authorization, verification, provenance, data isolation, or current-input correctness.

## I7 — Compatibility cannot weaken isolation

A legacy application does not gain broader access because it expects a conventional desktop. Habitats must mediate filesystem, device, network, credential, clipboard, inter-process, and host integration access.

## I8 — Normal outputs remain portable

The system should prefer ordinary, documented formats for user artifacts. A task-first OS must not trap the user's work inside an opaque AI-only database.

Examples include Markdown, PDF, ODF/OOXML, PNG/JPEG, CSV/Parquet, glTF, source code, and other ecosystem-standard formats where appropriate.

## I9 — Provider substitution is an architectural requirement

A semantic capability should be replaceable by another conforming provider without changing the task's semantic program. A model provider should likewise be replaceable behind a stable runtime interface when policy and capability requirements permit.

Provider selection may change an execution binding. It should not silently rewrite semantic meaning.

## I10 — AI uncertainty cannot silently change authority

Low confidence, ambiguity, conflicting instructions, or model disagreement may trigger clarification, safer planning, additional verification, or denial. It may never be resolved by broadening privileges silently.

## I11 — Hardware differences change placement, not the conceptual OS

The same task/capability model should operate across high-end workstations, ordinary laptops, phones, and constrained older devices. Hardware changes which providers can run locally and which work must degrade, defer, use peers, or use remote compute.

## I12 — Failure must be a normal state

Tasks, providers, models, devices, networks, and compatibility habitats will fail. The task model must represent partial completion, bounded retries, alternative providers, compensation/rollback, and durable recovery.

## I13 — Observability is part of the product

A user must be able to inspect what the system is doing without understanding process IDs or application internals. Task state, pending approvals, semantic steps, provider selection, data egress, cost, and failures are user-facing operating-system concepts.

## I14 — Security policy is independent of model policy

Provider safety settings, model system prompts, and model alignment behavior are defense-in-depth. They are not substitutes for operating-system authorization.

## I15 — The installer must not synthesize privileged code by default

Hardware adaptation should select from known, signed, testable kernels, drivers, services, compatibility components, and configuration profiles. AI may assist diagnosis and selection, but the default boot/install path must remain reproducible and rollback-safe.

## I16 — The OS remains useful when offline

Offline capability will vary with hardware, but core files, installed deterministic providers, task history, policy, recovery, local semantic registries, and locally available models/capabilities must remain usable without cloud access.

## I17 — A task can cross providers without losing identity

When work moves between local execution, remote services, peer devices, legacy habitats, or different models, the task identity, semantic program identity, authority boundaries, artifact lineage, and provenance chain must remain intact.

## I18 — User intent outranks provider convenience

The architecture should not force a user to care which application, model, framework, or device performs an ordinary task unless that choice materially affects quality, privacy, cost, compatibility, or control.

## I19 — Semantic programs are separate from runtime bindings

AIOS IR defines what the task means. Provider IDs, model instances, hardware placement, sandbox instances, process IDs, credentials, capability grants, and attempt-specific state belong to runtime bindings.

A runtime binding may vary without changing semantic program identity.

## I20 — Semantic validation does not depend on AI judgment

The trusted parser/normalizer/validator must be able to accept or reject executable AIOS IR without asking a model whether malformed, ambiguous, or hostile program structure is safe.

A model may propose repairs, but every repaired proposal is validated again from the beginning.

## I21 — Meaning belongs to semantic contracts, not provider claims

A provider does not define the meaning of a capability merely by claiming its name.

Stable semantic capability and type contracts define the interface; provider implementations must conform to them before interchangeable-provider claims are made.

## I22 — Meaningful type conversions are explicit

For v0.1, the system does not rely on implicit host-language coercions to connect semantic capability ports.

A meaningful conversion between semantic types must be represented explicitly so it can be validated, authorized where necessary, optimized safely, and reconstructed in provenance.

## I23 — Verification survives optimization

A compiler, optimizer, cached result, Skill, provider substitution, or legacy adapter may not silently remove a verification requirement that is part of the validated semantic program.

A transformation that weakens verification is a semantic change and must be treated as such.

## I24 — Learned or compiled Skills never inherit old authority

Skills can reuse validated structure and compiled computation. They cannot reuse a prior task's approval, capability token, bearer credential, secret value, or authority grant.

Every invocation receives a new task context and current policy evaluation.

## I25 — Adaptive efficiency must be measurable

The project may claim that repeated work becomes cheaper only when measurements support the claim.

Benchmarking should distinguish model/planning cost, validation/policy overhead, provider execution, memory/data movement, network/egress, compilation cost, and correctness/verification.

## How to use these invariants

Every future ADR and major pull request should state whether it:

- preserves all invariants;
- intentionally refines an invariant; or
- proposes changing an invariant, which requires an explicit architecture decision rather than an incidental implementation change.
