# ADR 0017 — Compiled Targets Do Not Carry Authority

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

Validated repeated AIOS IR subgraphs may eventually be lowered to WASM, native code, fused provider pipelines, queries, or accelerator graphs for efficiency.

If compiled output embeds the permissions/credentials of the task that caused compilation, Skill reuse would become an authority-escalation mechanism and would violate the task-scoped security model.

## Decision

Compiled targets contain executable computation and static semantic effect metadata, but **never reusable execution authority**.

Specifically:

- capability grants/tokens are supplied only through a fresh Execution Binding;
- raw long-lived credentials/secrets are not embedded in compiled output;
- task-specific approvals are not embedded;
- compiled code interacts with protected resources through host-mediated interfaces under current task authority;
- compiled target manifests record an authority/effect upper bound for validation/optimization, but that bound is descriptive—not a grant;
- invocation still passes current policy evaluation and provenance requirements;
- a compiled target that requires broader authority than the source semantic subgraph is invalid.

## Consequences

### Positive

- Skill compilation cannot turn one user's prior approval into ambient future authority;
- compiled artifacts can be cached/shared more safely when privacy rules permit;
- the same compiled computation can execute for multiple tasks with different scoped inputs/grants;
- runtime policy remains the authoritative security boundary;
- target invalidation/regeneration is independent of user credential rotation.

### Negative

- host-call mediation may add overhead compared with unrestricted native execution;
- compiler/runtime ABI design becomes important;
- some existing libraries expect ambient filesystem/network access and will need provider adapters or stronger isolation rather than direct compilation.

## Alternatives considered

### Bake task token into compiled target

Rejected because it creates reusable bearer authority and couples code cache lifetime to permission lifetime.

### Trust signed compiled Skills with persistent authority

Rejected. Signature/publisher trust may influence whether code is eligible to execute, but does not replace current principal/task/resource authorization.

### Compile only completely pure computation forever

Too restrictive as a permanent architecture. Task-local artifact effects may be safely supported through mediated host interfaces while preserving fresh authorization.

## Acceptance criteria

- compiled-target schema has no token/secret/approval-grant field;
- runtime can execute the same pure/task-local compiled target under two separate tasks with distinct current grants;
- expired/revoked prior task grants do not affect the ability to authorize a new task normally;
- compiled code cannot access a protected resource omitted from its current Execution Binding;
- optimizer rejects a target whose static effect/authority envelope exceeds source semantic contracts.

## Related

- I24
- `docs/27-skill-compilation-and-adaptive-optimization.md`
- `docs/36-aios-ir-compiler-and-lowering-boundary.md`
- `specs/compiled-target.schema.json`
- `specs/execution-binding.schema.json`
