# Research 06 — Authorization Policy Engine

**Research date:** 2026-09-15  
**Status:** provisional recommendation for issue #3; requires policy-model spike and adversarial tests.

## Question

Should the AI-native OS invent a policy language, use a general-purpose policy engine, or adopt an authorization-specific engine for task-scoped capability decisions?

## Requirements from our architecture

The authorization layer must reason deterministically over concepts such as:

```text
principal
  agent / provider / legacy app / user / system service

action
  read / write / create / send / execute / delete / administer

resource
  artifact / task output / network destination / secret / device / system function

context
  task ID
  acting-on-behalf-of user
  resource sensitivity
  data-egress destination
  approval presence/scope
  device posture
  time/expiry
  workspace/org policy
  impact class
```

It must default safely, support explicit denial, be testable/auditable, and integrate into the proposed Rust control plane.

## Cedar

Cedar is an open-source authorization policy language and engine designed around the question:

> Can this **principal** perform this **action** on this **resource** in this **context**?

That principal/action/resource/context (PARC) structure maps unusually closely to our authority model.

Cedar also provides:

- `permit` and `forbid` policies;
- default denial when no permit applies;
- `forbid` precedence over permits;
- entity attributes and hierarchies;
- request context;
- policy/schema validation;
- an authorization response that identifies determining policies;
- a Rust implementation available as the `cedar-policy` crate;
- tooling designed for analysis of authorization policies.

Cedar's current documentation explicitly discusses automated agents acting on behalf of users as a context-modeling scenario, which is directly relevant to our architecture.

Primary sources:

- https://docs.cedarpolicy.com/
- https://docs.cedarpolicy.com/auth/authorization.html
- https://docs.cedarpolicy.com/bestpractices/bp-using-the-context.html
- https://docs.cedarpolicy.com/policies/validation.html
- https://github.com/cedar-policy/cedar

## Open Policy Agent / Rego

OPA is a mature general-purpose policy engine using Rego. It supports authorization, admission control, data filtering, policy tests, server/Go integration, and compilation to WebAssembly.

Strengths:

- broad ecosystem;
- highly expressive policy/data rules;
- strong testing/tooling;
- can produce structured JSON decisions rather than only booleans;
- Wasm compilation gives language/runtime integration options;
- suitable for many future organization/cloud policy scenarios.

Tradeoffs for our v0.1:

- Rego is intentionally more general than our core authorization problem;
- the proposed control plane is Rust, while OPA's native embedding story centers on Go or Wasm/server integration;
- a general policy language makes it easier to mix authorization with unrelated policy computation;
- OPA documentation notes memory growth with loaded JSON data/rule sets, which matters to the project's older-device goal;
- using an external OPA server as a critical local authorization hop adds process/management complexity before we need it.

Primary sources:

- https://www.openpolicyagent.org/docs
- https://www.openpolicyagent.org/docs/policy-language
- https://www.openpolicyagent.org/docs/integration
- https://www.openpolicyagent.org/docs/policy-testing
- https://www.openpolicyagent.org/docs/policy-performance

OPA remains a strong candidate for organizational/cloud-policy bridges later. The core question is narrower: the local operating-system authority engine.

## Custom policy language

A custom language could fit every project concept exactly.

Do **not** start there.

Authorization-language design is security-sensitive work involving parsing, evaluation semantics, conflict rules, schema evolution, diagnostics, testing, tooling, and eventually analysis. Our novelty is the task/capability operating model, not inventing a novel boolean language.

A small amount of deterministic project-specific logic will still surround any engine, but that is different from inventing the policy evaluator.

## Provisional recommendation: Cedar inside the Rust authority module

Use Cedar as the **core authorization decision engine** for v0.1, embedded into the Rust control plane.

Map AI-OS concepts as follows:

```text
Cedar principal
  User / Agent / Provider / LegacyApp / SystemService / PeerNode

Cedar action
  semantic resource operation, e.g. Artifact::Read,
  Network::Send, TaskOutput::Create, System::Update

Cedar resource
  artifact:A17
  task-output:T91
  network:model-provider-X
  secret:service-X
  device:camera-front

Cedar context
  task identity
  viaAgent / onBehalfOf
  request-local impact/sensitivity
  requested egress metadata
  approval record reference/state
  device posture / offline mode
```

## Important separation: authorization vs approval workflow

Cedar produces Allow/Deny authorization decisions. Our UX/policy model additionally includes:

```text
REQUIRE_APPROVAL
ALLOW_WITH_NARROWER_SCOPE
```

Do not distort Cedar into an approval workflow engine.

Instead, use a deterministic **Authority Coordinator**:

```text
capability request
      ↓
request canonicalization + minimum-scope calculation
      ↓
deterministic impact/approval rule evaluation
      ↓
if approval required and absent → REQUIRE_APPROVAL
      ↓
Cedar PARC authorization on requested/effective resource action
      ↓
Allow / Deny
      ↓
issue task-scoped capability grant
```

### Narrower scope

`ALLOW_WITH_NARROWER_SCOPE` should mean the authority coordinator can safely derive a smaller request from policy/resource rules, then ask Cedar about that explicit smaller set.

It must not mean the model or Cedar evaluator silently rewrites broad authority into an opaque scope.

Example:

```text
Requested:
  read workspace:Payroll/*

Known task inputs:
  artifact:A17
  artifact:A12

Policy permits:
  only task-selected artifacts

Coordinator response:
  narrower candidate = [A17, A12]
  Cedar evaluates read on each resource
  issued token contains only permitted explicit artifacts
```

## Proposed entity model

Illustrative Cedar entities:

```text
AIOS::User::"U1"
AIOS::Agent::"planner-T91"
AIOS::Provider::"table-import"
AIOS::LegacyApp::"demo-win64"
AIOS::Artifact::"A17"
AIOS::TaskOutput::"T91"
AIOS::NetworkDestination::"model-provider-X"
AIOS::Secret::"provider-X-credential"
AIOS::Device::"camera-front"
```

Agent/provider entity attributes can include:

- publisher/trust class;
- task binding;
- capability identity;
- sandbox/isolation class;
- locality;
- review status.

Resource attributes can include:

- owner;
- sensitivity;
- workspace;
- retention class;
- task-local flag;
- destination/trust zone.

## Example policy ideas

These are conceptual; exact Cedar syntax/schema belongs in the spike.

### Provider may read task-selected artifacts

Permit provider/agent reads only when:

- resource is in the current task's selected/derived artifact set;
- provider's declared capability requires read;
- resource sensitivity is compatible with execution locality.

### Local-only forbids remote egress

A `forbid` policy should override other permits when:

- task privacy mode is local-only;
- action is network send/remote model invocation;
- destination is outside the local trust boundary.

### Agent can never directly access stored secrets

Forbid raw secret read by agent/model/legacy-app principals. Permit only the secret broker/system service to use secret material for an already-authorized operation.

## Capability tokens remain project-owned

Cedar is the authorization engine, not the runtime grant format.

Flow:

```text
Cedar decision + determining policy IDs
        ↓
Authority Coordinator
        ↓
opaque short-lived task-scoped capability token
        ↓
Provider Runner verifies token and constructs sandbox
```

The capability token should preserve the Cedar decision/provenance reference.

This allows execution to be fast and scoped without re-embedding arbitrary policy data in every provider.

## Policy validation and deployment

Treat policy as code:

- validate policies against a Cedar schema before activation;
- unit-test expected permit/forbid results;
- retain policy version/hash;
- stage policy updates before activation;
- record active policy version in decisions/provenance;
- keep a known-good policy set for recovery;
- fail closed if policy/schema fails to load.

AI may **suggest** policy edits, but policy activation is a deterministic administrative operation and should require appropriate approval.

## v0.1 policy spike

Before accepting an ADR, implement a small Rust test harness using `cedar-policy` covering:

1. provider reads one selected artifact → allow;
2. same provider reads unrelated artifact → deny;
3. agent tries raw secret read → deny;
4. local-only task attempts remote model send → forbid;
5. remote-allowed task with correct approval context → allow;
6. legacy app attempts host secret → deny;
7. task ID mismatch → deny;
8. expired grant is rejected by authority coordinator even if base resource policy would otherwise allow;
9. explicit forbid overrides broader permit;
10. malformed/invalid policy cannot be activated.

## Decision criteria after spike

Accept Cedar if:

- PARC maps cleanly without awkward entity tricks;
- the Rust crate integrates cleanly into `aiosd`;
- policies are understandable enough for audit/admin use;
- deny/forbid behavior is clear and testable;
- policy evaluation overhead is insignificant relative to task/provider work;
- schema validation catches expected policy mistakes.

Reconsider OPA or a small custom evaluator only if a concrete required policy class cannot be represented safely and intelligibly in Cedar.
