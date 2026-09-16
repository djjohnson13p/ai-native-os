# 87 — Cedar Authority Backend Mapping Spike

## Purpose

ADR 0010 identifies Cedar as a strong candidate policy backend. The Stage-0 Authority Coordinator is intentionally **engine-neutral**.

This document defines the bounded experiment required before Cedar may become the first production/reference backend:

> Map AIOS's concrete principal/action/resource/context decisions into Cedar without making Cedar policy syntax, entity IDs, or engine behavior the semantic authority ABI of AIOS.

If the mapping is awkward or unsafe, AIOS keeps its Authority Coordinator contracts and can use another deterministic engine.

## AIOS remains the authority contract

The stable interface is:

```text
AuthorityEvaluationRequest
      ↓
AIOS Authority Coordinator
      ↓
Policy Backend Adapter
      ↓
backend-specific decision/evidence
      ↓
AIOS PolicyDecision
      ↓
optional trusted Approval
      ↓
AIOS AuthorityGrant
```

Cedar does **not** receive AIOS IR and does not issue Capability Grants directly.

The adapter receives a normalized concrete request whose semantic validity/resource resolution/provider identity have already been established by trusted AIOS code.

## Proposed Cedar entity mapping

Candidate entity types:

```text
AIOS::User
AIOS::Agent
AIOS::Provider
AIOS::SystemService
AIOS::PeerNode
AIOS::Task
AIOS::Artifact
AIOS::SemanticObject
AIOS::OutputAllocation
AIOS::Service
AIOS::Credential
AIOS::Device
AIOS::SystemResource
AIOS::ExternalDestination
```

Do not create one generic `Resource` entity if doing so loses policy-relevant type distinctions.

### Principal

The Cedar request principal maps from the exact runtime principal in `AuthorityEvaluationRequest`:

```text
provider://org.ainative.provider.table-import
agent://task/T91/planner
system-service://artifact-store
peer://device/home-workstation
```

The logged-in human user is context/relationship/owner evidence where relevant; the provider does not become the user principal merely because the user started the Task.

### Action

Cedar actions map one-to-one from normalized AIOS authority classes wherever practical:

```text
artifact.read
artifact.write
object.read
object.update
network.connect
data.egress
credential.use
message.send
service.invoke
device.read
device.control
system.change
```

Action names remain AIOS semantic/security vocabulary. A Cedar adapter may encode them into Cedar action entities internally.

### Resource

The resource is the resolved concrete resource:

```text
artifact://A17
allocation://T91/report
object://party/acme
service://model/remote-A
credential://mail/account-A
device://camera/front
system://network/config
```

The semantic selector (`input:source`, `task.output`, `destination:remote-model`) can appear in context/auditing but cannot substitute for concrete resource resolution at runtime.

## Entity attributes / relationships

Candidate attributes needed by policy:

### Principal/workload

```text
publisher_id
package_or_build_hash
conformance_status
trust_class
locality
owner_user/org
```

### Task

```text
Task ID
semantic_program_hash
workspace/org
risk/effect summary
current state
```

### Artifact/Object

```text
owner/scope
sensitivity
semantic type/object type
retention class
source-of-truth/trust class where relevant
```

### Service/destination

```text
service class
trust domain
region/jurisdiction
local/peer/remote
provider/operator
retention class if known
```

### Credential

```text
owner
service/issuer
exportability
status
allowed locality
```

Relationships can express ownership/membership/trust-domain facts without turning them into ambient permission.

## Cedar context mapping

Attempt-specific facts belong in request context, not durable entity identity.

Candidate context:

```text
task_id
semantic_program_hash
registry_snapshot_id
node_id
capability
execution_binding_id
attempt_id
effect_classes[]
egress_mode
destination_class
requested_cost
current_time
approval_present / approval_id (only in post-approval reevaluation if used)
```

Do not place raw secrets, Artifact contents, model prompts, or arbitrary provider-supplied JSON into policy context.

## AIOS decision model vs Cedar decision model

AIOS has:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

A policy backend may only natively expose permit/deny.

Therefore `REQUIRE_APPROVAL` is an **Authority Coordinator composition result**, not something AIOS assumes Cedar natively returns.

One safe composition model:

```text
1. hard-deny policy evaluation
2. auto-allow eligibility evaluation
3. approval-policy classification
4. coordinator combines deterministic outputs:

hard deny -> DENY
auto allow + no approval rule -> ALLOW
otherwise if approval rule applies -> REQUIRE_APPROVAL
otherwise -> DENY
```

The exact backend representation can differ, but the externally visible AIOS decision semantics remain stable.

A single generic `permit` result must never be interpreted as permission to bypass an AIOS approval rule.

## Forbid precedence

Cedar's forbid/permit behavior may be useful for hard-deny policy, but the adapter must test that AIOS's expected deny precedence is preserved for:

- data sensitivity;
- local-only/no-egress policy;
- credential exportability;
- disabled/revoked provider;
- prohibited system changes;
- organization/legal/jurisdiction restrictions.

A human approval should not bypass a hard deny merely by adding an allow/permit fact.

## Example AIOS policy scenarios

### Selected Artifact read

```text
principal = provider table-import
Action    = artifact.read
resource  = artifact://A17
context.task = T91
```

Expected policy intent:

- allow if Artifact is a bound input for T91;
- provider/binding matches;
- sensitivity/locality policy permits;
- no broader filesystem read implied.

### Private data egress

```text
principal = remote-summary provider
Action    = data.egress
resource  = artifact://metrics-92
context.destination = service://model/remote-A
```

Expected:

- hard deny if local-only or destination not eligible;
- otherwise classify as approval-required under user policy;
- approval is exact to current Task/program/resource/provider/destination;
- post-approval grant remains narrowly scoped.

### Credential use

```text
principal = mail provider
Action    = credential.use
resource  = credential://mail/account-A
```

Expected:

- credential exportability/service/lifecycle validated by Credential Broker in addition to policy;
- policy may permit brokered use while denying raw export;
- policy permit cannot override NON_EXPORTABLE mechanics.

## Builtin fixture backend first

Issue #3 should not block on Cedar integration.

Recommended implementation order:

```text
Authority Coordinator interface
→ tiny deterministic builtin fixture policy backend
→ all authority fixture semantics/tests
→ Cedar adapter spike
→ differential tests between builtin expected decisions and Cedar adapter
```

This prevents Cedar integration quirks from defining the AIOS authority model.

## Differential test corpus

Run the same normalized requests through the fixture semantics and Cedar adapter.

Must include:

1. exact Artifact read allow;
2. unrelated Artifact deny;
3. wrong Task/provider/binding deny;
4. explicit hard deny despite approval record;
5. private egress approval-required composition;
6. local-only egress hard deny;
7. credential NON_EXPORTABLE deny for remote/export mode;
8. provider disabled/revoked deny;
9. one-shot grant decision unaffected by unrelated entity additions;
10. missing/unknown entity/action fails closed;
11. policy snapshot A vs B produces attributable differing result;
12. malicious context tries to inject/override principal/action/resource fields.

## Schema discipline

Cedar schema/entities should be generated or validated from a **versioned AIOS policy-entity mapping**, not scattered hand-written conversions across services.

The adapter must reject:

- unknown protected action mapping;
- unresolved resource entity;
- principal type mismatch;
- missing mandatory Task/binding context;
- malformed entity attribute type;
- policy-set/schema mismatch.

These are backend/Authority Coordinator errors, not IR validation errors.

## Policy snapshot identity

`PolicySnapshot` records:

```text
policy language/backend
policy-set hash
entity-schema hash
configuration hash
engine ID/version/build
```

For Cedar, the snapshot should identify the exact canonical policy set + Cedar schema/mapping + engine build used for the decision.

Changing policy updates current decision behavior without rewriting historical decisions/grants/provenance.

## Security boundaries

Cedar/policy code runs inside trusted policy infrastructure, but:

- policy files are configuration/code that require administrative provenance;
- policy update is itself a protected/system-change action;
- untrusted provider/model text cannot add policy;
- a provider cannot author entity relationships saying it owns/controls resources;
- policy evaluation cannot resolve arbitrary network resources on its own;
- the adapter supplies validated bounded context.

## Success criteria

The Cedar spike is successful if:

- all normalized Authority Coordinator fixture scenarios map naturally;
- hard deny/default deny/approval composition remains exact;
- missing/unknown mappings fail closed;
- Cedar entities/context contain no raw private payload/secret material;
- decisions are reproducible against a Policy Snapshot;
- performance is reasonable for local per-operation decisions (measure; do not guess);
- switching to/from Cedar does not change AIOS request/decision/grant schemas.

## Rejection criteria

Do not adopt Cedar as reference backend if the spike requires:

- encoding AIOS authority semantics into natural-language policy interpretation;
- making provider/model identity the human user identity;
- weakening exact resource resolution;
- bypassing trusted approval composition;
- treating policy permit as a Capability Grant;
- embedding Cedar policy syntax into AIOS IR/semantic capability contracts;
- significant uncontrolled dynamic-entity behavior that cannot fail closed;
- engine behavior incompatible with required deterministic/offline operation.

## Non-goals

- organization-scale policy administration UI;
- policy synchronization across devices;
- enterprise identity federation;
- global policy language standardization;
- permanently choosing Cedar before the spike passes.

## Principle

> **Cedar may implement AIOS policy evaluation; it must never become the definition of AIOS authority.**
