# 19 — Principal and Authority Model

## Purpose

Define who may request actions, where authority comes from, how it is scoped, and how the operating system prevents AI reasoning from becoming an implicit superuser.

This document describes semantics. The cryptographic/token encoding and policy language remain implementation decisions.

## Foundational rule

> **Reasoning proposes. Deterministic policy grants. Execution verifies.**

No planner, model, agent, learned skill, capability provider, remote service, or legacy application may create new authority for itself.

## Principals

A **principal** is an identity that can request or exercise a capability.

Initial principal kinds:

```text
user
system-service
agent
provider
model-provider
legacy-app
peer-node
```

A task is an authority context and provenance boundary. It is not necessarily a principal itself.

### User

The human/account initiating or approving work.

The user's normal login privileges are **not** automatically copied into agent/provider tokens.

### System service

A trusted component of the deterministic control plane, such as the policy engine, artifact broker, or provenance store.

Even trusted system services should have narrowly defined operating privileges rather than all services running as unrestricted root.

### Agent

A scoped reasoning worker associated with one task. Agents may request capabilities but cannot directly bypass the capability broker/policy engine.

### Provider

A deterministic or probabilistic implementation of a capability.

Providers exercise only the authority required by the invocation they are performing.

### Model provider

A local or remote inference runtime. Model providers receive only the data/context explicitly authorized for the model invocation.

### Legacy application

A traditional application running inside a compatibility habitat. Host integrations are separately granted capabilities, not inherited desktop access.

### Peer node

A trusted or semi-trusted external device that can provide resources or capabilities. Peer-node support is future work; its authority must still be task-scoped.

## Resources

Authority applies to named resources rather than vague machine-wide permissions.

Example resource namespaces:

```text
artifact:A123
data:D77
task-output:T42
network:internet
network:host:api.example.com
secret:provider/openai
clipboard:session
camera:front
microphone:default
gpu:0
legacy-profile:com.vendor.product
system:update
system:power
```

Resource identifiers should resolve through deterministic brokers where practical rather than exposing raw host implementation details to AI.

## Actions

Capabilities are semantic operations. Grants also need an action vocabulary for resources.

Common action classes:

```text
read
write
create
append
execute
connect
send
receive
list
modify
delete
install
administer
```

The exact allowed action set is resource-type dependent.

## Capability grant

A capability grant binds:

```text
who        principal
why        task ID
what       semantic capability
operation  actions
where      resource identifiers
when       issued + expiry
limits     constraints
source     policy/approval record
```

Example conceptual grant:

```yaml
task: T42
principal: provider:table-importer
capability: table.import
actions:
  - read
resources:
  - artifact:A123
expires: 2026-09-15T21:00:00Z
constraints:
  network: denied
  max_bytes: 50000000
```

## No ambient authority

The following are forbidden architecture patterns:

- giving the AI service the user's home directory by default;
- running the planner as root because privileged actions may eventually be needed;
- giving every provider the user's environment variables and credentials;
- exposing a whole cloud token when one API operation is needed;
- using the model's decision that an action is "safe" as authorization;
- treating a legacy desktop application as trusted merely because the user installed it;
- persisting a broad agent token because the user approved a similar task previously.

## Grant lifecycle

### 1. Request

A planner/provider requests a capability over named resources.

### 2. Policy evaluation

The deterministic policy engine considers:

- requesting principal;
- task intent and state;
- resource sensitivity;
- capability/action impact;
- device/user/org policy;
- current approval rules;
- whether data would cross a trust boundary;
- whether the requested scope is broader than necessary.

### 3. Decision

Possible outcomes:

```text
ALLOW
DENY
REQUIRE_APPROVAL
ALLOW_WITH_NARROWER_SCOPE
```

The final option is useful when the request is valid but overbroad.

### 4. Approval, if required

User approval creates an **approval record**, not a permanent blanket capability token.

Approval should describe:

- action;
- resource;
- destination, if external;
- reversibility;
- consequence/risk class;
- duration/scope being approved.

### 5. Token/grant issuance

The authority service issues a short-lived grant bound to the task and principal.

### 6. Execution-time verification

The execution broker/provider runner validates the grant immediately before exposing the resource or performing the side effect.

### 7. Provenance

The request, decision, approval, token ID, effective scope, and action result are recorded.

## Persistent preferences are policy, not immortal tokens

When a user says:

> Always allow my photo-resize skill to read images I explicitly select and write into its output folder.

that should create/update a deterministic policy rule.

Each future task still receives a new task-specific grant derived from that policy.

This keeps revocation, audit, and task attribution intact.

## Delegation

Default: **no delegation**.

If delegation is introduced, authority can only become narrower.

```text
Parent grant
  artifact:A read
  artifact:B write
  network denied

Child grant may be:
  artifact:A read

Child grant may NOT add:
  network allowed
  artifact:C read
```

Delegation depth should be explicit and bounded.

## Revocation

Prototype strategy:

- short token lifetimes;
- task cancellation invalidates outstanding task grants;
- provider process termination removes effective sandbox access;
- explicit revocation list/store for still-live token IDs when needed.

Future cryptographic distributed tokens require a more formal revocation design.

## File authority and TOCTOU

Raw path strings are insufficient for consequential authority because paths can be replaced, remounted, or redirected.

Where possible:

- authorize artifact/object identity;
- resolve/open resources through a trusted broker;
- pass already-open descriptors/handles into the provider sandbox;
- verify expected content hash/inode/metadata where relevant;
- avoid model-generated arbitrary paths.

## Secrets

A provider should normally receive a **secret operation** or short-lived derived credential rather than the stored long-lived secret.

Example:

```text
Bad:
  expose ~/.config/cloud/master-token to agent

Better:
  grant network.call capability to service X
  secret broker injects a task-scoped/short-lived credential into the isolated provider
```

Raw secret retrieval should be a separate high-sensitivity capability.

## Network and data egress

"Network access" is too broad for many tasks.

The policy model should support progressively narrower grants:

```text
network:none
network:loopback
network:host:example.com
network:service:model-provider-X
network:internet
```

For outbound user data, policy should additionally know which artifact/data handles are authorized to leave the local trust boundary.

The system must be able to answer:

> Exactly what data did this task send, to whom, and under which grant?

## Legacy application integration

Traditional desktop permissions should be decomposed into capabilities:

- open selected file;
- save selected artifact;
- clipboard read/write;
- microphone;
- camera;
- GPU;
- audio output;
- network destination;
- notifications;
- USB/device access;
- IPC/service access.

A compatibility habitat may emulate a traditional OS internally while the host exposes only the integrations authorized by the task/user policy.

## Impact classes

The existing approval levels can be interpreted as policy defaults:

```text
L0 — low-sensitivity read-only
L1 — reversible task-local writes
L2 — external communication or persistent modification
L3 — destructive/system/security-sensitive
L4 — irreversible/high-consequence
```

Impact class is not authority by itself. It informs whether user approval is required.

## Fail-closed rules

Execution must be denied when:

- token is expired;
- task ID does not match;
- principal does not match;
- capability/action is absent;
- resource is absent;
- constraints cannot be enforced;
- token/schema/signature is invalid;
- required approval cannot be verified;
- policy changed to prohibit the operation;
- the execution environment cannot provide the minimum required isolation.

The system may fall back to a *more restrictive/isolated* execution path, never silently to a weaker one.

## v0.1 implementation boundary

We do not need a globally distributed cryptographic capability system in v0.1.

A useful first implementation can use:

- deterministic policy service;
- database-backed opaque token IDs;
- short expirations;
- explicit task/principal/resource/action rows;
- provider runner enforcing filesystem/network/resource scope;
- provenance event linkage.

The semantics matter more than prematurely optimizing the token encoding.
