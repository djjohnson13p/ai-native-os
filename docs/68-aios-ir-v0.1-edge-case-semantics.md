# 68 — AIOS IR v0.1 Edge-Case Semantics

## Purpose

The main AIOS IR documents define the architecture, but a trusted validator also needs precise answers for small cases that would otherwise force implementers to guess.

This document closes those v0.1 edge cases for Issue #17.

It is intentionally conservative. Future IR versions can add richer control flow/resource selectors/cache semantics when workloads prove the need.

## 1. Semantic resource selectors

`authority_requests[].resource` is a **symbolic semantic selector**, not a host path, URL, database key, secret handle, provider ID, or runtime grant ID.

v0.1 resource selector grammar is ASCII symbolic tokens:

```text
<segment>[.<segment>...]
<segment>:<segment>[:<segment>...]
```

where each segment starts with an ASCII letter and then uses letters/digits/`_`/`-`/`.` as allowed by the schema profile.

Representative selectors:

```text
input:source
task.output
task.temp
destination:remote-model
service:model
credential:mail-send
device:camera
system:package-management
```

Explicitly forbidden in semantic IR resource selectors:

```text
/home/alice/file
C:\Users\Alice\file
file:///...
https://...
secret://actual-handle
credential://actual-runtime-handle
provider://...
token://...
```

Concrete runtime resource IDs/paths/handles are produced by policy/Execution Binding after validation.

### `input:<name>` contextual rule

If resource starts `input:`, `<name>` MUST identify an existing top-level program input.

Otherwise semantic validation fails.

### `task.output`

Represents the Task-owned output allocation class, not an arbitrary host directory.

The Artifact/output broker binds it to concrete allocations later.

### Other selector namespaces

`destination:*`, `service:*`, `credential:*`, `device:*`, and `system:*` are semantic classes. Their detailed policy meaning belongs to the corresponding authority/capability/domain contract, not filesystem/network parsing.

The validator treats unknown syntactically valid selector namespaces conservatively according to the referenced capability/authority contract. v0.1 registry fixtures should use only namespaces whose policy meaning is defined by the test environment.

## 2. Authority request uniqueness

Authority-request `reason` is non-semantic explanatory prose.

Therefore two requests with the same normalized:

```text
action
resource
```

are semantic duplicates even if `reason` differs.

v0.1 rule:

> **Reject duplicate `(action, resource)` requests rather than silently de-duplicate them.**

Reason code:

```text
IR_AUTHORITY_DUPLICATE_REQUEST
```

This keeps planner bugs visible and avoids hash/approval confusion.

Authority request ordering is non-semantic and is sorted by `(action, resource)` in the semantic-hash view.

## 3. `verify` operation role

Verification must remain visible in the semantic graph.

v0.1 rule:

```text
operation.kind == verify
    requires capability contract role == verifier

capability contract role == verifier
    requires operation.kind == verify
```

A verifier cannot be invoked with `kind=invoke` merely to hide a verification boundary.

An ordinary capability cannot be labeled `verify` merely to acquire stronger trust semantics.

Reason code:

```text
IR_CAPABILITY_ROLE_MISMATCH
```

## 4. Optional program inputs

A top-level program input with:

```text
required: false
```

may be absent when the Task is bound.

v0.1 rule:

- a required capability input port MUST NOT depend directly on an optional program input;
- an optional capability input port MAY reference an optional program input;
- if the program input is absent at execution binding, the optional capability port is unbound/omitted;
- any provider chosen for that capability must conform to the optional-port semantics.

Reason code for invalid direct dependency:

```text
IR_OPTIONAL_INPUT_TO_REQUIRED_PORT
```

This avoids inventing implicit null values or control flow.

A future IR can add explicit option/presence/branching types.

## 5. Nodes with no inputs

A node MAY have an empty `inputs` object if its Semantic Capability Contract has no required input ports.

Examples later could include:

- clock/time capability under explicit authority/semantics;
- random/nonce generator under declared execution class;
- device/status query;
- user-approved external fetch with no Task-data input.

If the capability contract has a required input missing from the node, validation fails normally.

## 6. Program outputs and unconsumed nodes

Every program output must resolve to an existing node output port.

Not every node must be an ancestor of a declared program output.

Why: an effectful node can be a required Task outcome even when its semantic receipt/result is not exported as a final user-facing program output.

Examples:

```text
mail.send
persistent_state.update
external publication
```

### Unconsumed PURE/verification work

A node with no path to:

- a declared program output; or
- an effectful node

and whose own derived effect is only `PURE` is likely dead work.

v0.1 behavior:

- do **not** make this a hard semantic invalidity;
- emit warning `IR_GRAPH_UNUSED_PURE_NODE`;
- keep the node in the semantic hash/source program;
- a future optimizer may omit it from a compiled target only under effect/verification-preservation rules.

A `verify` node that does not gate any consumed/effectful downstream path likewise receives the warning; it does not magically verify unrelated work.

Warnings never turn invalid programs valid or grant authority.

## 7. Egress declaration rules

### `mode=deny`

`destination_classes` MUST be absent or empty.

A nonempty destination list contradicts `deny`.

Reason code:

```text
IR_EGRESS_CONTRADICTION
```

### `mode=policy`

`destination_classes` MUST be present and nonempty.

The node must also contain at least one `data.egress` authority request whose resource is a `destination:<class>` selector matching one declared destination class.

For each declared destination class, v0.1 SHOULD require a matching `data.egress` request unless a later accepted authority contract defines a safe wildcard/group rule.

The bootstrap profile uses exact matching.

Missing/mismatched authority gives:

```text
IR_EGRESS_AUTHORITY_MISMATCH
```

Actual destination endpoint/provider remains runtime policy/binding state.

### Network without task-data egress

`NETWORK` and `DATA_EGRESS` remain separate effects.

A capability may use network without Task-data egress if its semantic contract and concrete sandbox/data interfaces make that distinction meaningful.

The validator must not infer `DATA_EGRESS` from all `NETWORK` effects automatically.

## 8. Cache policy vs execution class

v0.1 is intentionally conservative.

### `cache=never`

Allowed for every execution class.

### `cache=deterministic_only`

Allowed only when:

```text
execution_class == deterministic
```

### `cache=content_addressed`

Allowed only when:

```text
execution_class == deterministic
```

and semantic input/content identity required by the provider/capability is available under the eventual execution binding.

The validator checks the deterministic execution-class requirement; runtime checks whether concrete content identities are actually available before cache reuse.

A probabilistic/bounded-nondeterministic/opaque node asking for deterministic/content-addressed caching fails:

```text
IR_CACHE_EXECUTION_CLASS_MISMATCH
```

A future IR version may support seeded or explicitly reproducible nondeterministic cache profiles.

## 9. Fallback compatibility

A fallback is semantic recovery, not permission to switch to a broader operation.

For each fallback capability, v0.1 requires:

- fallback reference resolves in the same immutable Registry Snapshot;
- fallback is not the primary capability;
- compatible required input port names/types;
- compatible output port names/types needed by downstream graph;
- node's declared execution class is allowed by fallback contract;
- fallback authority classes do not require authority outside the node's declared requests/current semantic envelope;
- fallback egress behavior is compatible with the node's declared egress mode/destinations;
- fallback effect upper bound does not broaden beyond the node/program semantic envelope;
- recursive fallback closure is finite and non-cyclic.

A fallback with broader implementation possibilities may still be eligible later only if its concrete provider can be proven to satisfy the node's existing narrower constraints; v0.1 semantic validator SHOULD use the conservative contract-level check and reject ambiguity rather than assume narrowing will be possible.

Reason-code families:

```text
IR_FALLBACK_PORT_MISMATCH
IR_FALLBACK_EFFECT_BROADENING
IR_FALLBACK_AUTHORITY_BROADENING
IR_FALLBACK_EGRESS_BROADENING
IR_FAILURE_POLICY_RECURSIVE_FALLBACK
```

## 10. Duplicate final output references

Two different program output names MAY reference the same node output port.

Example:

```text
outputs:
  report: node.compose.report
  primary_document: node.compose.report
```

This is aliasing at the program-output interface and does not duplicate execution.

Both output names are semantic and therefore participate in the semantic hash.

## 11. Metadata cannot carry executable semantics

Top-level/node `metadata` is ignored by:

- semantic validity except structural size/DoS limits;
- authority/effect decisions;
- semantic hash;
- provider selection requirements;
- verification requirements.

Therefore this is not meaningful execution behavior:

```json
"metadata": {
  "please_grant_admin": true,
  "provider": "some-provider",
  "skip_verification": true
}
```

It remains inert metadata.

If a planner needs a value to affect execution, it must use a typed semantic field/contract.

## 12. Description/reason strings are never instructions to the validator

Descriptions and authority `reason` strings are human/debug prose.

The trusted validator:

- does not parse them as commands;
- does not use them to infer capability/type/authority;
- excludes them from semantic hash;
- does not send them to a model during validation.

This is a prompt-injection boundary.

## 13. Runtime values are not authoring-time IR literals in v0.1

AIOS IR v0.1 graph inputs are references to Task-bound program inputs or prior node outputs.

The IR does not currently define general arbitrary literal/constant nodes.

If a capability needs configuration constants in v0.1, use an explicit typed input/artifact/configuration capability pattern defined by the relevant contract rather than inventing ad-hoc JSON fields in `metadata`.

A future IR version can add typed literal semantics deliberately.

## 14. Side-effect receipt/result types

Effectful capabilities SHOULD still return a typed receipt/result/status object where useful.

The output does not make the external effect reversible and does not replace operation/provenance identity.

Example future shape:

```text
mail.send@1 -> communication.send_receipt@1
```

The receipt may be unused as a final program output while the send effect remains a valid Task outcome.

## 15. Warnings vs errors

Errors mean the program is not semantically executable under v0.1 and receives no semantic hash.

Warnings describe valid-but-suspicious/review-worthy structure and may accompany a semantic hash.

Initial warning family includes:

```text
IR_GRAPH_UNUSED_PURE_NODE
```

Warning behavior must be deterministic and bounded.

Policy may later choose to reject certain warnings for stricter environments, but the base semantic validator's validity result remains defined by this profile.

## Required tests

At minimum add tests for:

1. host path/URL rejected as authority resource selector;
2. `input:missing` rejected;
3. duplicate `(action, resource)` rejected even if reasons differ;
4. verifier role/kind mismatch rejected both directions;
5. optional program input -> required capability port rejected;
6. input-less capability accepted only when contract has no required ports;
7. unconsumed PURE node emits deterministic warning but valid hash;
8. effectful unconsumed node can remain valid;
9. egress deny + destination list rejected;
10. egress policy without destination rejected;
11. egress policy without matching data-egress authority rejected;
12. probabilistic/content-addressed cache rejected;
13. fallback cannot broaden effect/authority/egress;
14. duplicate final output aliases are valid;
15. executable-looking metadata/reason prose remains inert/non-semantic;
16. semantic hash equivalence persists across metadata/reason changes.

## Principle

> **When a semantic edge case can change authority, verification, reproducibility, or recovery, the validator must have a deterministic rule—not an implementation convention.**
