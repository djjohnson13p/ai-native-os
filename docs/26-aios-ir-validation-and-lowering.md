# 26 — AIOS IR Validation and Lowering Pipeline

## Purpose

AIOS IR exists to separate **what the task means** from **how one particular machine executes it**.

That separation only works if every transition from planner output to execution is deterministic, inspectable, and testable.

This document defines the v0.1 validation and lowering pipeline.

## Pipeline overview

```text
planner output
    │
    ▼
[1] parse
    │
    ▼
[2] structural schema validation
    │
    ▼
[3] normalization
    │
    ▼
[4] graph validation
    │
    ▼
[5] capability/type validation
    │
    ▼
[6] authority/effect consistency validation
    │
    ▼
[7] policy evaluation
    │
    ▼
[8] provider/resource resolution
    │
    ▼
[9] execution binding
    │
    ▼
[10] execution + verification + provenance
```

No later stage may reinterpret an earlier validation failure as permission to continue.

## Stage 1 — Parse

Input is treated as untrusted data.

Requirements:

- malformed serialization fails before any capability lookup;
- duplicate JSON keys should be rejected by the parser used for signed/canonical documents rather than silently accepting the final value;
- size/depth limits should be enforced before expensive processing;
- comments or surrounding natural language are not executable semantics.

The parser does not execute expressions.

## Stage 2 — Structural schema validation

Validate against `specs/aios-ir.schema.json`.

Structural validation covers items such as:

- required fields;
- allowed operation kinds;
- allowed execution classes;
- closed property sets where security-relevant;
- bounded integer ranges;
- structural shape of value references;
- structural shape of failure policies.

Passing this stage means only that the document has an allowed shape.

It does not establish authorization or capability compatibility.

## Stage 3 — Normalization

Normalization converts semantically equivalent accepted input into a stable representation before hashing, comparison, or optimization.

Normalization may include:

- sorting maps for canonical serialization;
- filling explicitly defined safe defaults;
- normalizing capability/type version notation;
- normalizing resource-unit fields to canonical integer units;
- removing non-semantic planner/debug metadata from the semantic hash;
- validating UTF-8 and Unicode normalization rules;
- rejecting ambiguous numeric representations where canonicalization cannot be guaranteed.

Normalization MUST NOT:

- add authority requests;
- infer permission from natural language;
- choose a provider;
- insert a remote egress allowance;
- remove a verification requirement;
- turn probabilistic work into deterministic work merely for optimization.

The result is assigned a semantic program hash.

## Stage 4 — Graph validation

The validator derives edges from input references and checks:

- node IDs are unique;
- all program-input references exist;
- all node references exist;
- all referenced output ports exist;
- all final output references exist;
- the graph is acyclic for IR v0.1;
- there are no self-dependencies;
- there are no disconnected required outputs;
- all retry/replan/fallback budgets are finite;
- a fallback list cannot recursively name itself in a way that produces an unbounded cycle.

### Deterministic traversal order

The runtime should derive a stable topological ordering for equivalent graphs, using node identity as a tie-breaker where needed.

This improves reproducibility of logs/tests but does not force independent nodes to execute serially.

## Stage 5 — Capability and type validation

Validation uses a read-only capability registry snapshot.

For each node:

1. resolve the semantic capability contract;
2. verify expected input port names;
3. verify input semantic types;
4. verify declared output port names/types;
5. verify execution-class compatibility;
6. verify declared effect categories;
7. verify fallback capability compatibility;
8. record the capability contract version used for validation.

The registry snapshot used to validate a program becomes part of provenance/execution binding.

### Unresolved planning mode

A planner may produce a proposal containing capabilities that are not locally installed, but that proposal is not runnable AIOS IR.

Before the task enters RUNNABLE state, every required node must either:

- resolve to an allowed capability contract; or
- be explicitly converted into a bounded unsupported/clarification result.

Unknown capability names do not become shell commands or arbitrary code.

## Stage 6 — Authority and effect consistency

This stage validates requests before asking policy to authorize them.

Checks include:

- the node requests only authority classes permitted by the capability contract;
- an `egress: deny` node does not request external network/data-transfer authority;
- raw secrets are absent;
- task-output writes target abstract task resources rather than arbitrary host paths;
- resource references are syntactically valid for the declared action;
- authority request scope is no broader than the semantic operation requires where this can be mechanically proven;
- verification nodes do not gain unrelated side-effect authority.

This stage can reject an unsafe request without involving user approval.

## Stage 7 — Deterministic policy evaluation

Policy evaluates concrete principal/action/resource/context requests.

Possible results:

- allow;
- deny;
- require explicit approval;
- allow under narrower scope;
- defer until a concrete provider/destination is selected.

Important distinction:

> A valid IR program can still be unauthorized.

The system should preserve that distinction in UX and provenance.

A program denied by policy remains structurally meaningful but cannot execute the denied operation.

## Stage 8 — Provider and resource resolution

The Capability Broker and Resource Broker select eligible execution implementations subject to:

- semantic capability version;
- current policy;
- hardware profile;
- sandbox requirements;
- data locality;
- egress restrictions;
- provider trust/conformance;
- availability;
- latency;
- cost;
- energy;
- user preference.

Provider selection produces a runtime binding, not a semantic IR mutation.

This lets the same program hash remain stable even if today's provider differs from yesterday's.

## Stage 9 — Execution binding

Each runnable node receives an execution record containing at minimum:

- task ID;
- program hash;
- node ID;
- capability ID/version;
- provider ID/version;
- concrete input artifact handles;
- output allocation handles;
- policy decision ID;
- grant/capability-token reference;
- execution/sandbox profile;
- placement/hardware identity;
- attempt number;
- timeout/resource limits;
- model descriptor for probabilistic model execution where relevant.

This runtime object is ephemeral/persisted execution state, not AIOS IR source.

## Stage 10 — Execution and verification

The executor launches only after the bound provider independently receives/verifies the authority it needs.

For every attempt, provenance records:

- execution start;
- effective provider;
- effective authority;
- concrete inputs;
- placement;
- external transfer where applicable;
- outputs;
- failure class;
- verification result;
- retry/fallback/replan decision.

A successful provider exit code is not sufficient if an explicit verifier fails.

## Failure taxonomy

The runtime should distinguish at least:

### `invalid_program`

Schema, graph, type, or semantic validation failed.

### `authorization_denied`

Policy denied a required action.

### `approval_required`

Execution is valid but waiting for a human decision.

### `provider_unavailable`

No eligible provider is currently runnable.

### `resource_unsatisfied`

Current hardware/policy cannot satisfy declared placement requirements.

### `provider_failed`

Provider started but failed its execution contract.

### `verification_failed`

Provider completed but output failed required verification.

### `compatibility_failed`

A legacy/opaque habitat could not satisfy its compatibility profile.

### `budget_exhausted`

Finite retry/fallback/replan budget was exhausted.

The planner may be consulted for a bounded replan only where the IR failure policy allows it.

## Lowering model

### Semantic IR (SIR)

AIOS IR v0.1 is effectively the project's **semantic IR**.

Properties:

- provider independent;
- authority-requesting but not authority-carrying;
- hardware abstract;
- typed;
- inspectable;
- content-addressable;
- suitable for optimization.

### Execution binding (XB)

The next layer is an execution binding rather than a second source language.

Properties:

- provider concrete;
- hardware/placement concrete;
- sandbox concrete;
- authority/grant concrete;
- attempt-specific;
- unsuitable for cross-device semantic identity.

### Compiled skill artifact

A validated repeated graph may later produce a compiled skill containing:

- source SIR hash;
- parameterized SIR template;
- compiled deterministic subgraphs;
- required capability contracts;
- conformance/test evidence;
- authority template (requests only);
- supported targets;
- invalidation conditions.

The compiled artifact still receives fresh execution bindings and fresh policy decisions.

## Optimization boundaries

### Safe examples

An optimizer may:

- fuse adjacent deterministic pure transformations;
- reuse content-addressed deterministic results;
- precompute constant deterministic nodes;
- parallelize independent nodes;
- choose a zero-copy data representation between compatible local providers;
- compile a deterministic subgraph to WASM/native code;
- remove an authority request proven unnecessary after transformation;
- replace a provider with another conforming provider.

### Unsafe without semantic revalidation

An optimizer may not silently:

- remove a verifier;
- weaken data sensitivity;
- allow remote execution where local-only was declared;
- widen filesystem/network/device scope;
- change a deterministic node to probabilistic;
- reuse output when a relevant input/hash/version changed;
- turn a user-approval requirement into automatic execution;
- merge tasks such that one task gains access to another task's authority.

## Canonical serialization and hashing

The v0.1 implementation should distinguish three representations:

1. **authoring JSON** — readable formatting, metadata allowed;
2. **normalized semantic object** — safe defaults resolved and non-semantic fields excluded;
3. **canonical serialization** — deterministic bytes used for hashing/signatures.

The canonicalization algorithm should be a published standard rather than an ad-hoc serializer. RFC 8785 JSON Canonicalization Scheme is a strong candidate for the JSON bootstrap phase.

The semantic hash should use a modern cryptographic hash such as SHA-256 initially and be algorithm-tagged, for example:

```text
sha256:9b0d...
```

The architecture should not make SHA-256 forever mandatory; algorithm agility belongs in the identifier.

## Versioning

`ir_version` versions **semantics**, not merely JSON layout.

Compatibility rules:

- an executor MUST reject an IR major version it does not understand;
- a minor version may add explicitly ignorable metadata only if semantics remain safe;
- new operation kinds/effect classes that alter execution meaning require explicit support;
- a migration tool may translate old IR to new IR, but must emit a new semantic hash;
- signed/compiled skill artifacts must record source IR version and hash.

## Deterministic validator boundary

The validator itself is part of the trusted computing base for AI-native execution.

The initial validator should therefore:

- be implemented in a memory-safe language where practical;
- avoid executing provider code during validation;
- use bounded resource consumption;
- produce machine-readable reason codes;
- never call an AI model to decide whether malformed IR is safe;
- have extensive negative/adversarial fixtures;
- be fuzzable;
- support reproducible validation against a fixed registry snapshot.

## Suggested validator result

Example:

```json
{
  "valid": false,
  "program_hash": null,
  "errors": [
    {
      "code": "IR_GRAPH_CYCLE",
      "node": "step_b",
      "detail": "cycle includes step_a -> step_b -> step_a"
    }
  ],
  "warnings": []
}
```

Stable reason codes are important for testing, UX, telemetry, and model feedback.

## Initial reason-code families

```text
IR_PARSE_*
IR_SCHEMA_*
IR_REFERENCE_*
IR_GRAPH_*
IR_TYPE_*
IR_CAPABILITY_*
IR_EFFECT_*
IR_AUTHORITY_*
IR_EGRESS_*
IR_FAILURE_POLICY_*
IR_VERSION_*
IR_CANONICALIZATION_*
```

Policy denials should use policy reason codes rather than being mislabeled as invalid IR.

## Relationship to planners

A model-assisted planner is allowed to be wrong.

That is a core design assumption.

The planner's contract is:

1. propose a constrained program;
2. receive deterministic validation errors;
3. optionally repair within a bounded planning budget;
4. stop or ask the user for clarification when the program cannot be made valid/authorized.

The validator's job is not to guess what the planner intended.

## v0.1 implementation target

Before the first full AI planner is trusted with execution, the project should be able to:

1. load `examples/aios-ir/demonstration-a.ir.json`;
2. validate it structurally;
3. validate all graph references and types against fixture capability contracts;
4. produce a stable semantic hash;
5. reject every fixture in `invalid-cases.json` with the expected reason code;
6. bind deterministic fixture providers;
7. execute the deterministic subset without any model planner;
8. emit provenance that links runtime execution back to the semantic program hash.

That proves the IR boundary independently of model quality.
