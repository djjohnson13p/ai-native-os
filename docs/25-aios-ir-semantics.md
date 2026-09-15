# 25 — AIOS IR Semantic Model

## Purpose

AIOS IR is the **provider-independent executable meaning** of a task after natural-language planning has been normalized, but before providers, credentials, capability grants, sandbox instances, and hardware placements are bound for a particular execution.

It is the layer where the project begins to own a computational model designed around AI-native operation rather than merely generating ordinary source code.

The key rule is:

> AIOS IR may describe requested work and requested authority, but it can never grant authority to itself.

The IR is therefore executable only after deterministic validation, policy evaluation, provider resolution, and runtime binding.

## Position in the pipeline

```text
Human intent
   ↓
Intent normalization
   ↓
Planner proposal (model-assisted or deterministic)
   ↓
Schema validation
   ↓
AIOS IR normalization + semantic validation
   ↓
Deterministic policy evaluation
   ↓
Capability/provider resolution
   ↓
Resource placement + sandbox binding
   ↓
Execution instance
   ↓
Provider/native/WASM/model/legacy execution
   ↓
Verification + provenance
```

A planner proposal is not yet AIOS IR merely because it is JSON. AIOS IR is a validated semantic graph with stricter invariants.

## What belongs in AIOS IR

AIOS IR owns semantics that should remain stable even when implementation languages or providers change:

- typed inputs and outputs;
- semantic capability invocation;
- deterministic/probabilistic/opaque execution classification;
- explicit authority requests;
- explicit external-egress policy intent;
- locality/resource constraints;
- bounded failure/retry/fallback behavior;
- verification operations;
- graph dependencies;
- program outputs;
- cache/reuse eligibility;
- semantic version information.

## What does not belong in AIOS IR

The semantic IR MUST NOT contain execution authority or host-specific accidental detail such as:

- bearer tokens;
- capability-grant tokens;
- passwords or long-lived credentials;
- raw secret values;
- arbitrary host executable paths;
- provider-specific API keys;
- transient process IDs;
- container IDs;
- VM instance IDs;
- file descriptors;
- resolved GPU device numbers;
- provider runtime handles;
- approval bypass flags;
- shell snippets used as an unrestricted escape hatch.

Those values belong in runtime binding records, secret mediation, execution profiles, or provider-specific internals.

## Program model

An AIOS IR program contains:

1. a version;
2. stable program identity;
3. a kind (`task_graph` or later `skill_graph`);
4. typed program inputs;
5. a directed acyclic graph of nodes for v0.1;
6. typed program outputs;
7. non-authoritative metadata.

For v0.1, general loops and unbounded dynamic control flow are intentionally excluded. Repetition is represented through bounded retry/fallback semantics or through a higher-level task/skill invocation.

This restriction makes validation, provenance, replay, resource estimation, and security analysis substantially easier.

## Type model

### Goal

The first type system should be small enough for models to generate reliably while still allowing deterministic validation.

Types are semantic identifiers rather than implementation-language classes.

Examples:

```text
artifact.table@1
artifact.report@1
artifact.image@1
data.metrics@1
text.narrative@1
verification.result@1
```

A type identifier does not imply Python, Rust, Arrow, XLSX, PNG, or another representation. Concrete representation is described by the artifact/provider contracts.

### Program inputs

Inputs declare semantic type and optionally an expected artifact/media constraint.

Example:

```json
{
  "source": {
    "type": "artifact.table@1",
    "required": true
  }
}
```

The actual artifact handle is bound when the task executes.

### Node outputs

Every named node output declares a semantic type.

A later node references a value structurally:

```json
{
  "source": "node",
  "node": "compute_metrics",
  "port": "metrics"
}
```

This is preferred to string interpolation such as `node://compute_metrics/metrics` inside the core semantic model because structural references are easier to validate and transform.

## Operation model

The v0.1 IR has two primary operation kinds.

### `invoke`

Invoke a semantic capability.

Examples:

```text
table.import@1
stats.compare_periods@1
chart.render@1
report.summarize@1
document.compose@1
```

The node identifies the capability, not a provider or executable.

### `verify`

Invoke a verifier whose purpose is to establish an explicit assurance claim about prior output.

Examples:

```text
verify.numeric_claims@1
verify.schema@1
verify.artifact_hash@1
```

Verification remains capability-oriented; `verify` is a semantic marker that lets the runtime and provenance layer distinguish validation gates from ordinary transformations.

Additional control operations may be added later only through a versioned IR change.

## Execution classes

Every executable node declares one execution class.

### `deterministic`

Given equivalent declared inputs and environment constraints, the provider is expected to produce semantically equivalent output.

Examples:

- CSV parsing under a fixed parser contract;
- arithmetic/statistics;
- hashing;
- schema validation;
- deterministic document transformation.

### `bounded_nondeterministic`

Output may vary for understood non-model reasons within a declared contract.

Examples might include hardware scheduling or operations whose ordering varies but whose final semantic result is bounded.

### `probabilistic`

A model or probabilistic algorithm may produce materially different valid outputs.

Examples:

- summarization;
- classification by generative model;
- plan generation;
- image generation.

### `opaque_external`

The result depends on an external system whose behavior the OS cannot fully characterize.

Examples:

- remote SaaS operation;
- legacy application automation;
- third-party transaction endpoint.

The class affects caching, replay, verification, skill compilation, and provenance.

## Authority request model

A node can declare authority that execution will require.

Example:

```json
"authority_requests": [
  {
    "action": "artifact.read",
    "resource": "input:source"
  },
  {
    "action": "artifact.write",
    "resource": "task.output"
  }
]
```

These are **requests**, not grants.

Rules:

1. no node may include a grant/token as proof that it is authorized;
2. the deterministic policy engine decides whether each requested action is permitted;
3. the runtime must independently verify the effective grant before a provider receives access;
4. a provider manifest constrains which authority classes that provider/capability may legitimately request;
5. an IR transformation may reduce requested authority without semantic reapproval, but broadening authority requires a new policy decision.

## Egress semantics

Every node declares an egress mode.

### `deny`

No task data may cross the local trust boundary for the node.

### `policy`

External transfer may be considered, but only after policy evaluation against concrete destination, data classification, and provider identity.

AIOS IR does not contain a secret mechanism to reinterpret `deny` as `policy` at runtime.

A semantic validator should reject obvious contradictions such as a node that declares `egress: deny` while simultaneously requesting external-network authority.

## Resource and locality constraints

A node may declare constraints that the Resource Broker must satisfy.

Examples:

```json
{
  "locality": ["local", "peer"],
  "max_latency_ms": 2000,
  "max_cost_microusd": 100000,
  "min_memory_bytes": 2147483648,
  "accelerator": {
    "kind": "gpu",
    "min_memory_bytes": 4294967296,
    "optional": true
  }
}
```

Constraints are requirements/preferences on execution, not provider selection commands.

The semantic IR MUST NOT hard-code a provider solely because the planner happened to know one.

## Failure semantics

Failure handling must be bounded.

Supported v0.1 modes:

- `stop`;
- `retry` with a finite maximum attempt count;
- `fallback` with a finite ordered list of semantic fallback capabilities;
- `replan` with a finite replan budget.

Examples:

```json
{
  "on_error": "retry",
  "max_attempts": 2
}
```

and:

```json
{
  "on_error": "fallback",
  "fallback_capabilities": [
    "table.import.compat@1"
  ]
}
```

Unbounded retry/replan loops are invalid IR.

Authority denial is not an ordinary provider failure. A fallback may not silently reinterpret an authorization denial as permission to use a broader provider or resource.

## Data-flow graph

For v0.1 the graph is a DAG.

Edges are derived from node input references rather than maintained as a second independent edge list.

Semantic validation must prove:

- every referenced input exists;
- every referenced node exists;
- every referenced output port exists;
- node IDs are unique;
- the graph is acyclic;
- no node consumes its own future output;
- declared types are compatible;
- final program outputs resolve to real values.

This avoids contradictory `depends_on` and data-reference graphs.

## Capability compatibility

Structural schema validation is insufficient.

Given a registry snapshot, semantic validation must also prove that:

- the capability identifier is known or explicitly allowed as unresolved during planning;
- input ports/types match the capability contract;
- output ports/types match the capability contract;
- execution class is compatible with the capability declaration;
- declared authority requests are within the capability's allowed authority classes;
- egress intent is compatible with provider/capability rules;
- fallback capabilities have compatible input/output semantics.

## Verification as data flow

Verification should create an explicit output that subsequent nodes consume.

Example:

```text
metrics ───────────────┐
                       ▼
narrative ──> verify.numeric_claims ──> verified_narrative
                                         │
chart ───────────────────────────────────┤
                                         ▼
                                  document.compose
```

This prevents an implementation from performing a verification check and then accidentally continuing to use the unverified value.

The verifier output may be a transformed/approved value or a verification result that must gate a later composition step.

## Cache semantics

Nodes may declare one of:

- `never`;
- `deterministic_only`;
- `content_addressed`.

Caching must include all semantically relevant inputs, capability version, provider conformance version where needed, execution environment assumptions, and policy constraints.

A cached result never carries old authority forward. Current policy is evaluated again before a cached artifact is exposed or used for a new side effect.

## Program identity and canonical form

The semantic program should be content-addressable after normalization.

For v0.1:

- JSON is the inspectable interchange representation;
- insignificant formatting and object-key order must not alter semantic identity;
- a canonicalization algorithm should be used before hashing/signing;
- the hash identifies the normalized semantic program, not runtime grants or provider bindings.

A future binary representation may replace JSON on hot paths without changing IR semantics.

## Separation from execution binding

AIOS IR intentionally stops before concrete execution authority.

A runtime execution instance binds:

```text
IR node
 + provider ID/version
 + artifact handles
 + policy decision
 + capability token/grant
 + sandbox/execution profile
 + hardware placement
 + model descriptor if applicable
 + attempt number
```

That binding belongs in execution/provenance records rather than mutating the semantic IR in place.

This makes the same semantic program reusable across:

- different computers;
- different model providers;
- different GPUs;
- local vs permitted remote execution;
- upgraded capability providers;
- different users with different policy.

## Transformation rules

An optimizer/compiler may transform IR only if the transformation preserves:

1. observable task semantics;
2. required verification;
3. authority upper bounds;
4. data sensitivity/egress restrictions;
5. failure bounds;
6. provenance reconstructability.

An optimization may reduce authority, resource use, cost, or model dependence.

It MUST NOT silently:

- remove a verifier;
- broaden egress;
- replace deterministic work with probabilistic work;
- increase requested authority;
- hide a side effect;
- convert a bounded retry into an unbounded loop.

## AI generation design rules

The IR should be deliberately easier for models to generate correctly than a general-purpose language.

Therefore v0.1 favors:

- closed enums;
- named typed ports;
- structural references;
- explicit side effects;
- explicit bounded failure behavior;
- no arbitrary `eval`;
- no arbitrary shell escape;
- no implicit globals;
- no implicit credentials;
- no ambient current-working-directory semantics;
- no provider-specific secrets;
- no unbounded loops;
- no authority encoded in natural-language comments.

## Relationship to `task-plan.schema.json`

The existing task-plan contract is retained as a planner-facing proposal format during transition.

Long term, there are three reasonable outcomes:

1. task-plan becomes a thin planning envelope whose executable portion is AIOS IR;
2. task-plan is replaced by AIOS IR after migration;
3. task-plan remains higher-level while AIOS IR is a deterministic lowering target.

For v0.1, option 3 is preferred because it preserves a clear boundary between a model/planner proposal and the normalized executable semantics accepted by the runtime.

## v0.1 non-goals

AIOS IR v0.1 is not intended to provide:

- a general-purpose replacement for Rust/C/C++;
- arbitrary pointer arithmetic;
- kernel-driver authoring;
- an unrestricted shell language;
- arbitrary dynamic linking;
- self-modifying code;
- general unbounded loops;
- a complete human-facing source language;
- direct raw-device privilege.

## Success criterion

The IR design is successful if Demonstration A can be represented end to end such that a validator can answer, before execution:

- what semantic capabilities are requested;
- what values flow between them;
- what authority each step requests;
- where external egress is forbidden or policy-controlled;
- which nodes are probabilistic;
- which verification gates exist;
- what failure behavior is permitted;
- what final outputs should exist;
- and whether the graph is structurally and semantically safe to bind for execution.
