# 30 — AIOS IR Reference Validator Implementation Plan

## Goal

Turn the semantic boundary defined by AIOS IR into a small deterministic component that can be implemented and tested before a full model-assisted planner exists.

This document is intentionally implementation-oriented so the first Codex session does not invent validator semantics or repository structure.

## Controlling implementation documents

For Issue #17, read this document together with:

- `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md` — current minimal crate/workspace shape;
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md` — required test classes;
- `docs/62-first-codex-session-runbook.md` — first-session workflow/stop conditions;
- `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md` — accepted semantic-hash field/order/default profile;
- ADR 0029 — accepted v0.1 semantic-hash identity boundary.

If an older conceptual crate split elsewhere conflicts with `docs/60`, use the smaller `docs/60` workspace for the spike and preserve the logical module responsibilities described here.

## Initial crate/package boundary

Current recommended spike shape:

```text
crates/
  aios-contracts/
  aios-registry/
  aios-ir/
cmd/
  aios-ir/
```

Logical responsibilities may later split into additional crates if implementation evidence improves isolation/reviewability/build ownership.

Do **not** preemptively create micro-crates for every validation pass.

## `aios-contracts`

Responsibilities:

- strongly typed AIOS IR v0.1 representation;
- semantic type/capability contract structures;
- registry snapshot structures;
- validation result/diagnostic structures;
- effect summary structures;
- stable reason-code enum/string mapping;
- schema/interface version constants.

Rules:

- no provider execution;
- no network;
- no policy authorization decision logic;
- no model integration;
- avoid general `serde_json::Value` escape hatches for security-relevant fields after strict parsing.

Non-authoritative `metadata` may remain generic where required by the schema, but it is excluded from permission decisions and semantic hashing.

## `aios-registry`

Responsibilities:

- load immutable semantic capability contracts;
- load immutable semantic type contracts;
- validate/index contract identity/version;
- identify/compute registry snapshot identity;
- provide read-only lookup APIs;
- reject duplicate/conflicting semantic contract identities.

Initial implementation may load repository fixture JSON from explicitly provided paths.

Rules:

- no provider code loading/execution;
- no network fetch;
- no package installation;
- no policy authorization decisions;
- the registry observed by one validation operation is immutable.

## `aios-ir`

Responsibilities are logical modules/passes such as:

```text
parse
limits
schema
index
references
graph
types
capabilities
effects
failure_policy
normalize
canonical
hash
diagnostics
validate
```

### Parse / strict input

Requirements:

- malformed serialization fails before semantic lookup;
- duplicate JSON object keys are rejected;
- size/depth limits are enforced before expensive work where practical;
- no expressions/scripts/comments are executed;
- invalid input is ordinary validator input, not an exceptional panic condition.

If the selected Rust JSON path cannot reliably detect duplicate keys, use a strict deserializer/visitor or another bounded parse strategy that can.

### Structural validation

Validate against `specs/aios-ir.schema.json` or an exactly equivalent generated/typed structural contract.

Structural validation covers:

- required fields;
- closed security-relevant property sets;
- enums/patterns/ranges;
- bounded arrays;
- shape of value references/failure policies;
- IR version support.

Passing schema validation does not imply semantic validity or authority.

## Validation passes

Suggested deterministic pass order:

```text
Pass 0: input/version/resource limits
Pass 1: strict structural/schema validation
Pass 2: node identity/index construction
Pass 3: program/node reference resolution
Pass 4: DAG/cycle validation
Pass 5: semantic type validation
Pass 6: semantic capability contract validation
Pass 7: execution-class compatibility
Pass 8: authority/effect consistency
Pass 9: egress consistency
Pass 10: bounded failure/fallback validation
Pass 11: required output reachability
Pass 12: static effect-summary derivation
Pass 13: normalization eligibility
Pass 14: semantic canonicalization/hash
```

An implementation can combine internal passes for efficiency only if reason-code behavior/security boundaries remain equivalent and testable.

No later pass may reinterpret an earlier hard failure as valid.

## Diagnostics model

Conceptual shape:

```text
ValidationDiagnostic {
  severity
  code
  message
  program_id?
  node_id?
  port?
  capability?
  json_pointer?
  related[]
}
```

Machine reason codes are API-like contract; human messages may improve over time.

Diagnostic count must be bounded.

## Initial reason codes

At minimum:

```text
IR_PARSE_INVALID
IR_PARSE_DUPLICATE_KEY
IR_SCHEMA_REQUIRED
IR_SCHEMA_ADDITIONAL_PROPERTY
IR_SCHEMA_ENUM
IR_VERSION_UNSUPPORTED
IR_LIMIT_DOCUMENT_SIZE
IR_LIMIT_DEPTH
IR_LIMIT_NODE_COUNT
IR_GRAPH_DUPLICATE_NODE_ID
IR_GRAPH_CYCLE
IR_REFERENCE_INPUT_NOT_FOUND
IR_REFERENCE_NODE_NOT_FOUND
IR_REFERENCE_PORT_NOT_FOUND
IR_TYPE_MISMATCH
IR_CAPABILITY_NOT_FOUND
IR_CAPABILITY_PORT_MISMATCH
IR_EXECUTION_CLASS_INCOMPATIBLE
IR_AUTHORITY_CLASS_NOT_ALLOWED
IR_EGRESS_CONTRADICTION
IR_FAILURE_POLICY_UNBOUNDED
IR_FAILURE_POLICY_RECURSIVE_FALLBACK
IR_OUTPUT_NOT_FOUND
IR_CANONICALIZATION_FAILED
```

Registry loader may define `REGISTRY_*` reason codes for duplicate/conflicting/invalid registry state rather than mislabeling those failures as program errors.

## Graph algorithm

Build a node index by ID.

For each node input referencing another node:

- verify node exists;
- verify referenced output port exists;
- add directed producer -> consumer edge.

Run deterministic cycle detection/topological sort.

Independent nodes may use lexicographic node ID as a stable tie-break for diagnostic/traversal output without requiring serial execution.

For semantic hashing, node authoring order is normalized by the profile in `docs/66`; do not use runtime topological order as an accidental hash specification.

## Type checking

For v0.1:

- resolve producer output semantic type;
- resolve consumer capability-contract input type;
- require exact compatible type/version under ADR 0014;
- emit `IR_TYPE_MISMATCH` on failure;
- never ask a model to infer an implicit conversion;
- planner repair requires inserting an explicit declared conversion capability and resubmitting.

## Capability checking

For each operation:

- resolve semantic capability contract;
- verify named input/output ports;
- verify semantic types;
- check operation role (`verify` semantics where required);
- check execution class;
- check allowed authority classes/effects;
- check egress semantics;
- check fallback contracts for compatible input/output semantics;
- associate the immutable contract/snapshot identity used for validation.

Unknown capability names never become shell commands/arbitrary code.

## Authority checking at IR stage

The validator does **not** decide whether the user permits an action.

It verifies only that:

- authority requests are structurally valid;
- the semantic capability is permitted to request the declared authority class;
- requested action/resource is semantically consistent enough for the IR contract;
- request/egress declarations are not self-contradictory;
- semantic IR contains no grant/token/credential/runtime binding fields.

Cedar/other policy authorization occurs afterward.

A validation success is **not** a grant.

## Static effect summary

Successful semantic validation derives the deterministic upper-bound summary specified in `docs/39-static-effect-and-authority-analysis.md` and `specs/effect-summary.schema.json`.

The summary includes, at minimum where defined:

- whole-program/per-node effect classes;
- requested authority classes;
- egress modes;
- probabilistic/opaque flags;
- verification barriers.

The summary is diagnostic/policy/compiler input. It never grants authority.

## Fallback validation

A fallback capability must:

- exist in the same immutable semantic registry context;
- differ from the primary capability;
- accept compatible inputs;
- produce compatible outputs;
- remain within allowed execution/effect semantics;
- not create a recursive/unbounded fallback closure.

Fallback ordering is semantic and preserved by semantic hashing.

## Normalization and semantic hashing

ADR 0029 and `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md` are controlling.

Important rules:

- `task_id` is not a valid AIOS IR v0.1 field;
- `program_id` is a logical label excluded from semantic hash;
- metadata/descriptions/authority reason prose are excluded;
- executable/authority/egress/verification/failure/cache/constraint semantics are included;
- specification-defined safe defaults are materialized;
- unordered semantic sets are sorted deterministically;
- node authoring order is normalized by node ID;
- fallback list order remains significant;
- canonical serialization uses RFC 8785 JCS semantics over the normalized semantic view;
- SHA-256 is domain-separated/tagged for the v0.1 profile;
- invalid programs do not receive an executable semantic hash.

The semantic-hash implementation must be centralized so later planner/daemon/UI/provider code cannot invent alternate hashing behavior.

## Validation output

Conceptual result:

```json
{
  "valid": true,
  "ir_version": "0.1",
  "program_id": "demo.analyze_numbers.v1",
  "semantic_hash": "sha256:...",
  "registry_snapshot": "sha256:...",
  "effect_summary": {},
  "diagnostics": []
}
```

`program_id` may be reported for diagnostics even though it is excluded from semantic hashing.

Invalid results must not receive a semantic hash treated as executable identity.

A raw-document hash may exist separately for debugging/quarantine but must use a distinct field/namespace.

## Resource limits

Initial configurable limits include:

```text
max serialized bytes
max JSON nesting depth
max nodes/program
max ports/node
max authority requests/node
max fallback entries
max registry contracts
max diagnostic count
```

Boundary/DoS behavior is specified by `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`.

## Test layers

### Repository fixtures

Load and exercise:

- `examples/aios-ir/demonstration-a.ir.json`;
- `examples/aios-ir/valid-cases.json`;
- `examples/aios-ir/invalid-cases.json`;
- `examples/aios-ir/invalid-semantic-cases.json`;
- `examples/aios-ir/provider-conformance-cases.json` where relevant to registry/conformance boundary;
- capability/type/registry/effect fixture records.

### Unit tests

At minimum:

- strict/duplicate-key parsing;
- value-reference parsing;
- node indexing/reference resolution;
- graph cycle detection;
- exact type matching;
- capability/port matching;
- authority/egress consistency;
- fallback closure;
- effect derivation;
- reason-code mapping;
- semantic-view normalization;
- JCS/domain-separated hash profile.

### Property/fuzz tests

Follow `docs/61`.

Core properties include:

- validator never panics on arbitrary bytes;
- invalid input never becomes executable without full `valid=true` semantic path;
- normalization is idempotent;
- formatting/metadata/program-label changes do not change semantic hash;
- semantic changes do change hash;
- registry snapshot remains immutable during one validation.

## CLI spike

Before daemon integration, expose a tiny development CLI:

```text
aios-ir validate program.json --registry examples/aios-ir/
aios-ir normalize program.json
aios-ir hash program.json --registry examples/aios-ir/
aios-ir effects program.json --registry examples/aios-ir/
aios-ir explain-error IR_GRAPH_CYCLE
```

This is development tooling, not the final user interface.

The CLI calls library semantics; it must not reimplement validation differently.

## No-code-execution rule

Validator tests must prove hostile validation cannot:

- run provider binaries;
- invoke a shell/process;
- contact network endpoints;
- load model runtimes;
- resolve credential/secret handles;
- inspect unrelated host files;
- authorize/grant capability use.

The CLI may read only explicitly supplied program/registry fixture paths needed for validation.

## Integration boundary

The Task Manager may transition a proposal toward `RUNNABLE` only after:

1. successful semantic validation;
2. current policy/authority evaluation;
3. provider/conformance resolution;
4. resource/sandbox binding.

Persistable validation evidence should identify:

- logical program ID;
- semantic program hash/profile;
- IR version;
- registry snapshot identity;
- validator version;
- effect summary;
- diagnostics/warnings;
- validation timestamp (outside semantic hash).

## Out of scope for Issue #17

Do not implement:

- Task daemon/persistence;
- Artifact store;
- Cedar policy engine;
- provider execution/supervision;
- Varlink provider IPC;
- model/planner adapters;
- GUI;
- peer/network/cloud/storage fabrics;
- package manager;
- Universal App Broker;
- Skill compiler/MLIR lowering;
- custom source language.

Those have separate stage/issue dependencies.

## Codex-ready definition

Issue #17 is `SPIKE_READY` when Codex can be told:

> Implement the deterministic AIOS IR v0.1 validator against the existing schemas/docs/fixtures and accepted semantic-hash profile. Do not implement planner/model/provider execution or authority policy. Reject malformed/ambiguous input deterministically, preserve stable reason codes, derive effect summaries, and make all current positive/negative/hash/limit tests pass.

The exact first-session procedure is `docs/62-first-codex-session-runbook.md`.

## Principle

> **The validator establishes meaning and rejects ambiguity; it never guesses intent, grants authority, or executes providers.**
