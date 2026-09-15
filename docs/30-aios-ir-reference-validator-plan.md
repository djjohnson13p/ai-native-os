# 30 — AIOS IR Reference Validator Implementation Plan

## Goal

Turn the semantic boundary defined by AIOS IR into a small deterministic component that can be implemented and tested before a full model-assisted planner exists.

This document is intentionally implementation-oriented so the first Codex session does not need to invent the validator architecture.

## Proposed crate/package boundary

Working Rust workspace shape:

```text
crates/
  aios-ir-model/
  aios-ir-schema/
  aios-ir-validate/
  aios-ir-canonical/
  aios-contract-registry/
  aios-reason-codes/
```

These names are provisional and can be simplified if implementation shows the split is excessive.

## `aios-ir-model`

Responsibilities:

- strongly typed Rust representation of AIOS IR v0.1;
- no provider execution;
- no network access;
- no policy decision logic;
- preserve semantic fields required for canonicalization.

Avoid exposing a general `serde_json::Value` escape hatch for security-relevant fields after parsing.

## `aios-ir-schema`

Responsibilities:

- package/embed schema version metadata;
- structural validation against `specs/aios-ir.schema.json`;
- strict unknown-field handling;
- document size/depth/node-count limits;
- duplicate-key rejection strategy.

If the chosen Rust JSON stack cannot reliably detect duplicate keys in security-sensitive input, implement or select a parser path that can.

## `aios-contract-registry`

Responsibilities:

- load immutable semantic capability contracts;
- load immutable semantic type contracts;
- identify registry snapshot/version/hash;
- provide lookup APIs only;
- perform no provider code execution.

Initial implementation can load repository fixture JSON into memory.

Long-term signing/distribution is outside the first validator task.

## `aios-ir-validate`

Suggested validation passes:

```text
Pass 0: version/limits
Pass 1: structural/schema
Pass 2: node identity/index construction
Pass 3: reference resolution
Pass 4: DAG/cycle validation
Pass 5: semantic type validation
Pass 6: capability contract validation
Pass 7: execution-class compatibility
Pass 8: authority/effect validation
Pass 9: egress consistency
Pass 10: bounded failure/fallback validation
Pass 11: output reachability
Pass 12: normalization eligibility
```

Each pass returns stable structured diagnostics rather than user-facing prose only.

## Diagnostics model

Suggested internal/result shape:

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

Reason codes are stable API; human messages may improve over time.

## First reason codes

At minimum implement:

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

## Validation output

Suggested result:

```json
{
  "valid": true,
  "ir_version": "0.1",
  "program_id": "demo.analyze_numbers.v1",
  "semantic_hash": "sha256:...",
  "registry_snapshot": "sha256:...",
  "diagnostics": []
}
```

Invalid results must not receive a semantic hash treated as executable identity.

It is acceptable to compute an internal raw-document hash for debugging, but it must not be confused with a validated semantic hash.

## Canonicalization

Proposed v0.1 path:

1. parse into strict typed representation;
2. fill only specification-defined semantic defaults;
3. remove explicitly non-semantic metadata from the semantic-hash view;
4. serialize with the selected canonical JSON algorithm;
5. hash canonical bytes with tagged SHA-256;
6. retain algorithm/version metadata.

The code should make it difficult for a later refactor to accidentally include runtime bindings or secrets in semantic identity.

## Metadata rule

Top-level/node `metadata` is non-authoritative and should not affect permission decisions.

For semantic hashing, v0.1 should exclude metadata unless a later ADR identifies a metadata field that changes execution meaning. Execution-semantic fields must never be smuggled into `metadata`.

## Graph algorithm

Build a node index by ID.

For each node input referencing another node:

- verify node exists;
- verify output port exists;
- add directed edge producer -> consumer.

Run deterministic cycle detection/topological sort.

Independent nodes may use lexicographic node ID as a stable tie-break for diagnostic/serialization order without requiring serial execution.

## Type checking

For v0.1:

- resolve producer output semantic type;
- resolve capability contract consumer input type;
- require exact compatible type/version under ADR 0014;
- emit `IR_TYPE_MISMATCH` on failure;
- never ask a model to infer an implicit conversion;
- a planner may repair by inserting a declared conversion capability and resubmitting.

## Capability checking

For each operation:

- resolve semantic capability contract;
- verify operation role (`verify` nodes should reference verifier-capable contracts where required);
- check named ports;
- check execution class;
- check declared authority classes;
- check egress mode;
- check fallback contracts for compatible input/output semantics.

## Authority checking at IR stage

The validator does **not** decide whether the user permits an action.

It verifies only that:

- the authority request is structurally valid;
- the semantic capability is allowed to request that authority class;
- request/egress declarations are not self-contradictory;
- semantic IR contains no grant/token fields.

Cedar/policy evaluation occurs afterward.

## Fallback validation

A fallback capability must:

- exist;
- not equal the primary capability;
- accept compatible input ports/types;
- produce compatible output ports/types;
- not require a broader execution class than the program allows;
- not create an unbounded recursive fallback chain.

For v0.1, cap fallback list length at the schema maximum and reject recursive closure.

## Resource limits

Initial configurable limits should include:

```text
max serialized bytes
max JSON nesting depth
max nodes per program
max ports per node
max authority requests per node
max fallback entries
max diagnostic count
```

The validator should stop producing additional diagnostics after a bounded maximum while still returning that validation failed.

## Test layers

### Unit tests

- value-reference parsing;
- node indexing;
- graph cycle detection;
- type matching;
- fallback closure;
- reason-code mapping;
- canonicalization.

### Fixture tests

Load:

- `examples/aios-ir/demonstration-a.ir.json`;
- `examples/aios-ir/valid-cases.json`;
- `examples/aios-ir/invalid-cases.json`;
- capability/type contract fixture registries.

### Property/fuzz tests

Targets should include:

- parser input;
- graph construction;
- canonicalizer;
- reference resolver;
- type/capability lookup boundaries.

Properties:

- validator never panics on arbitrary bytes;
- invalid input never becomes executable without `valid=true`;
- canonicalization is idempotent;
- key-order/whitespace changes do not change semantic hash;
- adding/removing semantic fields does change hash as expected.

## CLI spike

Before daemon integration, a tiny CLI is useful:

```text
aios-ir validate program.json --registry examples/aios-ir/
aios-ir normalize program.json
aios-ir hash program.json --registry examples/aios-ir/
aios-ir explain-error IR_GRAPH_CYCLE
```

This is development tooling, not the final user interface.

## No-code-execution rule

Validator tests must prove that validation of hostile input cannot:

- run provider binaries;
- invoke a shell;
- contact network endpoints;
- load model runtimes;
- resolve secret handles;
- open arbitrary artifact contents unless explicitly needed for a future type validator and separately authorized.

## Integration boundary

The Task Manager may transition a proposal toward `RUNNABLE` only after it has a successful validator result plus subsequent policy/provider/resource checks.

A semantic validation result should be persistable alongside:

- program hash;
- IR version;
- registry snapshot hash;
- validation timestamp;
- validator version;
- diagnostics/warnings.

## Codex-ready definition

This implementation task is ready when Codex can be told:

> Implement the deterministic AIOS IR v0.1 validator against the existing schemas/docs/fixtures. Do not implement planner/model/provider execution. Do not invent implicit type conversions. Do not add authority semantics. All current positive and negative fixtures must pass with stable reason codes.

At that point the work is primarily engineering rather than architecture invention.
