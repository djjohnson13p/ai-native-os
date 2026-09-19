# 61 — AIOS IR Validator Test, Fuzz, and Resource-Limit Matrix

## Purpose

Issue #17 is a trusted semantic boundary. Its test plan therefore needs more than a few valid JSON fixtures.

This document turns the validator requirements into explicit test classes so implementation can be judged mechanically.

Canonical/hash tests are controlled by ADR 0029 and `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md` rather than implementation guesswork.

## Test layers

```text
L0 parser/lexical robustness
L1 structural/schema validation
L2 graph/reference validation
L3 semantic registry/type/capability validation
L4 effect/authority/egress validation
L5 fallback/retry/output validation
L6 canonicalization/hash determinism
L7 provider-conformance boundary
L8 resource-limit/denial-of-service robustness
L9 fuzz/property tests
```

Every invalid path must fail without provider/model execution.

## L0 — parser / lexical robustness

Required cases:

| Case | Expected code/family |
| --- | --- |
| empty input | `IR_PARSE_INVALID` |
| truncated JSON | `IR_PARSE_INVALID` |
| invalid UTF-8/bytes where input API permits bytes | parse failure |
| duplicate object key | `IR_PARSE_DUPLICATE_KEY` |
| extreme numeric literal outside accepted representation | bounded parse/schema failure |
| deeply nested JSON | `IR_LIMIT_DEPTH` |
| oversized document | `IR_LIMIT_DOCUMENT_SIZE` |

Security property:

> No downstream validator pass sees a different interpretation of duplicate-key input than the parser that accepted it.

## L1 — structural/schema

Required cases include:

- missing `ir_version`;
- unsupported `ir_version`;
- missing `program_id`;
- missing nodes;
- forbidden `task_id` in semantic IR;
- additional security-relevant properties;
- provider/grant/token/credential/runtime-binding fields;
- invalid enum values;
- malformed value references;
- too many nodes/ports/authority requests/fallbacks;
- invalid identifier lengths/patterns.

Expected families:

```text
IR_SCHEMA_REQUIRED
IR_SCHEMA_ADDITIONAL_PROPERTY
IR_SCHEMA_ENUM
IR_VERSION_UNSUPPORTED
IR_LIMIT_*
```

## L2 — graph/reference

Required cases:

| Case | Expected |
| --- | --- |
| duplicate node ID | `IR_GRAPH_DUPLICATE_NODE_ID` |
| self-cycle | `IR_GRAPH_CYCLE` |
| multi-node cycle | `IR_GRAPH_CYCLE` |
| missing referenced input | `IR_REFERENCE_INPUT_NOT_FOUND` |
| missing producer node | `IR_REFERENCE_NODE_NOT_FOUND` |
| missing output port | `IR_REFERENCE_PORT_NOT_FOUND` |
| output references missing node/port | `IR_OUTPUT_NOT_FOUND` or reference family |
| disconnected optional node | valid/invalid according to explicit reachability rule |

Cycle detection must be deterministic independent of JSON object-key order or node authoring order.

## L3 — semantic registry/type/capability

Required cases:

- unknown capability;
- wrong capability version;
- unknown semantic type;
- producer/consumer exact-type mismatch;
- missing required capability input port;
- extra unsupported semantic port;
- invalid output type declaration;
- capability execution class inconsistent with contract;
- registry contains duplicate contract identity;
- program validated against different registry snapshot than claimed fixture identity.

Expected families include:

```text
IR_CAPABILITY_NOT_FOUND
IR_CAPABILITY_PORT_MISMATCH
IR_TYPE_MISMATCH
IR_EXECUTION_CLASS_INCOMPATIBLE
REGISTRY_*
```

## L4 — effects / authority / egress

Test the validator as a **semantic consistency checker**, not an authorization engine.

Required cases:

- operation requests authority class capability contract is not allowed to request;
- duplicate semantic authority request if the accepted v0.1 implementation uses reject-not-deduplicate behavior;
- program claims no egress while semantic operation requires remote/network egress;
- external-message effect missing from derived upper bound;
- secret-access capability represented as pure;
- system-change capability requests insufficient effect class;
- provider/grant/token/credential fields smuggled into semantic IR;
- verification barrier removed from a path that contract/program requires.

Expected families:

```text
IR_AUTHORITY_CLASS_NOT_ALLOWED
IR_EGRESS_CONTRADICTION
IR_EXECUTION_CLASS_INCOMPATIBLE
IR_SCHEMA_ADDITIONAL_PROPERTY or a dedicated forbidden-binding code
```

If duplicate semantic authority requests receive a dedicated reason code, add it to the stable reason-code catalog and regression fixtures before relying on it externally.

Success output must include derived effect summary but **never** a capability grant.

## L5 — failure policy / fallback / outputs

Required cases:

- unbounded retry;
- fallback to same capability recursively;
- A -> B -> A fallback closure;
- fallback with incompatible input types;
- fallback with incompatible output types;
- fallback requires execution class outside program constraint;
- unreachable required program output;
- optional branch failure policy incorrectly makes required output impossible;
- excessive fallback list.

Expected families:

```text
IR_FAILURE_POLICY_UNBOUNDED
IR_FAILURE_POLICY_RECURSIVE_FALLBACK
IR_OUTPUT_NOT_FOUND
IR_TYPE_MISMATCH / capability compatibility family
```

## L6 — canonicalization / semantic hash

The exact v0.1 profile is `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`.

### Equivalence tests — hash MUST remain equal

Create test pairs that differ only by:

1. whitespace;
2. JSON object-key order;
3. top-level metadata content/order;
4. node metadata content/order;
5. input/node/top-level description prose where present;
6. authority-request `reason` prose;
7. `program_id` only;
8. authoring node array order when references/IDs are unchanged;
9. semantic-set order for `media_types`;
10. semantic-set order for `locality`;
11. semantic-set order for `destination_classes`;
12. semantic-set order for authority requests;
13. omission vs explicit safe default (`required=true`, accelerator `optional=false`);
14. serialization by two standards-compliant JSON writers.

### Difference tests — hash MUST change

Create test pairs that differ by:

1. `ir_version`;
2. `kind`;
3. input semantic type;
4. input required/media-type constraint;
5. node ID;
6. capability ID/version;
7. operation kind (`invoke`/`verify`);
8. execution class;
9. input/data-flow reference;
10. declared output semantic type;
11. authority action;
12. authority resource;
13. egress mode/destination class;
14. locality/resource constraint;
15. ordered fallback content/order;
16. retry/replan budget;
17. cache policy;
18. final program output mapping.

### Forbidden/outside semantic hash

The same validated program MUST keep the same semantic hash when only runtime/external binding changes:

- Task ID;
- provider ID/version;
- provider package/build digest;
- device/hardware profile;
- CPU/GPU/peer placement;
- process/container/VM ID;
- policy decision/grant/token ID;
- credential/secret handle;
- network endpoint/route;
- cloud provider/region when semantics allow substitution;
- storage replica ID/location;
- filesystem/namespace materialization path;
- validation timestamp;
- validator process identity.

Most of these fields are structurally outside AIOS IR and should be tested through the semantic-view/hash API rather than by illegally adding them to valid IR.

### JCS / domain-separation tests

Test vectors must prove:

- the normalized semantic object is serialized using the selected RFC 8785 JCS-compatible implementation;
- hash input includes the single centrally defined AIOS IR v0.1 domain/version prefix;
- user-visible hash identifier records algorithm explicitly;
- no other module independently constructs a different semantic-hash prefix/serialization;
- raw authoring JSON hash cannot be confused with semantic hash.
- integer values at `2^53 - 1` remain accepted, while `2^53` and adjacent
  higher values are rejected before JCS serialization so distinct typed values
  cannot collapse to one ECMAScript number.

### Program-ID collision tests

Prove explicitly:

```text
program_id A + semantic graph X -> hash H
program_id B + semantic graph X -> hash H
program_id A + semantic graph Y -> hash H2 (H2 != H)
```

No persistence/helper API may assume `program_id` uniquely identifies exact executable meaning.

### Invalid-hash rule

Any program failing any semantic-validation pass must have:

```text
valid = false
semantic_hash = null
```

An optional raw-document/debug hash must use a separate field/type/namespace.

## L7 — provider conformance boundary

Although provider execution is out of scope for Issue #17, provider registration/conformance fixtures should prove the semantic separation.

Required checks:

- provider claims known capability/version;
- declared input/output ports are compatible with semantic contract;
- provider does not claim weaker isolation than allowed;
- provider effect/authority declaration is not narrower than actual semantic contract requirements in a dangerous way;
- provider-specific implementation metadata does not change AIOS IR semantic hash;
- two conforming provider manifests can satisfy the same semantic capability contract.

## L8 — resource limits

Suggested initial defaults are implementation choices, but tests must exist for boundaries.

Categories:

```text
max document bytes
max JSON depth
max nodes/program
max ports/node
max authority requests/node
max fallbacks/node
max string length where relevant
max registry contracts
max diagnostics/result
```

For each limit test:

```text
N-1 -> accepted if otherwise valid
N   -> accepted/rejected according to inclusive definition
N+1 -> deterministic limit error
```

No limit violation should cause uncontrolled memory growth, stack overflow, or excessively expensive diagnostic storms.

## Diagnostic bounding

For an input with thousands of independent errors, return at most the configured diagnostic maximum and an indicator that additional diagnostics were suppressed.

The result remains `valid=false`.

## L9 — property tests

Properties to encode:

### Canonicalization idempotence

```text
normalize(normalize(x)) == normalize(x)
```

for valid semantic programs.

### Hash stability

```text
hash(parse(serialize(valid_program))) == hash(valid_program)
```

under permitted serialization/authoring variation defined by `docs/66`.

### Program label independence

For equivalent validated semantic views:

```text
program_id != program_id'  => semantic_hash == semantic_hash'
```

when all included semantic fields are identical.

### No invalid executable identity

An invalid program must never receive a semantic hash/validated identity that downstream code could confuse with executable validation success.

### Topological consistency

For every accepted DAG, all producer references are valid dependencies of consumers under computed topological ordering.

### Registry immutability

A validation operation cannot observe two different definitions for the same contract identity during one run.

### Effects are monotonic upper bounds

Whole-program derived effect set contains the union/required closure of per-node semantic effects; optimizer/runtime may not infer a narrower security boundary from the validator summary than the program requires.

### Non-semantic stripping cannot hide semantics

Mutation generators that place capability/provider/grant/authority-like fields into `metadata` or descriptions must not cause those fields to affect execution/permission; if a semantic requirement exists only in excluded prose/metadata, it is not executable semantics.

## Fuzz targets

Priority order:

1. raw JSON/strict duplicate-key parser;
2. typed AIOS IR deserializer;
3. value-reference parser;
4. node-index/reference builder;
5. cycle/topological sorter;
6. registry loader/indexer;
7. type/capability checker;
8. fallback-closure validator;
9. semantic-view normalizer;
10. JCS canonicalizer/domain-separated hasher;
11. effect-summary derivation.

## Fuzz invariants

For arbitrary bytes/structures:

- no panic;
- no shell/process spawn;
- no network;
- no model/provider invocation;
- no unbounded recursion;
- no secret resolution;
- bounded memory/time according to harness limits where practical;
- success requires full validation path, never parser acceptance alone.

## Regression corpus

The Issue #17 R17-01–05 review repair gate additionally consumes:

- `examples/aios-ir/registry-structure-repair-cases.json`: raw schema/typed admission,
  optional omission/null/empty object/value parity;
- `examples/aios-ir/review-repair-cases.json`: exact integer lexical equivalence,
  safe-range/fractional adversaries, tolerance sign/underflow/overflow/subnormals,
  attacker-named diagnostic properties, and verification inventory versus outputs.

Integer tests must cover every constraint and retry/replan path without first
decoding fixture number spellings to floating point. Property tests include
decimal/exponent equivalents and fractional near-integer rejections. Tolerance
cases run against both contract classes and both tolerance fields. The original
bootstrap hashes must still reproduce after the repairs.

Every discovered crash, hash ambiguity, parser discrepancy, or security-significant invalid acceptance becomes a permanent regression fixture.

Name fixture by reason rather than incident date only, e.g.:

```text
duplicate-key-capability-smuggling.json
fallback-cycle-three-node.json
metadata-hash-confusion.json
program-id-hash-confusion.json
registry-duplicate-contract.json
```

## Fixture source of truth

The implementation should consume/validate repository fixtures under:

```text
examples/aios-ir/
```

Do not silently copy a stale private fixture set into the crate and stop testing the repository contracts.

Crate-local unit fixtures/test vectors may supplement but not replace architecture fixtures.

## CI gate — validator spike

Before Issue #17 can merge:

- formatter passes;
- static lint/type checks pass;
- unit tests pass;
- positive fixtures pass;
- invalid/adversarial fixtures fail with expected code family;
- canonicalization/hash equivalence/difference/runtime-isolation tests pass;
- JCS/domain-separation vectors pass;
- resource-limit tests pass;
- fuzz/property smoke run passes within CI-friendly budget;
- no test requires network/model/provider execution.

Longer fuzzing can run separately from every PR once infrastructure exists.

## Security review questions

Before merge ask:

1. Can one parser/validator stage interpret the same bytes differently from another?
2. Can metadata/description/reason prose alter execution semantics or permission without entering semantic hash?
3. Can an unknown field carry authority/provider/runtime binding data through validation?
4. Can `program_id` or Task ID be confused with exact semantic-program identity?
5. Can recursive graph/fallback input exhaust stack/CPU?
6. Can invalid registry state make a program appear valid nondeterministically?
7. Can success result exist without registry snapshot identity?
8. Can downstream code mistake `parsed` for `validated`?
9. Can diagnostic generation leak sensitive input unexpectedly?
10. Can any runtime binding change the semantic hash contrary to ADR 0029?

## Principle

> **The validator earns trust by rejecting ambiguity predictably and hashing only executable meaning—not by being clever about malformed programs or incidental labels.**
