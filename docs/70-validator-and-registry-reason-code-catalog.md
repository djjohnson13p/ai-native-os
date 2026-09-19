# 70 — v0.1 Validator and Registry Reason-Code Catalog

## Purpose

Issue #17 needs stable machine-readable diagnostics so tests, Task recovery, planners, developer tools, and future UI can react to failure classes without parsing English messages.

This catalog defines the bootstrap v0.1 validator/semantic-registry code families and points to the separate provider-conformance catalog.

Human messages MAY improve. Code meaning must not silently change once implementation/tests depend on it.

## Format

```text
IR_*        candidate program/semantic-graph problem
REGISTRY_*  loaded semantic registry/snapshot/contract problem
PROVIDER_*  separate provider-conformance/runtime namespaces
```

Provider-conformance codes are machine-listed in `specs/provider-conformance-reason-codes.json`.

Policy/authorization, provider-runtime, credential, recovery, package, and compatibility errors use their own catalogs. Do not overload IR codes for unrelated runtime failures.

## Severity

```text
error    validation cannot succeed / no executable semantic hash
warning  program is valid but carries deterministic structural concern
```

Warnings do not grant authority and remain bounded by the diagnostic limit.

## Parser / serialization

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_PARSE_INVALID` | error | input cannot be parsed as supported AIOS IR serialization |
| `IR_PARSE_DUPLICATE_KEY` | error | one JSON object contains a duplicate key |

## Structural schema

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_SCHEMA_REQUIRED` | error | required field/property missing |
| `IR_SCHEMA_ADDITIONAL_PROPERTY` | error | closed semantic structure contains an undeclared field |
| `IR_SCHEMA_ENUM` | error | field contains unsupported enum value |
| `IR_SCHEMA_PATTERN` | error | identifier/reference/resource selector violates required grammar |
| `IR_SCHEMA_TYPE` | error | value has wrong JSON/structural type |
| `IR_SCHEMA_RANGE` | error | numeric/string/array bound violated outside dedicated resource-limit codes |
| `IR_VERSION_UNSUPPORTED` | error | `ir_version` is structurally valid but unsupported by this validator |

Schema validators may generate detailed underlying messages, but externally map them to the most specific stable family above.

## Resource limits

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_LIMIT_DOCUMENT_SIZE` | error | serialized input exceeds configured maximum |
| `IR_LIMIT_DEPTH` | error | JSON/semantic nesting exceeds configured maximum |
| `IR_LIMIT_NODE_COUNT` | error | node count exceeds configured maximum |
| `IR_LIMIT_PORT_COUNT` | error | a node/program interface exceeds configured port maximum |
| `IR_LIMIT_AUTHORITY_REQUEST_COUNT` | error | authority-request count exceeds configured maximum |
| `IR_LIMIT_FALLBACK_COUNT` | error | fallback count exceeds configured maximum |
| `IR_LIMIT_STRING_LENGTH` | error | security/resource-sensitive string exceeds validator maximum not already caught by schema |
| `IR_LIMIT_DIAGNOSTICS` | warning | additional diagnostics were suppressed after configured maximum; result remains invalid if errors exist |

`IR_LIMIT_DIAGNOSTICS` can appear alongside errors and `diagnostics_truncated=true`.

## Graph / references

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_GRAPH_DUPLICATE_NODE_ID` | error | two nodes share an ID |
| `IR_GRAPH_CYCLE` | error | semantic data-flow/fallback graph contains forbidden cycle |
| `IR_GRAPH_UNUSED_PURE_NODE` | warning | pure/verification node has no path to program output or effectful descendant |
| `IR_REFERENCE_INPUT_NOT_FOUND` | error | value/authority reference names unknown program input |
| `IR_REFERENCE_NODE_NOT_FOUND` | error | value reference names unknown producer node |
| `IR_REFERENCE_PORT_NOT_FOUND` | error | producer exists but named output port does not |
| `IR_OUTPUT_NOT_FOUND` | error | declared program output cannot resolve to a valid node output |

## Type semantics

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_TYPE_NOT_FOUND` | error | syntactically valid semantic type major reference is absent from snapshot |
| `IR_TYPE_MISMATCH` | error | producer/program-input semantic type is incompatible with consumer contract port |
| `IR_OPTIONAL_INPUT_TO_REQUIRED_PORT` | error | optional program input directly supplies a required capability port in v0.1 |

## Capability semantics

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_CAPABILITY_NOT_FOUND` | error | syntactically valid semantic capability major reference is absent from snapshot |
| `IR_CAPABILITY_PORT_MISMATCH` | error | node port set does not satisfy resolved capability contract |
| `IR_CAPABILITY_ROLE_MISMATCH` | error | `verify` operation and verifier capability role do not match |
| `IR_EXECUTION_CLASS_INCOMPATIBLE` | error | node execution class is not permitted by capability contract |

## Effects / authority / egress

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_AUTHORITY_CLASS_NOT_ALLOWED` | error | node requests authority outside resolved capability contract envelope |
| `IR_REQUIRED_AUTHORITY_MISSING` | error | node omits authority required by capability semantic lower bound |
| `IR_AUTHORITY_DUPLICATE_REQUEST` | error | duplicate semantic `(action, resource)` request |
| `IR_EFFECT_CLASS_NOT_ALLOWED` | error | derived effect exceeds capability semantic effect envelope |
| `IR_EGRESS_NOT_ALLOWED` | error | node declares an egress mode that the resolved capability contract does not permit |
| `IR_EGRESS_CONTRADICTION` | error | egress structure contradicts itself (for example `deny` plus non-empty destination classes) or another closed semantic rule |
| `IR_EGRESS_AUTHORITY_MISMATCH` | error | policy-controlled egress lacks matching semantic `data.egress` authority request/destination class |
| `IR_CACHE_EXECUTION_CLASS_MISMATCH` | error | cache policy requires deterministic execution but node class is not deterministic |

Important distinction:

- a capability can permit `policy` egress while one particular IR node chooses `deny`;
- `network.connect` is not itself equivalent to `data.egress`;
- `policy` egress requires explicit matching `data.egress` authority semantics;
- authorization of the concrete destination occurs later in the Authority Coordinator, not in the validator.

## Failure / fallback

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_FAILURE_POLICY_UNBOUNDED` | error | retry/replan/repeated behavior has no accepted finite bound |
| `IR_FAILURE_POLICY_RECURSIVE_FALLBACK` | error | fallback closure is cyclic/recursive |
| `IR_FALLBACK_PORT_MISMATCH` | error | fallback cannot satisfy required input/output interface |
| `IR_FALLBACK_EFFECT_BROADENING` | error | fallback requires/broadens effect envelope beyond node semantics |
| `IR_FALLBACK_AUTHORITY_BROADENING` | error | fallback requires/broadens authority envelope beyond node semantics |
| `IR_FALLBACK_EGRESS_BROADENING` | error | fallback requires broader egress than node semantics |

## Canonicalization / semantic identity

| Code | Severity | Meaning |
| --- | --- | --- |
| `IR_CANONICALIZATION_FAILED` | error | a semantically valid typed program cannot be normalized/serialized under the accepted hash profile |

A canonicalization error produces no executable semantic hash.

If implementation discovers a stable sub-family is necessary (for example unsupported canonical number form), add a specific code through architecture/test update rather than encoding meaning only in prose.

## Registry structural / snapshot errors

| Code | Severity | Meaning |
| --- | --- | --- |
| `REGISTRY_SCHEMA_INVALID` | error | registry/snapshot/contract record fails structural schema |
| `REGISTRY_UNSUPPORTED_VERSION` | error | registry/snapshot format version unsupported |
| `REGISTRY_DUPLICATE_TYPE_MAJOR` | error | more than one active type contract for same `(type ID, major)` |
| `REGISTRY_DUPLICATE_CAPABILITY_MAJOR` | error | more than one active capability contract for same `(capability ID, major)` |
| `REGISTRY_ENTRY_NOT_FOUND` | error | snapshot references required contract content that is absent |
| `REGISTRY_CONTRACT_VERSION_MISMATCH` | error | snapshot/index major/version metadata disagrees with loaded contract record |
| `REGISTRY_CONTRACT_HASH_MISMATCH` | error | loaded contract bytes/canonical content do not match recorded digest |
| `REGISTRY_SNAPSHOT_HASH_MISMATCH` | error | snapshot canonical content does not match recorded snapshot digest |

## Registry semantic-contract consistency

ADR 0033's lower/upper effect/authority profile is now represented in the capability-contract schema.

| Code | Severity | Meaning |
| --- | --- | --- |
| `REGISTRY_REQUIRED_EFFECT_NOT_ALLOWED` | error | required effect absent from allowed effect set |
| `REGISTRY_REQUIRED_AUTHORITY_NOT_ALLOWED` | error | required authority absent from allowed authority set |
| `REGISTRY_PURE_EFFECT_CONTRADICTION` | error | `PURE` lower-bound semantics contradict non-PURE allowed/required semantics |

## Provider conformance namespace

Provider conformance is separate from semantic IR validation.

The canonical bootstrap list is `specs/provider-conformance-reason-codes.json`, including:

```text
PROVIDER_CONTRACT_NOT_FOUND
PROVIDER_CONTRACT_HASH_MISMATCH
PROVIDER_EXECUTION_CLASS_INCOMPATIBLE
PROVIDER_EFFECT_NOT_ALLOWED
PROVIDER_REQUIRED_EFFECT_MISSING
PROVIDER_AUTHORITY_NOT_ALLOWED
PROVIDER_REQUIRED_AUTHORITY_MISSING
PROVIDER_EGRESS_NOT_ALLOWED
PROVIDER_PORT_OR_TYPE_MISMATCH
PROVIDER_ISOLATION_INCOMPATIBLE
PROVIDER_SUITE_MISMATCH
PROVIDER_BUILD_IDENTITY_MISSING
PROVIDER_CONFORMANCE_FAILED
PROVIDER_CONFORMANCE_EXPIRED
PROVIDER_DECLARATION_INVALID
```

These do not authorize a provider. A provider can be structurally valid and conforming but still be disabled, untrusted for the current policy, unavailable, or denied authority at runtime.

Provider runtime/supervisor failures have a different catalog: `specs/provider-runtime-reason-codes.json`.

## Code selection precedence

Return the earliest/highest-confidence failure from the current deterministic validation stage and collect additional diagnostics only when doing so is bounded/safe.

Examples:

```text
duplicate key
  -> IR_PARSE_DUPLICATE_KEY
  (do not continue into schema/semantic passes)

unknown capability @2 in otherwise valid program
  -> IR_CAPABILITY_NOT_FOUND

registry contains two table.import major-1 contracts
  -> REGISTRY_DUPLICATE_CAPABILITY_MAJOR
  (registry is invalid before program lookup)
```

Do not mask a registry corruption as an `IR_CAPABILITY_NOT_FOUND` merely because lookup became ambiguous.

## JSON pointer/context

Diagnostics SHOULD include bounded structured context when known:

```text
node_id
port
capability
json_pointer
related[]
```

Context supplements the code. It does not change the code's meaning.

Schema classifications use structured error kinds/keywords, never substring
matching on rendered English messages. In particular, an undeclared property
named `pattern` or `required property` is still an additional-property violation.

## Reason-code change control

Before external stability:

- specific codes may be added;
- an overly broad code may be split with fixture updates;
- renaming a code already used in repository fixtures requires synchronized updates.

After a code is part of a stable public contract:

- do not recycle it for a different meaning;
- deprecate/alias intentionally if needed;
- human messages can change independently.

See `docs/65-contract-maturity-and-architecture-change-control.md`.

## Implementation rule

Reason codes should be represented as strongly typed enums/closed mappings in trusted components, with one canonical string representation per namespace.

Do not scatter ad-hoc reason-code string construction throughout validation or conformance passes.

## Principle

> **Machines react to stable codes; people read messages. Keep those concerns separate.**
