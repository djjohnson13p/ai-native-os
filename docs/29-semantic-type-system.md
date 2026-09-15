# 29 — AIOS Semantic Type System

## Purpose

AIOS IR and semantic capability contracts depend on types that mean the same thing regardless of whether a provider is written in Rust, Python, C++, WASM, a legacy application adapter, or a remote service.

The type system therefore distinguishes **semantic type** from **physical representation**.

```text
Semantic type: data.table@1

Possible representations:
- Arrow IPC
- in-process Arrow memory
- canonical JSON rows
- provider-private representation behind an adapter
```

A capability plans against the semantic type. The runtime negotiates an eligible physical representation.

## Core rule

> Type compatibility is explicit. Representation conversion is a capability, not an implicit guess.

This is especially important when AI generates the program: silent coercions make execution harder to reason about, verify, and secure.

## Type identity

Working form:

```text
namespace.name@major[.minor]
```

Examples:

```text
artifact.file@1
artifact.table@1
artifact.image@1
artifact.report@1
data.table@1
data.metrics@1
data.hash@1
text.plain@1
text.narrative@1
verification.result@1
```

The exact namespace governance can evolve, but semantic versions must not be silently redefined.

## Type contract

A semantic type contract should describe:

- type ID/version;
- kind;
- semantic description;
- optional machine-readable logical schema;
- allowed/candidate physical representations;
- content identity rules;
- canonicalization/equality rules where relevant;
- size/introspection properties;
- explicit conversion relationships;
- conformance suite.

`specs/type-contract.schema.json` is the first draft.

## Type kinds

Initial categories:

### `scalar`

Small atomic semantic values.

Examples:

```text
scalar.bool@1
scalar.integer@1
scalar.decimal@1
scalar.datetime@1
```

### `structured`

Machine-readable compound values passed through the control/data plane.

Examples:

```text
data.metrics@1
verification.result@1
```

### `artifact`

Durable or externally meaningful content represented by an Artifact Handle.

Examples:

```text
artifact.table@1
artifact.report@1
artifact.image@1
```

### `stream`

Potentially unbounded/time-oriented data.

Examples may later include:

```text
stream.audio@1
stream.video@1
stream.sensor@1
```

Streams require additional lifetime/backpressure semantics and are not a v0.1 priority.

### `handle`

Opaque capability-safe references whose target cannot be dereferenced without separate authority.

Examples may include:

```text
handle.secret@1
handle.device@1
handle.contact@1
```

The handle type contains identity/reference semantics, not the secret/device contents themselves.

## Semantic type vs media type

Media type answers "how are these bytes encoded?"

Semantic type answers "what does this value mean to the task?"

For example:

```text
text/csv
```

may physically encode an `artifact.table@1`, while:

```text
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
```

may also encode an `artifact.table@1` after an import capability interprets a selected worksheet/range.

The semantic type must not assume every XLSX is a clean table.

## Artifact boundary

An artifact handle carries instance metadata such as:

- artifact identity;
- content hash;
- media type;
- sensitivity;
- lineage;
- storage/locality;
- retention.

The semantic type contract does not carry instance sensitivity or user ownership.

This avoids treating all `artifact.report@1` values as having the same privacy classification.

## Physical representation negotiation

Provider A might consume `data.table@1` using Arrow IPC while Provider B requires canonical JSON.

The broker may:

1. choose compatible providers that already share a representation;
2. use zero-copy/shared-memory transport when policy/sandbox boundaries permit;
3. insert an explicit representation conversion capability;
4. reject the route if conversion would violate cost/privacy/resource constraints.

Representation negotiation should be visible in execution/provenance when it materially affects performance or data movement.

## No implicit semantic casts in v0.1

The v0.1 validator should require exact compatible semantic types.

Examples:

```text
data.metrics@1 -> text.narrative@1
```

is not an implicit cast.

It requires a capability such as:

```text
report.summarize@1
```

Similarly:

```text
artifact.table@1 -> data.table@1
```

requires:

```text
table.import@1
```

This makes the task graph honest about computation and side effects.

## Explicit conversion capabilities

Representation/type transformations should be named capabilities.

Examples:

```text
table.import@1
image.decode@1
image.encode@1
document.extract_text@1
metrics.to_table@1
```

A conversion can itself have authority, resource, and verification requirements.

## Optional values and nullability

Avoid language-specific nullable behavior.

In v0.1:

- a capability port is either required or optional at the contract level;
- if `null` is a semantically valid value, the type contract must say so explicitly;
- missing and null are distinct;
- providers may not substitute language-specific sentinel values such as NaN, None, null pointer, empty string, or -1 unless the semantic contract explicitly defines that mapping.

## Numbers and units

The type system should avoid ambiguous naked floating-point values for consequential domains.

Examples:

- currency should carry currency and use decimal/fixed-point or integer minor/micro units;
- durations should declare canonical units;
- timestamps should declare timezone/offset semantics;
- distances should declare units;
- percentages should distinguish ratio `0..1` from human percentage `0..100`.

The runtime should prefer exact integer/decimal representations for identifiers, money, counts, and permission-relevant limits.

## Table semantics

`data.table@1` should not mean "whatever a dataframe library happens to store."

A future type contract should define at least:

- ordered named columns;
- column semantic/logical types;
- nullable rules;
- row-order significance;
- missing-value representation;
- stable schema identity;
- optional column metadata such as units;
- deterministic serialization/canonicalization rules for conformance fixtures.

The implementation may use Arrow, Polars, pandas, native Rust structures, or another engine behind the contract.

## Metrics semantics

`data.metrics@1` should be machine-verifiable rather than a bag of prose.

A candidate shape:

```text
metric_id
label
value
value_type
unit
source_columns
method
period/baseline
confidence_or_tolerance where relevant
```

Narrative generation consumes these metrics. Numeric verification can then map prose claims back to typed authoritative values.

## Text semantics

The project should distinguish at least:

```text
text.plain@1
text.narrative@1
```

`text.narrative@1` may later carry structured claim annotations/citations rather than being only a string.

This helps verification and provenance.

## Verification types

A verifier should be able to return a typed result such as:

```text
verification.result@1
```

Possible fields:

```text
status: pass | fail | indeterminate
subject_ref
verifier_capability
checks[]
reason_codes[]
```

For transformations such as `verify.numeric_claims@1`, the capability may additionally return an approved/transformed value that later nodes consume.

## Equality and hashing

Different types require different semantic equality.

Examples:

- `data.hash@1` may require byte equality;
- `data.metrics@1` may require exact decimal equality or declared tolerance;
- `artifact.image@1` may allow semantic/image equivalence rather than byte equality depending on the capability contract;
- narratives generally do not have useful exact semantic equality.

Type contracts can define equality/canonicalization hooks used by conformance, caching, and verification.

## Type registry

The runtime should maintain a versioned semantic type registry alongside the capability registry.

A fixed type-registry snapshot should be part of reproducible IR validation.

A type contract should eventually be content-addressable and signed under the project registry/governance model.

## Evolution rules

### Major version

Required for incompatible semantic change.

Examples:

- field meaning changes;
- unit convention changes;
- null behavior changes;
- equality/canonicalization changes that invalidate old consumers.

### Minor version

May add backward-compatible optional information where consumers can safely ignore it.

### Conversion rather than mutation

If two useful semantic models differ materially, prefer an explicit conversion capability over pretending they are the same type.

## Model-provider boundary

Models should receive typed, minimized representations rather than entire arbitrary application states whenever possible.

A model adapter might transform `data.metrics@1` into a bounded structured prompt/context representation.

That representation conversion remains inside a provider adapter unless it has semantic significance; external egress still requires policy.

## Compatibility boundary

Legacy applications can consume/produce physical formats, but an adapter must validate/convert those formats before claiming semantic types.

A legacy application writing an XLSX file does not automatically prove the output is a valid `artifact.table@1` for downstream deterministic computation.

## AI generation advantages

A small explicit type system gives an AI planner strong constraints:

- it cannot feed an image directly into a statistics capability unless a declared conversion exists;
- it cannot treat prose as a capability token;
- it cannot silently turn an artifact handle into a host path;
- validator errors can identify exact incompatible ports;
- repair can be local rather than regenerating arbitrary code.

## v0.1 scope

The first implementation should define only the types needed for Demonstration A plus control-plane verification primitives.

Do not build an enormous universal ontology before workloads demand it.

A practical first set is:

```text
artifact.file@1
artifact.table@1
artifact.image@1
artifact.report@1
data.table@1
data.metrics@1
data.hash@1
text.plain@1
text.narrative@1
verification.result@1
```

## Architectural principle

> **Semantic meaning belongs above implementation representation, and every meaningful conversion should be visible to the system.**
