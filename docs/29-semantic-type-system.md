# 29 — AIOS Semantic Type System

## Purpose

AIOS IR and semantic capability contracts depend on types that mean the same thing regardless of whether a provider is written in Rust, Python, C++, WASM, a legacy application adapter, or a remote service.

The type system therefore distinguishes **semantic type** from **physical representation**.

```text
Semantic type family: data.table@1

Possible representations:
- Arrow IPC
- in-process Arrow memory
- canonical JSON rows
- provider-private representation behind an adapter
```

A capability plans against the semantic type family. The runtime negotiates an eligible physical representation.

## Core rule

> Type compatibility is explicit. Representation conversion is a capability, not an implicit guess.

This is especially important when AI generates the program: silent coercions make execution harder to reason about, verify, and secure.

## Type identity and v0.1 references

A semantic type contract has two related identities:

```text
semantic ID: data.table
full contract version: 1.0 (or later compatible 1.x)
```

AIOS IR v0.1 references the major semantic family exactly as:

```text
data.table@1
```

The immutable Registry Snapshot selects the exact full contract version/content for `(data.table, major 1)`.

For v0.1 IR:

- `data.table@1` is valid;
- unversioned `data.table` is invalid;
- `data.table@1.0` is invalid as an IR reference even though `1.0` is a valid full type-contract version;
- a major change is referenced as a new family, e.g. `data.table@2`.

ADR 0030 and `docs/67-v0.1-semantic-reference-and-version-resolution.md` are controlling.

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

## Why full contract version is separate from IR reference

IR needs a durable compatibility family while validation/provenance needs the exact contract content.

Therefore the validation evidence combines:

```text
semantic program hash
registry snapshot ID
IR/hash profile
```

The snapshot pins the exact type contract version/hash that gave `data.table@1` meaning for one validation.

A later compatible snapshot may select `data.table` contract 1.1 while the IR still says `data.table@1`; revalidation records the new snapshot rather than rewriting source IR.

## Type contract

A semantic type contract describes:

- semantic type ID;
- full contract version;
- kind;
- semantic description;
- optional machine-readable logical schema;
- allowed/candidate physical representations;
- content identity rules;
- canonicalization/equality rules where relevant;
- size/introspection properties;
- explicit conversion relationships;
- conformance suite.

`specs/type-contract.schema.json` is the bootstrap machine contract.

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

An Artifact Handle carries instance metadata such as:

- artifact identity;
- content hash;
- media type;
- sensitivity;
- lineage;
- storage/replica/locality state;
- retention.

The semantic type contract does not carry instance sensitivity or user ownership.

This avoids treating all `artifact.report@1` values as having the same privacy classification.

## Physical representation negotiation

Provider A might consume `data.table@1` using Arrow IPC while Provider B requires canonical JSON.

The broker may:

1. choose compatible providers that already share a representation;
2. use zero-copy/shared-memory transport when policy/sandbox boundaries permit;
3. insert an explicit representation conversion capability;
4. reject the route if conversion violates cost/privacy/resource constraints.

Representation negotiation should be visible in execution/provenance when it materially affects performance or data movement.

Physical representation choice does not change the semantic type family merely because one provider uses a different library/encoding.

## No implicit semantic casts in v0.1

The v0.1 validator requires exact compatible semantic major families.

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

Compatibility inside one major family is pinned/defined by the exact type contract selected in the Registry Snapshot; the validator does not silently coerce between different semantic families or majors.

## Explicit conversion capabilities

Representation/type transformations should be named semantic capabilities.

Examples:

```text
table.import@1
image.decode@1
image.encode@1
document.extract_text@1
metrics.to_table@1
```

A conversion can itself have authority, resource, effect, and verification requirements.

Type-contract `conversion_capabilities` references use the same major-family syntax in v0.1.

## Optional values and nullability

Avoid language-specific nullable behavior.

In v0.1:

- a capability port is required/optional at the capability-contract level;
- if `null` is a semantically valid value, the type contract says so explicitly;
- missing and null are distinct;
- providers may not substitute language-specific sentinels such as NaN, None, null pointer, empty string, or -1 unless the semantic contract explicitly defines that mapping.

## Numbers and units

The type system should avoid ambiguous naked floating-point values for consequential domains.

Examples:

- currency carries currency and uses decimal/fixed-point or integer minor/micro units;
- durations declare canonical units;
- timestamps declare timezone/offset semantics;
- distances declare units;
- percentages distinguish ratio `0..1` from human percentage `0..100`.

The runtime should prefer exact integer/decimal representations for identifiers, money, counts, and permission-relevant limits.

## Table semantics

`data.table@1` should not mean "whatever a dataframe library happens to store."

A stable type contract should define at least:

- ordered named columns;
- column semantic/logical types;
- nullable rules;
- row-order significance;
- missing-value representation;
- stable schema identity;
- optional column metadata such as units;
- deterministic serialization/canonicalization rules for conformance fixtures where required.

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
- `artifact.image@1` may allow semantic/image equivalence rather than byte equality depending on capability contract;
- narratives generally do not have useful exact semantic equality.

Type contracts can define equality/canonicalization hooks used by conformance, caching, and verification.

A type's equality/canonicalization rule is part of its full semantic contract content. An incompatible change requires a new major version.

## Type registry

The runtime maintains a versioned semantic type registry alongside the capability registry.

A fixed type/capability Registry Snapshot is part of reproducible IR validation.

For v0.1 the snapshot contains at most one active full type contract per `(type ID, major)` pair.

A type contract should eventually be content-addressable and signed under registry/governance rules, but v0.1 only needs deterministic local content identity/snapshot construction.

## Evolution rules

### Major version

Required for incompatible semantic change.

Examples:

- field meaning changes;
- unit convention changes;
- null behavior changes;
- equality/canonicalization changes that invalidate old consumers.

IR then references the new family, e.g. `data.metrics@2`.

### Minor version

May add backward-compatible optional information where consumers can safely ignore it according to the published compatibility contract.

The immutable Registry Snapshot selects the exact active minor/patch within one major for a validation.

### Patch version

Compatible correction/clarification that does not intentionally redefine semantic meaning.

The contract bytes/hash still change and are attributable in the new snapshot.

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
- it cannot silently turn an Artifact Handle into a host path;
- it cannot use an unversioned semantic type and hope the runtime selects latest;
- validator errors can identify exact incompatible ports;
- repair can be local rather than regenerating arbitrary code.

## v0.1 scope

The first implementation defines only the types needed for Demonstration A plus control-plane verification fixtures.

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

> **Semantic meaning belongs above implementation representation; AIOS IR names the semantic major family, and the immutable Registry Snapshot pins the exact contract that interpreted it.**
