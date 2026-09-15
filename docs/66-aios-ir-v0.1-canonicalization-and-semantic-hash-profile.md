# 66 — AIOS IR v0.1 Canonicalization and Semantic Hash Profile

## Purpose

Issue #17 requires a deterministic semantic hash, but a generic JSON canonicalizer alone cannot decide which AIOS IR fields are semantic.

This document closes that ambiguity for v0.1.

The semantic hash identifies the normalized executable meaning of an AIOS IR program under one IR version. It is intentionally distinct from:

- Task identity;
- logical/user-facing `program_id`;
- registry snapshot identity;
- provider/build identity;
- Execution Binding identity;
- package/Skill identity;
- authoring/debug metadata.

## Two identities

AIOS IR v0.1 uses two different concepts:

### Logical program identifier

`program_id` is a human/tool-friendly logical identifier such as:

```text
demo.analyze_numbers.v1
```

It assists diagnostics, source organization, provenance, and packaging.

Changing only `program_id` does **not** change executable semantic meaning.

### Semantic program hash

The semantic hash is derived from the normalized semantic view.

Two programs that differ only in non-semantic labels/descriptions/metadata should produce the same semantic hash.

Two programs that differ in executable meaning, requested authority/effects, verification, failure behavior, types, or constraints should produce different semantic hashes.

## Task identity is not AIOS IR

`task_id` is a runtime/control-plane identity and MUST NOT appear in AIOS IR v0.1.

The Task record/execution binding links a Task to a validated semantic program hash.

This avoids making the same reusable semantic graph hash differently merely because a different Task invokes it.

## Semantic hash pipeline

```text
untrusted authoring JSON
    ↓ strict parse / duplicate-key rejection / limits
structurally valid AIOS IR
    ↓ semantic validation against immutable registry snapshot
validated typed program
    ↓ construct semantic-hash view
normalized semantic value
    ↓ RFC 8785 JCS canonical JSON bytes
canonical bytes
    ↓ domain-separated SHA-256
semantic program hash
```

An invalid program does not receive an executable semantic hash.

## Registry identity is separate

The validation result records:

```text
semantic_program_hash
registry_snapshot_id
validator_version
IR version
```

The same semantic program hash can be validated against a later compatible registry snapshot without pretending the registry bytes are part of the program itself.

Whether prior validation evidence can be reused against another snapshot is a compatibility/policy decision.

## Included semantic fields

The v0.1 semantic-hash view includes:

### Top level

- `ir_version`;
- `kind`;
- `inputs` excluding descriptions;
- normalized `nodes`;
- `outputs`.

### Program input

Include:

- semantic `type`;
- normalized `required` value;
- `media_types` as a semantic set.

Exclude:

- `description`.

### Node

Include:

- `id`;
- `operation.kind`;
- `operation.capability`;
- `execution_class`;
- input references;
- output semantic types;
- authority requests excluding human reason text;
- egress semantics;
- resource/locality constraints;
- failure policy;
- cache policy.

Exclude:

- `description`;
- `metadata`.

### Authority request

Include:

- `action`;
- `resource`.

Exclude:

- `reason`.

The reason is explanatory prose and cannot change permission semantics.

## Excluded fields

The semantic hash excludes:

```text
program_id
all metadata objects
all description strings
authority request reason strings
Task identity
validation timestamp
validator build ID
registry snapshot ID
provider ID/version
package/build ID
hardware/device/accelerator identity
Execution Binding/grant/policy-decision IDs
process/container/VM IDs
network endpoint/address
credential/secret handle or value
filesystem/namespace materialization path
provenance event IDs
```

Most runtime fields are already structurally forbidden from AIOS IR. The exclusion list also protects the canonicalization implementation from later accidentally using surrounding runtime records as hash input.

## Included field rationale

### `kind`

`task_graph` vs `skill_graph` is included because it is an IR-level semantic class with different lifecycle/reuse expectations even when the executable nodes happen to match.

### Node IDs

Node IDs are included in v0.1. They participate in graph references, diagnostics, provenance, and transformation identity.

Renaming every node while preserving graph topology therefore changes v0.1 semantic hash.

Graph-isomorphism normalization is deliberately not attempted.

### Resource/locality constraints

Constraints are included because they can change whether/where execution is permitted and are part of the requested semantic execution envelope.

### Cache policy

Cache policy is included because reuse/freshness behavior can affect observable execution/provenance/privacy expectations.

### Authority requests and egress

These are always included because an authority/egress change is security-semantic change even if the pure mathematical output would be identical.

### Verification

Verification is represented through operation kind/capability/data flow and is therefore included. Removing/bypassing a verifier changes the hash.

## Default normalization

Only specification-defined defaults may be inserted.

For v0.1:

```text
program input `required` absent -> true
accelerator constraint `optional` absent -> false
```

No default may be inferred from natural-language descriptions/metadata.

Empty optional containers should be normalized consistently according to the typed semantic model. The reference implementation should prefer one canonical representation rather than retaining authoring differences such as absent vs empty `constraints` when they have identical specified semantics.

The exact typed normalization behavior becomes test-locked in the reference validator.

## Ordering rules

JSON object property ordering is removed by RFC 8785 canonical serialization.

In addition, the semantic-hash view normalizes IR collections according to their semantic ordering.

### Unordered semantic sets

Sort deterministically:

- program input `media_types`;
- node `authority_requests` by normalized `(action, resource)`;
- egress `destination_classes`;
- locality constraints;
- any future field explicitly declared as a semantic set.

Exact duplicate semantic authority requests SHOULD be rejected or de-duplicated by one published v0.1 rule before hashing. The reference validator should prefer rejection so planner bugs remain visible rather than silently rewritten.

### Ordered semantic lists

Preserve order:

- `fallback_capabilities`, because fallback preference is ordered;
- any future sequence whose ordering changes behavior.

### Nodes

Node array authoring order is **not** semantic execution order because graph edges come from references.

For the hash view, nodes are sorted lexicographically by node ID after uniqueness/reference validation.

Runtime topological scheduling remains separate.

## String handling

IR semantic identifiers are already restricted to ASCII-compatible grammar where specified.

v0.1 canonicalization MUST NOT silently Unicode-normalize arbitrary semantic resource strings because an opaque resource identifier may treat code-point sequences as distinct.

Rules:

- require valid UTF-8 at parse boundary;
- preserve accepted semantic string code points exactly;
- use RFC 8785 string escaping/order rules;
- descriptions/metadata/reasons are excluded anyway;
- future resource-reference contracts should prefer structured/ASCII-safe identifiers where security-sensitive equivalence matters.

## Number handling

AIOS IR v0.1 semantic numeric fields are integers with schema bounds.

The reference implementation should deserialize them into bounded integer types appropriate to each field and reject out-of-range values before canonical hashing.

This avoids floating-point canonicalization ambiguity in the v0.1 semantic program.

## Canonical serialization

After constructing the normalized semantic-hash view, serialize using RFC 8785 JSON Canonicalization Scheme (JCS) semantics.

Important:

- JCS canonicalizes the already-selected semantic value;
- JCS does not decide which fields are semantic;
- authoring JSON is never hashed directly;
- do not rely on ordinary serializer map iteration order as the canonicalization specification.

If implementation evidence shows that a chosen JCS crate cannot meet strict requirements, replace the crate—not the semantic profile—unless an explicit ADR changes the profile.

## Domain separation

Do not hash raw canonical JSON as an untyped identifier without context.

Conceptually hash bytes under a domain/version tag such as:

```text
AIOS-IR-SEMANTIC\0v0.1\0<JCS bytes>
```

The exact byte-level prefix must be implemented once centrally and locked by test vectors.

User-visible identifier form SHOULD remain algorithm-tagged, for example:

```text
sha256:<lowercase hex>
```

or a later versioned identifier format if the implementation ADR chooses one.

The domain/version tag prevents accidental hash equivalence with unrelated content-hash namespaces.

## Hash-algorithm agility

SHA-256 is the v0.1 bootstrap algorithm.

Architecture rules:

- algorithm is explicit in stored identifier/result metadata;
- implementations do not infer algorithm from digest length;
- future algorithms can coexist;
- changing hash algorithm does not redefine semantic meaning, but creates a different content identifier encoding/evidence record.

## Required equivalence tests

These changes MUST NOT alter semantic hash:

1. JSON whitespace;
2. JSON object-key order;
3. top-level metadata content/order;
4. node metadata content/order;
5. top-level/node/input descriptions;
6. authority `reason` text;
7. `program_id` only;
8. authoring node array order when graph/references are unchanged;
9. semantic-set authoring order (`locality`, `destination_classes`, `media_types`, authority requests);
10. omission vs explicit specification-defined safe default.

## Required difference tests

These MUST alter semantic hash:

1. `ir_version`;
2. `kind`;
3. input semantic type/required/media-type constraints;
4. node ID;
5. capability/version;
6. operation kind (`invoke` vs `verify`);
7. execution class;
8. any data-flow reference;
9. declared output type;
10. authority action/resource;
11. egress mode/destination class;
12. locality/resource constraint;
13. fallback order/content;
14. retry/replan budget;
15. cache policy;
16. final program output mapping.

## Runtime-isolation tests

The semantic hash MUST remain unchanged when the same validated program is rebound to:

- a different conforming provider;
- another provider package/build version that implements the same contract;
- CPU vs GPU vs trusted peer;
- different sandbox/process/container ID;
- different Task ID;
- another valid capability token/grant;
- another namespace materialization path;
- another eligible network endpoint;
- another permitted cloud region/provider.

Those changes belong to Execution Binding/placement/provenance/package records.

## Program-ID collision rule

Because `program_id` is excluded from the semantic hash, two logical program IDs may point to the same semantic hash.

That is valid.

Conversely, the same `program_id` may have multiple semantic revisions/hashes over time.

Therefore no database/API may use `program_id` as a substitute for semantic hash when exact executable meaning matters.

## Signing

If semantic IR is signed later, sign a structured statement that binds at least:

```text
semantic hash algorithm + value
IR version
registry/contract compatibility context as required by the signing purpose
publisher/signer identity
signature profile version
```

Do not sign pretty-printed authoring JSON and call it semantic identity.

## Failure behavior

Canonical hash generation occurs only after full semantic validation.

If canonicalization fails:

```text
valid = false
semantic_hash = null
reason family = IR_CANONICALIZATION_*
```

A raw-document hash may be recorded separately for debugging/quarantine, but it MUST NOT be confused with validated semantic program identity.

## Implementation ownership

Canonical semantic-view construction and hash domain separation should live in one trusted library boundary used by CLI/daemon/tests.

Do not reimplement hash rules independently in planner, provider, UI, package manager, or cloud services.

## Migration

A future AIOS IR major semantic version may define a different canonicalization profile.

Old semantic hashes remain interpretable with their recorded IR/hash profile versions.

Migration from old IR to new IR creates a newly validated semantic program/hash rather than rewriting historical identity.

## Decision summary

For v0.1:

```text
Task ID          OUTSIDE AIOS IR
program_id       logical label; excluded from semantic hash
metadata         excluded
description      excluded
authority reason excluded
kind             included
nodes            sorted by ID for hash view
semantic sets    sorted deterministically
ordered fallback preserved
safe defaults    materialized
canonical bytes  RFC 8785 JCS of normalized semantic view
hash             domain-separated SHA-256
```

## Principle

> **Hash executable meaning, not formatting, labels, runtime placement, or explanatory prose.**
