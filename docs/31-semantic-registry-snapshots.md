# 31 — Semantic Registry Snapshots

## Purpose

AIOS IR can only be validated reproducibly if the meanings of referenced semantic types and capabilities are themselves identifiable.

A program validated against today's `table.import@1` contract must not silently acquire different meaning tomorrow because a registry record was edited in place or because a validator dynamically selected another "latest compatible" contract.

The project therefore treats the semantic registry as **versioned, content-addressed input to validation**.

## Registry layers

The semantic registry contains two primary record classes for v0.1:

```text
Type Contracts
  define what values mean

Capability Contracts
  define what operations mean
```

Provider manifests are not part of semantic meaning. They live in the implementation/provider registry and declare implementations of semantic contracts.

## AIOS IR reference model

Under ADR 0030, AIOS IR v0.1 semantic references use exactly:

```text
<semantic-id>@<major>
```

Examples:

```text
data.table@1
table.import@1
experimental.example@0
```

Contract records themselves carry full versions such as:

```text
1.0
1.1
1.1.2
```

The Registry Snapshot pins which exact full contract version/content gives one major family meaning for one validation.

See `docs/67-v0.1-semantic-reference-and-version-resolution.md`.

## Snapshot

A **Registry Snapshot** is an immutable manifest identifying the exact semantic contract set used by one validation.

It contains:

- snapshot schema version;
- registry generation/version label;
- type contract IDs/full versions/content hashes;
- capability contract IDs/full versions/content hashes;
- canonical snapshot hash;
- creation metadata;
- optional signing/publisher metadata later.

`specs/registry-snapshot.schema.json` defines the bootstrap structural contract.

## v0.1 uniqueness invariant

For v0.1, one Registry Snapshot MUST contain **at most one active contract for each `(semantic ID, major version)` pair** within each contract class.

Examples:

Valid:

```text
table.import 1.1
chart.render 1.0
```

Invalid/ambiguous if both appear in the same active snapshot:

```text
table.import 1.0
table.import 1.1
```

because both would satisfy `table.import@1`.

Snapshot construction/governance chooses the active full version before validation. The trusted IR validator performs a deterministic lookup; it does not dynamically select the highest compatible version.

This uniqueness rule is semantic registry validation and may require code beyond what JSON Schema can express cleanly.

## Snapshot index

A validator can build immutable indexes conceptually as:

```text
TypeIndex[(type_id, major)] -> exact contract record/hash
CapabilityIndex[(capability_id, major)] -> exact contract record/hash
```

Registry loading must fail if:

- the same `(ID, major)` maps to multiple active records;
- a snapshot entry's declared version disagrees with the referenced contract full version;
- a contract content hash does not match the loaded bytes once real hashes are generated;
- type and capability records are malformed;
- required referenced content is absent.

No partially valid registry becomes executable input.

Strict bundle ingestion checks raw record structure against the embedded Snapshot,
Type Contract and Capability Contract schemas before typed decoding. Optional
`Option<T>` representation is not evidence that explicit null is schema-valid.
The R17-01 repair corpus includes omission, null, empty nested objects and valid
values. Numeric tolerance authoring is additionally constrained by docs72 before
lossy binary64 interpretation. Semantic cross-record checks remain mandatory.

## Why snapshots matter

They make several questions answerable:

- What exact `data.table` contract gave `data.table@1` meaning when this task ran?
- Which exact `stats.compare_periods` contract was used to type-check the graph?
- Did a provider later claim conformance to the same contract or a changed one?
- Can an old task be replayed under its historical semantics?
- Does a compiled Skill need revalidation after a registry update?

Without snapshots, semantic major references alone would be vulnerable to mutable-history behavior.

## Content hashes

Each semantic contract should be normalized/canonicalized and assigned an algorithm-tagged digest.

Example:

```text
sha256:7a0f...
```

The snapshot itself receives a digest over its canonical semantic content.

A runtime need not trust a contract merely because it has a hash. Hashes establish identity/integrity, not publisher trust or authorization.

## Immutability rule

Once a contract ID/version/hash tuple has been used in a released snapshot, its canonical semantic content must not be rewritten in place.

Corrections that alter canonical contract content create a new content hash and, where semantic compatibility requires it, a new contract version.

An incompatible semantic change requires a new major contract version/family.

Editorial documentation excluded from canonical contract identity may evolve without changing semantic meaning if it is clearly non-semantic.

## Validation relationship

A successful IR validation result records at least:

```text
logical program_id
semantic_program_hash
semantic_hash_profile
registry_snapshot_id
validator version/build identity
IR version
```

The exact meaning of one validation is attributable through the semantic program plus the exact registry snapshot used to resolve semantic families.

The Registry Snapshot ID is **not** folded into the semantic program hash under ADR 0029. They remain separate identities.

## Same program, later compatible snapshot

A later snapshot may select a compatible newer minor/patch contract for an existing major family.

Example:

```text
Snapshot A:
  data.table major 1 -> contract 1.0

Snapshot B:
  data.table major 1 -> contract 1.1
```

The AIOS IR can remain:

```text
data.table@1
```

and retain the same semantic program hash because its requested semantic-family graph is unchanged.

But the new validation result records Snapshot B.

Reusing old validation/compiled output against the later snapshot is an explicit compatibility/revalidation decision; semantic-hash equality alone is not sufficient proof.

## Incompatible contract change

An incompatible semantic change requires a new major family:

```text
data.table@2
```

Changing IR from `@1` to `@2` is a semantic program change and changes the semantic hash.

## Provider relationship

A provider implementation declaration should identify the semantic family and exact contract evidence it claims to implement/test against.

Conceptually:

```text
provider
  semantic_ref table.import@1
  contract_version 1.1
  contract_hash sha256:...
  conformance suite conformance://table.import/1
  conformance status tested
```

The active Registry Snapshot decides what `table.import@1` means for the current validation.

If the provider's tested contract differs, provider resolution/conformance logic must establish compatibility rather than silently assuming it.

A provider cannot supply a private definition of a semantic major family merely because its manifest names it.

## Registry update behavior

A registry update can result in:

### Additive contract family

A new type/capability major family can be added without invalidating programs that do not reference it.

### Compatible minor/patch contract evolution

A new snapshot may select a newer compatible full contract within the same major family.

The program's major reference may remain unchanged, but validation evidence binds to the new snapshot.

### Incompatible change

Requires a new major semantic version/family and program revalidation/replanning/migration where needed.

### Revocation/security issue

A separate trust/revocation layer may mark an otherwise historically valid contract/provider/Skill unsafe for new execution. Historical provenance remains intact.

## No network or package resolution during trusted validation

If a required `(ID, major)` is missing from the loaded Registry Snapshot, the validator fails closed.

It MUST NOT:

- fetch a contract from the internet;
- ask a package catalog for "latest";
- query a model for a substitute;
- merge another registry automatically;
- reinterpret an unversioned name.

A separate pre-validation registry acquisition/update process may produce a new verified local snapshot, after which validation starts again against that explicit snapshot.

## Local/offline behavior

The system should retain the Registry Snapshots needed to understand installed Skills, persisted tasks, validation evidence, and recovery state when offline.

Remote registry availability must not be required to interpret the machine's own recent Task history.

## Garbage collection

Registry data referenced by:

- persisted Tasks/validation results;
- provenance retention policy;
- installed Skills;
- compiled artifacts;
- active rollback/recovery state;
- conformance evidence

should not be deleted merely because a newer snapshot exists.

A later storage policy can compact old registries while preserving enough canonical data to verify historical references.

## Signing

Cryptographic signatures are desirable for distributed registries but deliberately separated from semantic identity.

Future registry signing should answer:

- who published this snapshot;
- which keys are trusted for which namespaces;
- how keys are rotated/revoked;
- how local/community/organization registries coexist;
- whether transparency logs are useful.

A signature proves publisher/integrity evidence, not automatic semantic correctness or runtime authority.

v0.1 only needs deterministic local snapshot construction, validation, and hashing.

## Namespaces

Long term, third-party semantic namespaces are necessary.

The project should avoid a central architecture that forces all innovation through one global ontology owner while preventing semantic collisions.

Possible forms include:

```text
core.table.import@1
org.example.domain.operation@1
```

The current short bootstrap IDs are fixtures, not the final governance decision.

## Validator requirements

The v0.1 registry/IR validator must:

1. load all semantic type/capability records from one explicitly supplied local snapshot/bundle;
2. validate structural contract records;
3. reject duplicate/ambiguous `(ID, major)` entries;
4. reject snapshot-entry/full-contract version-major mismatch;
5. verify generated content hashes against the supplied contracts;
6. build immutable lookup indexes;
7. resolve every IR semantic type/capability major reference from that snapshot;
8. never merge conflicting registries silently;
9. include snapshot identity in successful validation output;
10. fail closed on absent/ambiguous/incompatible references;
11. perform no network/catalog/provider/model retrieval during trusted validation.

Registry failures should use stable `REGISTRY_*` reason-code families distinct from malformed-program errors.

## Recommended bootstrap registry reason codes

At minimum, consider:

```text
REGISTRY_SCHEMA_INVALID
REGISTRY_DUPLICATE_TYPE_MAJOR
REGISTRY_DUPLICATE_CAPABILITY_MAJOR
REGISTRY_ENTRY_NOT_FOUND
REGISTRY_CONTRACT_VERSION_MISMATCH
REGISTRY_CONTRACT_HASH_MISMATCH
REGISTRY_SNAPSHOT_HASH_MISMATCH
REGISTRY_UNSUPPORTED_VERSION
```

Exact final catalog should be test-locked before external tooling depends on it.

## Compiled Skill invalidation

A compiled Skill/target records source semantic program hash plus exact source registry validation evidence.

Registry updates should trigger revalidation when:

- a required major family changes;
- a referenced contract/provider is revoked/marked unsafe;
- conformance rules materially change;
- a compiled target's recorded source snapshot is not accepted under current compatibility policy.

An unrelated additive registry change should not invalidate every Skill automatically.

## v0.1 fixtures

`examples/aios-ir/registry-snapshot.json` identifies the contract fixtures used for Demonstration A. Its checked-in contract hashes and snapshot ID are generated semantic identities that the strict loader recomputes and verifies exactly.

The explicit `BootstrapGenerate` path is non-production development/test tooling for constructing generated identities from deliberately marked placeholder inputs. A registry built through that path remains non-strict and cannot produce executable semantic-program identity through the validator.

Version-resolution fixtures should test:

- successful `@major` resolution;
- unversioned/`@major.minor` IR structural rejection;
- missing `(ID, major)`;
- duplicate `(ID, major)` registry entries;
- snapshot/contract major mismatch;
- same IR validated against two compatible snapshots with unchanged semantic hash but different snapshot ID.

## Architectural principle

> **IR names the semantic compatibility family; the immutable registry snapshot pins exactly what that family meant for a validation. Meaning must be versioned as carefully as code.**
