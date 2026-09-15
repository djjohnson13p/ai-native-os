# 31 — Semantic Registry Snapshots

## Purpose

AIOS IR can only be validated reproducibly if the meanings of referenced semantic types and capabilities are themselves identifiable.

A task validated against today's `table.import@1` contract must not silently acquire different meaning tomorrow because a registry record was edited in place.

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

## Snapshot

A **Registry Snapshot** is an immutable manifest identifying the exact semantic contract set used by one validation.

It contains:

- snapshot schema version;
- registry generation/version label;
- type contract IDs/versions/content hashes;
- capability contract IDs/versions/content hashes;
- canonical snapshot hash;
- creation metadata;
- optional signing/publisher metadata later.

`specs/registry-snapshot.schema.json` defines the bootstrap contract.

## Why snapshots matter

They make several questions answerable:

- What did `data.table@1` mean when this task ran?
- Which exact `stats.compare_periods` contract was used to type-check the graph?
- Did a provider later claim conformance to the same contract or a changed one?
- Can an old task be replayed under its historical semantics?
- Does a compiled Skill need revalidation after a registry update?

Without snapshots, semantic version strings alone are vulnerable to accidental mutable-history behavior.

## Content hashes

Each semantic contract should be normalized/canonicalized and assigned an algorithm-tagged digest.

Example:

```text
sha256:7a0f...
```

The snapshot itself receives a digest over its canonical semantic content.

A runtime need not trust a contract merely because it has a hash. Hashes establish identity/integrity, not publisher trust or authorization.

## Immutability rule

Once a contract ID/version/hash tuple has been used in a released snapshot, its semantic content must not be rewritten in place.

Corrections that change meaning require a new semantic version/contract hash.

Editorial documentation outside the canonical contract may evolve without changing the semantic hash if it is explicitly non-semantic.

## Validation relationship

A successful IR validation result records:

```text
semantic_program_hash
registry_snapshot_hash
validator_version
IR version
```

This tuple makes the result reproducible enough for debugging, compiled-Skill invalidation, and provenance.

## Provider relationship

A provider implementation declaration should identify the specific semantic contract it claims to implement.

Conceptually:

```text
provider
  implements chart.render@1.0
  contract_hash sha256:...
  conformance suite conformance://chart.render/1
  conformance status tested
```

If the active registry uses a different incompatible contract hash, the provider is not silently assumed conforming.

## Registry update behavior

A registry update can result in:

### Additive contracts

New type/capability contracts can be added without invalidating programs that do not reference them.

### Compatible minor contract evolution

If the version policy explicitly defines compatibility, a later compatible minor version may satisfy a range. The validator must still record exactly which contract it resolved.

### Incompatible change

Requires a new major semantic version and revalidation/replanning where needed.

### Revocation/security issue

A separate trust/revocation layer may mark an otherwise historically valid contract/provider/Skill unsafe for new execution. Historical provenance remains intact.

## Local/offline behavior

The system should retain the registry snapshots needed to understand installed Skills, persisted tasks, and recovery state when offline.

Remote registry availability must not be required to interpret the machine's own recent task history.

## Garbage collection

Registry data referenced by:

- persisted tasks;
- provenance retention policy;
- installed Skills;
- signed/compiled artifacts;
- active rollback/recovery state

should not be deleted merely because a newer snapshot exists.

A later storage policy can compact old registries while preserving enough canonical data to verify historical references.

## Signing

Cryptographic signatures are desirable for distributed registries but deliberately separated from initial semantic identity.

Future registry signing should answer:

- who published this snapshot;
- which keys are trusted for which namespaces;
- how keys are rotated/revoked;
- how local/community/organization registries coexist;
- whether transparency logs are useful.

v0.1 only needs deterministic local snapshot construction and hashing.

## Namespaces

Long term, third-party semantic namespaces may be necessary.

The project should avoid a central architecture that forces all innovation through one global ontology owner.

At the same time, semantic collisions must be prevented.

Possible future forms include:

```text
core.table.import@1
org.example.domain.operation@1
```

The current unprefixed v0.1 capability IDs are bootstrap fixtures, not a final namespace-governance decision.

## Validator requirements

The validator must:

1. resolve all semantic type/capability refs from one identified snapshot;
2. never merge conflicting contracts from multiple registries silently;
3. include snapshot identity in a successful validation result;
4. fail closed on ambiguous or incompatible resolution;
5. avoid network retrieval during trusted validation unless a future explicit pre-validation registry-fetch stage supplies verified local content.

## Compiled Skill invalidation

A compiled Skill records source IR hash plus semantic contract dependencies.

Registry updates should trigger revalidation when:

- a required contract major version changes;
- a referenced contract is revoked/marked unsafe;
- a conformance rule changes materially;
- the Skill's declared compatibility range no longer resolves.

An unrelated registry addition should not invalidate every Skill.

## v0.1 fixture

`examples/aios-ir/registry-snapshot.json` should identify the contract fixtures used for Demonstration A.

For early repository fixtures, placeholder content hashes may be replaced by generated values once the reference canonicalizer exists. The important architectural rule is that implementation must eventually compute rather than hand-author these hashes.

## Architectural principle

> **Meaning must be versioned as carefully as code.**
