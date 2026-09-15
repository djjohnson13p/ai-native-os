# ADR 0037 — Published Artifacts Are Immutable Content Instances

- Status: **Accepted for the v0.1 / Phase-I substrate**
- Date: 2026-09-15

## Context

AIOS needs durable, reproducible Task inputs/outputs while later supporting filesystem Views, cloud/peer replicas, exports, mutable logical documents/products, and provider sandboxing.

If Artifact identity is the current host path or mutable file contents, Task replay/provenance/integrity and future storage placement become unreliable.

## Decision

For v0.1:

1. A published Artifact identifies one immutable content/version instance plus core lineage.
2. Artifact ID is distinct from byte content hash; identical bytes may back multiple Artifact records with different lineage/retention context.
3. Physical bytes may be content-deduplicated in an internal immutable Blob Store.
4. Host paths, cloud object keys, mount points, and replicas are Storage/Namespace projections, not Artifact identity.
5. User/provider output is first written to a Task-scoped Output Allocation/staging area; providers cannot write directly to the final blob index/store.
6. Publication computes/verifies content hash and size before creating a durable published Artifact record.
7. Publication is idempotent through a stable publication/allocation identity.
8. Crash windows between filesystem blob placement and metadata commit are recovered explicitly; orphan bytes never become published output merely because they exist.
9. Editing/transformation creates a new Artifact; a durable mutable logical document/product identity belongs to the Semantic Object layer.
10. Exporting an Artifact to a user path is a separate authorized capability and does not rename/move the Artifact identity.

Detailed semantics are in `docs/75-v0.1-artifact-store-content-identity-and-publication.md`.

## Consequences

### Positive

- stable Task inputs/outputs independent of path/replica changes;
- deterministic integrity and lineage;
- safe deduplication without conflating semantic instances;
- provider sandboxing can use exact handles/projections;
- later peer/cloud storage can be added without rewriting Artifact identity;
- user-facing files remain exportable/portable.

### Costs

- local copy-in/import is initially more expensive than referencing arbitrary mutable paths;
- publication needs staging + recovery/GC;
- logical mutable documents require an Object/version relationship above Artifacts;
- blob-store and metadata durability cannot be one filesystem/database ACID transaction and need explicit recovery rules.

## Security impact

Providers receive only explicitly bound read handles and output allocations, not ambient filesystem/blob-store access.

Credentials/secrets remain separate handle/store types and are not ordinary Artifact content by default.

## Related

- I8, I31, I32
- R-DATA-001..005
- R-STOR-001..007
- `docs/20-user-object-model.md`
- `docs/55-storage-sync-replica-fabric.md`
- `docs/58-files-namespaces-semantic-projection.md`
- `docs/75-v0.1-artifact-store-content-identity-and-publication.md`
- GitHub Issue #4
