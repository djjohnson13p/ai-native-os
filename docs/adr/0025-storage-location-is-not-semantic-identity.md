# ADR 0025 — Storage Location Is Not Semantic Identity

- Status: **Proposed**
- Date: 2026-09-15

## Context

AIOS objects/artifacts may exist simultaneously on local storage, trusted peers, organization systems, cloud services, archives, caches, exports, and legacy filesystems.

If a path, bucket key, database row, provider ID, or replica location becomes the identity of the work, moving/syncing/failing over would rewrite semantic history and couple the Universal Object Graph to storage implementation.

## Decision

AIOS will distinguish:

- semantic Object identity;
- Artifact identity;
- immutable content identity/hash;
- replica identity/location;
- namespace projection/path.

Storage/replica/namespace changes MUST NOT alter semantic Object identity and SHOULD NOT alter Artifact identity unless new content/version semantics require a new Artifact.

Source-of-truth promotion/failover is explicit, policy-controlled, and recorded in provenance.

## Consequences

### Positive

- objects survive device/cloud/provider migrations;
- peer/cloud caches remain disposable;
- backups/archives do not become accidental authorities;
- paths can remain familiar compatibility surfaces;
- Resource Broker can move computation toward data without changing program meaning.

### Costs

- runtime needs explicit replica/projection records;
- synchronization must reason about revisions/source of truth;
- legacy path-based tools require materialization/projection adapters;
- garbage collection needs policy/lineage awareness.

## Security

Replica creation/movement remains a data-egress/retention decision and requires current policy.

Possession of a replica does not imply permission to decrypt/read/mutate it.

## Related

- `docs/55-storage-sync-and-replica-fabric.md`
- `docs/58-files-namespaces-and-semantic-projection.md`
- `specs/storage-replica.schema.json`
- `specs/namespace-projection.schema.json`
