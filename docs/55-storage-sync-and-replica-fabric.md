# 55 — Storage, Sync, and Replica Fabric

## Purpose

AIOS needs a storage model that scales from one offline laptop to a personal compute fabric, self-hosted services, organization infrastructure, public cloud, and large engineering/media datasets without making a filesystem path, cloud bucket, database row, or vendor account the identity of user work.

The governing principle is:

> **Semantic identity describes what something is. Storage describes where one representation or authoritative state currently lives.**

## Identity layers

AIOS intentionally separates:

```text
Object ID       = semantic identity of a thing
Artifact ID     = identity of durable content/representation
Content hash    = identity of exact immutable bytes/content
Replica ID      = one stored copy/location of an object state or artifact
Namespace path  = human/legacy projection used to reach something
Storage backend = implementation/location that persists bytes/state
```

None of these identifiers should be silently substituted for another.

Moving a document from local NVMe to a NAS, peer device, or cloud replica does not change the Document object identity.

Renaming `/Projects/A/quote.pdf` does not create a different Quote object.

## Storage classes

A replica may live in one of several classes:

```text
LOCAL_DURABLE
LOCAL_CACHE
REMOVABLE
TRUSTED_PEER
SELF_HOSTED
ORGANIZATION_MANAGED
PUBLIC_CLOUD
ARCHIVE
EXTERNAL_AUTHORITATIVE
```

The class does not by itself imply trust or authority. Trust comes from identity/policy; authority comes from grants.

## Replica roles

Each replica has an explicit role:

### `AUTHORITATIVE`

The source from which the current semantic state is considered canonical under the active source-of-truth policy.

### `MIRROR`

A durable secondary copy intended to track an authoritative source.

### `CACHE`

Disposable acceleration copy. Eviction must not destroy the only durable state.

### `ARCHIVE`

Long-retention historical copy that may intentionally lag current state.

### `EXPORT`

Portable representation created for interoperability or delivery. An export is not automatically editable semantic source.

### `DERIVED`

Regenerable representation/output whose lineage points to authoritative source inputs.

## Artifact storage

Immutable or versioned artifacts should be content-addressable where practical.

Conceptually:

```text
artifact://task/T91/report
content hash: sha256:...

replicas:
  local://laptop/object-store/...
  peer://home-server/content/...
  cloud://backup-provider/...
```

The Artifact identity may outlive any one replica.

For very large artifacts, chunked content addressing should permit resumable transfer, deduplication, partial verification, and cache locality without requiring one giant blob read/write.

## Semantic object state

Objects are generally mutable through revisions.

A replica of object state therefore records at least:

```text
object ID
semantic type/version
object revision
source-of-truth role
provider/external version when federated
content/state digest where practical
last successful synchronization
```

A stale replica MUST NOT silently overwrite a newer authoritative revision.

## Consistency classes

Not every object requires the same synchronization semantics.

Candidate classes:

### `AUTHORITATIVE_SINGLE_WRITER`

One authority owns mutation ordering. Replicas are read-mostly mirrors/caches.

Useful for many financial, engineering-release, and configuration objects.

### `OPTIMISTIC_VERSIONED`

Writers submit expected revisions/ETags. Conflicts are explicit.

### `APPEND_ONLY`

Events/provenance/logs append with monotonic/causal identity and do not rewrite historical entries.

### `MERGEABLE`

The domain contract defines a deterministic merge operation for concurrent updates.

### `COLLABORATIVE_REALTIME`

A specialized provider may use CRDT/OT or another collaboration protocol. The algorithm is provider/runtime detail; semantic conflict/authority rules remain AIOS-visible.

### `EXTERNAL_SOURCE_MANAGED`

An external system remains authoritative and AIOS mirrors/federates under its version rules.

AIOS should not pretend every data type can be safely multi-writer merged.

## Sync is not source-of-truth transfer

Replicating data to another location does not make that location authoritative.

Example:

```text
object://quote/q-1042
  authoritative: local business object store revision 9
  mirror: home server revision 9
  cloud backup: revision 8
  PDF export: derived from revision 9
```

The existence of three copies does not create three competing Quote identities.

Promoting a mirror to authoritative state is an explicit recovery/failover action with provenance.

## Offline-first operation

Offline operation should preserve:

- access to locally available authoritative/mirrored objects permitted by policy;
- installed semantic registries;
- task/provenance history;
- queued transfers/mutations where semantics permit;
- local deterministic capabilities;
- local credentials that remain valid for offline operations.

When connectivity returns, the system reconciles rather than assuming the offline copy is newer merely because it changed locally.

## Queueing and delayed synchronization

Queued operations carry:

```text
Task ID
operation ID
semantic object/artifact target
expected revision/version
policy/grant state or requirement for reauthorization
intended service identity
payload/content digest
expiry/deadline
```

A queued operation that depended on expired authority or stale state must be revalidated before transmission.

## Backup is not sync

The architecture distinguishes:

```text
sync       keep working replicas reasonably current
backup     create recoverable historical restore points
archive    retain long-term records under policy
cache      improve performance and remain disposable
export     produce interoperable/deliverable representation
```

Deleting a source should not automatically destroy every backup/archive merely because a sync engine observed the deletion.

Retention and legal/organization policy decide deletion propagation.

## Tombstones and deletion

Durable deletion should use explicit tombstone/version semantics when synchronization is involved.

A tombstone records that a deletion was intentional at a particular revision rather than treating absence as proof of deletion.

Sensitive deletion requirements may additionally trigger cryptographic key destruction or secure-erasure mechanisms appropriate to the backend, while provenance may retain non-sensitive evidence that an action occurred.

## Encryption and key separation

Storage encryption should support:

- device-local encryption;
- user/personal-fabric encryption;
- organization-managed encryption;
- service-managed encryption where policy permits;
- object/artifact-level encryption for especially sensitive data.

A storage provider should receive only the keys/handles required by policy.

Cloud possession of encrypted bytes does not automatically imply cloud authority to decrypt them.

## Data residency and locality

Replica creation is a data-movement decision and must obey:

- sensitivity classification;
- residency/jurisdiction constraints;
- organizational policy;
- retention policy;
- cost quotas;
- device/service trust;
- user intent.

Resource placement should account for replica locality before moving large data unnecessarily.

## Large-data behavior

Engineering, media, scientific, model, and database workloads may involve gigabytes or terabytes.

The fabric should support eventually:

- chunked manifests;
- sparse/partial materialization;
- streaming providers;
- range reads;
- deduplicated immutable chunks;
- peer-local caches;
- accelerator-adjacent caches;
- resumable transfer;
- snapshot references rather than full copies;
- lifecycle/temperature tiers.

The semantic architecture must not require every capability to copy entire artifacts into the control-plane database.

## Namespace projection

Conventional files and folders remain essential for compatibility and human workflows.

AIOS therefore provides namespace projections over artifacts/objects.

Example:

```text
~/Projects/Enclosure/Quote-1042.pdf
```

may project:

```text
object://quote/q-1042
representation -> artifact://quote/q-1042/pdf/r9
```

The path is a convenient address, not the semantic identity.

A legacy application habitat can receive a narrowly materialized filesystem projection rather than unrestricted access to the user's entire home directory.

## Garbage collection

Garbage collection must distinguish:

- unreferenced caches;
- derived/regenerable artifacts;
- durable user-managed artifacts;
- legal/retention-held data;
- snapshots needed for rollback;
- provenance references;
- pinned offline data;
- shared/peer replicas.

Reference counting alone is insufficient across disconnected devices and archives; retention policy and reconciliation state matter.

## Failure and recovery

When a storage target fails:

1. record replica/provider failure;
2. preserve object/artifact semantic identity;
3. determine whether another verified replica exists;
4. validate replica revision/hash;
5. rebind reads/writes when policy permits;
6. never promote a stale mirror silently;
7. retain provenance of failover/recovery.

## v0.1 boundary

The first implementation does not need distributed storage.

Stage 1 needs only:

- local durable Artifact store;
- content hashes;
- transactional Task/provenance/object metadata;
- explicit representation/lineage records;
- interfaces that do not assume a permanent host path.

Later peer/cloud storage should plug into those contracts rather than force identity migration.

## Principle

> **The same work can have many replicas and representations, but only explicit semantic/source-of-truth rules decide what is authoritative.**
