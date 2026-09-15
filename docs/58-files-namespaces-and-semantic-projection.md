# 58 — Files, Namespaces, and Semantic Projection

## Purpose

AIOS should reduce application/data silos without breaking the enormous ecosystem built around files, folders, paths, removable media, network shares, and file-oriented applications.

The project therefore keeps files as a first-class interoperability mechanism while refusing to make a pathname the semantic identity of user work.

## Core rule

> **Paths are projections. Artifacts/Objects carry identity.**

A path may change because the user reorganized a workspace, mounted a different volume, synced to another device, or exported a different representation.

The underlying semantic identity can remain stable.

## Three layers

```text
Semantic object
    ↓ represented by
Artifact/version
    ↓ projected/materialized as
File / directory / stream / URI / legacy path
```

Example:

```text
object://document/proposal-91
    ↓
artifact://document/proposal-91/editable/r12
    ↓
~/Projects/Proposal/Proposal.docx
```

Exporting PDF creates another representation rather than redefining the Document:

```text
artifact://document/proposal-91/pdf/r12
```

## Conventional filesystem compatibility

The Linux filesystem remains the practical substrate for many providers and legacy applications.

AIOS should initially use mature filesystem semantics rather than invent a new kernel filesystem.

The semantic layer sits above it and can progressively provide richer projections.

## Workspace namespaces

A Workspace may expose a namespace containing:

- user files;
- semantic object projections;
- task outputs;
- mounted/removable storage;
- federated/cloud-backed materializations;
- shared organization resources;
- legacy application exchange folders.

The namespace can look familiar to humans while retaining underlying identity/lineage metadata.

## Projection record

A projection should be able to record:

```text
projection ID
workspace/session
path or URI
object/artifact target
representation role
access mode
materialization state
source replica
revision/content hash
sync/export policy
```

Two paths can project the same immutable artifact.

One path can later project a newer artifact revision while the Object ID remains unchanged.

## Rename and move

Renaming/moving a projection normally changes only presentation/location metadata.

It must not automatically:

- create a new semantic object;
- destroy lineage;
- invalidate external mappings;
- reset provenance;
- change authority.

## Import

A conventional file entering AIOS is initially an Artifact with detected representation/media semantics.

Example:

```text
/home/user/imports/customer-list.xlsx
    ↓ import
artifact://import/...
media type: spreadsheet/xlsx
```

A later task may infer/create a Dataset semantic object from it, but file possession alone does not prove semantic identity or source-of-truth status.

## Export

Export converts/project semantic state into an interoperable representation.

Example:

```text
object://quote/q-1042
  -> export PDF
  -> artifact://quote/q-1042/pdf/r9
  -> /Exports/Quote-1042.pdf
```

The export may be lossless, lossy, view-only, or archival; that equivalence is recorded.

## Legacy application views

A legacy application habitat should receive a deliberately materialized filesystem view.

Example:

```text
/habitat/input/report.csv        read-only
/habitat/output/                 writable task-local output
```

rather than the user's full home directory.

The broker imports outputs back into Artifact/Object semantics after execution.

## Virtual/materialized files

Some projections may be virtual until accessed.

Possible states:

```text
METADATA_ONLY
PLACEHOLDER
PARTIAL
MATERIALIZED
DIRTY_LOCAL
SYNC_PENDING
CONFLICTED
OFFLINE_UNAVAILABLE
```

Large cloud/peer artifacts can therefore appear in a workspace without being downloaded eagerly.

## Streams

Not every useful resource should become a regular file.

AIOS should also support typed streams/handles for:

- camera/audio capture;
- database query results;
- live logs;
- remote object ranges;
- large media processing;
- sensor feeds;
- model/token streams.

A legacy path may be materialized only when a provider requires it.

## File watching and mutation

When a projected editable file changes outside AIOS-native capability paths, the projection layer must reconcile the mutation.

Possible strategies by representation/domain:

- import as a new Artifact version;
- parse into a new semantic object revision;
- mark the semantic representation as externally modified;
- require user/provider reconciliation if the representation is lossy or ambiguous.

It must not silently assume every byte-level file edit is a valid semantic mutation.

## Conflicts

Path conflicts and semantic conflicts are distinct.

Examples:

```text
PATH CONFLICT:
  two files want /Reports/summary.pdf

SEMANTIC CONFLICT:
  two edits target object://quote/q-1042 revision 7
```

Resolving a filename collision does not resolve an object revision conflict.

## Aliases and links

AIOS may expose aliases/links so one semantic object appears in multiple contexts.

Example:

```text
/Customers/Acme/Quote.pdf
/Projects/Enclosure/Commercial/Quote.pdf
```

Both can reference the same Artifact/Object without duplicating semantic identity.

## External filesystems and shares

NFS/SMB/cloud-drive/removable-media adapters should be treated as storage/namespace providers.

Mounting a share establishes reachability, not trust/authority.

Imported/projected resources retain source/provider metadata and obey current policy.

## Search

Search should eventually span both traditional paths and semantic relationships.

The user can search by:

- filename/path;
- text/content;
- semantic object type;
- related Party/Project/Product;
- Task/provenance;
- date/revision;
- representation/media type.

This is more powerful than forcing the user to remember which application/folder owns something.

## Portable escape hatch

Users must retain the ability to export ordinary directory trees/files independent of AIOS.

The Universal Object Graph should add interoperability, not become a prison.

Important user work should remain exportable to documented formats and conventional storage.

## v0.1 boundary

Stage 1 should implement only:

- Artifact handles rather than unrestricted host paths in control-plane contracts;
- one local content/output store;
- explicit import/export;
- narrowly materialized provider directories;
- representation hashes/lineage.

Rich virtual filesystems and semantic workspace mounts can come later.

## Principle

> **Keep the universal file ecosystem as an interoperability surface while moving durable meaning above paths and application-owned folders.**
