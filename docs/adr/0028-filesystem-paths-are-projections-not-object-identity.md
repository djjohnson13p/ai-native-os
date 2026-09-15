# ADR 0028 — Filesystem Paths Are Projections, Not Object Identity

- Status: **Proposed**
- Date: 2026-09-15

## Context

Files/folders remain indispensable for compatibility, portability, existing tools, removable media, developer workflows, and user control.

But application/data unification requires stable identity that survives rename, move, sync, export, and storage/provider changes.

## Decision

AIOS will keep conventional filesystem/path access as an interoperability/presentation surface while treating semantic Object/Artifact identity as the durable identity layer.

A path may project or materialize an Object/Artifact representation.

Rename/move of a projection MUST NOT by itself create/destroy semantic identity.

Legacy application habitats SHOULD receive narrowly materialized filesystem projections rather than unrestricted host filesystem access.

## Consequences

### Positive

- compatibility with normal files remains strong;
- semantic identity survives reorganization/migration;
- one object can appear in several workspace contexts without duplication;
- legacy apps can participate through constrained exchange paths;
- users retain ordinary export/backup escape hatches.

### Costs

- projection/materialization reconciliation is required;
- external file edits may need import/reparse/conflict handling;
- path conflicts and semantic revision conflicts must be distinguished;
- future workspace search/indexing spans semantic and filesystem metadata.

## Non-goal

This ADR does not require a custom kernel filesystem or virtual filesystem for v0.1.

## Related

- `docs/58-files-namespaces-and-semantic-projection.md`
- `docs/55-storage-sync-and-replica-fabric.md`
- `specs/namespace-projection.schema.json`
