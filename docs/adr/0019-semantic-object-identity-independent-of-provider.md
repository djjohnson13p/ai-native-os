# ADR 0019 — Semantic Object Identity Is Independent of Provider

- Status: **Proposed**
- Date: 2026-09-15

## Context

The Universal Software Fabric is intended to replace application silos with shared semantic objects and capabilities.

If AIOS object identity is inherited from whichever CRM, database, CAD package, billing service, or document provider currently stores the record, provider substitution would break cross-domain relationships and recreate application ownership at a higher layer.

The same real entity may already have many external identifiers.

## Decision

AIOS will assign/maintain a stable semantic `object://` identity independent of any provider-specific identifier.

Provider/external IDs are mappings on the object record or federation layer, not the canonical AIOS identity.

A source system may remain authoritative for object state or selected attributes while AIOS retains stable semantic identity.

Changing providers MUST NOT require changing the AIOS object ID solely because the external system's identifier changed.

Views, providers, databases, and legacy applications MUST NOT implicitly become owners of semantic identity.

## Consequences

### Positive

- cross-domain relationships survive provider changes;
- one Party/Product/Project can be referenced by CRM, billing, engineering, documents, and communication workflows;
- migration/federation becomes explicit;
- task/provenance history remains stable across provider substitution;
- external systems can coexist without forcing one vendor's record ID into platform semantics.

### Costs

- identity resolution/deduplication becomes a real subsystem;
- federation mappings must be maintained;
- merges/splits require explicit provenance and redirect/tombstone semantics;
- field-level source-of-truth/conflict handling becomes necessary.

## Security

Knowing an `object://` identifier does not grant authority to read or mutate the object.

Authorization remains deterministic and can be field/relationship/provider sensitive.

## Alternatives rejected

### Use external provider ID as canonical identity

Rejected because provider migration changes platform identity and creates vendor coupling.

### Put all objects in one central AIOS database

Rejected as a universal requirement. Some domains need specialized stores and some external systems must remain authoritative.

### Let AI infer object equivalence on every task

Rejected for canonical identity. AI may propose matches/merges, but durable identity changes require deterministic rules/approval/provenance.

## Related

- `docs/40-universal-software-fabric.md`
- `docs/42-universal-object-graph-and-data-federation.md`
- `docs/44-tier0-universal-object-model.md`
- `specs/object-record.schema.json`
- `specs/semantic-object-contract.schema.json`
