# 42 — Universal Object Graph and Data Federation

## Purpose

A universal software fabric cannot depend on every domain storing its state in one giant database.

Different workloads need different physical representations:

- relational tables;
- graph stores;
- object/document stores;
- content-addressed files;
- CAD/geometry databases;
- time-series stores;
- vector indexes;
- source repositories;
- immutable ledgers;
- external systems of record.

AIOS therefore needs a semantic identity/relationship layer above physical storage.

Working name: **Universal Object Graph (UOG)**.

## Core idea

```text
Semantic Object Identity
        ↓
Relationships / versions / lineage / policy
        ↓
One or more physical representations
```

The graph does not replace specialized stores. It gives AIOS a consistent way to reason across them.

## Object record

A conceptual object record includes:

```text
object_id
semantic_type
semantic_version
revision/version
labels
owner/principal
sensitivity
relationships
artifact representations
external identities
source-of-truth designation
provenance
retention
created/modified timestamps
```

## Example

```text
object://product/enclosure-v7
  type: engineering.part@1
  relationships:
    belongs_to -> object://product/controller-x
    customer   -> object://org/acme
    bom        -> object://bom/controller-x-v7
    quote      -> object://quote/q-812
  representations:
    artifact://cad/native/991
    artifact://cad/step/1442
    artifact://drawing/pdf/501
```

The system can understand that those artifacts represent one semantic engineering object without pretending the file formats are equivalent.

## Sources of truth

Some objects will be authoritative in external or specialized systems.

AIOS must distinguish:

```text
NATIVE      — AIOS-managed source of truth
FEDERATED   — external system remains authoritative
MIRRORED    — local synchronized representation with explicit rules
DERIVED     — computed from other objects
EPHEMERAL   — task-local/transient
```

The AI must not silently turn a cache into an authoritative record.

## Federation adapters

Adapters may expose external systems such as:

- SQL databases;
- SaaS CRMs;
- accounting platforms;
- ERP systems;
- source repositories;
- cloud storage;
- PLM/PDM systems;
- engineering databases;
- local application data.

Adapters translate external identities and operations into semantic objects/capabilities while preserving source-system constraints.

## Mutation rules

Every mutation must identify:

- semantic object;
- requested operation;
- target source of truth;
- authority;
- expected revision/precondition;
- transactional/compensation behavior;
- provenance.

Optimistic concurrency/version checks should prevent an AI task from overwriting unseen newer state.

## Cross-domain relationships

The graph exists primarily to make relationships first-class.

Examples:

```text
Customer -> Contract
Customer -> Opportunity
Opportunity -> Quote
Quote -> ProductRevision
ProductRevision -> CADAssembly
ProductRevision -> BOM
BOM -> SupplierPart
Order -> Invoice
Invoice -> Payment
Project -> Repository
Project -> Meeting
Project -> Drawing
```

That permits task planning across domains without hard-coded point-to-point application integrations.

## Query model

The system should support semantic queries such as:

```text
find unpaid invoices for organizations with open support escalations
find product revisions referenced by active quotes
find CAD parts changed since the last approved manufacturing BOM
find meetings/messages related to Project X that mention a delayed supplier
```

The query planner may federate across multiple stores/providers while enforcing policy and minimizing data movement.

## Privacy and least disclosure

Object relationships can themselves be sensitive.

A provider should receive only the object fields/relations necessary for its capability.

The Object Graph is not a universal permission bypass.

Object reads are mediated through normal AIOS authority/effect rules.

## Portable export

Users must remain able to export ordinary files and structured domain data.

The UOG should improve interoperability without trapping data in an AIOS-only ontology.

## Evolution

The semantic graph must support schema evolution and multiple concurrent semantic versions.

A migration from `crm.contact@1` to `crm.contact@2` must be explicit rather than silently changing historical task meaning.

## Long-term benefit

Traditional enterprise/software integration often creates an N-by-N matrix of connectors.

The AIOS target is:

```text
external/native system
       ↓ adapter/provider
semantic object + capability layer
       ↓
AIOS task/IR composition
```

This does not remove domain complexity, but it prevents every new software capability from requiring custom integration with every other one.
