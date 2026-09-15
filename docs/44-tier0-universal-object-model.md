# 44 — Tier-0 Universal Semantic Object Model

## Purpose

The Universal Software Fabric needs a small set of durable cross-domain objects that can participate in many workflows before specialized Domain Packs exist.

These are not database tables and they are not application records. They are semantic identities that can be projected into many stores, views, providers, and legacy systems.

The design goal is to prevent every Domain Pack from reinventing `customer`, `document`, `project`, `invoice`, or `message` with incompatible identities.

## Design rules

Tier-0 objects MUST:

- have stable `object://` identity independent of provider/database implementation;
- have explicit semantic type and version;
- separate durable semantic identity from physical representations;
- support native, federated, mirrored, derived, and ephemeral source states;
- preserve provenance and source-of-truth metadata;
- expose relationships through typed predicates;
- avoid vendor/application names in semantic identifiers;
- be narrow enough to compose across many domains;
- permit domain-specific extension without silently changing core meaning.

Tier-0 objects SHOULD NOT attempt to encode every industry-specific field.

## Proposed first object set

### `core.party@1`

A legal/social/business actor identity that may represent a person, organization, household, team, government entity, or another party class.

Core fields should remain minimal:

```text
party_kind
names
identifiers[]
contact_points[]
status
```

Domain Packs may extend this with CRM segmentation, HR employment facts, supplier qualification, healthcare-specific identifiers, etc., subject to policy and privacy.

### `core.document@1`

A logical document identity independent of one representation.

A Document may have representations such as:

```text
DOCX
ODF
Markdown
PDF
HTML
plain text
native structured representation
```

The object identity survives conversion/export.

### `core.dataset@1`

A logical structured dataset/table identity.

It may reference representations such as CSV, Parquet, Arrow, XLSX, database query results, or an external table/view.

### `core.message@1`

A communication unit with sender/recipient relationships, content, channel metadata, threading, and delivery state.

The semantic object is not tied to email, chat, SMS, or a specific vendor.

### `core.conversation@1`

A threaded/related communication context containing Messages and linked Parties/objects.

### `core.calendar_event@1`

A scheduled time-bound event with participants, time-zone-aware interval, recurrence/exception data, location/resource references, and status.

### `core.project@1`

A durable coordination container with objective, status, membership, related objects, and milestones.

### `core.task_item@1`

A human/business work item. This is distinct from the AIOS **Task** control-plane execution object.

To avoid ambiguity:

```text
AIOS Task          = operating-system execution/audit unit
core.task_item@1   = domain work-management object
```

### `commerce.product@1`

A thing/service offered, purchased, designed, manufactured, or tracked commercially.

This becomes a bridge object between CRM, billing, inventory, CAD/BOM, commerce, and manufacturing.

### `commerce.line_item@1`

A quantity/pricing/tax/discount-bearing reference to a product/service or another billable concept.

### `commerce.quote@1`

A proposed commercial offer composed of LineItems and commercial terms.

### `commerce.invoice@1`

A request/record for payment with immutable issuance semantics defined by the Billing Domain Pack.

### `commerce.payment@1`

A payment event/record linked to one or more obligations such as invoices.

## Why these are Tier-0/Tier-0-adjacent

The set intentionally spans generic and commercial primitives because the first serious cross-domain demonstration should prove that one object identity can move through:

```text
communication
→ knowledge/document extraction
→ CRM/business relationship
→ product/engineering context
→ quote/billing
→ reporting/communication
```

This gives much more architectural evidence than another isolated office-document demo.

## Stable object identity

Object identity is allocated by the semantic object layer, not by a provider.

Example:

```text
object://party/acme-industries
object://product/enclosure-v7
object://quote/q-2026-1042
```

External mappings are attributes of the object record:

```text
CRM external id: 99881
billing external id: C-31002
email/contact id: abc@example.test
ERP vendor/customer id: A00941
```

Changing CRM providers MUST NOT change the AIOS object identity.

## Object state vs representation

An object may have multiple representations.

Example:

```text
object://document/proposal-91
  ├── artifact://.../proposal.docx
  ├── artifact://.../proposal.pdf
  ├── artifact://.../proposal.md
  └── federated source: external document service
```

Representations may be authoritative, lossless, lossy, view-only, or unknown-equivalence.

A PDF rendering does not automatically become the editable semantic source merely because it is convenient to display.

## Extension model

A specialized Domain Pack extends shared objects through explicit semantic relationships or versioned extension contracts rather than modifying core meaning privately.

Example:

```text
core.party@1
  ├── crm.account-profile@1
  ├── procurement.supplier-profile@1
  └── hr.worker-profile@1
```

The same Party can participate in multiple roles without creating multiple identities for the same real actor.

## Typed relationships

Relationship predicates are semantic contracts too.

Examples:

```text
party.member_of -> party
party.contact_for -> party
project.has_member -> party
project.has_work_item -> task_item
quote.for_party -> party
quote.contains -> line_item
line_item.references -> product
invoice.derived_from -> quote
invoice.for_party -> party
payment.settles -> invoice
product.has_design -> engineering object
message.about -> any semantic object
```

A relationship contract defines allowed source/target types, cardinality, direction/inverse, and mutation rules.

## Mutation and optimistic concurrency

Every durable object has a monotonically increasing revision.

Mutations SHOULD include an expected revision/precondition.

Example:

```text
update object://quote/q-2026-1042
expected_revision = 7
```

If the authoritative record is now revision 8, the mutation fails or enters deterministic conflict resolution. AI may propose a merge, but it may not silently overwrite a newer authoritative version.

## Federated objects

A federated object may be AIOS-native in identity while another system remains source of truth for some or all fields.

Example:

```text
object://party/acme-industries
source_state = federated
source_of_truth.external_system = external-crm
```

Reads can be normalized into AIOS semantics.

Writes require a capability/provider that understands source-system versioning and policy.

## Provenance

Every material object mutation should be attributable to:

- AIOS Task;
- principal;
- capability;
- provider/adapter;
- source revision;
- resulting revision;
- authority grant/policy decision;
- relevant artifacts;
- external-system mutation identifiers where applicable.

## Privacy

Universal identity does not mean universal visibility.

Object attributes and relationships may require finer-grained sensitivity/policy than the object record as a whole.

Future versions may therefore support field/relationship-level protection labels. v0.1 architecture must not assume that possession of an object ID grants access to all attributes.

## Open questions

Before these contracts stabilize:

- Which object types belong in true Core vs separate foundational packs?
- How are extension contracts named/versioned?
- Which predicates are global and which belong to a Domain Pack?
- How much schema validation belongs in object contracts vs providers?
- How are field-level authority and disclosure represented without making ordinary operations unusably complex?
- How are object merges/splits represented when duplicate identities are discovered?

## Principle

> **One real thing should have one durable AIOS identity whenever practical, even if many applications, databases, files, and providers represent it.**
