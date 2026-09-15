# 41 — Domain Capability Architecture

## Purpose

Define how AIOS can grow from a small prototype into a broad software platform without recreating application silos.

The core rule is:

> Domain functionality is added as semantic objects, capabilities, validation rules, engines/providers, and views—not as mandatory monolithic applications.

## Layer model

```text
Task / intent
    ↓
AIOS IR
    ↓
Cross-domain semantic object graph
    ↓
Domain Packs
    ↓
Semantic capability contracts
    ↓
Provider engines
    ↓
Storage / devices / external systems
```

## Domain object model

Each Domain Pack defines durable semantic objects.

Examples:

### Business

```text
Party
Person
Organization
Account
Contact
Lead
Opportunity
Product
Quote
Order
Invoice
Payment
LedgerEntry
Project
TaskItem
```

### Engineering

```text
Part
Assembly
Material
Constraint
Drawing
Model3D
BOM
Schematic
Net
Component
PCB
Simulation
ManufacturingOperation
```

### Knowledge / media

```text
Document
Paragraph
Table
SlideDeck
Slide
Image
VectorScene
VideoTimeline
AudioTimeline
Asset
Annotation
```

The semantic object does not dictate one physical file format or one database schema.

## Object identity and references

Objects require stable IDs that survive provider substitution and UI changes.

Example:

```text
object://org/acme
object://customer/19
object://product/enclosure-v7
object://invoice/2026-00481
object://cad/assembly/88
```

Objects may link to artifacts, tasks, external identifiers, and other objects.

## Capability naming

Capabilities should describe outcomes/actions, not products.

Good:

```text
document.render_pdf@1
crm.create_opportunity@1
billing.issue_invoice@1
cad.solve_constraints@1
eda.run_spice_simulation@1
database.execute_query@1
```

Avoid semantic contracts like:

```text
photoshop.run
salesforce.update
excel.calculate
```

Vendor/application-specific adapters may exist as providers, but vendor names do not define the platform semantics.

## Capability granularity

Capabilities should be neither trivial syscall wrappers nor entire applications.

Too small:

```text
ui.click_button
memory.copy_512_bytes
```

Too large:

```text
run_entire_crm
build_complete_aircraft
```

Preferred granularity captures a meaningful domain operation with testable preconditions and outputs:

```text
crm.merge_contacts
invoice.calculate_totals
cad.extrude_profile
cad.generate_bom
pcb.run_design_rule_check
image.apply_mask
document.track_change
```

## Domain invariants

Each Domain Pack should define deterministic invariants where possible.

Examples:

### Billing/accounting

- currency/rounding policy is explicit;
- debit/credit constraints are validated;
- issued-document mutation rules are explicit;
- tax/calculation source and jurisdiction are recorded.

### CAD

- unit systems are explicit;
- geometry tolerance is explicit;
- constraint state is inspectable;
- exported geometry records source-model identity/version.

### EDA

- electrical rules and design-rule versions are recorded;
- library/footprint identity is preserved;
- simulation model/version is attributable;
- fabrication outputs link back to source design.

AI may help choose or explain operations, but deterministic domain invariants must not be delegated solely to model judgment.

## Views replace application ownership

A human may still need specialized visual workspaces.

Examples:

```text
CRM board view
ledger view
spreadsheet grid
CAD viewport
schematic editor
PCB layout editor
video timeline
code editor
```

These are **Views** over semantic objects and capabilities.

A View does not own the underlying object identity or become the only route through which the data can be changed.

This permits:

- voice/text task interaction;
- direct manipulation for experts;
- automation/agents;
- alternative accessibility views;
- third-party UI providers;
- headless execution.

## Cross-domain transactions

A single task may require operations across multiple packs.

Cross-domain work must retain:

- one Task identity;
- step-specific authority;
- object/artifact lineage;
- transactional boundaries where possible;
- compensation rules where atomic transactions are impossible;
- verification before final commitment for consequential changes.

Example:

```text
CAD revision
  → BOM update
  → cost recalculation
  → quote revision
  → CRM activity
  → customer communication
```

Each step can fail independently without hiding partial state.

## Provider maturity levels

For each capability AIOS may track:

```text
REFERENCE
CONFORMING
EXPERIMENTAL
BRIDGED_LEGACY
REMOTE_ONLY
UNAVAILABLE
```

The user should not have to understand these levels unless they affect reliability, privacy, cost, or control.

## Expansion order

The platform should expand by dependency leverage rather than trying to implement every software category simultaneously.

Suggested order:

### Tier 0 — cross-domain primitives

- artifacts/content addressing;
- documents/text;
- tables;
- structured data;
- search/indexing;
- identity/contacts;
- messages/events;
- workflows;
- database/query abstraction;
- charts/visualization.

### Tier 1 — general productivity/business

- office/knowledge;
- CRM;
- billing/invoicing;
- project/work management;
- inventory/order basics;
- analytics/BI.

### Tier 2 — creative/developer

- raster/vector;
- media pipelines;
- source/code/build/test;
- web/app development.

### Tier 3 — engineering-heavy

- CAD;
- EDA/PCB;
- simulation;
- GIS;
- BIM;
- CAM.

This is not a statement of importance. It is a dependency/implementation-risk strategy.

## Reference implementations vs ecosystem

AIOS should provide enough reference implementations to keep the platform usable and testable, but it should not require the core project to become the best implementation of every specialized algorithm.

The architecture succeeds when a third party can provide a substantially better geometry solver, renderer, database engine, accounting engine, or model runtime while preserving AIOS semantic contracts.

## Compatibility as acquisition path

Before a capability has a native provider, existing software can participate through bridges.

Example:

```text
cad.export_step@1
     ↓
provider option A: AIOS-native geometry engine
provider option B: bridged FreeCAD engine
provider option C: bridged proprietary CAD app in user-owned habitat
provider option D: remote policy-approved service
```

This lets AIOS gain useful coverage progressively rather than waiting for complete independent implementations.

## Success criterion

The Domain Capability Architecture is working when users can perform workflows that traditionally span many applications while the implementation remains modular enough that domain engines, views, storage systems, and model providers can be replaced independently.
