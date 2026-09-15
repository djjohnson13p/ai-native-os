# 40 — Universal Software Fabric

## Vision

The long-term goal is not merely to run existing applications on an AI-native operating system. It is to progressively absorb the useful capabilities that applications provide into one coherent, open, task-first software fabric.

The user should not need to choose between separate word processors, spreadsheet packages, CRMs, billing systems, CAD packages, PCB tools, database clients, project managers, image editors, or dozens of other application silos for ordinary work.

Instead, the system should expose a growing set of semantic capabilities and domain objects that AIOS can compose directly.

The target is therefore broader than an operating system plus compatibility layer:

> **If a useful software capability exists, AIOS should eventually be able to provide, compose, interoperate with, or transparently route to that capability through one semantic system.**

This document calls that long-term layer the **Universal Software Fabric (USF)**. The name is provisional.

## What this does not mean

The project should not become one gigantic monolithic executable containing every feature ever implemented by every software vendor.

That would recreate the same coupling, security, release, and maintenance problems the architecture is trying to remove.

Instead:

```text
one semantic operating model
        ↓
many domain object models
        ↓
many composable capabilities
        ↓
many interchangeable providers/engines
        ↓
one task-first user experience
```

The unification happens at the semantic object/capability/task layers, not by forcing all code into one process or repository module.

## Applications become domain capability collections

A conventional application bundles:

- data model;
- business rules;
- computation;
- UI;
- storage assumptions;
- automation;
- permissions;
- import/export;
- plugin model;
- often its own scripting environment.

AIOS should separate those concerns.

For example, what is currently called a CRM can be decomposed into objects such as:

```text
Person
Organization
Account
Contact
Lead
Opportunity
Activity
Conversation
Quote
Order
Invoice
Payment
```

with capabilities such as:

```text
crm.create_contact
crm.merge_duplicate_contacts
crm.score_lead
crm.update_opportunity
crm.summarize_account
sales.generate_quote
billing.issue_invoice
billing.reconcile_payment
```

There may still be a CRM-style workspace/view for humans, but the capability set is available to every AIOS task without requiring the user to open a CRM application first.

## Domain packs

The Fabric should grow through **Domain Packs**.

A Domain Pack is not an app. It is a versioned collection of:

- semantic object/type contracts;
- semantic capability contracts;
- invariants and validation rules;
- reference providers;
- provider conformance tests;
- import/export adapters;
- optional UI/workspace projections;
- Skills/templates;
- policy profiles;
- domain-specific provenance/verification rules.

Example packs:

### Office / knowledge

- rich documents;
- spreadsheets/tables;
- presentations;
- PDF/document processing;
- notes/knowledge bases;
- forms;
- publishing/layout.

### Data / databases

- relational data;
- document/key-value/graph data;
- schema design;
- query;
- ETL/ELT;
- BI/visualization;
- statistics;
- data quality;
- lineage.

### Business operations

- CRM;
- ERP;
- billing/invoicing;
- accounting/bookkeeping;
- purchasing;
- inventory;
- order management;
- subscriptions;
- project/work management;
- help desk/customer support;
- HR/payroll where jurisdictionally appropriate.

### Creative media

- raster graphics;
- vector graphics;
- page layout;
- photography;
- audio editing/mixing;
- video editing/compositing;
- animation;
- 3D modeling/sculpting/rendering.

### Engineering / design

- 2D CAD;
- 3D parametric CAD;
- CAM;
- mechanical assemblies;
- simulation/CAE;
- PCB/EDA;
- schematic capture;
- circuit simulation;
- FPGA/HDL workflows;
- GIS;
- architecture/BIM;
- scientific/technical computing.

### Software development

- source editing;
- repository/version control;
- builds;
- dependency management;
- testing;
- debugging;
- profiling;
- CI/CD;
- API design/testing;
- container/image workflows;
- database development.

### Communication / coordination

- email;
- chat;
- calendars;
- meetings;
- contacts;
- notifications;
- shared workspaces;
- task/project coordination.

These are examples, not a closed list.

## The principle: best capability, not best application

The project should study mature software categories and identify the strongest underlying ideas:

- interaction models;
- algorithms;
- workflows;
- data structures;
- interoperability standards;
- automation patterns;
- collaboration models;
- undo/versioning models;
- domain validation;
- high-value specialized features.

Those ideas should inform independently implemented AIOS semantic capabilities where legally and technically appropriate.

The goal is not to copy a vendor's proprietary source code, assets, trademarks, patented implementation where restricted, or protected UI expression.

The goal is to build interoperable, independently implemented capabilities that learn from decades of software design while remaining open and composable.

## Universal object graph

Domain Packs should connect through shared semantic identities rather than copy data into isolated application databases.

Example:

```text
Organization: ACME Corp
 ├── people/contacts
 ├── CRM opportunities
 ├── projects
 ├── contracts/documents
 ├── invoices/payments
 ├── messages/meetings
 ├── CAD assets/products
 ├── source repositories
 └── analytics
```

These do not need to be stored in one physical database.

AIOS should expose a federated object graph that provides stable identity, relationships, lineage, policy, and provenance while allowing domain-optimal physical storage underneath.

## One task can cross what used to be many applications

Example intent:

> "The customer approved the revised enclosure. Update the design, calculate the new manufacturing cost, revise the quote, create the invoice schedule, update the opportunity, and send the customer a change summary for approval."

A conventional environment could require CAD, spreadsheet/ERP, CRM, billing, word processing, and email tools.

In the Fabric, one Task may compose:

```text
cad.modify_parametric_model
cad.verify_constraints
bom.generate
cost.estimate
sales.quote.revise
billing.schedule.create
crm.opportunity.update
document.change_summary.compose
mail.draft
```

Every capability still has its own authority, verification, provenance, and provider binding.

The user experiences one coherent task.

## Domain engines vs domain experiences

Some domains require extremely sophisticated specialized engines.

Examples include:

- geometric kernels;
- EDA/PCB routing;
- SPICE simulation;
- video codecs;
- GPU rendering;
- database engines;
- finite-element solvers;
- accounting/tax calculation engines.

AIOS should not pretend that an LLM replaces those engines.

The architecture should instead make the engine a provider behind semantic contracts.

A mature open-source engine may be reused, improved, wrapped, replaced, or eventually reimplemented when evidence justifies it.

The AI-native layer supplies orchestration, intent, composition, authority, adaptation, verification, and cross-domain integration.

## Constant expansion without architectural decay

"If it is software, build it in" can only scale if additions do not increase coupling exponentially.

Every new capability/domain must therefore enter through stable contracts:

```text
Domain semantic types
      ↓
Semantic capability contracts
      ↓
Conformance suites
      ↓
Provider implementations
      ↓
Task/IR composition
```

A new CAD capability should not need custom knowledge of the CRM runtime.

A billing capability should not need a special direct integration with every database provider.

Cross-domain composition occurs through semantic types, object relationships, artifact handles, events, and AIOS IR.

## Native, adapted, and legacy capability sources

The Fabric may satisfy a capability through several maturity levels:

1. **AIOS-native reference implementation** — maintained directly by the project/community.
2. **AIOS-native third-party provider** — conforms to an open semantic contract.
3. **Adapted open-source engine** — mature external project exposed through AIOS contracts.
4. **Legacy application capability bridge** — existing application driven/exposed through the Universal App Broker.
5. **Remote service provider** — policy-approved service implementing a compatible contract.
6. **Unavailable capability** — system explains what is missing rather than fabricating support.

This lets the system expand long before AIOS has independently implemented every category.

## Quality competition still exists underneath

Unifying the user experience should not eliminate technical competition.

Multiple providers can compete to implement:

```text
cad.solve_constraints@1
image.remove_background@1
database.query@1
billing.calculate_tax@1
render.pathtrace@1
```

AIOS may select among them based on:

- correctness/conformance;
- user policy;
- hardware;
- privacy;
- cost;
- latency;
- energy;
- feature level;
- trust;
- determinism;
- reproducibility.

This keeps innovation modular instead of forcing the entire platform to wait for one monolithic implementation.

## Long-term objective

The end state is not "an operating system with lots of bundled apps."

It is closer to:

> **A universal, continuously expanding computational environment in which most software functionality exists as composable semantic capabilities, AI translates intent into those capabilities, specialized deterministic engines perform the work, and traditional applications survive as compatibility/UI providers rather than the primary unit of computing.**

That is the software-side counterpart to AIOS IR on the programming-language side:

```text
Programming-language silos → AIOS semantic IR
Application silos          → Universal Software Fabric
Hardware silos             → Resource/Execution Fabric
```

Together they define the larger AI-native platform vision.
