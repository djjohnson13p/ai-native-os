# 47 — Cross-Domain Reference Workflow

## Purpose

Demonstrate what the Universal Software Fabric is trying to replace: a real outcome that today would normally require separate CAD/PLM, spreadsheet/costing, CRM, billing, document, and communication applications.

This is an architecture fixture, not a v0.1 implementation requirement.

## Scenario

A synthetic customer, Acme Industries, has approved revision 7 of an enclosure.

The user asks:

> Acme approved enclosure revision 7. Make sure the approved design is the one we're quoting, regenerate the BOM and manufacturing cost, revise their quote, update the opportunity, create the invoice draft, and send a concise confirmation with the new drawing and price.

In an application-centric environment this may require manually coordinating:

```text
CAD/PLM
spreadsheet/costing
CRM
quoting
billing/accounting
document/PDF tools
email/chat
file storage
```

In AIOS it should be one Task over shared semantic objects and capabilities.

## Starting semantic objects

```text
object://party/acme-industries
  type: core.party@1

object://product/enclosure
  type: commerce.product@1

object://engineering/enclosure-r7
  type: engineering.design@1

object://crm/opportunity/acme-enclosure
  type: crm.opportunity@1

object://quote/acme-enclosure-q12
  type: commerce.quote@1
```

Key relationship:

```text
object://product/enclosure
  product.has_design
    -> object://engineering/enclosure-r7
```

External mappings might include CRM/ERP/CAD-provider IDs, but they do not replace these AIOS identities.

## Semantic capability graph

A candidate normalized task graph could be:

```text
engineering.design.read_revision@1
        ↓
engineering.bom.generate@1
        ↓
manufacturing.cost.estimate@1
        ↓
commerce.quote.recalculate@1
        ↓
commerce.quote.verify@1
        ↓
crm.opportunity.update@1
        ↓
billing.invoice.create_draft@1
        ↓
engineering.drawing.render@1
        ↓
document.customer_summary.compose@1
        ↓
communication.message.send@1
```

The important property is that no node says `open <application>`.

A legacy application may still implement one node through a bridge.

## Provider possibilities

### BOM generation

Potential providers:

```text
AIOS-native engineering provider
open-source CAD/PLM engine adapter
legacy CAD habitat adapter
policy-approved remote engineering service
```

### Costing

Potential providers:

```text
AIOS-native costing provider
ERP adapter
spreadsheet compatibility provider
custom organization provider
```

### CRM update

Potential providers:

```text
AIOS-native CRM object store
federation adapter to an existing CRM
legacy UI automation only as a last-resort compatibility provider
```

The semantic graph remains the same when providers change.

## Detailed execution stages

### Stage 1 — resolve approved design

Inputs:

- Product object;
- design relationship;
- customer approval evidence/message/document;
- expected design revision.

Checks:

- design revision is exactly R7;
- Product relationship points to R7 or task proposes an explicit controlled update;
- approval evidence is linked in provenance;
- no stale R6 artifact is used merely because it is cached locally.

### Stage 2 — generate deterministic engineering/commercial facts

Generate:

- BOM;
- material/quantity list;
- manufacturing operations if known;
- deterministic cost inputs;
- estimated manufacturing cost under an explicit costing policy/version.

All units/currencies/rounding/tolerance rules are explicit.

### Stage 3 — revise Quote

The task reads the current Quote at an expected revision.

It proposes a new revision referencing:

- Product;
- design revision/hash;
- BOM identity;
- cost model/version;
- line items;
- currency;
- pricing policy;
- expiration/terms.

The quote is deterministically verified before commit.

If another actor changed the Quote since planning, optimistic concurrency fails and the task replans instead of overwriting.

### Stage 4 — update Opportunity

The CRM capability updates the Opportunity through whichever provider is authoritative.

If it is federated:

- external expected version is checked;
- AIOS object identity remains stable;
- external response/version is persisted;
- mutation is recorded in provenance.

### Stage 5 — create Invoice draft

The invoice is created as a draft linked to:

```text
Party
Product
Quote
Project/Opportunity where applicable
```

The draft does not become `issued` merely because it exists.

Issue/payment semantics remain separate higher-consequence capabilities.

### Stage 6 — produce drawing and customer summary

Rendering may use any conforming provider.

The summary references verified values from the Quote/Invoice/BOM rather than asking a model to invent or independently recalculate them.

AI may generate explanatory prose, but numeric claims pass verification.

### Stage 7 — irreversible communication gate

Before sending:

- recipient Party/contact point is policy-authorized;
- quote/invoice/design revisions are rechecked;
- required approval is current;
- attachment hashes are final;
- message preview/final body is persisted;
- operation has a stable idempotency key where the channel supports one.

Only then does `communication.message.send@1` execute.

## Failure examples

### Design mismatch

Approval references R7, Product relationship still points to R6.

Result:

- do not generate final quote silently from R6;
- task enters repair/clarification/update path;
- no customer communication occurs.

### CRM conflict

Opportunity external revision changed after planning.

Result:

- conditional mutation fails;
- task re-reads/reconciles;
- no blind overwrite.

### Invoice draft succeeds, message denied

Result:

- task may retain or compensate invoice draft according to plan/domain policy;
- message remains unsent;
- partial state is visible;
- task does not claim full success.

### Communication timeout with unknown result

Result:

- mark send operation outcome `OUTCOME_UNKNOWN`;
- query provider/status if possible;
- do not blindly resend and risk duplicate communication.

## User-facing experience

The default UI should not show seven application windows.

It could show:

```text
Acme enclosure revision task

✓ Approved design verified: R7
✓ BOM regenerated
✓ Manufacturing cost recalculated
✓ Quote revised: $...
✓ Opportunity updated
✓ Invoice draft created
✓ Drawing + summary prepared
○ Send confirmation — approval required
```

Expanding any step reveals:

- semantic capability;
- provider;
- objects/artifacts read/written;
- policy/authority;
- external transfer;
- verification;
- provenance;
- rollback/compensation state.

## Why this reference flow matters

This scenario tests the central claim of the project better than simply making a chatbot launch applications.

If it works, then:

- application boundaries are no longer workflow boundaries;
- shared object identity reduces data duplication/integration glue;
- domain-specific deterministic engines coexist with AI reasoning;
- providers can change without changing user intent;
- high-consequence effects remain inspectable and controlled.

## Long-term extension

The same graph can later expand into:

```text
inventory availability
supplier RFQs
purchase orders
CAM/manufacturing instructions
quality plans
shipping
accounting journal entries
support/customer history
product documentation
marketing renderings
```

without redefining the operating model.

## Principle

> **The proof of the Universal Software Fabric is not how many applications it imitates; it is how naturally one verified Task can cross domains that used to require many applications.**
