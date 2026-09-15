# 45 — Cross-Domain Transactions and Compensation

## Purpose

The Universal Software Fabric makes it possible for one AIOS Task to perform work that today spans many applications and systems.

That creates a hard problem: most cross-domain workflows cannot be one database transaction.

A task may update:

- an AIOS-native object store;
- a federated CRM;
- a billing system;
- a CAD model;
- a document artifact;
- an email provider;
- an external payment or manufacturing system.

Some operations are reversible, some compensatable, and some irreversible once observed externally.

The architecture therefore needs explicit transaction semantics rather than pretending distributed atomicity exists everywhere.

## Transaction classes

Every side-effecting semantic capability SHOULD declare one transaction class.

### `ATOMIC_LOCAL`

The operation is fully transactional within one trusted local store.

Examples:

- create/update AIOS-native object records in one SQLite/PostgreSQL transaction;
- commit a group of task-local artifacts atomically.

### `CONDITIONAL_REMOTE`

A remote/federated operation supports optimistic version/precondition semantics but not a shared AIOS transaction.

Examples:

- update CRM opportunity only if external revision/ETag matches;
- update a remote document only if version token matches.

### `IDEMPOTENT_EXTERNAL`

An external side effect can be retried safely using a stable idempotency key.

Examples may include APIs that explicitly support idempotent create/payment-request operations.

### `COMPENSATABLE`

The effect cannot be atomically rolled back, but a declared compensation capability exists.

Examples:

- reserve inventory → release reservation;
- create draft invoice → void draft;
- create calendar event → cancel event.

Compensation is a new effect with its own authority/provenance. It is not erasure of history.

### `IRREVERSIBLE_EXTERNAL`

The effect cannot reliably be undone after external observation.

Examples:

- send an email/message;
- publish a public artifact;
- submit an order after a non-cancellable cutoff;
- perform certain financial/regulatory submissions.

These operations require stricter completion ordering and approval policy.

## Execution ordering rule

A cross-domain plan SHOULD order effects from most reversible to least reversible when semantics allow.

Conceptually:

```text
pure calculation
→ local drafts
→ reversible local writes
→ conditional remote updates
→ compensatable external effects
→ irreversible external effects
```

This is not a universal sorting rule: domain dependencies may require another sequence. But the planner/runtime should minimize the chance that an irreversible action occurs before a later deterministic validation failure.

## Commit barriers

AIOS IR should support or derive **commit barriers**.

A commit barrier marks a point after which one or more subsequent effects require all prior mandatory verification/authorization to be satisfied.

Example:

```text
calculate BOM
calculate quote
render approval document
verify totals
──────── COMMIT BARRIER ────────
revise external CRM opportunity
issue invoice
send customer message
```

The barrier does not make the external systems atomic. It prevents avoidable irreversible work before the task has established the facts needed to proceed.

## Cross-domain operation record

Every side-effect attempt should have a stable operation identity:

```text
operation://task/T91/node/revise-quote/attempt/1
```

The persisted record should include:

```text
operation id
AIOS task id
semantic program hash/node id
semantic capability
provider/adapter
object/artifact targets
expected source revisions
idempotency key if supported
transaction class
compensation capability if any
policy/grant references
start/completion timestamps
provider/external operation id
outcome certainty
```

## Outcome certainty

After timeout/crash/network loss, the runtime MUST distinguish:

```text
NOT_STARTED
STARTED_NO_EFFECT
COMPLETED
FAILED_NO_EFFECT
FAILED_PARTIAL_EFFECT
OUTCOME_UNKNOWN
```

`OUTCOME_UNKNOWN` is a first-class recovery state.

An unknown external mutation MUST NOT be blindly retried when duplication could produce harm.

## Compensation graph

A plan may contain compensation edges.

Example:

```text
reserve_inventory
    compensation -> release_inventory

create_invoice_draft
    compensation -> void_invoice_draft
```

A compensation graph must be bounded and independently authorized.

It must not assume that compensation restores the world to an observationally identical previous state.

## Saga-style orchestration

For broad business workflows, the task runtime effectively acts like a policy-aware saga coordinator:

```text
step A commit
step B commit
step C fails
     ↓
can C retry safely?
     ├─ yes -> retry/fallback
     └─ no
         ↓
compensate B?
compensate A?
record partial/non-reversible state
```

The term "saga" is implementation vocabulary; AIOS semantic contracts should describe the actual effect/compensation semantics rather than depend on one framework.

## Object revision preconditions

All mutable semantic object writes SHOULD support preconditions such as:

```text
expected_revision
expected_content_hash
expected_external_version
expected_relationship_state
```

Conflicts should fail closed into a re-read/replan/clarification path.

The AI planner may propose reconciliation, but deterministic persistence/adapters enforce the precondition.

## Irreversible-action gate

Before an `IRREVERSIBLE_EXTERNAL` action, the control plane should confirm:

- all prerequisite deterministic validation passed;
- all required approvals are current;
- referenced objects/artifacts are still at expected revisions;
- external destination is policy-approved;
- previous operation attempt is not already known/possibly completed;
- provenance is durable up to the action boundary.

## Example: engineering-to-customer workflow

User intent:

> The customer approved the enclosure revision. Update the design-derived BOM and quote, update the opportunity, create the invoice draft, and send a confirmation summary.

Possible sequence:

```text
1. read approved Product/Design revision             PURE/READ
2. generate BOM                                      PURE
3. calculate manufacturing cost                      PURE
4. revise Quote draft                                ATOMIC_LOCAL
5. verify price, currency, terms                     PURE/VERIFY
6. commit Quote revision                             ATOMIC_LOCAL or CONDITIONAL_REMOTE
7. update federated Opportunity                      CONDITIONAL_REMOTE
8. create Invoice draft                              COMPENSATABLE
9. render customer summary                           ARTIFACT_WRITE
10. verify recipient + final values                  PURE/VERIFY
11. send confirmation                                IRREVERSIBLE_EXTERNAL
```

If step 7 conflicts because the CRM opportunity changed, the task stops before invoice/message issuance and replans.

If step 8 succeeds but step 11 is denied, the invoice draft may remain valid or be compensated according to task/domain policy.

## Completion semantics

A cross-domain AIOS Task is `COMPLETED` only when its declared required outcomes are satisfied.

It may still record warnings such as:

- optional capability unavailable;
- compensation performed;
- non-critical mirrored system stale;
- legacy representation export failed.

If a required irreversible action has unknown outcome, the task MUST NOT claim clean success or clean failure until reconciled or explicitly resolved.

## Why this belongs in the OS architecture

Without this layer, AI orchestration across CRM, billing, engineering, communications, and databases would be dangerous because the model could treat API calls as if they were ordinary local functions.

AIOS must know that:

```text
compute a total
```

and:

```text
charge/send/publish/submit
```

are fundamentally different classes of operations.

## Principle

> **The wider the software fabric becomes, the more explicit side effects, preconditions, compensation, and irreversible-action boundaries must become.**
