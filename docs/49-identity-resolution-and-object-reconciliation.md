# 49 — Identity Resolution and Object Reconciliation

## Purpose

The Universal Object Graph only works if AIOS can determine when records from different applications, files, databases, services, and devices refer to the same real-world or logical thing **without silently merging distinct things**.

Identity resolution is therefore a core semantic service, not an import-script convenience.

Examples:

```text
CRM account 99881
billing customer C-31002
email contact acme@example.test
project client ACME
ERP account A00941
```

may all refer to one `core.party@1` object, while two people with the same name may be completely different Parties.

## Principle

> **AI may propose identity matches; deterministic rules, evidence, policy, and explicit merge state decide whether identities are linked or merged.**

Possessing similar text is not sufficient authority to collapse object identity.

## Identity states

AIOS should distinguish:

```text
DISTINCT
POSSIBLE_MATCH
LIKELY_MATCH
LINKED_EQUIVALENT
MERGED
SPLIT
CONFLICTED
```

`LIKELY_MATCH` is not the same as `MERGED`.

A probabilistic matcher may raise confidence, but durable object consolidation requires deterministic gates appropriate to the object's consequence level.

## Evidence model

Candidate matching can use evidence such as:

- exact external identifiers;
- verified email/phone/address identifiers;
- normalized legal/business names;
- domain names;
- tax/business IDs where legally appropriate;
- account relationships;
- shared document provenance;
- user-confirmed aliases;
- graph neighborhood consistency;
- temporal consistency;
- source-system merge history.

AI/embedding similarity may be used as discovery evidence, but not as sole proof for consequential merges.

## Evidence classes

Suggested evidence classes:

```text
AUTHORITATIVE_ID
VERIFIED_IDENTIFIER
STRONG_STRUCTURED_MATCH
WEAK_STRUCTURED_MATCH
GRAPH_CONTEXT
SEMANTIC_SIMILARITY
USER_ASSERTION
PROVIDER_ASSERTION
CONTRADICTION
```

Evidence retains source/provenance and timestamp.

## Resolution pipeline

```text
source record discovered
        ↓
normalize identity-relevant fields
        ↓
retrieve candidate AIOS objects
        ↓
derive evidence set
        ↓
apply deterministic contradictions
        ↓
score/rank remaining candidates
        ↓
resolution proposal
        ↓
policy / consequence gate
        ↓
link, request confirmation, create new object, or reject
```

## Hard contradictions

Some evidence should prevent automatic merge regardless of similarity score.

Examples:

- conflicting verified government/business identifiers;
- mutually exclusive lifecycle facts;
- incompatible authoritative source mappings;
- explicit user separation;
- domain rule says identities cannot coexist;
- known previous split event.

Contradictions are machine-readable reason codes, not hidden model intuition.

## Link vs merge

AIOS should support equivalence links without immediately deleting identity history.

```text
object://party/acme-crm-import
    equivalent_to
object://party/acme-industries
```

A later merge can establish one canonical object while retaining alias/tombstone mappings.

This supports safe gradual reconciliation and reversible correction.

## Merge record

Every merge should record:

```text
merge_id
surviving_object_id
retired_object_ids[]
source revisions
resolution evidence
policy/approval decision
field conflict decisions
relationship rewrites
timestamp
provenance events
```

Retired IDs remain resolvable as aliases/tombstones so historical provenance does not break.

## Split record

Incorrect merges must be repairable.

A split operation should preserve history and explicitly redistribute:

- external mappings;
- attributes;
- relationships;
- artifacts;
- domain extensions;
- provenance references.

A split is not history deletion.

## Field-level source of truth

Object identity and field authority are separate problems.

Example:

```text
core.party identity: AIOS canonical
legal_name: ERP authoritative
billing_address: billing system authoritative
primary_sales_contact: CRM authoritative
notes: AIOS-native
```

The same object can therefore federate fields from multiple sources.

Each managed field should be able to carry:

```text
value
source/provider
source revision
observed_at
authority class
confidence if derived
sensitivity
```

## Conflict policy

When sources disagree, AIOS should not silently choose whichever source was read last.

Conflict strategies include:

```text
AUTHORITATIVE_SOURCE_WINS
LATEST_VERIFIED_WINS
USER_CONFIRMATION_REQUIRED
DOMAIN_RULE
PRESERVE_MULTIVALUE
DERIVE_NEW_VALUE
BLOCK_MUTATION
```

The selected strategy is part of semantic/domain policy.

## Consequence levels

Resolution policy should be stricter for objects whose identity affects money, access, legal records, or irreversible actions.

Example classes:

```text
LOW       local note/tag duplicate
MEDIUM    project/contact consolidation
HIGH      customer/vendor/account merge
CRITICAL  financial/legal/security identity
```

A high-confidence AI match may be enough to suggest a duplicate contact but insufficient to merge two financial counterparties automatically.

## Privacy

Identity resolution can be privacy-sensitive because it joins data that was previously separated.

Therefore:

- resolution searches require explicit authority;
- cross-source joining is provenance-visible;
- private identifiers are not automatically exposed to providers;
- matching should run locally where practical;
- remote match providers receive minimized/authorized features only;
- deletion/retention rules apply to evidence caches;
- organization/user policy may forbid specific joins entirely.

## Object lookup API semantics

AIOS should distinguish:

```text
resolve exact-id
find candidates
propose equivalence
link equivalence
merge identities
split identity
inspect evidence
```

A provider capable of `find candidates` does not automatically have authority to `merge identities`.

## Cross-domain benefit

With safe identity resolution, a task can reason about one durable object across domains:

```text
customer email
   ↓
core.party
   ├── crm.account-profile
   ├── billing.customer-profile
   ├── project.client-role
   ├── product ownership/history
   └── conversation/document relationships
```

The object graph becomes genuinely shared instead of a collection of imported duplicates.

## v0.1 / early-stage scope

Do not attempt universal real-world entity resolution in the first prototype.

Early work should prove:

1. exact external mapping;
2. candidate matching with synthetic records;
3. contradiction handling;
4. explicit link vs merge;
5. revision-safe merge record;
6. reversible split fixture;
7. field-level source attribution;
8. no model can directly mutate canonical identity.

## Principle

> **Identity should become more connected as evidence improves, but never more destructive merely because a model is confident.**
