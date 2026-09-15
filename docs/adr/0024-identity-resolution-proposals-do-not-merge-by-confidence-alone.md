# ADR 0024 — Identity Resolution Proposals Do Not Merge by Confidence Alone

- Status: **Proposed**
- Date: 2026-09-15

## Context

The Universal Object Graph must reconcile duplicate representations across CRM, billing, email, project systems, files, databases, and future Domain Packs.

Probabilistic matching is useful for discovering likely equivalence, but a false merge can corrupt relationships, financial records, permissions, provenance, or legal/business state.

## Decision

AI/model/provider confidence may rank identity candidates and propose equivalence, but it cannot by itself perform a durable merge.

Merge/link actions pass deterministic contradiction checks, consequence policy, revision preconditions, and any required approval.

AIOS preserves merge/split history and retired object IDs as resolvable aliases/tombstones so provenance remains valid.

## Consequence sensitivity

Low-impact duplicate objects may permit policy-controlled automatic linking after strong evidence.

High/critical identities require stronger evidence and/or explicit approval.

Known contradictions fail closed regardless of similarity score.

## Consequences

### Positive

- object graph can learn/reconcile safely;
- false-positive entity resolution is repairable/auditable;
- model upgrades do not silently rewrite canonical identity;
- financial/legal/security domains can impose stricter rules.

### Costs

- identity resolution needs evidence/proposal/merge records;
- some apparent duplicates remain unresolved until confirmation;
- split/repair tooling must exist.

## Related

- `docs/44-tier0-universal-object-model.md`
- `docs/49-identity-resolution-and-object-reconciliation.md`
- `specs/identity-resolution.schema.json`
- `specs/object-record.schema.json`
