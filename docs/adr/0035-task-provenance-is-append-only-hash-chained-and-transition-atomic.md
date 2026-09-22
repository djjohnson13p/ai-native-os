# ADR 0035 — Task Provenance Is Append-Oriented, Hash-Chained, and Transition-Atomic

- Status: **Accepted for the v0.1 / Phase-I substrate**
- Date: 2026-09-15

## Context

AIOS Task state, authorization, provider execution, Artifact publication, verification, egress, recovery, and irreversible effects must remain reconstructable without relying on AI-generated explanations or mutable debug logs.

A Task-state update recorded separately from its material provenance event creates failure windows where the current state and audit/recovery history disagree.

A plain mutable event table also makes accidental/history-tampering harder to detect.

## Decision

For v0.1:

1. Each Task has an append-oriented provenance stream identified by
   `task:<task-stream-key>`, where the v0.1 key is the lowercase SHA-256 digest
   of `"AIOS-TASK-PROVENANCE-STREAM-ID\0v1\0" || task_id UTF-8`, prefixed with
   `v1:sha256:`. This deterministic opaque identity preserves already committed
   Stage-1 chain hashes; the typed event payload continues to carry `task_id`.
2. Journal records carry a monotonically increasing per-stream sequence beginning at 1.
3. Each journal record links to the previous record hash; the first record uses a null previous hash.
4. Record hashes use a canonical, domain-separated profile over the typed record content excluding the record's own hash and detached signatures.
5. Normal control-plane APIs never edit/delete a committed provenance record; corrections/reconciliation append new records.
6. Material Task-state transitions and the corresponding provenance append occur in the same local SQLite transaction whenever both are managed by the same v0.1 control-plane store.
7. Consequential external effects that require durable pre-effect provenance MUST NOT proceed when the required journal append cannot commit.
8. Stream verification is deterministic and requires no AI/model/provider/network access.
9. The local hash chain is described as **tamper-evident**, not tamper-proof against an attacker capable of rewriting the full database and all trusted checkpoints.
10. Later signed/remote checkpoints may strengthen evidence without changing historical event identity.
11. Every material Task state transition is represented by `task.transitioned`
    with a required typed transition identity object; free-form event details do
    not carry the authoritative transition identity.

The detailed profile is `docs/73-v0.1-provenance-journal-and-hash-chain.md`.

## Journal envelope

The existing semantic `Provenance Event` payload remains distinct from its journal ordering/integrity envelope.

Conceptually:

```text
ProvenanceJournalRecord {
  stream_id
  sequence
  previous_event_hash
  event
  event_hash
  hash_profile
}
```

This avoids forcing every future event payload schema consumer to own journal-storage mechanics while still giving the persisted stream deterministic ordering/integrity.

## Transaction boundary

A state transition should conceptually commit:

```text
expected Task revision check
allowed-transition check
next provenance sequence/head check
provenance journal record insert
Task current-state/revision update
```

in one transaction.

If any part fails, neither the transition nor its provenance append becomes durable.

## Privacy

Provenance records references and material execution facts; it does not copy arbitrary user content, prompts, credentials, or provider debug dumps by default.

Artifact/Object IDs, content hashes, provider/package IDs, semantic program/node IDs, policy/grant references, transfer destination identities, reason codes, and status are preferred over payload duplication.

## Consequences

### Positive

- deterministic Task history ordering independent of wall-clock anomalies;
- crash-consistent Task-state/provenance updates;
- tampering/deletion/reordering is detectable under normal verification;
- recovery can distinguish current materialized state from historical facts;
- future signatures/checkpoints can layer on top without redesigning event semantics;
- provenance stays separate from high-volume logs/traces.

### Costs

- append serialization is required for material events;
- transaction ownership between Task/provenance libraries must be explicit;
- hash canonicalization/versioning is another trusted-core primitive;
- local hash chains alone do not protect against a fully privileged database rewrite.

## Security impact

The provenance subsystem is part of correctness for consequential effects. It is not an authorization engine, and a valid event/hash does not grant permission.

Secret/private payloads must not be copied into `details` merely for convenience.

## Compatibility impact

The existing `provenance-event.schema.json` remains the event payload contract. v0.1 journal ordering/integrity is represented by a separate envelope schema so the change is additive at the architecture level.

## Related

- `docs/22-end-to-end-reference-flow.md`
- `docs/24-task-state-machine.md`
- `docs/35-v0.1-persistence-model.md`
- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- `specs/provenance-event.schema.json`
- `specs/provenance-journal-record.schema.json`
- GitHub Issue #5
