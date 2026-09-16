# ADR 0042 — Persist Intent Before Effects and Preserve Unknown Outcomes

- Status: **Proposed / controlling for v0.1 recovery implementation**
- Date: 2026-09-15

## Context

AIOS coordinates Task state, provider attempts, Artifact publication, grants, and eventually external side effects. Process/device failure can occur after an operation starts but before the caller receives its result.

Without a durable ordering rule, recovery can duplicate work, publish partial output, resurrect expired authority, or falsely report success/failure.

## Decision

Before a protected/observable operation starts, AIOS persists a stable attempt/operation identity and enough binding/authority context to recognize it after restart.

Before claiming completion, AIOS persists durable result/publication evidence.

If the system cannot prove whether an externally observable non-idempotent effect occurred, the durable state is `OUTCOME_UNKNOWN` and automatic blind retry is prohibited until deterministic reconciliation resolves it or policy/human handling chooses another safe path.

For local Task/Artifact/provenance state, stable transition/publication IDs provide idempotent commit/reply recovery.

## Consequences

### Positive

- response loss does not imply duplicate execution;
- Artifact staging does not masquerade as publication;
- Task/provenance state is recoverable deterministically;
- one-shot grant consumption is not reset after a crash;
- external effects remain honest when outcome is uncertain.

### Costs

- more durable attempt/idempotency records;
- explicit reconciliation code paths;
- some Tasks pause instead of automatically retrying;
- filesystem + SQLite publication requires a recoverable multi-resource protocol.

## Security impact

Recovery never broadens authority or recreates secrets from logs. Expired/revoked grants remain invalid after reboot. A model cannot convert `OUTCOME_UNKNOWN` to success/failure by assertion.

## Related

- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- `docs/74-v0.1-task-manager-transition-and-cas-contract.md`
- `docs/75-v0.1-artifact-store-content-identity-and-publication.md`
- `docs/78-v0.1-execution-binding-and-provider-supervisor.md`
- `docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md`
- `specs/recovery-assessment.schema.json`

## Principle

> **Uncertain history is safer than confidently inventing history.**
