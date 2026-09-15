# ADR 0036 — Task State Transitions Use CAS and Commit Atomically with Provenance

- Status: **Accepted for the v0.1 / Phase-I substrate**
- Date: 2026-09-15

## Context

AIOS Tasks are long-lived durable execution objects. Concurrent workers, user actions, policy changes, provider completions, cancellation, replanning, and crash recovery can all race to change current Task state.

Last-writer-wins state mutation would lose newer facts and make recovery unsafe. Separately committing Task state and material provenance creates contradictory durable history after partial failures.

## Decision

For v0.1:

1. The Task Manager is the only component that commits Task current-state transitions.
2. Every mutation request supplies `expected_revision`, `expected_state`, and stable `transition_id`.
3. The Task Manager uses compare-and-swap semantics: stale revision/state fails without Task mutation or transition provenance append.
4. Every successful Task current-record mutation increments Task revision exactly once.
5. `transition_id` is idempotent: exact retry returns/reconstructs the prior result; reusing the ID for a different transition is rejected.
6. Allowed adjacency from `docs/24-task-state-machine.md` is enforced deterministically.
7. Target-state guards (runnable/completion/rollback/blocker/recovery rules) are enforced in addition to adjacency.
8. Material Task-state transition plus corresponding provenance journal append commits in the same SQLite transaction under ADR 0035.
9. Terminal states are immutable except the explicitly guarded `FAILED -> ROLLING_BACK` compensation path.
10. Step/provider-attempt state is stored separately from the coarse Task state and has its own identity/revision/attempt semantics.
11. Unknown external side-effect outcome is first-class and blocks unsafe blind retry/completion.

Detailed semantics are in `docs/74-v0.1-task-manager-transition-and-cas-contract.md`.

## Consequences

### Positive

- stale worker races fail safely;
- current Task state and material history cannot diverge through ordinary partial commit;
- retry after response loss does not duplicate transitions/events;
- terminal history remains stable;
- recovery has structured attempt/outcome evidence;
- model/provider output remains advisory rather than direct state mutation.

### Costs

- transition requests/results need stable IDs and conflict handling;
- Task Manager must own the state transaction boundary;
- some worker updates must reload/reconcile after CAS failure;
- completion/runnable transitions require deterministic guard queries rather than simple status assignment.

## Security impact

A Task transition is not authorization. Execution/side effects still require current policy/grants.

CAS/idempotency IDs are concurrency controls, not capabilities.

## Related

- `docs/24-task-state-machine.md`
- `docs/35-v0.1-persistence-model.md`
- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- `docs/74-v0.1-task-manager-transition-and-cas-contract.md`
- ADR 0035
- GitHub Issue #1
