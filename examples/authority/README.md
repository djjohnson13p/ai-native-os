# Authority Coordinator Fixtures

Synthetic fixtures for:

- `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`
- ADR 0039
- `specs/authority-evaluation-request.schema.json`
- `specs/authority-candidate-reservation.schema.json`
- `specs/approval-request.schema.json`
- `specs/approval-decision.schema.json`
- `specs/authority-grant-record.schema.json`
- `specs/policy-snapshot.schema.json`
- `specs/authority-reason-codes.json`

The fixtures test deterministic scoping/approval/grant behavior. They do not contain real secrets, credentials, user data, or production policy.

A provider/model may request authority but cannot create policy decisions, approvals, or grants directly.

`candidate-reservation.json` is a synthetic positive pending reservation with both input-read and output-allocation-write resources. `candidate-reservation-cases.json` names declarative negative mutations; the executable reservation and migration regressions are in the Task Manager Rust tests. A candidate carries no executable authority, even if its reserved IDs match a later binding.

`evaluation-exact-export.json` is a positive sealed `data.egress` request.
`crates/aios-task-manager/tests/authority_evaluation_schema.rs` checks it,
omitted/null egress and sealed fields, action/resource-kind mismatches, and
the historical local-read request shape. It also rejects missing/null
purpose or sensitivity and multiple source references.
