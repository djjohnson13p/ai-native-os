# Authority Coordinator Fixtures

Synthetic fixtures for:

- `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`
- ADR 0039
- `specs/authority-evaluation-request.schema.json`
- `specs/approval-request.schema.json`
- `specs/approval-decision.schema.json`
- `specs/authority-grant-record.schema.json`
- `specs/policy-snapshot.schema.json`
- `specs/authority-reason-codes.json`

The fixtures test deterministic scoping/approval/grant behavior. They do not contain real secrets, credentials, user data, or production policy.

A provider/model may request authority but cannot create policy decisions, approvals, or grants directly.
