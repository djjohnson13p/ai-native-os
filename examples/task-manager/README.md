# Task Manager Fixtures

Synthetic fixtures for:

- `docs/24-task-state-machine.md`
- `docs/74-v0.1-task-manager-transition-and-cas-contract.md`
- ADR 0036
- `specs/task-record.schema.json`
- `specs/task-transition-request.schema.json`
- `specs/task-transition-result.schema.json`
- `specs/step-execution-record.schema.json`
- `specs/task-reason-codes.json`

The fixture set is intentionally about deterministic state/CAS/recovery behavior. It does not execute models/providers or decide policy authority.

## Files

- `transition-cases.json` — legal/illegal/CAS/idempotency/completion/recovery cases.
- `step-outcome-cases.json` — provider-attempt and external-effect certainty cases.

All IDs/data are synthetic.
