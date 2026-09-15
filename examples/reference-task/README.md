# Reference Task Contract Fixtures

These files represent the v0.1 Demonstration A request:

> Understand these numbers, identify important changes, create a chart and a concise report, and save the result.

The fixtures are architecture examples, not runtime output from an implemented system yet.

They are intended to become the first schema-validation and end-to-end test inputs when implementation begins.

## Files

- `artifact-input.json` — user-selected spreadsheet represented as an artifact handle
- `task-plan.json` — typed capability graph
- `provider-table-import.json` — deterministic table-import provider manifest
- `provider-chart-render.json` — sandboxed chart provider manifest
- `policy-local-read.json` — example deterministic policy decision
- `capability-token-table-import.json` — example task-scoped grant
- `execution-profile-table-import.json` — example P2 sandbox profile
- `model-request-report.json` — provider-neutral report-composition model request
- `hardware-laptop.json` — ordinary x86_64 laptop resource profile
- `compatibility-windows-demo.json` — Demonstration B Wine profile example
- `provenance-events.jsonl` — illustrative ordered event stream

## Fixture rules

1. IDs are deliberately synthetic and non-secret.
2. No real user path, credential, account identifier, or private data belongs in fixtures.
3. Examples should validate against the corresponding schemas where applicable.
4. A future CI job should validate every positive fixture and ensure intentionally invalid fixtures are rejected.
5. Fixtures should be updated with schema changes in the same pull request.

## Not an authority source

These files demonstrate structures. Copying a capability token or policy decision fixture into a running system must never grant real authority.
