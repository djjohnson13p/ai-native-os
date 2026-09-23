# 82 — Stage-1 Deterministic Core Codex Runbook

## Purpose

`docs/62-first-codex-session-runbook.md` covers the first implementation spike: Issue #17, the AIOS IR validator.

This runbook defines what should happen **after #17 succeeds** so Codex does not jump from a validator directly into a model planner, GUI, cloud stack, or Universal Software Fabric.

The Stage-1 objective is a deterministic operating spine that can execute one semantic capability safely **without any AI model at all**.

## Stage-1 completion demonstration

At the end of this runbook, a test should be able to do:

```text
create Task
→ import synthetic input as Artifact
→ load validated AIOS IR
→ resolve semantic capability contract
→ select registered deterministic provider
→ resolve concrete resource handles
→ deterministic policy allow / scoped grant
→ create immutable Execution Binding
→ launch one bounded provider
→ publish output Artifact
→ append/verify provenance
→ transition Task to completion
→ restart/recover and prove state remains coherent
```

No model planner is needed for this proof.

## Dependency sequence

```text
A. #17 AIOS IR validator/canonicalizer
      ↓
B. #1 Task Manager
      ↓
C. #4 Artifact Store
      ↓
D. #5 Provenance integration/hardening
      ↓
E. #2 Semantic + Provider Registry runtime
      ↓
F. #3 Authority Coordinator
      ↓
G. Credential Broker minimal local boundary
      ↓
H. Provider Supervisor + deterministic fixture provider
      ↓
I. Stage-1 integration/recovery test
```

Some libraries may be developed in parallel after their prerequisites are stable, but integration should respect this order.

## Shared rules for every Codex assignment

Before coding:

1. read root `AGENTS.md`;
2. read the GitHub issue and comments;
3. read relevant `SPIKE_READY` entry in `specs/contract-maturity.json`;
4. read controlling ADRs/docs/schemas/fixtures;
5. report direct contradictions before implementation;
6. use feature branch + PR;
7. do not broaden the issue to future fabrics.

Every completion report states:

```text
issue/workstream
architecture sources followed
invariants preserved
contracts changed and why
tests/fixtures run
security boundary exercised
known limitations
follow-up architecture conflicts
```

## B — Task Manager (#1)

### Goal

Implement durable Task state, revision/CAS transitions, transition idempotency, and deterministic guards.

### Required sources

```text
docs/24-task-state-machine.md
docs/34-task-ir-lifecycle.md
docs/35-v0.1-persistence-model.md
docs/73-v0.1-provenance-journal-and-hash-chain.md
docs/74-v0.1-task-manager-transition-and-cas-contract.md
docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md
specs/task-record.schema.json
specs/task-transition-request.schema.json
specs/task-transition-result.schema.json
specs/task-reason-codes.json
examples/task-manager/
```

### Bounded assignment

> Implement Issue #1 as a local Rust Task Manager/persistence module using the current SQLite v0.1 model. Enforce CAS revision/state preconditions, allowed transitions, transition IDs/idempotency, structured guards/reason codes, and atomic Task+provenance transition commits. Do not implement planner/model logic, provider execution, GUI, networking, or policy semantics. If schema/SQL/docs conflict, stop and propose an explicit contract reconciliation.

### Merge gate

- legal/illegal transition fixtures;
- revision-race test;
- transition response-loss/idempotency test;
- terminal-state test;
- crash/reopen persistence test;
- provenance transaction rollback test.

## C — Artifact Store (#4)

### Goal

Implement immutable Artifact identity/content storage and output publication without ambient paths.

### Required sources

```text
docs/75-v0.1-artifact-store-content-identity-and-publication.md
docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md
specs/artifact-handle.schema.json
specs/artifact-output-allocation.schema.json
specs/artifact-publication-request.schema.json
specs/artifact-publication-result.schema.json
specs/artifact-reason-codes.json
examples/artifact-store/
```

### Bounded assignment

> Implement Issue #4 as a local content-addressed Artifact Store with typed Artifact records, user/synthetic import, scoped reader handles, output allocations, streamed staging, SHA-256 content identity, idempotent publication, lineage metadata, and startup reconciliation. Do not expose blob-store root paths to providers. Do not implement cloud/peer sync or universal namespace projection.

### Merge gate

- changed source after import does not mutate Artifact;
- duplicate bytes may dedupe blob while preserving Artifact identity;
- output cannot escape allocation;
- crash-before-metadata produces no published Artifact;
- committed publication survives lost response;
- missing/corrupt blob detected.

## D — Provenance (#5)

### Goal

Implement/finish append-oriented Task provenance integrated with Task and Artifact transactions.

### Required sources

```text
docs/73-v0.1-provenance-journal-and-hash-chain.md
specs/provenance-event.schema.json
specs/provenance-checkpoint.schema.json
specs/provenance-reason-codes.json
examples/provenance/
```

### Bounded assignment

> Implement Issue #5 as a local append-only per-Task provenance journal with monotonic sequence, JCS/domain-separated hash chaining, bounded structured details, stream verification, and caller-owned SQLite transaction support. Preserve privacy/minimization rules. Do not implement remote transparency logs or claim tamper-proof security against a privileged full-store attacker.

### Merge gate

- valid chain verifies;
- changed/reordered/deleted event fails verification;
- concurrent sequence allocation safe;
- Task transition/provenance atomic;
- portable export re-verifies.

## E — Semantic + Provider Registry (#2)

### Goal

Make semantic meaning immutable/reproducible while provider availability remains runtime state.

### Required sources

```text
docs/28-capability-contracts-and-conformance.md
docs/29-semantic-type-system.md
docs/31-semantic-registry-snapshots.md
docs/72-v0.1-semantic-contract-and-registry-hash-profile.md
docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md
specs/capability-contract.schema.json
specs/type-contract.schema.json
specs/registry-snapshot.schema.json
specs/provider-registration.schema.json
specs/provider-conformance-result.schema.json
examples/registry-lifecycle/
```

### Bounded assignment

> Implement Issue #2 with separate immutable semantic registry snapshots and mutable provider-registration/health state. Generate/verify contract hashes and snapshot identities; resolve AIOS IR major selectors to one exact contract in a fixed snapshot; validate provider declarations/conformance metadata without executing provider code. Do not make installed provider inventory change semantic meaning.

### Merge gate

- exact historical snapshot re-opens offline;
- duplicate/conflicting semantic identity fails closed;
- provider add/remove does not change semantic program hash;
- two conforming providers can register for one capability;
- invalid provider authority/effect claim rejected.

## F — Authority Coordinator (#3)

### Goal

Implement deterministic no-ambient-authority policy/approval/grant lifecycle.

### Required sources

```text
docs/19-principal-and-authority-model.md
docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md
docs/adr/0039-runtime-authority-is-intersection-not-declaration.md
specs/authority-evaluation-request.schema.json
specs/policy-decision.schema.json
specs/policy-snapshot.schema.json
specs/approval-request.schema.json
specs/approval-decision.schema.json
specs/authority-grant-record.schema.json
specs/capability-token.schema.json
specs/authority-reason-codes.json
examples/authority/
```

### Policy backend rule

Cedar can be the first backend **only behind the AIOS Authority Coordinator interface**.

If Cedar integration complicates the first spike, begin with a tiny deterministic builtin fixture policy backend that exercises AIOS semantics, then run a separate Cedar mapping test. Do not let Cedar syntax become the operating-system authority ABI.

### Bounded assignment

> Implement Issue #3 with concrete authority-request normalization, exact resource resolution, default-deny deterministic decisions, structured approval records, opaque runtime token handles backed by durable scoped grant records, expiry/revocation/use counts, and point-of-use validation. Planner/model/provider code may request but cannot create decisions/approvals/grants. Do not implement organization-scale policy distribution.

### Merge gate

Run every case in `examples/authority/authority-cases.json` plus expiry/revocation/race tests.

## G — Credential Broker minimum boundary

### Goal

Prove secrets can be mediated without becoming ambient provider data.

### Required sources

```text
docs/56-cryptographic-identity-trust-and-credential-fabric.md
docs/79-v0.1-credential-broker-and-secret-mediation.md
docs/adr/0041-credentials-are-mediated-capabilities-not-ambient-secrets.md
specs/credential-handle.schema.json
specs/credential-use-request.schema.json
specs/credential-use-result.schema.json
specs/credential-reason-codes.json
examples/credentials/
```

### Bounded assignment

Use a synthetic local credential store only. Prove brokered use and exportability checks. Do not integrate real user passwords/cloud accounts in the first test.

> Implement a minimal Credential Broker library using synthetic secrets in test-only secure-store fixtures. Support opaque handles, point-of-use Authority Grant validation, `BROKERED_OPERATION`, one short-lived delegation fixture, revocation/expiry/exportability, and redacted results. Never persist raw test secret values in Task/provenance fixtures.

## H — Provider Supervisor + deterministic fixture provider

### Goal

Execute one validated deterministic capability without ambient host authority.

### Required sources

```text
docs/78-v0.1-execution-binding-and-provider-supervisor.md
docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md
docs/adr/0040-execution-bindings-are-immutable-attempt-receipts.md
specs/execution-binding.schema.json
specs/execution-profile.schema.json
specs/provider-invocation-request.schema.json
specs/provider-invocation-result.schema.json
specs/provider-runtime-reason-codes.json
examples/provider-runtime/
```

### First provider

Use the smallest deterministic fixture with obvious semantics, e.g. `artifact.hash@1` or `text.uppercase@1`.

`artifact.hash@1` is preferable if Artifact Store is ready because it exercises:

```text
Artifact read grant
→ provider handle
→ deterministic computation
→ typed result/provenance
```

### Bounded assignment

> Implement a local Provider Supervisor and exactly one deterministic fixture provider. Create immutable attempt-specific Execution Bindings, launch the known registered provider under a restrictive execution profile, pass typed handle refs/grant refs, enforce deadlines/cancellation, validate structured results, and record attempt/provider identity. Do not add generic shell execution, arbitrary provider discovery, network access, model execution, or remote RPC.

## I — deterministic spine integration test

This is the Stage-1 exit gate.

### Scenario

Input: a synthetic file Artifact.

Semantic program: a minimal AIOS IR graph containing a deterministic `artifact.hash@1` node.

Expected flow:

```text
Task CREATED
→ semantic program validated
→ Task RUNNABLE
→ Artifact input resolved
→ provider resolved
→ authority request artifact.read
→ deterministic allow + one-shot grant
→ immutable Execution Binding
→ provider invocation
→ deterministic hash result
→ output/structured result recorded
→ provenance appended
→ Task COMPLETED
```

Then run crash simulations at:

```text
before provider launch
after provider start
before result persistence
after result persistence/before Task transition
```

Recovery must produce deterministic safe state with no duplicate protected operation.

## Stage-1 stop condition

Once the deterministic spine works, stop adding more deterministic-core machinery unless required by acceptance tests.

The next phase becomes:

```text
hardware/resource profiling
→ model runtime interface
→ planner produces proposal
→ proposal lowers to already-trusted AIOS IR
```

The planner is intentionally a **consumer** of the deterministic spine, not its implementation shortcut.

## Principle

> **Before giving AIOS intelligence, prove it can execute and recover one typed operation correctly without intelligence.**
