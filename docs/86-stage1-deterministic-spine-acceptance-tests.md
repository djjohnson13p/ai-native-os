# 86 — Stage-1 Deterministic Spine Acceptance Tests

## Purpose

`docs/17-v0.1-acceptance-tests.md` defines the overall v0.1 demonstration/release gate. This document adds a stricter intermediate gate:

> **Before model/planner orchestration is allowed to become the primary development focus, AIOS must execute and recover one typed deterministic capability through the complete trusted core without any AI model.**

This gate exists to prove that intelligence will sit on top of a real operating substrate rather than substitute for one.

## Reference scenario

Use a synthetic input file Artifact and a minimal validated AIOS IR program containing one deterministic capability:

```text
artifact.hash@1
```

Reference flow:

```text
Task CREATED
→ input Artifact imported
→ AIOS IR validated/canonicalized
→ semantic Registry Snapshot fixed
→ Task RUNNABLE
→ provider registration/conformance resolved
→ concrete Authority Evaluation Request
→ deterministic ALLOW + one-shot Artifact-read grant
→ immutable Execution Binding
→ Provider Supervisor starts local fixture provider
→ provider reads only bound Artifact through trusted broker/handle
→ computes deterministic hash
→ structured result accepted
→ result/provenance committed
→ Task COMPLETED
```

No model, remote service, GUI, cloud, legacy application, or arbitrary shell execution is required.

## Gate S1 — Task durability and CAS transitions

### S1.1 Stable Task identity

Pass criteria:

- Task survives daemon/process restart with same Task ID, original intent, revision, state, and active semantic-program linkage;
- Task identity never derives from provider/process ID.

### S1.2 Revision conflict

Run two transitions against the same expected revision.

Pass criteria:

- exactly one can commit when mutually exclusive;
- stale transition receives deterministic conflict/revision reason;
- no last-writer-wins state corruption.

### S1.3 Transition idempotency

Commit a Task transition but simulate loss of caller response, then resend the same `transition_id`.

Pass criteria:

- prior committed result is returned/reconstructed;
- revision increments once;
- material provenance event appears once.

### S1.4 Illegal transition

Attempt an invalid state jump.

Pass criteria:

- fails closed;
- Task state/revision unchanged;
- structured reason code returned.

## Gate S2 — Artifact identity and publication

### S2.1 Import snapshot

Import a synthetic input file, then mutate/delete the original host source.

Pass criteria:

- imported Artifact identity/content remains unchanged;
- hash verifies against AIOS-managed content;
- external path is not the Artifact identity.

### S2.2 Output allocation confinement

Give a provider one output allocation and make it attempt another/unrelated destination.

Pass criteria:

- unrelated destination cannot be finalized through trusted Artifact Store;
- provider never receives the store root as ambient write authority.

### S2.3 Crash before publication

Crash after some output/staging bytes exist but before publication metadata commits.

Pass criteria:

- no published Artifact becomes downstream-visible;
- staging/orphan content is reconciled/cleaned according to policy;
- Task does not claim successful output.

### S2.4 Publication response loss

Commit publication, lose response, repeat same publication identity.

Pass criteria:

- same Artifact/publication result is returned;
- no duplicate publication/lineage/provenance side effect.

### S2.5 Integrity failure

Corrupt/remove content backing a published Artifact fixture.

Pass criteria:

- integrity check fails before trusted downstream consumption/completion;
- recovery/failure is explicit.

### S2.6 Exact placement receipt at restart

Crash after a trusted import has durably copied and verified its pending bytes
and committed an exact placement receipt, but before the final no-overwrite
link. Restart and repeat with a publication whose allocation expires just
before hard-link admission; include an old pending file with no receipt.

Pass criteria:

- the receipted import may finish content placement, but does not invent a published Artifact;
- the denied publication and old unreceipted file remain private and cannot be promoted by filename/hash alone;
- a path replacement after verification cannot substitute bytes during recovery;
- migration 0020 does not backfill authority for old files.

## Gate S3 — Provenance integrity

### S3.1 Complete deterministic story

Reference Task must contain material provenance for:

- Task creation;
- Artifact import;
- semantic validation/snapshot selection;
- provider resolution;
- authority request/decision/grant;
- Execution Binding;
- provider invocation/result;
- Artifact/result publication where applicable;
- Task completion.

### S3.2 Hash-chain verification

Pass criteria:

- valid stream verifies;
- mutation/reordering/deletion of a journal event fails verification;
- sequence/hash-chain remains valid after restart/recovery append.

### S3.3 Privacy/minimization

Pass criteria:

- no raw secret/bearer token bytes;
- no full user Artifact content unless a specific event contract explicitly requires bounded content (the reference scenario should not);
- provider stdout/stderr is not treated as authoritative provenance.

## Gate S4 — Semantic/provider registry separation

### S4.1 Immutable semantic meaning

Pass criteria:

- AIOS IR validates against one exact Registry Snapshot;
- exact semantic contract hashes are attributable;
- provider registration changes do not modify the semantic program hash.

### S4.2 Provider substitution eligibility

Register two conforming fixture providers for `artifact.hash@1` (a second may be synthetic/not selected in the first end-to-end run).

Pass criteria:

- both resolve to the same semantic capability contract;
- provider identity/build remains runtime state;
- non-conforming provider is rejected before execution eligibility.

### S4.3 Effect/authority envelope

Pass criteria:

- provider declaring network effect for `artifact.hash@1` fails conformance;
- provider cannot claim authority outside semantic contract allowed envelope.

## Gate S5 — Authority Coordinator

### S5.1 Exact one-shot Artifact read

Pass criteria:

- provider receives authority to read only the bound input Artifact;
- same grant cannot read another Artifact;
- one-shot use cannot be reused after consumption.

### S5.2 Wrong principal / Task / binding

Attempt to use grant from:

- another provider principal;
- another Task;
- another Execution Binding.

Pass criteria:

- all fail closed with stable reason codes.

### S5.3 Expiry/revocation/cancellation

Pass criteria:

- expired grant rejected;
- revoked grant rejected;
- Task cancellation blocks future protected accesses during an in-flight provider attempt.

### S5.4 Model/provider cannot issue authority

Pass criteria:

- provider/planner-originated record cannot masquerade as policy decision, trusted approval, or grant;
- only trusted Authority Coordinator path produces durable grant state.

### S5.5 Network vs egress distinction

Use a separate fixture if needed.

Pass criteria:

- `network.connect` grant alone is insufficient for `data.egress`;
- `data.egress` is bound to exact destination/resource/policy/approval facts.
- an export writer with a test destructor that writes to its destination is
  retired under a distinct admitted marker before success/provenance commit;
  a later destination drop or replay cannot write again;
- revocation or expiry before destructor entry prevents that write and leaves
  the prior effect `OUTCOME_UNKNOWN`; an unused or rejected destination cannot
  execute an effectful factory-capture destructor.

## Gate S6 — Credential mediation

The main `artifact.hash@1` scenario does not need a credential. Run the Credential Broker as a separate trusted-core fixture.

### S6.1 Non-exportable brokered operation

Pass criteria:

- synthetic non-exportable private key/secret can perform a bounded brokered fixture operation;
- source secret bytes never enter provider invocation/result/provenance.

### S6.2 Wrong scope/provider/Task

Pass criteria:

- handle alone is not permission;
- grant for credential A/provider A/Task A cannot use credential B/provider B/Task B.

### S6.3 Placement/exportability

Pass criteria:

- local-only credential cannot follow execution to peer/remote provider;
- export-with-approval path requires exact current approval.

### S6.4 Secure-store outage

Pass criteria:

- operation fails closed;
- no model-generated/recovered secret substitute is accepted.

## Gate S7 — Immutable Execution Binding / Provider Supervisor

### S7.1 Binding immutability

Pass criteria:

- after attempt begins, DB/runtime rejects mutation of provider, input/output refs, grants, placement, or attempt identity;
- new Stage-1 receipts pin exact non-null contract/manifest/build hashes, conformance evidence, and the effective trust source; a disabled provider or future-dated decision cannot retroactively authorize an old binding;
- retry/substitution creates new binding/attempt.

### S7.2 No ambient host authority

Run malicious/diagnostic fixture provider that tries to access:

- unrelated Artifact/file;
- outbound network;
- environment secret;
- user HOME/config;
- unsupported device/session IPC.

Pass criteria:

- accesses unavailable/denied under the chosen execution profile;
- reference hash provider still succeeds with only required Artifact-read interface.

### S7.3 No shell command injection

Pass criteria:

- typed provider invocation does not interpret Artifact contents/metadata/model text as a shell command;
- no generic `/bin/sh -c <model output>` route exists in trusted provider execution.

### S7.4 Structured result validation

Return:

- valid success;
- declared semantic error;
- malformed result with exit code 0;
- provider crash.

Pass criteria:

- states remain distinguishable (`SUCCEEDED`, `SEMANTIC_FAILURE`, `PROVIDER_FAILURE` etc.);
- exit code alone cannot produce semantic success.

### S7.5 Deadline/cancellation

Pass criteria:

- timeout/cancellation is durable/attributable;
- subsequent protected accesses fail after revocation/cancel boundary.

## Gate S8 — Crash/recovery certainty

Inject failures at deterministic boundaries.

### S8.1 Before provider launch

Expected:

```text
NOT_STARTED
```

Pass:

- safe new-attempt option only after normal current checks;
- old grant/binding not assumed reusable.

### S8.2 Provider running, no published effect

Kill provider after start but before durable output/result.

Pass:

- `FAILED_NO_EFFECT` or `FAILED_PARTIAL_EFFECT` according to staging evidence;
- no final output;
- retry only if semantic failure budget/current facts permit.

### S8.3 Result/publication committed, Task transition lost

Pass:

- recovery sees durable result/publication;
- reconciles Task/provenance;
- provider is not rerun merely because the response/state-transition result was lost.

### S8.4 Grant consumption committed, response lost

Pass:

- grant use remains consumed after restart;
- replay cannot restore authority.

### S8.5 Unknown external-effect fixture

Use a synthetic opaque-external operation with lost response and no status/idempotency proof.

Pass:

- certainty = `OUTCOME_UNKNOWN`;
- automatic blind retry blocked;
- recovery requires external reconciliation/human-safe path.

### S8.6 Local recovery without AI/network

Pass criteria:

- the entire deterministic reference Task can be reopened/reconciled offline with no model provider.

## Gate S9 — Cross-record consistency

### S9.1 Identity linkage

For every attempt verify:

```text
Task ID
semantic program hash
Registry Snapshot
node ID
provider/build
Execution Binding
Authority Grant/policy decision
Artifact refs
provenance
```

are mutually consistent.

### S9.2 Stale semantic/policy/provider state

Simulate restart after:

- Registry active snapshot changes;
- provider registration disabled;
- policy snapshot changes.

Pass criteria:

- historical records remain interpretable under historical identities;
- new attempt eligibility uses current rules rather than silently rewriting history;
- completed historical semantic meaning does not change retroactively.

## Stage-1 exit criteria

All of the following must be true before model/planner orchestration becomes the primary implementation focus:

1. Issue #17 validator gate passes;
2. S1–S9 relevant local deterministic tests pass;
3. one full `artifact.hash@1` Task succeeds through all trusted services without AI;
4. malicious provider fixture cannot obtain ambient host authority;
5. crash injection cannot expose partial Artifact as complete output;
6. response-loss tests do not duplicate transitions/publications/grant uses/provider operations;
7. provenance can reconstruct the exact provider/build/binding/authority used;
8. recovery preserves `OUTCOME_UNKNOWN` where certainty is unavailable;
9. all contract changes discovered during implementation are reconciled through ADR/schema/fixture updates rather than hidden in code;
10. architecture docs are updated to describe actual implemented behavior.

## Relationship to v0.1 release acceptance

Passing this Stage-1 gate does **not** complete `docs/17-v0.1-acceptance-tests.md`.

It earns the project permission to add:

```text
Resource Broker
→ model runtime
→ planner/orchestrator
→ full Demonstration A
→ task-first user experience
```

without asking AI intelligence to compensate for a weak deterministic substrate.

## Principle

> **AIOS earns the right to add autonomy only after it can safely execute, attribute, persist, and recover one useful operation without autonomy.**
