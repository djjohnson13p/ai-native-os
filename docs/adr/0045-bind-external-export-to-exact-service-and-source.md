# ADR 0045 — Bind External Export Authority to an Exact Service and Source

Status: Proposed for the remaining Issue #3 Authority Coordinator work.

## Context

ADR 0044 reserves a bounded local Artifact candidate with denied egress. That
profile is useful, but Issue #3 and the Stage-1 merge gate also require policy
decisions for data egress, destination-specific approval, and independent
`network.connect` authority. The current Artifact export adapter checks an
existing `data.egress` grant for a destination *class*. A class is not an exact
service identity: two services in the same class cannot safely share one
approval or grant.

## Decision

Keep the ADR 0044 local-only profile unchanged. Add a separate, explicitly
selected profile for **local execution with mediated external export**. Local
provider placement grants neither network access nor export authority. Only a
trusted coordinator may resolve and reserve an export request only when the
validated node has `egress.mode=policy` and a matching declared `data.egress`
selector/destination class, Task privacy is explicitly `local-first` or
`remote-allowed`, and the same
candidate contains an independently validated `artifact.read` request for the
exact source. Finalization issues both grants atomically; export use checks the
issued read grant again. The Task contract has no residency constraint field in
v0.1. This first profile therefore admits only Tasks with no residency
restriction; a caller cannot express or infer a residency exemption from the
`privacy` field. A later profile needs a typed Task residency field, a trusted
service-region resolver, and an admission/finalization/use check before any
residency-restricted export can be enabled.
`local-only` data is ineligible even when provider execution remains local.
The first profile seals one exact source Artifact/content revision, one exact
service, one trusted export adapter, one purpose/sensitivity, and one export
operation with a whole-operation byte ceiling. Provider-supplied strings are
proposals, not authoritative resolution. A multi-source or multi-operation
profile needs a separate explicit accounting rule.

Policy evaluates `network.connect` and `data.egress` independently. A
`network.connect` decision or grant cannot authorize Task-data transfer. An
external export requires a `data.egress` decision over the complete sealed
tuple; private data can require a structured approval. A changed source,
service, provider/build, semantic program, binding, policy activation, or
approval state makes the old decision stale. Hard deny wins over approval.
The canonical grant resource is an `external-destination` with a sealed exact
service identity and source/operation metadata; a destination class alone is
not its resource identity. The request, approval, grant, export intent, and
provenance contracts must share that representation. Only current allowed
decisions can enter the existing atomic finalizer, which
issues exact grants and immutable receipts under its Task ownership and
trusted-time fences.

The export boundary must compare the exact tuple before creating a destination
writer and again at protected use. Its intent, effect marker, provenance, and
recovery evidence must carry the service identity and source identity. Existing
class-only export intents remain historical records under their original
version; they cannot be upgraded into the new exact-service grant by inference.
An in-memory trusted sink can prove the authorization and byte-release path
without implementing a network transport in Issue #3. A later real transport
must independently satisfy `network.connect` authority; `data.egress` alone
never grants connectivity.

Unknown, destructive, credential, and otherwise unsupported requests remain
denied with typed reason codes and no grant. This decision does not add remote
provider execution, ambient sockets, organization policy distribution, or
credential delivery.

## Verification

The public-path evidence map for this decision is:

| Boundary | State transition and adversarial check | Observable evidence |
| --- | --- | --- |
| Candidate admission | Validated IR and trusted Task, source Artifact, service, and adapter resolution reserve one immutable export tuple. Reject undeclared egress, local-only data, a missing pinned source-read request, and same-class service substitution. | No candidate, writer-factory call, or released byte on rejection. |
| Policy and approval | Evaluate the entire tuple under one policy activation; approval fingerprints the same tuple. Reject hard deny and changed service, source, program, provider/build, binding, or policy activation. | Typed decision reason and no issued egress grant. |
| Finalization | Recheck fresh evidence and approval before atomically issuing an exact `external-destination` grant with the binding. | No grant or runnable binding on stale or denied authority. |
| Export use | The trusted destination issuer, writer construction, write/flush, and completion check the same tuple, source-read authority, expiry, revocation, and whole-operation byte ceiling. | An unauthorized request invokes no writer and releases zero bytes; withdrawal after an external effect prevents further bytes and records an unknown outcome when appropriate. |
| Recovery | Authenticated intent, effect marker, provenance, and reconciliation retain the exact tuple. Historical class-only intents cannot acquire it by replay. | Response-loss replay creates no second writer or transfer; uncertain effects remain fenced until trusted reconciliation. |

Tests must enter through the coordinator's real reservation, evaluation,
finalization, and Artifact export APIs. A helper-level grant check or synthetic
grant insertion alone cannot prove any row above.

Run every `examples/authority/authority-cases.json` case against production
decision, issuance, and use paths. In particular, a same-class different
service, different source Artifact, undeclared egress or destination class,
Task `local-only` data, missing read authority, byte-ceiling expansion,
network-only grant, stale approval, revocation, expiry, one-shot race, response
loss, restart, and retained destination handle must release no bytes. Include
an approved export as a positive control. Fixture dispatch
may set up each scenario, but must assert actual coordinator output and effect
behavior rather than restating the fixture's expected result.

## Compatibility

The new profile is additive. Historical local-only candidates and grants do
not gain egress. Historical class-only intents may support authenticated
outcome replay or reconciliation, but cannot reopen a writer, release further
bytes, or acquire an upgraded grant. Schema and migration changes must retain
immutable identity, replay, cancellation, and old-session quarantine
guarantees. AIOS IR semantic hashes remain independent of runtime destination,
binding, and grant details.
