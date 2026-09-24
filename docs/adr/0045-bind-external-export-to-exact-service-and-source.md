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
selector/destination class, Task privacy and residency constraints permit the
transfer, and the source has independently valid `artifact.read` authority.
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
