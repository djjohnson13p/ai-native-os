# Machine-Readable Contracts

This directory contains draft contracts for the AI-native operating-system control plane and its surrounding platform fabrics.

They exist so architecture decisions can be tested independently of implementation language, model provider, Linux distribution, UI toolkit, network transport, database, storage backend, package catalog, or cloud vendor.

## Status / maturity

All contracts are **pre-v1**.

A schema being present here does not mean implementation exists.

Contract maturity/change rules:

- `docs/65-contract-maturity-and-architecture-change-control.md`
- `specs/contract-maturity.schema.json`
- `specs/contract-maturity.json`

Maturity levels:

```text
DRAFT
SPIKE_READY
PROTOTYPE
CONFORMANCE_CANDIDATE
STABLE
```

No current AIOS contract is `STABLE`.

## Contract principles

1. **Provider-neutral** — no model/cloud/application/database/programming-language vendor is a mandatory semantic concept.
2. **Task-scoped execution** — runtime protected actions retain Task/principal/binding context while reusable semantic-program identity remains Task-independent where specified.
3. **Handles over ambient paths/secrets** — prefer typed Artifact/Object/resource/credential handles over unrestricted host paths or secret propagation.
4. **Plans are not authority** — AIOS IR can request authority; deterministic policy/grants govern execution.
5. **Semantic contracts precede providers** — a capability/type has stable meaning before an implementation claims it.
6. **Semantic IR is separate from runtime binding** — providers, Task ID, device, grants, paths, endpoints, and sandbox instances are outside semantic-program identity.
7. **Required vs allowed effects/authority are explicit** — capability contracts declare semantic lower bounds and maximum implementation envelopes.
8. **Versioned meaning** — successful validation records the immutable Registry Snapshot used to interpret the program.
9. **Presentation/storage/network/cloud are projections/runtime fabrics** — they may change without redefining Task/Object/program meaning.
10. **Authentication is not authorization** — identity/credential evidence never replaces deterministic Task authority.
11. **Signed is not automatically trusted** — signatures prove integrity/publisher evidence, not semantic conformance/runtime permission.
12. **Execution Bindings are immutable receipts** — retries/substitution create new bindings/attempts.
13. **Unknown outcome remains unknown** — recovery cannot manufacture completion/failure when external effect certainty is lost.
14. **Bulk data stays out-of-band** — large files/media/model weights do not travel inside normal control-plane JSON.
15. **Fail closed** — unknown required semantics/versions/authority mappings do not widen behavior.
16. **Portable inspectable bootstrap** — JSON/JSON Schema are bootstrap interchange forms, not a permanent hot-path mandate.
17. **Hash executable meaning, not labels/runtime state** — semantic hashing follows the controlling AIOS IR/registry hash profiles.

## Current contract families

### AIOS IR / semantic compute

| Contract | Purpose |
| --- | --- |
| `aios-ir.schema.json` | provider-independent AI-native semantic execution graph |
| `ir-validation-result.schema.json` | deterministic validation result + semantic hash/registry identity |
| `validator-output.schema.json` | validator bundle including derived effect summary |
| `validator-reason-codes.json` | stable validator diagnostics |
| `effect-summary.schema.json` | derived program/node effects, authority classes, verification barriers |
| `capability-contract.schema.json` | provider-independent capability meaning, required/allowed effect+authority bounds |
| `type-contract.schema.json` | semantic type/representation/equality contract |
| `registry-snapshot.schema.json` | immutable semantic contract-set identity |
| `compiled-target.schema.json` | compiled deterministic target tied to source semantics without authority |
| `skill-manifest.schema.json` | reusable/compiled Skill metadata |

### Task lifecycle / persistence

| Contract | Purpose |
| --- | --- |
| `task-plan.schema.json` | planner-facing proposal envelope during transition |
| `task-record.schema.json` | durable Task identity/current state |
| `task-transition-request.schema.json` | CAS/idempotent Task transition request |
| `task-transition-result.schema.json` | committed/rejected Task transition result |
| `task-reason-codes.json` | stable Task Manager reason codes |
| `step-execution-record.schema.json` | mutable execution-attempt lifecycle state |
| `persistence-v0.1.sql` | aligned SQLite draft for trusted-core durability/recovery |

### Artifact/data substrate

| Contract | Purpose |
| --- | --- |
| `artifact-handle.schema.json` | stable Artifact identity/type/hash/sensitivity/origin metadata |
| `artifact-output-allocation.schema.json` | bounded Task/node output staging allocation |
| `artifact-publication-request.schema.json` | idempotent request to finalize staged output |
| `artifact-publication-result.schema.json` | publication result / published Artifact identity |
| `artifact-reason-codes.json` | stable Artifact Store diagnostics |

### Provenance / audit

| Contract | Purpose |
| --- | --- |
| `provenance-event.schema.json` | typed material event payload |
| `provenance-journal-record.schema.json` | stream/sequence/hash-chain envelope around event payload |
| `provenance-checkpoint.schema.json` | independently verifiable journal checkpoint |
| `provenance-verification-result.schema.json` | stream verification result |
| `provenance-projection-manifest.schema.json` | privacy-redacted portable projection descriptor |
| `provenance-projected-record.schema.json` | independently hashed projected JSONL record |
| `provenance-projection-verification-result.schema.json` | projection-only offline verification result and explicit limitations |
| `provenance-reason-codes.json` | stable provenance diagnostics |

### Authority / approvals / policy

| Contract | Purpose |
| --- | --- |
| `authority-evaluation-request.schema.json` | concrete runtime request derived from validated semantic authority |
| `policy-decision.schema.json` | engine-neutral deterministic ALLOW/DENY/REQUIRE_APPROVAL decision |
| `policy-snapshot.schema.json` | exact policy/engine/config identity for reproducible attribution |
| `approval-request.schema.json` | trusted structured approval prompt facts |
| `approval-decision.schema.json` | authenticated user/admin approval outcome |
| `authority-grant-record.schema.json` | durable scoped runtime grant state/scope/usage/expiry |
| `capability-token.schema.json` | opaque token-handle metadata referencing the durable grant; no embedded scope/secret bytes |
| `authority-reason-codes.json` | stable Authority Coordinator diagnostics |

### Credentials / trust identities

| Contract | Purpose |
| --- | --- |
| `trust-identity.schema.json` | user/device/service/workload/provider/publisher cryptographic identity metadata |
| `credential-handle.schema.json` | opaque credential metadata/exportability/lifecycle without raw secret |
| `credential-use-request.schema.json` | exact grant/binding-scoped request for credential-backed operation |
| `credential-use-result.schema.json` | mediated result/delegation metadata without source secret |
| `credential-reason-codes.json` | stable Credential Broker diagnostics |

### Providers / execution bindings

| Contract | Purpose |
| --- | --- |
| `capability-manifest.schema.json` | provider implementation declaration using canonical effect vocabulary |
| `provider-registration.schema.json` | provider package/trust/conformance registration state |
| `provider-conformance-result.schema.json` | provider-vs-contract conformance result |
| `execution-binding.schema.json` | immutable attempt-specific semantic-node → provider/resources/grants/placement receipt |
| `execution-profile.schema.json` | sandbox/process/container/VM isolation profile |
| `provider-invocation-request.schema.json` | typed bounded request delivered by Provider Supervisor |
| `provider-invocation-result.schema.json` | structured semantic/runtime outcome for one invocation |
| `provider-runtime-reason-codes.json` | Provider Supervisor diagnostics |

### Crash recovery

| Contract | Purpose |
| --- | --- |
| `recovery-assessment.schema.json` | durable evidence/certainty/safe-action reconciliation record |
| `recovery-reason-codes.json` | stable recovery diagnostics |

### Component distribution / models / compatibility

| Contract | Purpose |
| --- | --- |
| `component-package.schema.json` | content-addressed/signed distributable component metadata |
| `model-request.schema.json` | provider-neutral model invocation request |
| `model-result.schema.json` | provider-neutral model result |
| `compatibility-profile.schema.json` | legacy application habitat/translation profile |

### Hardware / resource placement

| Contract | Purpose |
| --- | --- |
| `hardware-profile.schema.json` | relatively stable normalized hardware/security facts |
| `resource-snapshot.schema.json` | live memory/load/thermal/network/provider resource state |
| `placement-decision.schema.json` | hard eligibility + objective ranking/selection with reason codes |

### Universal Software / Object Fabric

| Contract | Purpose |
| --- | --- |
| `domain-pack.schema.json` | Domain Pack objects/capabilities/Views/adapters/policy/dependencies |
| `semantic-object-contract.schema.json` | stable semantic object-type contract |
| `relationship-contract.schema.json` | typed object relationship semantics |
| `object-record.schema.json` | durable/federated object identity/source/lineage metadata |
| `identity-resolution.schema.json` | cross-source match/link/merge proposal evidence/policy state |

### Storage / namespace / replica fabric

| Contract | Purpose |
| --- | --- |
| `storage-replica.schema.json` | replica role/location/consistency/encryption/retention state |
| `namespace-projection.schema.json` | mapping semantic identity into legacy path/URI/workspace projections |

### Presentation Fabric

| Contract | Purpose |
| --- | --- |
| `display-profile.schema.json` | current display/input/accessibility/trust context |
| `view-contract.schema.json` | semantic object/action requirements for a View |

### Network / cloud / service fabrics

| Contract | Purpose |
| --- | --- |
| `network-service-descriptor.schema.json` | stable service identity/trust/capabilities/current endpoints |
| `network-transfer.schema.json` | explicit Task-scoped material transfer/provenance |
| `remote-service-descriptor.schema.json` | cloud/edge/self-hosted service trust/region/cost/lifecycle/capabilities |

## Core semantic/runtime relationship

```text
Planner proposal
    ↓
AIOS IR
    ↓ deterministic validation against
Immutable Semantic Registry Snapshot
    ↓ emits
Validation Result + Effect Summary + Semantic Hash
    ↓
Concrete resource/provider resolution
    ↓
Authority Evaluation → Policy → optional Approval → scoped Grant
    ↓
Immutable Execution Binding
    ↓
Provider Supervisor / typed Provider Invocation
    ↓
Artifact publication + structured result
    ↓
Task transition + Provenance
    ↓
Recovery evidence if any boundary fails
```

No layer below semantic validation gains permission merely because the program is valid.

No provider gains semantic authority merely because it is signed, registered, or conforming.

## AIOS IR v0.1 identity rule

For Issue #17:

```text
Task ID          outside AIOS IR
program_id       authoring/family label; excluded from semantic hash
metadata         excluded
description      excluded
authority reason excluded
runtime binding  excluded
```

Semantic capability/data flow/types/effects/authority action+selector/egress/verification/failure/cache/constraints are included.

See ADR 0029 and `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`.

## Effect vocabulary

Canonical effect names are uppercase:

```text
PURE
ARTIFACT_READ
ARTIFACT_WRITE
NETWORK
DATA_EGRESS
EXTERNAL_MESSAGE
SECRET_ACCESS
PERSISTENT_STATE
DEVICE_ACCESS
SYSTEM_CHANGE
LEGACY_OPAQUE
```

Semantic capability contracts declare **required** lower bounds and **allowed** upper bounds. Provider manifests declare their actual implementation envelope using the same vocabulary.

See `docs/69-v0.1-capability-effect-and-authority-contract-profile.md`.

## Schema IDs

Until the project has a stable domain, schemas use:

```text
https://ai-native-os.example/specs/...
```

No runtime should fetch that host. Cross-schema references resolve from a bundled local trusted schema set.

## Versioning

Before v1.0:

- breaking changes are allowed under change control;
- security/semantic changes update ADR/docs + schema + positive/negative fixtures + acceptance tests together;
- unknown major/interface versions fail closed;
- historical released snapshots/migrations are not silently edited once implementations depend on them.

Semantic major/minor concepts:

```text
major — incompatible meaning
minor — explicitly compatible additive evolution
patch — editorial/constraint clarification with no semantic change
```

## Fixture directories

```text
examples/aios-ir/          semantic validator/registry/provider-conformance
examples/task-manager/     state/CAS/idempotency
examples/artifact-store/   import/output/publication/crash cases
examples/provenance/       append/hash-chain/correction cases
examples/registry-lifecycle/ semantic/provider activation cases
examples/authority/        policy/approval/grant adversarial cases
examples/credentials/      secret mediation/exportability cases
examples/provider-runtime/ binding/supervisor/runtime cases
examples/recovery/         crash/outcome-certainty reconciliation
examples/reference-task/   broader control-plane reference path
examples/domain-fabric/    future cross-domain semantic object examples
examples/platform-fabric/  future presentation/network/cloud/storage interfaces
```

All fixtures must remain synthetic. Placeholder hashes explicitly labeled as placeholders are not cryptographic evidence.

## Structural validation is not semantic trust

Passing JSON Schema validation does **not** prove:

- AIOS IR is semantically valid;
- requested action is authorized;
- provider conforms to the contract;
- package/publisher is trustworthy;
- credential use is permitted;
- Artifact content is benign;
- two semantic objects are the same real entity;
- storage replica is current/authoritative;
- cloud/peer/display path satisfies policy;
- model output is correct;
- external action occurred exactly once.

Those are separate validator/policy/conformance/identity/sandbox/verification/provenance/recovery responsibilities.
