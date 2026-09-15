# Machine-Readable Contracts

This directory contains draft contracts for the AI-native operating-system control plane and its surrounding platform fabrics.

They exist so architecture decisions can be tested independently of implementation language, model provider, Linux distribution, UI toolkit, network transport, database, storage backend, package catalog, or cloud vendor.

## Status

All schemas are **pre-v1 architecture drafts**. Breaking changes are expected while v0.1 is being designed and prototyped.

A schema being present here does not mean the implementation exists yet.

## Contract principles

1. **Provider-neutral** — no OpenAI-, Anthropic-, Google-, Microsoft-, Apple-, cloud-, database-, storage-, package-catalog-, or application-specific field is a mandatory core semantic concept.
2. **Task-scoped** — machine-actionable operations retain task identity and authority context.
3. **Handles over arbitrary paths** — contracts prefer artifact/resource/object identifiers rather than unrestricted host paths.
4. **Plans are not authority** — planner/IR schemas describe proposed work; policy/grant schemas govern permission.
5. **Semantic contracts precede providers** — a capability/type/object has provider-independent meaning before an implementation claims to provide it.
6. **Semantic IR is separate from execution binding** — providers, hardware placement, grant references, network paths, and sandbox instances are bound after IR validation.
7. **Versioned meaning** — successful semantic validation records the exact registry snapshot of type/capability contracts used to interpret a program.
8. **Presentation is separate from identity** — display/View schemas describe projections of Tasks/objects rather than redefining them.
9. **Network/cloud are runtime fabrics** — service endpoints, network paths, cloud regions, and remote workers do not become semantic Task/object identity.
10. **Object identity is separate from storage/provider records** — federated/external IDs are mappings to durable AIOS object identity.
11. **Storage/namespace are projections** — replicas, caches, filesystem paths, mounts, and cloud object keys do not become semantic identity or authority.
12. **Authentication is not authorization** — trust identities and credentials provide evidence/tools; deterministic policy still authorizes protected actions.
13. **Signed is not automatically trusted** — component/package signatures establish publisher/integrity evidence, not semantic conformance or runtime authority.
14. **Bulk data out-of-band** — large files/media/model weights should not be embedded in ordinary control-plane JSON messages.
15. **Explicit versions** — contracts carry schema/interface versions as implementation stabilizes.
16. **Fail closed for execution** — unknown required fields/versions/capabilities must not be silently interpreted as broader permission.
17. **Portable serialization first** — JSON Schema is the first interchange notation because it is inspectable and easy to fixture-test. It is not a permanent requirement for all hot-path runtime communication.

## Current schemas

### Semantic compute / execution

| Schema | Purpose |
| --- | --- |
| `aios-ir.schema.json` | provider-independent AI-native semantic execution graph |
| `ir-validation-result.schema.json` | deterministic structural/semantic validation result, diagnostics, semantic hash, and registry identity |
| `registry-snapshot.schema.json` | immutable/content-addressed set of semantic type/capability contracts used for validation |
| `capability-contract.schema.json` | stable semantic meaning of a capability independent of providers |
| `type-contract.schema.json` | semantic type identity/representation/equality contract |
| `execution-binding.schema.json` | concrete attempt-specific provider/authority/resource binding for one IR node |
| `execution-profile.schema.json` | effective process/container/VM isolation profile |
| `effect-summary.schema.json` | deterministic summary of semantic effects/authority classes/verification boundaries |
| `compiled-target.schema.json` | compiled deterministic target identity linked to semantic source without carrying authority |
| `skill-manifest.schema.json` | versioned reusable/compiled procedure metadata |

### Task / policy / provenance

| Schema | Purpose |
| --- | --- |
| `task-plan.schema.json` | planner-facing typed capability proposal graph during v0.1 transition |
| `task-record.schema.json` | durable task identity/state plus validated semantic-program identity |
| `artifact-handle.schema.json` | stable identity and metadata for task data/output |
| `capability-token.schema.json` | task/principal-scoped authority grant representation |
| `policy-decision.schema.json` | deterministic authorization decision record |
| `provenance-event.schema.json` | append-oriented execution/audit event linked to semantic program and runtime binding identities |
| `persistence-v0.1.sql` | draft SQLite persistence layout for control-plane recovery/state |

### Identity / trust / credential mediation

| Schema | Purpose |
| --- | --- |
| `trust-identity.schema.json` | stable user/device/service/workload/provider/publisher identity and key lifecycle metadata |
| `credential-handle.schema.json` | opaque mediated credential metadata/scope/exportability without raw secret material |

### Providers / models / compatibility / distribution

| Schema | Purpose |
| --- | --- |
| `capability-manifest.schema.json` | provider declaration of semantic contracts implemented, conformance status, and runtime requirements |
| `provider-registration.schema.json` | registration/conformance/trust state for a provider implementation |
| `component-package.schema.json` | signed/content-addressed distributable provider/Domain-Pack/View/Skill/model/adapter package metadata |
| `model-request.schema.json` | provider-neutral AI/model invocation request |
| `model-result.schema.json` | provider-neutral model invocation result |
| `compatibility-profile.schema.json` | known legacy-app habitat/translation profile |

### Hardware / resource placement

| Schema | Purpose |
| --- | --- |
| `hardware-profile.schema.json` | relatively stable normalized hardware/security profile |
| `resource-snapshot.schema.json` | time-sensitive available memory/load/thermal/network/provider resource state |
| `placement-decision.schema.json` | candidate eligibility/ranking/selection with machine-readable reasons |

### Universal Software / Object Fabric

| Schema | Purpose |
| --- | --- |
| `domain-pack.schema.json` | versioned Domain Pack declaration of objects/capabilities/Views/adapters/policy/dependencies |
| `semantic-object-contract.schema.json` | stable semantic contract for an object type |
| `relationship-contract.schema.json` | typed relationship predicate/source/target/cardinality semantics |
| `object-record.schema.json` | durable/federated semantic object identity, representations, relationships, source state, and lineage |
| `identity-resolution.schema.json` | cross-source identity match proposal/evidence/consequence/policy state |

### Storage / namespace / replica fabric

| Schema | Purpose |
| --- | --- |
| `storage-replica.schema.json` | explicit artifact/object/package/model replica location, role, consistency, encryption, retention, and sync state |
| `namespace-projection.schema.json` | mapping of semantic Object/Artifact/stream identity into file/path/URI/workspace materialization without redefining identity |

### Presentation Fabric

| Schema | Purpose |
| --- | --- |
| `display-profile.schema.json` | current display/input/accessibility/trust context for presentation selection |
| `view-contract.schema.json` | semantic object/action requirements for an adaptive/specialized View |

### Network / cloud / service fabrics

| Schema | Purpose |
| --- | --- |
| `network-service-descriptor.schema.json` | stable service identity, trust state, capabilities, and current reachable endpoints |
| `network-transfer.schema.json` | explicit task-scoped bulk/material transfer record with policy/path/provenance state |
| `remote-service-descriptor.schema.json` | cloud/edge/self-hosted remote service classes, trust, region, cost, lifecycle, and capabilities |

Planned contracts may include provider health, richer model descriptors, peer pairing/attestation evidence, operation-attempt/compensation records, object merge/split records, sync sessions, collaboration sessions, package revocation metadata, update activation records, and registry-signing/transparency metadata as implementation requires them.

## Semantic/runtime relationship

The intended core execution relationship is:

```text
Planner proposal
    ↓
AIOS IR
    ↓ validated against
Semantic Type + Capability Registry Snapshot
    ↓ implemented by
Provider Manifests
    ↓ selected/bound through
Policy + Resource Broker
    ↓ creates
Execution Binding + Execution Profile
    ↓ emits
Artifacts + Provenance
```

The broader platform adds orthogonal runtime context:

```text
Semantic Objects / Domain Packs
        │
        ├──── Presentation Profile + View Contract
        ├──── Resource Snapshot + Placement Decision
        ├──── Network Service + Transfer Record
        ├──── Storage Replica + Namespace Projection
        ├──── Trust Identity + Credential Handle
        ├──── Component Package + Activation State
        └──── Remote Service / Compatibility Provider
```

Those runtime fabrics may change without silently changing semantic program/object identity.

No layer below AIOS IR may reinterpret the program as carrying authority simply because it passed schema validation.

A successful IR validation identifies both the semantic program hash and the registry snapshot used to give that program meaning.

## Schema IDs

Until the project has a final name/domain, schemas use the documentation-only domain:

```text
https://ai-native-os.example/specs/...
```

No software should attempt to fetch that URL at runtime.

When the project gains a stable domain, schema IDs can move through an explicit compatibility/versioning ADR.

## Versioning approach

Before v1.0:

- breaking changes are allowed;
- every breaking change should update fixtures/tests in the same change;
- consumers should reject schema versions they cannot interpret safely;
- optional fields should be preferred for additive compatible evolution;
- authority/security semantics must not change accidentally through a schema-only edit.

For stable interfaces, use semantic major/minor concepts:

```text
major — incompatible contract/semantic change
minor — additive compatible fields/capabilities
patch — documentation/constraint clarification that does not change valid semantics
```

The exact version-string placement is still being standardized.

## Fixtures

### AIOS IR

`examples/aios-ir/` contains:

- a complete Demonstration A AIOS IR program;
- semantic capability/type fixtures;
- a bootstrap registry snapshot;
- validation/effect/binding fixtures;
- a candidate reusable Skill manifest;
- valid compact IR programs;
- invalid/adversarial IR programs with expected reason codes.

### Platform fabrics

`examples/platform-fabric/` contains synthetic fixtures for:

- compact and workstation presentation profiles;
- paired peer service/trust identity;
- remote service descriptor;
- explicit peer data transfer;
- storage replica state;
- mediated credential handle metadata;
- component package metadata;
- namespace projection;
- cross-source identity-resolution proposal.

### General fixture rule

A schema should not be considered implementation-ready until it has:

- at least one minimal valid fixture;
- at least one realistic valid fixture;
- invalid fixtures for important missing/contradictory security/identity/version fields;
- automated validation in CI.

For AIOS IR and security-sensitive contracts, semantic/adversarial validation is also required; structural validation alone is insufficient.

## Security note

Passing JSON Schema validation only proves structural conformance.

It does not prove:

- the provider/service/peer/publisher is trustworthy;
- the requested action/transfer/credential use is authorized;
- the AIOS IR graph is semantically valid;
- a capability provider conforms to its semantic contract;
- a registry publisher should be trusted;
- two object records really represent the same entity;
- a storage replica is current/authoritative merely because it exists;
- a signed component is safe or deserves broad authority;
- a remote display is safe for confidential output;
- a cloud region/provider satisfies policy;
- a compatibility profile is safe;
- model output is factually correct;
- an artifact is non-malicious.

Those decisions belong to semantic validation, policy, identity resolution, storage/source-of-truth logic, sandboxing, verification, provenance, conformance, and trust systems.
