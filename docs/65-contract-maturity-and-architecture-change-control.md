# 65 — Contract Maturity and Architecture Change Control

## Purpose

AIOS needs room to learn from prototypes without letting every implementation experiment redefine public semantics.

This document establishes maturity states and change-control rules for requirements, ADRs, schemas, semantic contracts, reason codes, conformance suites, and runtime interfaces.

The objective is not bureaucracy. It is to make clear **what an implementation may rely on today** and what compatibility obligation exists when a contract changes.

## Maturity states

### `DRAFT`

Architecture exploration.

Characteristics:

- breaking changes expected;
- no implementation compatibility promise;
- fixtures/examples may still expose unresolved questions;
- implementation should not infer permanence.

A Draft can still be security-sensitive and must not be bypassed casually; it simply has no external stability promise.

### `SPIKE_READY`

A bounded implementation experiment may rely on the current contract.

Requirements:

- purpose/security boundary defined;
- controlling invariants/ADRs identified;
- positive fixture(s) exist;
- important negative/adversarial fixture(s) exist or are specified;
- major semantic ambiguities needed by the spike are closed;
- explicit non-goals exist;
- breaking change remains allowed if the spike produces evidence.

Compatibility obligation:

- if the spike reveals a required breaking change, update docs/schema/fixtures/tests together and document why.

Issue #17 is the current reference `SPIKE_READY` workstream.

### `PROTOTYPE`

A repository implementation exists and is exercised by automated tests.

Requirements:

- implementation exists in the main development line;
- contract fixtures are automated;
- migration/version consequences are understood;
- security-sensitive behavior has adversarial tests;
- architecture docs match actual behavior.

Compatibility obligation:

- breaking changes require explicit migration/test updates and release-note/ADR rationale.

### `CONFORMANCE_CANDIDATE`

Multiple independent implementations/providers can reasonably target the contract.

Requirements:

- public conformance suite;
- stable reason/error semantics where relevant;
- version-negotiation/compatibility rules;
- at least two implementations/providers or one reference + one independent test implementation where practical;
- known edge cases documented.

Compatibility obligation:

- breaking semantic changes require a new major contract version or explicit migration bridge.

### `STABLE`

The project is making a compatibility promise to external consumers.

Requirements:

- conformance suite mature;
- security review appropriate to scope;
- upgrade/migration strategy;
- versioning policy enforced;
- deprecation window/process documented;
- governance ownership clear.

Compatibility obligation:

- incompatible semantic change requires a new major version/contract identity;
- deprecated versions remain supported according to release policy.

## Maturity is per contract, not per repository

One repository release can contain different maturity levels.

Example:

```text
AIOS IR v0.1          PROTOTYPE
artifact handle v0.1  PROTOTYPE
CAD assembly v0.1     DRAFT
network peer v0.1     SPIKE_READY
```

Do not label the entire platform stable because one subsystem is mature.

## Architecture source hierarchy

When sources appear inconsistent, use this escalation order rather than guessing:

1. System invariants (`docs/15-system-invariants.md`)
2. Accepted controlling ADRs
3. Architecture requirements (`docs/16-requirements.md`)
4. Semantic contract/spec documentation
5. Machine-readable schemas/contracts
6. Acceptance/conformance tests and fixtures
7. Implementation behavior
8. Examples/prose not designated as controlling

This is not a license to ignore a lower source. A contradiction means the repository needs reconciliation.

A `Proposed` ADR remains a proposal, but implementation should not silently choose a different architecture without recording the competing decision.

## Contract-change categories

### Editorial

No valid/invalid instance or semantic meaning changes.

Examples:

- typo;
- clearer prose;
- additional non-normative example.

Can usually keep version unchanged.

### Additive compatible

Existing valid consumers remain valid; new optional semantics/capability can be ignored safely under the version rules.

Examples:

- optional diagnostic context field;
- new optional provider metadata;
- new capability contract in a registry.

Usually minor-version change once stable.

### Validation-tightening

Previously accepted input becomes invalid because the prior acceptance was unsafe/ambiguous or outside intended semantics.

This is compatibility-sensitive even if it appears to be "just validation."

Requirements:

- regression fixture;
- security/semantic rationale;
- migration impact review.

### Semantic change

Same serialized shape would mean something different.

This is dangerous and generally requires a new major semantic contract/version rather than reinterpreting old data.

### Authority/security change

Changes requested effects, authority, egress, credential use, isolation, approval, or trust assumptions.

Always requires explicit architecture/security review and corresponding negative tests.

### Representation/runtime-only change

Provider implementation, storage location, hardware placement, runtime transport, compression, or internal encoding changes without semantic-contract change.

Should not change semantic program/object identity when the architecture says those fields are runtime-only.

## Change bundle rule

A breaking semantic/security contract change is incomplete unless the same PR/change set addresses all affected layers where applicable:

```text
ADR/design rationale
requirements
schema/contract
positive fixtures
negative/adversarial fixtures
reason codes
acceptance/conformance tests
traceability matrix
migration/compatibility notes
implementation
```

Do not merge a code change first and "fix the architecture docs later" for security/semantic boundaries.

## Stable ID rules

Requirement IDs, reason codes, semantic type IDs, capability IDs, effect classes, and relationship predicates can become ecosystem dependencies.

Rules:

- do not recycle a retired ID for incompatible meaning;
- do not change a stable reason code to mean a different error class;
- breaking semantic capability/type meaning uses a new major version;
- aliases/deprecations should remain resolvable/documented during their support window;
- provider-specific implementation names do not become semantic IDs merely through popularity.

## Schema-version rule

`schema_version` describes the serialization/contract schema version, not necessarily the semantic capability/type version.

Keep these concepts separate.

Example:

```text
manifest schema: 0.2
capability: table.import@1
provider package: 0.7.4
```

They can evolve independently.

## Reason-code maturity

Validator/policy/recovery reason codes should progress through the same maturity model.

Before `STABLE`:

- new codes may be added;
- overly broad codes may be split;
- codes should not be renamed casually once tests/issues/tooling consume them.

At `STABLE`:

- code meaning is API;
- human message text remains free to improve;
- new detail belongs in structured fields rather than encoding semantics into prose.

## Registry snapshot implications

Semantic validation binds to an immutable registry snapshot.

Therefore:

- modifying a semantic contract creates a new contract content identity/snapshot;
- old validation evidence remains attributable to the old snapshot;
- a later registry update does not retroactively change what an old semantic program meant;
- re-execution may require revalidation against a current compatible snapshot according to policy/Skill rules.

## Package/update implications

Package updates are runtime/distribution changes until they also change declared semantic/effect/authority contracts.

An implementation update may preserve the same semantic capability version if it remains conforming.

If it requests broader authority/effects or changes semantics, the component activation pipeline treats that as an explicit diff requiring current policy and possibly contract version changes.

## Experimental extensions

Research should be possible without polluting stable core registries.

Use explicit experimental namespaces/registries where appropriate, for example conceptually:

```text
experimental.engineering.generative_mesh@0
```

Experimental identifiers must not impersonate stable contracts.

## Deprecation

Once stable third-party consumers exist, deprecation should include:

- replacement contract/version if applicable;
- migration/conversion path;
- deprecation reason;
- support horizon;
- tool warning/conformance status;
- eventual removal conditions.

## Contract review checklist

Before promoting maturity, ask:

```text
Is the semantic meaning unambiguous?
Are authority/effect/egress semantics explicit?
Are runtime/provider details kept separate?
Are positive and negative fixtures present?
Can malformed/hostile input fail closed?
Can a second implementation interpret the contract independently?
Are version/migration rules clear?
Does provenance retain enough identity/version information?
Does the contract preserve relevant system invariants?
```

## Current maturity guidance

Until explicit per-contract metadata is automated, use these defaults:

- AIOS IR/semantic registry/validator contracts: `SPIKE_READY` for Issue #17, otherwise pre-v1;
- Task/Artifact/Provenance/Authority contracts: late `DRAFT` / preparing for `SPIKE_READY` Phase I;
- Resource/Presentation/Network/Cloud/Storage/Trust/Package/Object/Domain contracts: `DRAFT`/interface-shaping unless a specific issue says otherwise;
- no current contract is `STABLE` for external compatibility.

## Automation later

As implementation begins, the repository may add a machine-readable contract index containing:

```text
contract ID
version
maturity
owner/workstream
controlling ADRs
schema path
fixture paths
conformance suite
introduced/deprecated versions
```

Do not add this registry until it reduces rather than duplicates maintenance burden.

## Principle

> **Prototype aggressively, but make semantic/security changes explicit enough that experiments cannot silently become permanent architecture.**
