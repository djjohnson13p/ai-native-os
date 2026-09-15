# 57 — Component Distribution, Supply Chain, and Update Trust

## Purpose

AIOS is intended to expand continuously through providers, Domain Packs, Views, Skills, compatibility adapters, model runtimes, policy bundles, and compiled targets.

That growth is impossible to manage safely if software installation is merely "download code and run it."

The platform therefore needs a unified component distribution model that keeps package identity, semantic contracts, publisher identity, conformance, authority, update behavior, and rollback inspectable.

## Component classes

The distribution layer may carry:

```text
CAPABILITY_PROVIDER
DOMAIN_PACK
VIEW_PROVIDER
SKILL
MODEL_RUNTIME
MODEL_ASSET
COMPATIBILITY_ADAPTER
POLICY_BUNDLE
SEMANTIC_REGISTRY_BUNDLE
COMPILED_TARGET
SYSTEM_EXTENSION
DEVELOPMENT_TOOL
```

The component class affects validation and activation rules.

## Package identity

A package has a stable logical identity/version and immutable content digest.

Example:

```text
package: org.ainative.provider.table-import
version: 0.3.1
content: sha256:...
```

Mutable registry URLs are discovery locations, not package identity.

## Package manifest

A package should declare at least:

- package/component class;
- semantic version;
- publisher identity;
- immutable content digest;
- included component manifests;
- supported platform/architecture/runtime requirements;
- semantic capability/type dependencies;
- requested authority/effect classes;
- isolation requirements;
- declared network/service requirements;
- license metadata;
- build provenance/SBOM references;
- conformance suite/status;
- upgrade/rollback compatibility;
- optional migration requirements.

## Signatures prove origin, not safety

A valid signature establishes provenance/integrity for bytes under a publisher key.

It does not establish that the component is:

- correct;
- non-malicious;
- high quality;
- semantically conforming;
- secure enough for broad authority;
- compatible with the current system.

Those claims require separate checks.

## Intake pipeline

A component discovered from any catalog/registry should pass a deterministic activation pipeline:

```text
1. acquire immutable package bytes/manifest
2. verify digest
3. verify publisher signature/trust policy
4. parse manifest strictly
5. evaluate platform/runtime compatibility
6. inspect authority/effect/network requirements
7. verify semantic-contract dependencies
8. run/verify required conformance suites
9. evaluate supply-chain/build metadata
10. stage in quarantine/inactive state
11. request policy/user approval where required
12. activate atomically
13. record package provenance + active version
```

No model decision substitutes for steps that protect execution integrity.

## Authority-diff gate

An update that adds or broadens requested authority is not a routine patch.

Examples:

```text
old version: artifact.read + task-output.write
new version: artifact.read + network.internet + secret.use
```

The update must expose this semantic/authority difference and trigger the appropriate policy/approval path.

A silent permission expansion is prohibited even when the new package is signed by the same publisher.

## Semantic-contract diff gate

Updates may also change:

- provided capability versions;
- input/output semantic types;
- determinism claims;
- effect classes;
- verification requirements;
- migration behavior;
- minimum isolation.

Changes that alter semantic meaning or provider interchangeability require explicit contract/version handling rather than being hidden as implementation detail.

## Atomic activation and rollback

Installation/update should separate **staging** from **activation**.

Conceptually:

```text
active v1
   ↓
stage v2
   ↓
validate/conformance/migrate dry run
   ↓
atomic activation pointer -> v2
   ↓
health/conformance gate
   ├── success -> retain v2
   └── failure -> rollback pointer -> v1
```

State migrations that are not backward compatible require stronger backup/rollback planning.

## Package stores and catalogs

AIOS should not require one centralized app store.

Possible discovery sources:

- project/community registry;
- organization-managed registry;
- local/offline bundle;
- peer mirror;
- source repository release;
- vendor/provider catalog.

Trust policy can differ by source/publisher/component class.

The catalog is not a root of trust by itself.

## Mirrors

Because package identity is content-addressed, mirrors may serve immutable bytes without becoming semantic publishers.

The system verifies digest/signature after retrieval.

This enables:

- offline installation media;
- organization caches;
- peer distribution;
- geographic mirrors;
- long-term reproducibility.

## Dependencies

Dependencies should distinguish:

```text
semantic dependency
runtime dependency
package dependency
optional provider dependency
build-only dependency
```

The solver must not resolve a dependency by silently substituting a semantically incompatible component.

Where possible, depend on semantic capability contracts rather than one provider package.

Example:

```text
requires capability: image.decode.png@1
```

instead of:

```text
requires package: vendor-specific-png-library
```

unless ABI/runtime coupling genuinely requires the latter.

## Domain Packs

A Domain Pack may reference many capabilities without bundling every implementation.

Example:

```text
CAD Domain Pack
  semantic contracts
  conformance suites
  reference Views
  reference Skills
  optional provider recommendations
```

Users can replace the geometry solver/provider while retaining domain semantics.

## Skills and compiled targets

A Skill or compiled target package must include the source semantic-program identity/contract dependencies required to validate reuse.

It never carries old task grants or user credentials.

A compiled target becomes invalid if its semantic registry, compiler compatibility, hardware target, provider assumptions, or verification dependencies no longer satisfy its manifest.

## Model assets

Large model weights should be treated as content-addressed assets referenced by a runtime/provider manifest.

Metadata should include where practical:

- model identity/version;
- content digest;
- architecture/format;
- license/use restrictions;
- size/quantization;
- required runtime/backend;
- provenance/source;
- safety/trust metadata used by policy.

A model file itself does not gain OS authority.

## SBOM and build provenance

Security-sensitive components should expose machine-readable build provenance/SBOM where possible.

This allows AIOS or administrators to answer:

- which source revision produced this binary?
- what dependencies are included?
- which compiler/toolchain version built it?
- is a known-vulnerable dependency present?
- can the artifact be reproduced/verified?

Reproducible builds are desirable but not assumed for every ecosystem initially.

## Revocation and quarantine

The system should support:

```text
ACTIVE
DISABLED
QUARANTINED
REVOKED
SUPERSEDED
ROLLED_BACK
```

Reasons may include:

- compromised signing key;
- security vulnerability;
- conformance failure;
- malicious behavior;
- policy change;
- incompatible system update.

Revocation should not erase historical provenance explaining which Tasks used the component.

## License and legal metadata

Because the Universal Software Fabric will incorporate/adapt many open-source engines and standards, package intake must preserve:

- SPDX-like license identifiers where available;
- source-offer requirements;
- redistribution constraints;
- trademark/asset restrictions;
- patent notices when relevant;
- model/data license restrictions;
- attribution requirements.

The platform should prefer architectures that make license boundaries explicit rather than accidentally combining incompatible components into one derivative binary.

## Security update policy

Critical security fixes may justify accelerated deployment, but they still must not bypass:

- signature/integrity validation;
- compatibility checks;
- authority-diff inspection;
- rollback safety where practical;
- provenance.

An emergency update channel is policy, not an excuse for arbitrary code execution.

## Offline operation

A machine should be able to install/update from an authenticated offline bundle containing:

- package manifests;
- immutable package bytes/content references;
- publisher/key chain material needed for verification;
- registry snapshots/dependency metadata;
- revocation status as of bundle creation.

The UI should make stale revocation metadata visible rather than pretending the offline bundle is current forever.

## v0.1 boundary

The first prototype does not need a public component marketplace.

It does need package/component metadata sufficient to:

- identify a provider build/version;
- verify local fixture hashes;
- associate provider manifests/conformance state;
- activate only known development components;
- preserve an upgrade/rollback path for trusted-core components.

## Principle

> **AIOS can grow continuously only if new capability is easy to add but difficult to smuggle into trusted execution without identity, contracts, policy, conformance, and rollback.**
