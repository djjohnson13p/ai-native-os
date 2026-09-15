# 43 — Software Coverage Expansion Strategy

## Objective

AIOS is intended to expand continuously until a user can accomplish most software-mediated work without thinking in terms of separate application products.

This cannot be achieved by waiting for the core project to independently rewrite every mature software category.

The strategy is therefore to acquire capability coverage progressively while preserving one semantic model.

## Coverage ladder

For any desired capability, use the highest practical rung available:

```text
0  UNAVAILABLE
1  LEGACY-LAUNCH
2  LEGACY-BRIDGED
3  EXTERNAL/REMOTE PROVIDER
4  OPEN-SOURCE ENGINE ADAPTER
5  AIOS-NATIVE PROVIDER
6  OPTIMIZED/COMPILED NATIVE PROVIDER
7  MULTIPLE CONFORMING PROVIDERS
```

A capability may climb this ladder over time without changing the user's Task or the semantic capability identifier.

Example:

```text
cad.export_step@1

2027: bridged legacy CAD application
2028: adapted open-source CAD engine
2029: AIOS-native provider
2030: CPU + GPU providers selected by hardware
```

The dates are illustrative only. The important property is semantic continuity.

## Build-vs-integrate decision

For every new domain capability, evaluate:

1. Does a high-quality open-source engine already exist?
2. Can it be cleanly isolated behind AIOS contracts?
3. Does its license fit the intended distribution model?
4. Can it run on target hardware efficiently?
5. Is its architecture maintainable/security-auditable?
6. Does wrapping it preserve the AIOS semantic/effect/authority model?
7. Would rewriting it produce a measurable long-term benefit?
8. Is the capability strategically important enough for a reference implementation?

Default:

> Reuse mature generic engines when they are good enough; own the semantic contract, integration boundary, tests, and user experience. Rewrite only when there is a concrete advantage.

## What “better” means

AIOS should not claim to be better merely because functionality is bundled.

A native capability should improve one or more measurable dimensions:

- task completion time;
- cross-domain composability;
- memory/compute efficiency;
- offline availability;
- hardware adaptability;
- privacy;
- reliability;
- reproducibility;
- accessibility;
- automation;
- undo/recovery;
- interoperability;
- cost;
- inspectability;
- security/least authority;
- provider substitutability.

For mature specialist software, feature parity may take years. AIOS should report capability maturity honestly rather than call a shallow implementation "better."

## Domain backlog structure

Every software domain should maintain a capability matrix rather than a vague app-cloning roadmap.

Example — CAD:

| Capability | Semantic contract | Provider status | Maturity |
| --- | --- | --- | --- |
| sketch constraints | `cad.sketch.solve@1` | none | unavailable |
| extrude | `cad.feature.extrude@1` | open-engine adapter | experimental |
| STEP export | `cad.export.step@1` | legacy bridge | works-with-limitations |
| drawing render | `cad.drawing.render@1` | native provider | conforming |

This makes progress incremental and testable.

## Capability intake process

When adding a feature inspired by existing software:

1. describe the user outcome without vendor terminology;
2. identify common/open standards and data models;
3. separate fundamental domain behavior from one product's UI conventions;
4. define semantic inputs/outputs/effects/authority;
5. identify correctness/verifiability rules;
6. identify import/export compatibility requirements;
7. create conformance fixtures;
8. select or build an initial provider;
9. add a human View only where direct manipulation benefits the user;
10. benchmark and iterate.

## Feature research catalog

The project may maintain comparative research describing useful approaches seen across software categories.

Research should focus on questions such as:

- Which workflow is fastest/least error-prone?
- Which data model is most interoperable?
- Which undo/history model is safest?
- Which expert controls are indispensable?
- Which repetitive steps should disappear under AI orchestration?
- Which standards permit round-trip compatibility?

This research informs AIOS design but must not become unauthorized copying of proprietary implementation details.

## Independent evolution

A capability's semantics and provider implementation evolve separately.

```text
semantic contract v1
 ├── provider A v3.2
 ├── provider B v1.7
 └── legacy adapter v5
```

A breaking semantic change produces a new contract major version with explicit migration/conversion.

## Reference implementations

The core project should prioritize reference implementations for:

- security-critical primitive capabilities;
- cross-domain primitives;
- functions needed for the flagship demonstrations;
- strategically important offline capabilities;
- capabilities where no adequate reusable engine exists;
- conformance/reference correctness.

It should avoid becoming the sole maintainer of every specialized solver, renderer, codec, database, and industry rules engine.

## Community scaling

The eventual platform should make it possible for communities to own Domain Packs:

```text
core AIOS project
   ├── office/data foundation
   ├── business domain community
   ├── CAD/engineering community
   ├── EDA/electronics community
   ├── media community
   ├── scientific community
   └── vertical industry packs
```

Shared contracts and conformance tooling keep those domains interoperable.

## Continuous improvement loop

```text
user tasks
   ↓
telemetry/feedback only under explicit privacy policy
   ↓
identify friction / missing capability
   ↓
research competing approaches
   ↓
new or improved semantic capability/provider
   ↓
conformance + security + benchmark gates
   ↓
release
   ↓
Skill/compiler optimization from repeated real patterns
```

Private user content must not become a communal training/feature-mining dataset by default.

## Scope discipline

The universal long-term mission must not destroy the near-term project.

v0.1 remains narrowly focused on proving:

- AIOS IR;
- authority/effect enforcement;
- artifacts/provenance;
- capability/provider substitution;
- hardware/resource adaptation;
- task-first UX;
- one legacy compatibility path;
- one compiled/reused Skill path.

Universal Software Fabric work at v0.1 is architectural: define the scaling model now so early implementation does not create barriers later.

## End-state principle

AIOS should grow like a platform, not like a giant bundle.

> **Continuously absorb useful software capability into a common semantic fabric while allowing the best engine—native, open-source, legacy, local, peer, or remote—to perform the work under AIOS policy and provenance.**
