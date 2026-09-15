# ADR 0018 — Applications Are Domain Capability Collections, Not the Native Unit of Software

- Status: Proposed
- Date: 2026-09-15

## Context

The long-term AIOS vision extends beyond launching legacy applications. The platform is intended to absorb useful software functionality into a unified task-first environment covering productivity, business operations, databases, creative tools, engineering/CAD/EDA, development, communication, and future domains.

If each category is rebuilt as another monolithic AIOS application, the project will reproduce the application silo model it is trying to replace.

## Decision

AIOS will treat a conventional application primarily as one historical packaging of:

- domain objects;
- domain capabilities;
- provider engines;
- storage;
- UI/views;
- automation;
- import/export;
- permissions.

Native AIOS functionality should instead be decomposed into versioned **Domain Packs** containing semantic object/type contracts, semantic capability contracts, conformance tests, reference/third-party providers, optional views, adapters, policy profiles, and Skills.

Traditional applications remain supported through the Universal App Broker and may also act as capability providers.

## Consequences

### Positive

- AIOS tasks can compose functionality across domains without manually switching applications.
- Specialized engines can be replaced independently.
- Multiple providers can compete behind one semantic capability.
- Human UIs can evolve independently from object lifetime and automation.
- Legacy software can provide coverage during migration.
- Cross-domain AI planning has a stable semantic target.

### Negative / cost

- Semantic contract design becomes a major platform responsibility.
- Domain modeling is difficult and requires subject-matter expertise.
- Some mature applications contain tightly coupled workflows that will not decompose cleanly at first.
- Conformance testing and version evolution require sustained governance.
- The platform must avoid creating an over-generalized ontology that loses domain precision.

## Constraints

1. Domain Packs MUST NOT gain ambient authority.
2. Domain semantic meaning MUST remain distinct from provider implementation.
3. Specialized deterministic engines MUST be used where correctness/performance demands them; AI reasoning is not a substitute for geometry, simulation, accounting, database, or similar engines.
4. User data MUST remain exportable in ordinary documented formats where practical.
5. AIOS MUST support legacy applications during transition rather than requiring complete native reimplementation before adoption.
6. Implementations inspired by existing software MUST respect applicable source-code, asset, trademark, patent, format, and license constraints; the architecture calls for independent interoperable capabilities, not unauthorized copying.

## Related

- `docs/40-universal-software-fabric.md`
- `docs/41-domain-capability-architecture.md`
- `docs/42-universal-object-graph-and-data-federation.md`
- ADR 0003 — task-first primary abstraction
- ADR 0005 — legacy applications via habitats
- ADR 0013 — semantic capability contracts separate from providers
