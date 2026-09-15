# ADR 0023 — Cloud Is a Provider/Placement Domain, Not Semantic Authority

- Status: **Proposed**
- Date: 2026-09-15

## Context

AIOS should be able to use powerful public cloud, private cloud, self-hosted servers, managed edge, and specialist SaaS/model providers while remaining useful offline and avoiding semantic lock-in to one infrastructure vendor.

If cloud resource names, APIs, or storage locations define Task/object meaning, portability and local-first operation disappear.

## Decision

Cloud/edge services are provider and placement classes below AIOS semantic contracts.

Task identity, semantic program identity, object identity, authority, and provenance remain AIOS concepts independent of the chosen cloud provider.

A cloud storage path is a representation/location, not object identity. A cloud compute instance is an execution target, not Task identity. A SaaS record may remain an external source of truth, but it is represented through federation rather than becoming the universal semantic model.

## Requirements

- boot/recovery must not require public cloud;
- remote use requires explicit policy/egress eligibility;
- cost and residency can be hard constraints;
- provider-specific adapters remain below provider-neutral semantic contracts;
- self-hosted alternatives should be possible for eligible core services;
- remote failures remain recoverable/inspectable locally.

## Consequences

### Positive

- cloud can scale compute/services without owning architecture;
- multi-provider/self-hosted paths remain possible;
- users can stay local/offline where practical;
- infrastructure can change without object/task migrations.

### Costs

- AIOS must maintain abstraction and conformance layers;
- provider-specific optimizations need separate runtime bindings;
- remote state consistency/recovery must be explicit.

## Related

- `docs/52-cloud-edge-and-service-fabric.md`
- `docs/48-resource-placement-and-personal-compute-fabric.md`
- `specs/remote-service-descriptor.schema.json`
- ADR 0020
