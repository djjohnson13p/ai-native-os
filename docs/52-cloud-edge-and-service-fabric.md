# 52 — Cloud, Edge, and Service Fabric

## Purpose

AIOS should be able to use cloud infrastructure extensively without becoming dependent on one cloud vendor, one account, or even the presence of cloud connectivity.

Cloud is a **placement and service domain**, not the architectural center of the operating system.

The same semantic Task should be able to run:

- entirely on one device;
- across user-owned peers;
- on an organization-managed edge/server;
- on a private cloud;
- on public cloud providers;
- through specialized SaaS/model services;
- or in a hybrid combination.

## Principle

> **The cloud expands the user's available capability and compute pool; it does not own the meaning of the Task or become the mandatory source of truth.**

## Service classes

AIOS should distinguish several remote infrastructure roles.

```text
REMOTE_COMPUTE
REMOTE_MODEL
OBJECT_STORAGE
SYNC_REPLICA
DATABASE_SERVICE
DOMAIN_PROVIDER
RENDER/BUILD_FARM
MANAGED_EDGE
RELAY
DIRECTORY/REGISTRY
BACKUP/ARCHIVE
COLLABORATION_SERVICE
```

One provider can implement multiple classes, but the semantic contracts remain separate.

## Deployment topologies

### Device-local

Everything required by the Task runs on the current device.

### Personal fabric

User-owned devices provide compute/storage/services.

### Home/private edge

A home server/NAS/workstation cluster supplies durable storage, models, media processing, builds, rendering, etc.

### Organization edge

Company-managed infrastructure provides controlled services near users/data/devices.

### Private cloud

Organization/user controls the infrastructure or tenant with explicit operational policy.

### Public cloud

AIOS binds to cloud-hosted providers under cost, privacy, locality, identity, and egress policy.

### SaaS / specialist provider

External service implements a narrow semantic capability such as OCR, payment gateway, model reasoning, geocoding, simulation, or compliance service.

## Control-plane independence

The local AIOS control plane should retain enough state to understand:

- Task identity/state;
- semantic program identity;
- current policy;
- object/artifact references;
- outstanding remote operations;
- provenance;
- recovery status.

A remote service outage must not erase the user's ability to understand what the machine was doing.

## Remote execution unit

Remote placement should transmit a bounded execution package/reference set rather than upload an unrestricted user environment.

A remote execution request should identify:

```text
task / node
semantic program hash
capability contract
provider contract
input artifact/object references
content hashes
policy/egress decision
required isolation
resource requirements
output allocation/return contract
operation/idempotency identity
expiry/deadline
```

Long-lived user secrets should be replaced with scoped/short-lived credentials where possible.

## Data locality

The Resource Broker should consider where authoritative/large data already resides.

Example:

```text
2 GB dataset on laptop
800 GB media library on home server
CAD assembly on workstation
company database in managed cloud region
```

Computation should often move toward the data instead of blindly copying data toward the strongest processor.

This decision remains subordinate to policy and semantic requirements.

## Cloud object/storage model

AIOS should distinguish:

- semantic object identity;
- artifact/content identity;
- replica/cache location;
- authoritative source state;
- backup/archive state.

A cloud bucket/file path is a storage location, not the identity of the user's Document/Product/Task.

This allows replicas to move between local storage, NAS, and cloud object stores without changing semantic identity.

## Sync

Synchronization should be explicit about consistency semantics.

Possible classes:

```text
LOCAL_ONLY
BACKUP_ONLY
ASYNC_REPLICA
MULTI_WRITER
AUTHORITATIVE_REMOTE
AUTHORITATIVE_LOCAL
FEDERATED_EXTERNAL
```

Not every object needs real-time multi-writer sync.

The system should avoid building a universal conflict-free abstraction where domain correctness requires stronger semantics.

## Collaboration

Real-time collaborative editing is a domain/view capability, not proof that every data structure should use one collaboration algorithm.

Different domains may use:

- operation transforms;
- CRDTs;
- optimistic transactions;
- branch/merge;
- locks/leases;
- append-only event logs;
- domain-specific merge logic.

AIOS should expose shared identity, authorization, provenance, and session primitives while allowing the domain to choose the correct collaboration model.

## Cloud provider portability

AIOS should own interfaces above vendor infrastructure.

Infrastructure adapters can map to provider-specific services for:

- virtual machines;
- containers;
- GPUs;
- object storage;
- databases;
- queues;
- secrets/KMS;
- load balancing;
- edge/serverless functions.

But an AIOS Task should not semantically depend on a particular vendor resource name unless the user intentionally requested that vendor-specific service.

## Multi-cloud and failover

Multi-cloud should not be pursued as a slogan.

A service becomes portable when:

- semantic capability contract is provider-neutral;
- data representation is portable or convertible;
- state/recovery semantics are known;
- credentials/policy exist for alternatives;
- switching cost is measured;
- conformance tests prove equivalent behavior.

Critical infrastructure may support warm/cold alternatives, but unnecessary duplication wastes cost and complexity.

## Cost governance

Remote compute introduces monetary effects that local software historically hides less often.

The system should support:

```text
per-task budget
per-capability ceiling
monthly/user/org budget
approval threshold
estimated vs actual cost
provider rate metadata
spot/preemptible eligibility
batch/deferred pricing preference
```

Cost is a runtime constraint and provenance fact.

A model cannot approve spending merely by deciding stronger compute would be helpful.

## Cloud privacy and residency

Remote eligibility may depend on:

- object/artifact sensitivity;
- organization policy;
- region/jurisdiction;
- provider contract/trust;
- retention/training terms;
- encryption capability;
- data-processing agreement;
- user choice.

These are hard filters before objective optimization.

## Trusted execution / confidential compute

Where hardware-supported confidential execution is available, it may become an additional candidate trust/isolation attribute.

It does not magically make an otherwise unauthorized remote provider eligible.

Remote attestation can strengthen a trust decision but does not replace semantic policy.

## Managed service lifecycle

AIOS-managed remote services should have explicit lifecycle state:

```text
DECLARED
PROVISIONING
READY
DEGRADED
DRAINING
OFFLINE
FAILED
REVOKED
```

Provisioning, credentials, configuration, updates, and teardown need provenance and rollback/recovery rules.

## Self-hosting

A serious open platform should allow users/organizations to host eligible services themselves.

Self-hostable reference services may eventually include:

- object/artifact synchronization;
- semantic registry mirror;
- model serving;
- build/render workers;
- collaboration relay;
- backup/archive;
- organization policy/directory;
- remote Task worker.

Self-hosting is not mandatory for every specialist capability, but core platform operation should not require one proprietary cloud account.

## Edge devices and gateways

The Service Fabric should extend below conventional PCs into:

- home automation hubs;
- industrial gateways;
- robots;
- vehicles;
- lab equipment;
- sensors;
- cameras;
- manufacturing equipment.

These devices may expose narrow semantic capabilities rather than running the full AIOS user environment.

Example:

```text
sensor.temperature.read@1
machine.job.status@1
printer.fabricate@1
camera.capture@1
robot.move_fixture@1
```

Safety-critical physical control requires domain-specific hard real-time/safety systems and must not be delegated to unconstrained language-model output.

## Cloud-native applications vs AIOS-native services

AIOS should prefer decomposed capability services rather than moving monolithic application architecture unchanged into the cloud.

For example, instead of a cloud CRM being the only path:

```text
Party/Opportunity semantic objects
+ CRM capability contracts
+ local/federated/cloud providers
+ optional CRM View
```

The same architecture applies to billing, databases, engineering, media, and development infrastructure.

## v0.1 scope

Cloud work before the local substrate is stable should remain narrow.

The prototype only needs:

1. one simulated or test remote provider;
2. explicit egress authorization;
3. placement/cost record;
4. cancellation/failure handling;
5. result artifact return;
6. proof that local-only mode remains functional;
7. no cloud requirement for boot/recovery.

## Principle

> **AIOS should be cloud-capable everywhere and cloud-dependent nowhere that does not inherently require a remote service.**
