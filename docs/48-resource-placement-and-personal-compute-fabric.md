# 48 — Adaptive Resource Placement and Personal Compute Fabric

## Purpose

AIOS should preserve one semantic operating model across old laptops, phones, desktops, workstations, servers, accelerators, trusted user-owned peers, and permitted remote compute.

Hardware should change **where/how** a semantic capability runs, not what the Task means.

This document turns the Resource Broker concept into a deterministic placement pipeline.

## Core invariant

For a validated semantic node:

```text
semantic_program_hash
capability contract
input semantic types
requested effects/authority
verification requirements
```

must remain stable when execution moves between eligible providers/devices.

Placement changes create a new Execution Binding, not a new semantic program.

## Static profile vs dynamic snapshot

AIOS should distinguish:

### Hardware Profile

Relatively stable facts:

- CPU architecture/features;
- total cores/memory;
- accelerator devices/backends;
- storage classes;
- security/isolation capabilities;
- platform/firmware characteristics.

### Resource Snapshot

Time-sensitive facts:

- currently available memory;
- CPU/GPU/NPU utilization;
- free accelerator memory;
- thermal state;
- battery/power state;
- network latency/bandwidth/metering;
- storage pressure;
- provider queue/health;
- peer reachability;
- estimated monetary/energy cost.

A provider can be hardware-compatible yet temporarily ineligible because current resources are insufficient.

## Candidate placement classes

```text
LOCAL_CURRENT_DEVICE
LOCAL_SANDBOX
LOCAL_ACCELERATOR
TRUSTED_PEER
MANAGED_EDGE
REMOTE_PROVIDER
DEFERRED
UNAVAILABLE
```

`DEFERRED` is a deliberate outcome when constraints can likely be satisfied later without changing semantics.

## Two-stage selection

### Stage 1 — hard eligibility

A candidate is removed if it violates any hard requirement.

Examples:

- policy forbids remote egress;
- input sensitivity exceeds provider allowance;
- architecture/backend is incompatible;
- required semantic capability/version absent;
- provider conformance/trust below minimum;
- insufficient memory/device capability;
- required isolation cannot be established;
- task requires offline execution but candidate is remote;
- latency/cost deadline is a hard user/policy constraint;
- legal/jurisdiction/data-residency rule excludes candidate.

Hard constraints are never traded away for speed or model quality.

### Stage 2 — objective ranking

Eligible candidates receive a policy-controlled score.

Potential objective dimensions:

```text
quality/reliability
latency
memory pressure
data movement
energy/battery
monetary cost
thermal impact
startup/warm-cache cost
provider availability
user preference
locality preference
future reuse/cache value
```

No one universal weight set is correct. Profiles may prefer privacy/locality, battery life, lowest cost, lowest latency, or maximum quality.

## Lexicographic safety before scoring

The Resource Broker should not collapse safety/policy and convenience into one weighted score.

Conceptually:

```text
1. semantic compatibility
2. authority/policy eligibility
3. security/isolation eligibility
4. correctness/conformance eligibility
5. resource feasibility
6. objective optimization among remaining candidates
```

A remote model with a fantastic performance score cannot outscore a `local-only` rule because it never enters the eligible set.

## Explainable placement decision

Every decision should produce structured reason codes.

Example:

```text
selected: peer://home-workstation/gpu0

rejected local laptop GPU:
  INSUFFICIENT_ACCELERATOR_MEMORY

rejected remote provider:
  POLICY_REMOTE_EGRESS_DENIED

selected peer over CPU fallback:
  LOWER_ESTIMATED_LATENCY
  LOWER_LOCAL_THERMAL_COST
  SAME_TRUST_DOMAIN
```

The UI can summarize this as:

> Rendering on your workstation because this laptop lacks sufficient GPU memory; your files remain within your paired devices.

## Personal compute fabric

Trusted user-owned devices can form a **Personal Compute Fabric**.

Examples:

```text
phone
laptop
home workstation
desktop GPU
home server/NAS
headless accelerator box
```

Each peer advertises bounded capability/resource summaries under explicit trust/pairing.

The system should not treat a paired device as automatically equivalent to the current device.

Peer policy considers:

- ownership/trust state;
- current user/session authorization;
- encryption/authentication;
- data sensitivity;
- physical/network reachability;
- remote-unlock status;
- hardware attestation where useful/available;
- allowed capabilities;
- retention/caching policy.

## Work migration

For pure/deterministic capability nodes, migration can be straightforward if inputs are content-addressed and authority remains valid.

For stateful/opaque/legacy nodes, migration may be impossible or require checkpoint support.

Migration eligibility should therefore be declared per provider/capability.

Possible classes:

```text
NON_MIGRATABLE
RESTARTABLE
CHECKPOINTABLE
REPLICABLE
STATELESS
```

## Data movement as a first-class cost

Moving 20 GB of CAD/video/model data to a remote GPU can cost more time/energy than running slower locally.

Placement estimates should account for:

```text
input bytes not already present
output bytes
network throughput/latency
compression/conversion cost
cache hit probability
sensitivity/egress rules
```

The broker should prefer computation near authoritative/large data when practical.

## Model placement

Model routing is a special case of provider placement.

Candidate model descriptors include:

- semantic capabilities/modalities;
- context limits;
- hardware/backend requirements;
- quantization/precision;
- expected quality class;
- memory footprint;
- warm/cold load cost;
- privacy/locality;
- price/rate limits for remote providers.

Escalation can be bounded:

```text
compiled Skill
→ tiny local model
→ larger local model
→ trusted peer model
→ policy-permitted remote model
```

The Task does not automatically escalate merely because a provider failed; escalation must remain within privacy/cost/authority policy.

## Graceful degradation

An old or constrained device should remain useful if it can run the deterministic base.

Examples:

- no NPU/GPU → CPU or peer/remote provider;
- low RAM → smaller streaming provider;
- offline → installed deterministic providers/local model only;
- weak CPU → defer heavy compilation/rendering;
- battery low → avoid local high-power provider unless urgent;
- no virtualization → exclude providers requiring VM isolation.

The system reports capability constraints rather than declaring the whole OS unsupported.

## Capability classes instead of device editions

Avoid fixed product editions such as "AIOS Lite" vs "AIOS Pro" as the fundamental architecture.

A device has a current effective capability set derived from:

```text
hardware profile
+ resource snapshot
+ installed providers
+ paired peers
+ policy
+ network availability
+ user/org configuration
```

That set can change dynamically.

## Scheduling fairness and reservations

Long-running tasks should not starve interactive work.

The broker/scheduler should eventually support:

- task priority/urgency;
- interactive vs batch classes;
- memory/accelerator reservations;
- background throttling;
- thermal/battery budgets;
- per-user/org quotas;
- remote cost budgets.

AI may recommend scheduling changes, but hard resource reservations/limits are deterministic.

## Failure and rebinding

When a provider/device fails:

1. persist failure/provenance;
2. determine side-effect certainty;
3. preserve semantic node identity;
4. invalidate the failed Execution Binding;
5. re-evaluate eligible candidates;
6. create a new binding if retry/fallback is safe;
7. never reuse an old grant if its scope/expiry/provider binding is no longer valid.

## Reference example

Task node:

```text
capability: engineering.drawing.render@1
input: object://engineering/enclosure-r7
```

Candidates:

```text
Laptop CPU provider
  eligible, estimated 48 s

Laptop integrated GPU provider
  rejected: insufficient memory

Paired workstation GPU provider
  eligible, estimated transfer+render 7 s

Remote cloud renderer
  rejected: confidential design / remote egress denied
```

Selected:

```text
TRUSTED_PEER: paired workstation GPU
```

The semantic program hash does not change.

## Future distributed concerns

Later phases may need:

- distributed leases;
- peer capability discovery;
- secure content-addressed transfer;
- resumable streams;
- remote attestation;
- multi-device artifact cache;
- clock/replay handling;
- split computation;
- accelerator topology awareness.

None requires changing the principle that semantic identity and authorization are above placement.

## Principle

> **The user owns a pool of compute, not a pile of separate devices. AIOS should use that pool under explicit policy while preserving one semantic Task model.**
