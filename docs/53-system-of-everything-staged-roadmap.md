# 53 — System-of-Everything Staged Roadmap

## Mission

The long-term objective is intentionally expansive:

> Build an open AI-native computing platform in which programming, applications, data, devices, networks, cloud services, storage, identities, software distribution, and domain software progressively converge behind one task-first semantic operating model.

That end state cannot be implemented as one giant project plan.

The architecture must therefore make **universal scope compatible with narrow staged execution**.

## Strategic rule

> **At every stage, build the smallest substrate that makes the next ten categories easier rather than implementing one category as a special case.**

This is the prioritization rule for the project.

## End-state stack

```text
Human / Organization Intent
            ↓
Task + Policy + Provenance
            ↓
AIOS IR / future AI-native language
            ↓
Universal Semantic Object Graph
            ↓
Universal Software Fabric / Domain Packs
            ↓
Capability + Provider Ecosystem
            ↓
Presentation Fabric
Network / Service Fabric
Resource / Personal Compute Fabric
Storage / Namespace Fabric
Identity / Trust / Credential Fabric
Component Distribution / Supply Chain Fabric
Cloud / Edge Fabric
Compatibility Fabric
            ↓
Linux + hardware + mature low-level ecosystems
```

The layers are coupled through contracts, not one monolithic binary.

## Stage 0 — Architecture constitution

Status: **current**.

Goal: prevent implementation convenience from defining the platform accidentally.

Required outputs:

- system invariants;
- Task/Artifact/Object semantics;
- authority/effect model;
- AIOS IR;
- semantic types/capabilities;
- provider contracts;
- provenance;
- resource placement;
- presentation/network/cloud interfaces;
- storage/replica/namespace model;
- cryptographic identity/credential boundary;
- component distribution/update-trust boundary;
- Universal Software Fabric scaling model;
- compatibility strategy;
- recovery model;
- bounded implementation issues.

Exit gate:

> A developer/Codex task can implement a component without deciding what the OS fundamentally means.

See `docs/59-pre-codex-foundation-closure-plan.md` for the closure criteria separating must-settle, interface-only, and deliberately deferred decisions.

## Stage 1 — Trusted semantic substrate

Working target: **v0.1 core**.

Implement only the deterministic foundation needed to prove the architecture:

```text
Task persistence/state machine
Artifact store/handles + content hashes
Provenance log
Semantic registry
AIOS IR parser/validator/canonicalizer
Effect/authority summary
Capability registry/conformance
Policy/authority coordinator
opaque credential-handle boundary
Execution Binding
provider/component build/version attribution
basic provider supervisor
local transactional persistence/recovery
```

The first local Artifact store should already distinguish Artifact identity from host path so later storage/replica implementations do not require identity migration.

No polished desktop required.

No broad software suite required.

No universal networking required.

No public package marketplace required.

Exit gate:

- valid semantic program executes deterministic fixture providers;
- malformed/hostile program fails closed;
- provider substitution works;
- restart recovery works;
- authority/provenance remain correct;
- provider/component version is attributable;
- fixture providers do not require ambient filesystem/network/secret access.

## Stage 2 — Adaptive orchestration

Add intelligence without making intelligence the enforcement layer.

```text
model runtime interface
planner -> AIOS IR proposal
Resource Broker
hardware/resource profiler
local/remote policy routing
verification nodes
Skill reuse
compiled deterministic subgraph experiment
```

Exit gate:

- flagship Task works from high-level intent;
- numerical/factual deterministic claims are independently verifiable;
- same semantic program can be placed differently without semantic rewrite;
- repeated work demonstrates measurable reduction in planning/model use.

## Stage 3 — Task-first adaptive shell

Build the first real human experience.

Priorities:

```text
Task home/history
intent input
artifact/object attachment
approval UI
progress/recovery
provenance inspection
result/artifact presentation
traditional-app escape hatch
adaptive compact/desktop Views
basic workspace/namespace projection
```

The Presentation Broker begins here.

Exit gate:

- ordinary Demonstration A use no longer feels like a developer CLI;
- phone/compact and desktop simulation expose the same Task with different projections;
- privileged approvals use trusted system UI;
- path/namespace presentation does not redefine Artifact/Object identity.

## Stage 4 — Personal Compute + Network + Storage Fabric

Connect the user's devices before making public cloud central.

Implement:

```text
stable peer identity/pairing
authenticated encrypted peer sessions
resource/capability advertisement
content-addressed transfer
Network Broker
transfer provenance
peer placement
resumable transfer
peer Artifact replica/mirror
source-of-truth-safe synchronization
basic remote surface support
key rotation/revocation for paired devices
```

Exit gate:

- laptop can place eligible work on paired workstation;
- phone/laptop/workstation retain one Task identity;
- confidential data can be restricted to the personal trust domain;
- network loss/reconnect is recoverable;
- a peer replica can fail/recover without changing Artifact/Object identity;
- revoking a lost peer does not invalidate historical provenance.

## Stage 5 — Universal Object Graph + Tier-0 Software Fabric

Now begin attacking application/data fragmentation directly.

Implement a narrow but reusable first object set:

```text
Party
Document
Dataset
Message/Conversation
CalendarEvent
Project/TaskItem
Product
Quote/Invoice/Payment (draft/reference scope first)
```

Implement:

- stable object identity;
- source-of-truth/federation metadata;
- relationships;
- identity-resolution proposals;
- explicit merge/split;
- optimistic revision updates;
- object/Artifact replica linkage;
- first Domain Pack manifests;
- first cross-domain Task.

Exit gate:

> One Task crosses at least three former application categories without point-to-point application integration.

## Stage 6 — General productivity/business coverage

Expand by dependency leverage:

### Knowledge/office

- structured documents;
- tables/spreadsheets;
- presentations;
- PDF/forms;
- search/notes/knowledge.

### Business foundation

- CRM basics;
- quoting;
- billing/invoice drafts;
- project/work management;
- inventory/order primitives;
- analytics/BI;
- communication/calendar.

Use the coverage ladder:

```text
legacy bridge
→ external provider
→ open-engine adapter
→ AIOS-native provider
→ optimized/multiple providers
```

At this stage, the component distribution pipeline should be able to stage/verify/activate Domain Packs/providers and expose authority/semantic diffs during updates.

Do not wait for native perfection before enabling useful workflows.

Exit gate:

- meaningful small-business/knowledge workflows can run task-first;
- at least one domain has multiple conforming providers;
- portable import/export is demonstrated;
- one provider/Domain-Pack update demonstrates safe staged activation/rollback.

## Stage 7 — Creative + developer fabric

Add domains with high composability and mature open engines:

- raster/vector graphics;
- page/layout;
- audio/video pipelines;
- 3D scene/assets;
- source editing;
- build/test/debug/profile;
- repositories/CI;
- database development;
- web/app workflows.

Specialized Views become important here; natural language is not sufficient for every expert task.

Storage Fabric must handle large/streamed/partially materialized assets rather than copying every dataset through the control-plane database.

Exit gate:

- one Task composes media/code/data/document capabilities;
- direct manipulation and AI orchestration coexist cleanly;
- large Artifact handling demonstrates streaming/chunk/locality behavior.

## Stage 8 — Engineering fabric

Only after object/capability/view/resource foundations are proven should the project tackle the most demanding specialist domains broadly:

```text
2D/3D parametric CAD
assemblies/BOM
CAE/simulation
CAM
EDA/schematic/PCB
circuit simulation
FPGA/HDL
GIS
BIM
scientific computing
```

Reuse mature geometry, solver, compiler, simulation, and rendering engines aggressively where appropriate.

AIOS owns semantics, orchestration, policy, provenance, interoperability, and user experience before it owns every numerical kernel.

Exit gate:

- engineering objects connect natively to Product/BOM/costing/documentation/project objects;
- deterministic engineering rules remain outside unconstrained model reasoning;
- expert Views meet real direct-manipulation needs;
- large source/derived engineering representations preserve object identity across storage/provider changes.

## Stage 9 — Cloud / organization / collaboration fabric

Cloud comes after local and peer semantics are stable enough that cloud does not define them.

Implement progressively:

- remote Task workers;
- object/artifact sync/replication;
- collaboration sessions;
- self-hostable services;
- organization identity/policy;
- private/public cloud adapters;
- managed edge;
- cost/residency policy;
- organization secret/credential brokers;
- backup/archive;
- package/provider mirrors/registries;
- remote render/build/model pools.

Exit gate:

- same semantic workload can move among local, peer, self-hosted, and public-cloud candidates;
- cloud outage does not destroy local control-plane understanding;
- provider portability is demonstrated where claimed;
- cloud replica/provider changes do not alter Object/Task semantic identity;
- organization credential/publisher trust remains separable from runtime authorization.

## Stage 10 — Physical/ambient computing

Extend the capability fabric to devices and environments:

- home automation;
- sensors;
- labs;
- manufacturing;
- robotics;
- vehicles;
- cameras;
- printers/fabrication;
- industrial gateways.

Safety-critical real-time control must retain specialized deterministic/safety-certified boundaries where applicable.

The AIOS layer orchestrates intent and capability; it does not pretend an LLM is a motor controller or safety PLC.

## Stage 11 — Language/toolchain maturation

This stage runs in parallel but only escalates when evidence justifies it.

Progression:

```text
JSON structural AIOS IR
→ optimized binary/structural IR
→ human/AI-oriented source syntax
→ compiler/optimizer ecosystem
→ increasing self-hosting
→ re-evaluate Rust/C/C++ lower layers
```

A full custom language/runtime proceeds only when benchmarks/security/generation quality show real advantage.

## Stage 12 — System of Everything

This is not a version number with a finish date.

It is an operating principle:

- every useful software category can become a Domain Pack/capability set;
- every useful compute target can become a provider/placement target;
- every relevant device can expose capabilities;
- every user object can retain semantic identity across systems/storage locations;
- every workflow can be decomposed into inspectable, authorized, recoverable Tasks;
- software/components can expand continuously through inspectable supply-chain/update boundaries;
- legacy/application boundaries progressively become optional rather than mandatory.

The platform is never "complete." Coverage expands continuously.

## Parallel tracks

Stages are dependency priorities, not a ban on parallel research.

Safe parallel tracks include:

```text
A. semantic core / validator
B. security / policy / recovery / credential mediation
C. Resource + Network + Storage Fabric research
D. Presentation/View contracts
E. Universal Object/Domain contracts
F. compatibility adapters
G. compiler/Wasm/MLIR experiments
H. component distribution / supply-chain / licensing / conformance
I. cloud/org/collaboration research
```

Implementation should merge only when dependencies and invariants are satisfied.

## Anti-scope-explosion rules

For every proposed feature ask:

1. Does it prove a foundational abstraction?
2. Does it unlock many later domains?
3. Does it close a major security/recovery gap?
4. Is it required for the current stage exit gate?
5. Can an existing engine/provider satisfy it temporarily?

If the answer is no to all five, defer it.

Examples of things to defer early:

- polishing dozens of desktop widgets;
- native implementation of every office format;
- complete CAD feature parity;
- multi-cloud orchestration before one remote provider works;
- universal mesh networking before basic peer transfer works;
- distributed filesystem work before the local Artifact identity/replica contracts are proven;
- public package marketplace before staged local component activation works;
- custom kernel/driver stack;
- full custom language compiler before IR benchmarks.

## Priority order from this point

The current recommended order is:

```text
1. Finish semantic contracts/validator readiness
2. Finish authority + local persistence + effect + credential-handle contracts
3. Implement v0.1 trusted substrate
4. Add planner/model + resource placement
5. Add task-first adaptive shell + basic namespace projection
6. Add peer/network + first replica/storage fabric
7. Add Tier-0 object graph / first cross-domain Domain Pack
8. Add safe component activation/update pipeline as ecosystem coverage grows
9. Expand productivity/business capability coverage
10. Expand creative/developer capability coverage
11. Expand engineering capability coverage
12. Scale cloud/org/edge/collaboration/storage services
13. Continue toward universal coverage indefinitely
```

This keeps the project's ambition intact without allowing the ambition to prevent us from producing the first working system.

## Principle

> **The ultimate scope can be everything, but the next implementation milestone must always be small enough to test.**
