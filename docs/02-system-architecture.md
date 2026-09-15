# 02 — System Architecture

## High-level stack

```text
┌──────────────────────────────────────────────────────────────┐
│                        Human / External Intent               │
│          voice · text · gesture · automation · API           │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Intent & Task Layer                                          │
│ interpret · clarify · decompose · track · explain            │
└──────────────────────────────┬───────────────────────────────┘
                               │ Task Graph
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Orchestration Plane                                          │
│ planner · capability broker · policy engine · agent runtime  │
│ verifier · provenance · skill compiler                       │
└───────────────┬──────────────────────┬───────────────────────┘
                │                      │
                ▼                      ▼
┌──────────────────────────┐  ┌───────────────────────────────┐
│ Resource Broker          │  │ Universal App Broker          │
│ CPU/GPU/NPU/RAM/network  │  │ native · Linux · Win ·       │
│ local/peer/remote        │  │ Android · web · VM/container │
└──────────────┬───────────┘  └───────────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Execution Plane                                              │
│ deterministic services · models · WASM · containers · VMs   │
│ legacy applications · remote services · peer devices        │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Deterministic System Base                                    │
│ kernel · drivers · storage · network · identity · sandboxing │
│ secure boot · rollback · update · recovery                   │
└──────────────────────────────────────────────────────────────┘
```

## Control plane vs execution plane

The architecture separates *deciding what should happen* from *performing the work*.

### Control plane

Responsible for:

- interpreting intent;
- task planning;
- capability resolution;
- policy checks;
- permission grants;
- compute placement;
- execution monitoring;
- verification;
- provenance;
- learning reusable procedures.

### Execution plane

Responsible for:

- running deterministic programs;
- invoking models;
- running compatibility environments;
- rendering documents/images/3D scenes;
- executing data transforms;
- operating hardware;
- performing remote calls.

This separation lets the system replace providers without rewriting the operating model.

## Core services

### Intent Service

Converts human input into a structured task definition. It may ask for clarification only when ambiguity materially affects outcome, authority, cost, or safety.

### Task Manager

Owns task lifecycle and state transitions.

Suggested states:

```text
CREATED → PLANNING → WAITING_FOR_AUTH → RUNNABLE → RUNNING
        → VERIFYING → COMPLETED
                         ↘ FAILED
                         ↘ ROLLED_BACK
                         ↘ PAUSED
```

### Capability Broker

Maintains a registry of available functionality and provider metadata.

### Policy Engine

Determines whether a proposed action is allowed under user, device, organization, and task policy.

### Agent Runtime

Runs scoped reasoning workers under explicit authority.

### Resource Broker

Chooses where and how work executes based on hardware, privacy, latency, energy, cost, and availability.

### Universal App Broker

Routes legacy packages and applications into the appropriate execution habitat.

### Provenance Service

Creates an append-only task history suitable for user inspection and debugging.

### Skill Compiler

Converts stable recurring plans into reusable deterministic or semi-deterministic procedures after validation.

## Data plane

Data should be referenced through typed handles instead of copied blindly among applications.

Examples:

```text
data://local/documents/report-2026-09
artifact://task/83/output/chart-2
secret://vault/provider-token/openai
stream://camera/front
model://local/text-small
```

Handles can carry:

- ownership;
- sensitivity labels;
- retention policy;
- allowed transforms;
- trust boundaries;
- content hash;
- provenance linkage.

This is intended to reduce unnecessary copies and prevent arbitrary provider access.
