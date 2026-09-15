# 01 — Design Principles

## 1. The task is the primary user-level object

The operating environment organizes work around goals and tasks, not application launches.

A task has:

- an intent;
- inputs;
- constraints;
- required capabilities;
- permissions;
- a plan;
- execution state;
- outputs;
- provenance;
- and reusable learnings.

## 2. Capabilities are more fundamental than applications

An application can expose capabilities, but it is not the only provider type. A capability may be implemented by:

- a native deterministic service;
- a local AI model;
- a remote AI service;
- a command-line program;
- an existing desktop application;
- an Android application;
- a web service;
- a WASM component;
- a container;
- or a remote device.

## 3. Deterministic where possible, probabilistic where useful

AI should not be used merely because AI exists.

Examples:

- parsing a stable file format should normally be deterministic;
- calculating totals should normally be deterministic;
- selecting relevant evidence from ambiguous context may use AI;
- interpreting an underspecified human request may use AI;
- destructive actions require deterministic policy checks even when proposed by AI.

## 4. Reason once, compile when stable, reuse thereafter

The system should detect repeated successful task patterns and offer to convert them into reusable skills or deterministic procedures.

This reduces:

- inference cost;
- latency;
- nondeterminism;
- energy use;
- and repeated exposure of data to external models.

Compiled procedures remain inspectable and revocable.

## 5. Local-first privacy

The default policy is:

> Keep private data local unless a task explicitly permits a remote boundary crossing.

Remote execution must be visible in provenance.

## 6. Least authority for agents

Agents do not inherit the user's full authority. Every task receives narrow, revocable, time-bounded capabilities.

## 7. Hardware diversity is normal

The same system should scale from old or low-power devices to high-end workstations by changing execution strategy, not by changing the user's conceptual model.

## 8. Graceful degradation over installation rejection

Where practical, low-resource devices should run a reduced local control plane and use remote or peer compute for expensive tasks. The system must remain useful even when some capabilities are unavailable.

## 9. Models are replaceable infrastructure

No system ABI may require one AI vendor. Models are providers selected according to policy and task requirements.

## 10. Legacy applications are transitional capability islands

Existing software should remain usable through transparent habitats. Where feasible, the system can learn how a legacy program exposes useful functions and present those functions as capabilities.

## 11. Provenance is mandatory

For meaningful operations, the system records:

- what data was read;
- which capabilities ran;
- which model/provider was used;
- what crossed a device or trust boundary;
- what modifications were made;
- and which human approvals were required.

## 12. Recovery outranks autonomy

A system that cannot reliably recover should not autonomously modify critical state.

Boot, rollback, policy, package trust, and recovery remain intentionally conservative.
