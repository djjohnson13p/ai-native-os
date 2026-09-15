# 14 — Terminology and Core Abstractions

This document establishes a shared vocabulary for the architecture. Terms are intentionally narrower than ordinary AI-product language so that implementation discussions do not drift.

## Task

A **task** is the primary unit of user intent and system execution.

A task has:

- a user or system origin;
- an intent statement;
- constraints;
- authority boundaries;
- inputs and referenced data;
- a plan or plan history;
- execution state;
- outputs/artifacts;
- provenance;
- verification results;
- retention policy.

A task is not an application session. One task may use many capability providers and may outlive any individual process.

## Intent

**Intent** is a structured representation of what the user wants accomplished, not how to accomplish it.

Intent should capture outcome, constraints, preferences, deadlines, acceptable cost, privacy requirements, and approval boundaries when known.

## Plan

A **plan** is a typed, inspectable graph that proposes how to satisfy an intent.

A plan is not authority. Every side effect remains subject to deterministic policy and capability checks.

## Capability

A **capability** is a named, typed operation the system can invoke.

Examples:

```text
table.import
stats.summarize
chart.render
document.compose
image.mask
archive.extract
legacy.launch
network.fetch
```

Capabilities describe *what can be done*. Providers describe *how it is done*.

## Capability provider

A **capability provider** is an implementation of one or more capabilities. A provider may be:

- a deterministic native service;
- a command-line program;
- a WASM module;
- a sandboxed process;
- a local AI model;
- a remote AI/model service;
- a legacy application adapter;
- a hardware service;
- a peer device.

## Agent

An **agent** is a scoped reasoning worker operating on behalf of a task. An agent has no ambient user authority. It can only request or exercise capabilities granted to its task and principal.

## Artifact

An **artifact** is a durable or inspectable result of a task: a document, image, dataset, model output, source tree, rendered scene, executable, report, or other typed result.

Artifacts have stable identity, content hashes when practical, provenance links, sensitivity labels, and format metadata.

## Data handle

A **data handle** references data without requiring blind copying between providers. A handle carries policy-relevant metadata and can resolve to local, remote, streamed, encrypted, or generated content.

## Capability token

A **capability token** is a deterministic, scoped grant of authority. It binds a principal/task to allowed operations over specified resources for a limited period and context.

## Policy

**Policy** is the deterministic logic that decides whether a requested action is allowed, denied, or requires user approval.

AI may propose policy-relevant context; AI does not grant itself authority.

## Provenance

**Provenance** is the append-only history of what the system considered and did: inputs, plans, providers, permissions, external transfers, transformations, outputs, verification, approvals, failures, and rollback information.

## Skill

A **skill** is a reusable, versioned procedure learned or authored from one or more successful task patterns. A skill may contain deterministic and model-assisted steps.

A skill is not trusted merely because it was learned previously.

## Skill compilation

**Skill compilation** is the process of converting a repeated probabilistic workflow into a more deterministic, cheaper, testable procedure where safe.

## Resource broker

The **resource broker** decides *where* work should execute: local CPU/GPU/NPU, peer device, remote provider, container, VM, or deferred queue.

## Universal App Broker

The **Universal App Broker** accepts legacy software/package intent and routes it to the correct compatibility habitat. It may combine OS API translation, CPU architecture translation, containers, VMs, remote execution, and application-specific profiles.

"Universal" is an architectural goal, not a claim that every proprietary application can be made compatible.

## Habitat

A **habitat** is an execution environment that supplies the assumptions expected by a provider or legacy application: libraries, OS APIs, filesystem shape, registry/configuration, graphics stack, architecture translation, network policy, and sandboxing.

## Deterministic system base

The **deterministic system base** contains the components that must not depend on unconstrained model output for correctness: boot, hardware discovery, identity, policy enforcement, sandboxing, updates, rollback, recovery, secret storage, and the minimum trusted control plane.

## AI-native

**AI-native** means AI reasoning is represented as an explicit operating-system service and planning primitive with bounded authority, not merely embedded in a desktop application or assistant UI.

## Applicationless computing

**Applicationless computing** is the long-term interaction model in which users primarily request outcomes and manipulate artifacts/tasks rather than selecting monolithic applications. It does not mean traditional applications cease to exist; compatibility is a required transition path.
