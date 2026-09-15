# 00 — Project Charter

## Mission

Create an open-source, AI-native operating environment in which **human intent, tasks, agents, capabilities, policy, context, provenance, and hardware resources are first-class system objects**, while traditional software remains available through compatibility environments during the transition away from application-centric computing.

## The problem

Modern operating systems still organize user interaction around concepts inherited from earlier computing eras:

- applications;
- windows;
- files and folders;
- menus;
- explicit program selection;
- manual transfer of information between tools;
- operating-system-specific package formats;
- and human-operated graphical workflows.

AI systems can automate those interfaces, but automation through GUIs is an adaptation layer. It does not change the underlying abstraction.

The project asks a different question:

> If a computer were designed around machine reasoning and human intent from the beginning, what would replace the application as the primary unit of work?

Our working answer is: **the task**.

A task may require dozens of capabilities, some deterministic and some model-driven. The system should discover, authorize, schedule, compose, execute, verify, and record them without requiring the user to manually decide which application owns each step.

## Working definition

An AI-native operating system is not merely an OS with an assistant. It is a system where:

- user intent becomes a structured task;
- task execution is planned dynamically;
- software functionality is discoverable as capabilities;
- agents operate under task-scoped authority rather than inheriting all user privileges;
- hardware and compute location are scheduled according to capability, privacy, cost, latency, and energy constraints;
- repeated successful reasoning can be compiled into safer reusable procedures;
- traditional applications are treated as compatibility-hosted capability providers where possible;
- and the user can inspect how a result was produced.

## Strategic posture

### Reuse the mature base

The project should initially reuse a mature kernel and low-level userspace rather than spending years reproducing hardware support. Linux is the current baseline candidate because of its driver coverage, virtualization support, containers, namespaces, open development model, and broad architecture support.

### Replace the interaction model above the base

The innovation belongs primarily in:

- the intent/task graph;
- the capability broker;
- the agent runtime;
- the policy engine;
- the resource broker;
- the compatibility broker;
- the memory/learning layer;
- the provenance system;
- and the task-first human interface.

## Long-term outcome

At maturity, a user should be able to ask for an outcome without knowing which installed program, model, processor, device, or remote service is required. The system chooses among them while preserving user control and transparency.

The user should still be able to invoke a traditional application explicitly when desired. Applicationless computing is a destination, not a migration prerequisite.

## Project test

Every major architecture decision should answer this question:

> Does this move intelligence and capability composition into the operating model itself, or does it merely automate a conventional desktop?

If the answer is the latter, the design should be reconsidered.
