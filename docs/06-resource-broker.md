# 06 — Resource Broker

## Purpose

The resource broker maps task requirements onto available compute without forcing the user to care where execution happens.

It treats hardware availability as a first-class system input.

## Resource inventory

The broker consumes a normalized hardware profile including:

- CPU architecture and features;
- logical/physical cores;
- RAM and memory pressure;
- GPU/NPU availability;
- accelerator memory;
- storage type and free space;
- network quality and metering;
- battery/energy state;
- thermal limits;
- trusted peer devices;
- remote providers permitted by policy.

A draft schema exists at [`../specs/hardware-profile.schema.json`](../specs/hardware-profile.schema.json).

## Execution modes

### Local

All computation occurs on the current device.

Best for:

- sensitive data;
- deterministic operations;
- low-latency actions;
- offline use;
- low-cost tasks.

### Hybrid

Sensitive preprocessing occurs locally, with selected non-sensitive or minimized context sent to remote compute.

### Peer

Work is scheduled to another trusted user-owned device.

Example: a phone requests a 3D render from a home workstation.

### Remote

A permitted remote provider executes the task.

### Deferred

Expensive non-urgent work waits for power, network, thermal, or resource conditions to improve.

## Placement policy

A placement decision should consider:

```text
privacy > authority > correctness > availability > latency > cost > energy
```

The exact ordering can be policy-driven, but privacy and authority are hard constraints.

## Model routing

The broker should support tiered reasoning:

```text
simple classification       → tiny local model
structured extraction       → local/small model
routine deterministic work  → compiled procedure
complex reasoning           → stronger local or remote model
specialized vision/audio    → specialist provider
```

This is essential to the long-term efficiency goal.
