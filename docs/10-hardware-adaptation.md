# 10 — Hardware Adaptation and Installation

## Principle

The operating environment should adapt to hardware rather than assume a narrow reference machine.

## Deterministic bootstrap

The earliest boot/install stages should remain minimal and deterministic.

They are responsible for:

- CPU architecture detection;
- memory discovery;
- storage enumeration;
- firmware/boot mode;
- display and input basics;
- network availability;
- accelerator discovery;
- secure-boot/TPM-equivalent features when present;
- recovery environment.

AI may assist **after** a trustworthy hardware profile exists, but should not invent privileged drivers during the critical boot path.

## Hardware profile

The installer creates a normalized profile used by the resource broker.

Example:

```yaml
cpu:
  architecture: x86_64
  cores: 8
memory:
  total_gib: 16
gpu:
  class: integrated
  vram_gib: 2
network:
  status: available
ai_tier:
  local_reasoning: small
  local_vision: constrained
  recommended_mode: hybrid
```

## Installation classes

Rather than fixed editions, the installer composes services according to capability.

Possible resulting profiles:

### Control-plane thin

For very low-resource hardware. Runs deterministic services and light local intelligence, delegating expensive tasks when permitted.

### Balanced local

Runs routine models and document/data capabilities locally, with optional remote escalation.

### Local-first workstation

Runs large local models, rendering, development, and compatibility workloads.

### Edge/headless

Runs services and agents without a conventional desktop.

## Hardware evolution

A hardware change should trigger profile refresh and service recomposition, not OS reinstall.

Examples:

- adding an NPU enables new local model providers;
- connecting an eGPU enables local render capabilities;
- pairing a workstation adds a trusted peer execution target.
