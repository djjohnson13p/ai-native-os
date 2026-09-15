# ADR-0001 — Start above a mature Linux base

- Status: Proposed
- Date: 2026-09-15

## Context

Writing a new kernel would consume substantial effort on drivers, filesystems, networking, power management, hardware enablement, virtualization, and recovery before testing the AI-native architecture.

## Decision

Prototype the system above a mature Linux base. Do not require kernel changes for v0.1.

## Consequences

Positive:

- immediate hardware support;
- access to containers and virtualization;
- faster validation of novel architecture;
- easier contributor onboarding.

Negative:

- some early abstractions may be constrained by Linux conventions;
- project may be mislabeled as “just another distro.”

Mitigation: clearly define the novel operating model and keep service interfaces portable.
