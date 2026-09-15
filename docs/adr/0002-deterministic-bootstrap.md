# ADR-0002 — Keep bootstrap and recovery deterministic

- Status: Proposed
- Date: 2026-09-15

## Context

AI can help adapt system configuration to diverse hardware, but privileged boot-time hallucination or generated driver behavior would make recovery and security unacceptable.

## Decision

Hardware enumeration, boot, rollback, core policy loading, and recovery use deterministic trusted components. AI may recommend configuration only after a trustworthy hardware profile and policy environment exist.

## Consequences

- safer recovery;
- reproducible installation;
- AI remains replaceable;
- slower experimentation in the lowest system layers, intentionally.
