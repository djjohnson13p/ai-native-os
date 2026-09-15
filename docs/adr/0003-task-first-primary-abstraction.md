# ADR-0003 — Make the task the primary user-level abstraction

- Status: Proposed
- Date: 2026-09-15

## Context

The project aims to eliminate unnecessary manual app selection and cross-app coordination.

## Decision

The primary object exposed to users and orchestration is a task containing intent, constraints, authority, plan, state, outputs, and provenance.

Applications remain available as providers or explicit fallback interfaces.

## Consequences

- capability composition becomes central;
- UI design shifts from launcher-centric to task-centric;
- application compatibility can be decoupled from the primary interaction model.
