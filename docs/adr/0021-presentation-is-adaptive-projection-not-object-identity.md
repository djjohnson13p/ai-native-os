# ADR 0021 — Presentation Is an Adaptive Projection, Not Object/Task Identity

- Status: **Proposed**
- Date: 2026-09-15

## Context

AIOS must operate across phones, laptops, large workstations, multi-display setups, remote surfaces, voice-first devices, headless systems, accessibility interfaces, and future display classes.

If UI layout/toolkit/window state becomes part of the semantic identity of Tasks or objects, the platform will reproduce application/device silos.

## Decision

Task identity, semantic object identity, AIOS IR, and authority semantics are independent of the concrete GUI/View used to present them.

Presentation occurs through a View/Presentation Broker that selects an eligible projection using display/input/accessibility/trust context.

A different presentation may expose different amounts of information or interaction detail, but it may not silently change the Task's semantic meaning or authority.

## Security

System authorization/approval controls for consequential actions must be rendered by trusted UI components or trusted presentation contracts and must accurately describe the target/effect.

Untrusted provider content cannot impersonate system permission UI.

## Consequences

### Positive

- one Task can move across devices/screens;
- specialized direct-manipulation Views coexist with natural-language interaction;
- accessibility can be a first-class alternate projection;
- remote surfaces do not require moving computation;
- UI technology can evolve without semantic migrations.

### Costs

- View contracts and display profiles become explicit architecture;
- navigation/transient UI state must be separated from durable task/object state;
- remote presentation requires its own policy/latency/security model.

## Related

- `docs/20-user-object-model.md`
- `docs/23-task-shell-ux.md`
- `docs/50-adaptive-presentation-and-device-ui.md`
- `specs/display-profile.schema.json`
