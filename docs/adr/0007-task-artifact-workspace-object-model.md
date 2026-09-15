# ADR 0007 — Task, Artifact, and Workspace Object Model

- **Status:** Accepted for architecture draft
- **Date:** 2026-09-15

## Context

Removing the application as the primary unit of work creates a design question: what replaces it?

A single replacement object is insufficient. Execution, durable content, organizational context, conversation, and visual presentation have different lifecycles and security properties.

## Decision

Use the following object model:

- **Task** — primary unit of intent, authorization, execution, status, verification, cancellation, and provenance.
- **Artifact** — primary durable content/data object and unit of lineage/versioned output.
- **Workspace** — optional durable organizational/context container grouping related tasks and artifacts without automatically granting authority.
- **Conversation** — an interaction channel/history that may create or refine tasks; not the operating-system execution object.
- **Application** — a legacy/provider/UI entity available through compatibility or explicit launch, but not the primary native unit of work.
- **Window/view** — a presentation of one or more objects; closing a view does not inherently destroy the underlying task/artifact.

## Consequences

### Positive

- long-running tasks survive UI/conversation restarts;
- artifacts remain portable and independent of provider choice;
- one task can compose many providers without exposing application switching to the user;
- direct manipulation/editor views remain possible;
- workspace context can be useful without becoming ambient authority;
- legacy applications have a clear place during transition.

### Costs

- the shell must present several object types coherently;
- artifact representation/version semantics require design;
- workspace defaults must be prevented from becoming accidental blanket permissions;
- application-centric file associations become one compatibility/view-routing input rather than the whole desktop model.

## Rejected alternatives

### Conversation as the primary object

Rejected because tasks can be non-conversational, long-running, automated, and durable beyond chat history.

### Workspace as the primary authority boundary

Rejected because grouping related work should not implicitly expose every workspace artifact to every task/provider.

### Artifact as the only primary object

Rejected because actions, approvals, retries, model/provider decisions, and long-running orchestration need an execution lifecycle separate from durable content.

## Related

- `docs/03-task-intent-model.md`
- `docs/20-user-object-model.md`
- `specs/artifact-handle.schema.json`
