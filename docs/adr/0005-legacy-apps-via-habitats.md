# ADR-0005 — Treat legacy applications as habitat-routed providers

- Status: Proposed
- Date: 2026-09-15

## Context

Users cannot migrate to an AI-native environment if abandoning essential existing software is a prerequisite.

## Decision

Introduce a Universal App Broker that detects package/runtime requirements and routes software into suitable native, compatibility, container, translation, VM, browser, or remote habitats.

“Native” in the user experience means transparent launch and integration, not that every binary executes directly against one kernel ABI.

## Consequences

- broad migration path;
- complexity is isolated in the broker/habitat layer;
- compatibility is testable per app/profile;
- some platforms will remain partial or legally constrained.
