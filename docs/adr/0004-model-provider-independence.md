# ADR-0004 — Keep AI model providers replaceable

- Status: Proposed
- Date: 2026-09-15

## Context

An open operating system cannot make one proprietary model or vendor part of its permanent ABI.

## Decision

Models are capability providers selected through policy and resource routing. Core task/capability schemas must not embed provider-specific assumptions.

## Consequences

- supports local and remote models;
- avoids vendor lock-in;
- enables cost/quality/privacy routing;
- requires provider abstraction and conformance tests.
