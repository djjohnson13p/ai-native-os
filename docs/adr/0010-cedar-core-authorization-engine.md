# ADR 0010 — Cedar as the Core Authorization Evaluator

- **Status:** Proposed — requires Rust authorization spike
- **Date:** 2026-09-15

## Context

The project requires fine-grained deterministic authorization over task-scoped principals, actions, resources, and request context. Inventing a new policy language would add security-critical semantics and tooling unrelated to the project's primary innovation.

## Proposed decision

Use the open-source **Cedar** policy language/evaluator as the v0.1 core authorization engine, embedded in the Rust authority module.

Map AI-OS concepts onto Cedar principal/action/resource/context entities while keeping these responsibilities outside Cedar:

- approval workflow;
- minimum-scope calculation;
- task-state validation;
- token issuance/revocation/expiry;
- sandbox construction;
- provenance storage;
- user-facing explanation formatting.

Cedar returns the base deterministic Allow/Deny authorization result. The project-owned Authority Coordinator may return `REQUIRE_APPROVAL` before evaluation or derive an explicit narrower candidate request, then authorize that request.

Capability tokens remain project-owned short-lived runtime grants carrying references to the determining policy decision.

## Why Cedar

- purpose-built for authorization;
- principal/action/resource/context model aligns with the architecture;
- explicit permit/forbid semantics and default denial;
- schema validation for policy correctness;
- determining-policy information supports provenance;
- Rust crate fits the proposed Rust control plane;
- policies remain separate from application/provider code.

## Why not OPA/Rego as the first local engine

OPA is capable and remains relevant for organizational/cloud integration, but its general-purpose policy model, Go/server/Wasm integration choices, and broader policy scope add complexity to a small Rust local control plane before that flexibility is required.

This is not a rejection of future OPA bridges.

## Validation required

Run the policy spike defined in `docs/research/06-authorization-policy-engine.md`, including explicit forbids, task/resource isolation, egress control, secret mediation, invalid policies, and agent/legacy-app cases.

## Consequences

- the project avoids creating its own authorization language;
- Cedar schema/entities become part of the security architecture and need versioning/tests;
- approval semantics remain visibly distinct from authorization semantics;
- AI-generated policy changes can be linted/analyzed but never self-activate;
- recovery must include a known-good policy/schema set.

## Related

- `docs/19-principal-and-authority-model.md`
- `docs/research/06-authorization-policy-engine.md`
- issue #3
