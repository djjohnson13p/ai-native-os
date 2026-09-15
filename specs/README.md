# Machine-Readable Contracts

This directory contains draft contracts for the AI-native operating-system control plane.

They exist so that architecture decisions can be tested independently of implementation language, model provider, Linux distribution, or UI toolkit.

## Status

All schemas are **pre-v1 architecture drafts**. Breaking changes are expected while v0.1 is being designed and prototyped.

A schema being present here does not mean the implementation exists yet.

## Contract principles

1. **Provider-neutral** — no OpenAI-, Anthropic-, Google-, Microsoft-, Apple-, or other vendor-specific fields are mandatory operating-system concepts.
2. **Task-scoped** — machine-actionable operations retain task identity and authority context.
3. **Handles over arbitrary paths** — contracts prefer artifact/resource identifiers rather than passing unrestricted host paths.
4. **Plans are not authority** — planner/IR schemas describe proposed work; policy/grant schemas govern permission.
5. **Semantic contracts precede providers** — a capability/type has provider-independent meaning before an implementation claims to provide it.
6. **Semantic IR is separate from execution binding** — providers, hardware placement, grant references, and sandbox instances are bound after IR validation.
7. **Bulk data out-of-band** — large files/media/model weights should not be embedded in ordinary control-plane JSON messages.
8. **Explicit versions** — contracts should carry a schema/interface version once implementation begins.
9. **Fail closed for execution** — unknown required fields/versions/capabilities must not be silently interpreted as broader permission.
10. **Portable serialization first** — JSON Schema is the first interchange notation because it is easy to inspect and generate fixtures for. It is not a permanent requirement for all hot-path runtime communication.

## Current schemas

| Schema | Purpose |
| --- | --- |
| `aios-ir.schema.json` | provider-independent AI-native semantic execution graph |
| `capability-contract.schema.json` | stable semantic meaning of a capability independent of providers |
| `type-contract.schema.json` | semantic type identity/representation/equality contract |
| `execution-binding.schema.json` | concrete attempt-specific provider/authority/resource binding for one IR node |
| `skill-manifest.schema.json` | versioned reusable/compiled procedure metadata |
| `task-plan.schema.json` | planner-facing typed capability proposal graph during v0.1 transition |
| `task-record.schema.json` | durable task identity/state record |
| `capability-manifest.schema.json` | provider declaration of implemented capabilities and runtime requirements |
| `hardware-profile.schema.json` | normalized local hardware/resource profile |
| `artifact-handle.schema.json` | stable identity and metadata for task data/output |
| `capability-token.schema.json` | task/principal-scoped authority grant representation |
| `policy-decision.schema.json` | deterministic authorization decision record |
| `provenance-event.schema.json` | append-oriented execution/audit event |
| `execution-profile.schema.json` | effective process/container/VM isolation profile |
| `model-request.schema.json` | provider-neutral AI/model invocation request |
| `model-result.schema.json` | provider-neutral model invocation result |
| `compatibility-profile.schema.json` | known legacy-app habitat/translation profile |

Planned contracts may include provider health, semantic registry snapshots, skill package signatures, model descriptors, and richer stream/device contracts as required by implementation.

## Semantic layers

The intended relationship is:

```text
Planner proposal
    ↓
AIOS IR
    ↓ references
Semantic Type + Capability Contracts
    ↓ implemented by
Provider Manifests
    ↓ selected/bound through
Policy + Resource Broker
    ↓ creates
Execution Binding + Execution Profile
    ↓ emits
Artifacts + Provenance
```

No layer below AIOS IR may reinterpret the program as carrying authority simply because it passed schema validation.

## Schema IDs

Until the project has a final name/domain, schemas use the documentation-only domain:

```text
https://ai-native-os.example/specs/...
```

No software should attempt to fetch that URL at runtime.

When the project gains a stable domain, schema IDs can move through an explicit compatibility/versioning ADR.

## Versioning approach

Before v1.0:

- breaking changes are allowed;
- every breaking change should update fixtures/tests in the same change;
- consumers should reject schema versions they cannot interpret safely;
- optional fields should be preferred for additive compatible evolution;
- authority/security semantics must not change accidentally through a schema-only edit.

For stable interfaces, use semantic major/minor concepts:

```text
major — incompatible contract/semantic change
minor — additive compatible fields/capabilities
patch — documentation/constraint clarification that does not change valid semantics
```

The exact version-string placement is still being standardized.

## IR fixtures

`examples/aios-ir/` contains:

- a complete Demonstration A AIOS IR program;
- semantic capability-contract fixtures;
- semantic type-contract fixtures;
- five valid compact IR programs;
- more than ten invalid/adversarial IR programs with expected reason codes.

These fixtures distinguish structural JSON Schema errors from semantic graph/registry/security errors.

## General fixtures

A schema should not be considered implementation-ready until it has:

- at least one minimal valid fixture;
- at least one realistic valid fixture;
- invalid fixtures for missing required authority/type/version fields;
- automated validation in CI.

For AIOS IR and security-sensitive contracts, semantic/adversarial validation is also required; structural validation alone is insufficient.

## Security note

Passing JSON Schema validation only proves structural conformance.

It does not prove:

- the provider is trustworthy;
- the requested action is authorized;
- the AIOS IR graph is semantically valid;
- a capability provider conforms to its semantic contract;
- a compatibility profile is safe;
- model output is factually correct;
- the artifact is non-malicious;
- a signed manifest deserves policy trust.

Those decisions belong to semantic validation, policy, sandbox, verification, provenance, and trust systems.
