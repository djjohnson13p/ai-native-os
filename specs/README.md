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
4. **Plans are not authority** — planner schemas describe proposed work; policy/grant schemas govern permission.
5. **Bulk data out-of-band** — large files/media/model weights should not be embedded in ordinary control-plane JSON messages.
6. **Explicit versions** — contracts should carry a schema/interface version once implementation begins.
7. **Fail closed for execution** — unknown required fields/versions/capabilities must not be silently interpreted as broader permission.
8. **Portable serialization first** — JSON Schema is the first interchange notation because it is easy to inspect and generate fixtures for. It is not a permanent requirement for all hot-path runtime communication.

## Current schemas

| Schema | Purpose |
| --- | --- |
| `task-plan.schema.json` | typed capability execution graph proposed for a task |
| `capability-manifest.schema.json` | what a provider implements and what it requires |
| `hardware-profile.schema.json` | normalized local hardware/resource profile |
| `artifact-handle.schema.json` | stable identity and metadata for task data/output |
| `capability-token.schema.json` | task/principal-scoped authority grant representation |
| `provenance-event.schema.json` | append-oriented execution/audit event |
| `execution-profile.schema.json` | effective process/container/VM isolation profile |
| `model-request.schema.json` | provider-neutral AI/model invocation request |
| `compatibility-profile.schema.json` | known legacy-app habitat/translation profile |

Planned contracts include policy decisions, model results/descriptors, task persistence/state, provider health, and skill manifests.

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

## Fixtures

`examples/` will contain valid and intentionally invalid contract instances.

A schema should not be considered implementation-ready until it has:

- at least one minimal valid fixture;
- at least one realistic valid fixture;
- invalid fixtures for missing required authority/type/version fields;
- automated validation in CI.

## Security note

Passing JSON Schema validation only proves structural conformance.

It does not prove:

- the provider is trustworthy;
- the requested action is authorized;
- a compatibility profile is safe;
- model output is factually correct;
- the artifact is non-malicious;
- a signed manifest deserves policy trust.

Those decisions belong to the policy, sandbox, verification, and trust systems.
