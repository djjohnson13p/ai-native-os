# AI-Native OS — Agent Instructions

This file is intentionally a **map, not the architecture encyclopedia**. The repository documentation is the system of record.

## Mission

Build an open AI-native computing platform where human intent becomes typed, inspectable, authorized Tasks over semantic capabilities/objects, with replaceable providers and a deterministic security/recovery foundation.

## Non-negotiable rules

1. **AI/model output is proposal, not authority.** Never add a path where a model/planner/Skill can grant itself permissions.
2. **AIOS IR meaning is separate from runtime binding.** Provider IDs, hardware, process IDs, credentials, network endpoints, grants, and sandbox instances do not belong in semantic program identity.
3. **Trusted validation/policy/recovery are deterministic.** Do not require a model for parser/validator correctness, authorization, privilege transitions, rollback, boot/recovery, or secret mediation.
4. **Provider-neutral semantics.** Do not make one model vendor, cloud, application, database, programming language, storage provider, or package catalog a mandatory semantic dependency.
5. **No ambient filesystem/network/secret authority.** Use typed Artifact/Object/resource handles, explicit network/service grants, and mediated credential handles.
6. **Verification survives optimization.** Provider substitution, compilation, caching, or Skill reuse may not silently remove required verification.
7. **Stable identity survives placement/presentation/storage changes.** Task/Object/Artifact/semantic-program identity is separate from GUI View, device, path, replica, cloud region, or network endpoint.
8. **Signed does not mean safe.** Package/provider signatures establish provenance/integrity evidence, not semantic conformance or runtime authority.
9. **Do not silently change architecture contracts to make implementation easier.** If a contract is unimplementable, stop at that boundary and propose an ADR/schema/fixture change.
10. **Stage discipline matters.** Do not build broad GUI/cloud/network/domain suites to solve a trusted-core issue.

## Read before changing code/contracts

Always start with the issue/task, then read the smallest relevant source set.

Core constitution:

- `docs/15-system-invariants.md`
- `docs/16-requirements.md`
- `docs/17-v0.1-acceptance-tests.md`
- `docs/53-system-of-everything-staged-roadmap.md`
- `docs/59-pre-codex-foundation-closure-plan.md`
- `docs/64-requirements-traceability-matrix.md`
- `docs/65-contract-maturity-and-architecture-change-control.md`

Architecture decisions:

- `docs/adr/`

Machine contracts:

- `specs/README.md`
- relevant schema(s) in `specs/`

Executable/test fixtures:

- `examples/aios-ir/`
- `examples/reference-task/`
- `examples/domain-fabric/`
- `examples/platform-fabric/`

Issue #17 / validator work additionally requires:

- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/30-aios-ir-reference-validator-plan.md`
- `docs/31-semantic-registry-snapshots.md`
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`
- `docs/62-first-codex-session-runbook.md`

## Contract-change rule

If you modify a security/semantic contract:

1. explain why the existing contract fails;
2. update the relevant ADR/design document;
3. update requirement/traceability entries when affected;
4. update schema(s);
5. update positive + negative fixtures;
6. update acceptance tests/reason codes where applicable;
7. call out compatibility/migration impact.

Follow `docs/65-contract-maturity-and-architecture-change-control.md` for maturity/version/change rules.

Do not make a schema-only change that silently changes authority semantics.

## Code boundaries

Trusted-core code should prefer strongly typed data and explicit enums over generic unvalidated JSON after parsing.

Untrusted/provider/model/legacy execution must stay behind bounded process/component/container/VM interfaces appropriate to the issue.

Avoid arbitrary `eval`, shell execution, dynamic code loading, unrestricted host paths, unrestricted sockets, environment-secret inheritance, or blanket user permissions in core runtime paths.

## Testing expectations

For any implementation task, run every repository-defined formatter/linter/unit/fixture/integration check that applies after changes.

Security-sensitive code should include negative/adversarial tests, not success-path tests only.

For parser/validator code, include malformed/random-input robustness and resource-limit tests; no hostile input should panic the validator.

If exact build/test commands are not yet present in the repository, do not invent architecture by choosing a permanent toolchain convention without documenting the decision.

## Completion report

A PR/task completion summary should state:

- issue addressed;
- architecture docs/contracts followed;
- invariants preserved or intentionally changed;
- files/modules changed;
- tests/checks run and results;
- known limitations/non-goals;
- any contract/ADR follow-up required.

## Secrets and personal data

Never commit credentials, tokens, private keys, passwords, real personal documents, production provider responses, or user-private datasets. Use synthetic fixtures.

## Governing principle

> Implement the smallest testable component that preserves the architecture and makes the next layer easier.
