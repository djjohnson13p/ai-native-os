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
9. **Execution Bindings are immutable attempt receipts.** Retry, provider substitution, changed placement, or changed authority creates a new attempt/binding rather than rewriting history.
10. **Authorize credential use, not secret possession.** Long-lived secret material stays behind the Credential Broker whenever the ecosystem permits mediation.
11. **Unknown outcome stays unknown.** Do not convert uncertain irreversible/opaque effects into ordinary retryable failure without deterministic reconciliation evidence.
12. **Do not silently change architecture contracts to make implementation easier.** If a contract is unimplementable, stop at that boundary and propose an ADR/schema/fixture change.
13. **Stage discipline matters.** Do not build broad GUI/cloud/network/domain suites to solve a trusted-core issue.

## Current project stage

Stage 0 architecture is **closed enough for bounded trusted-core implementation**, not globally stable.

Read:

- `docs/81-stage0-architecture-closure-audit.md`
- `specs/contract-maturity.json`

`SPIKE_READY` means a bounded prototype may rely on the contract under change-control rules. It does **not** mean third-party compatibility is frozen.

Issue #17 is complete. Follow `docs/82-stage1-core-substrate-codex-runbook.md` in stage order; use Issue #38 and the active issue/PR handoff for current state. Do not jump directly to planner/model/GUI/cloud work.

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
- `docs/81-stage0-architecture-closure-audit.md`

Architecture decisions:

- `docs/adr/`

Machine contracts:

- `specs/README.md`
- `specs/contract-maturity.json`
- relevant schema(s)/reason-code registries in `specs/`

Executable/test fixtures:

- `examples/aios-ir/`
- `examples/task-manager/`
- `examples/artifact-store/`
- `examples/provenance/`
- `examples/registry-lifecycle/`
- `examples/authority/`
- `examples/credentials/`
- `examples/provider-runtime/`
- `examples/recovery/`
- `examples/reference-task/`
- `examples/domain-fabric/`
- `examples/platform-fabric/`

## Issue #17 / validator work

Additionally read:

- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/28-capability-contracts-and-conformance.md`
- `docs/29-semantic-type-system.md`
- `docs/30-aios-ir-reference-validator-plan.md`
- `docs/31-semantic-registry-snapshots.md`
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/60-v0.1-rust-workspace-and-trusted-core-boundaries.md`
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`
- `docs/62-first-codex-session-runbook.md`
- `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`
- `docs/67-v0.1-semantic-reference-and-version-resolution.md`
- `docs/68-aios-ir-v0.1-edge-case-semantics.md`
- `docs/69-v0.1-capability-effect-and-authority-contract-profile.md`
- `docs/70-validator-and-registry-reason-code-catalog.md`
- `docs/71-validator-spike-readiness-checklist.md`
- `docs/72-v0.1-semantic-contract-and-registry-hash-profile.md`

## Stage-1 deterministic core work

For post-validator work, start with:

- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- `docs/74-v0.1-task-manager-transition-and-cas-contract.md`
- `docs/75-v0.1-artifact-store-content-identity-and-publication.md`
- `docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md`
- `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`
- `docs/78-v0.1-execution-binding-and-provider-supervisor.md`
- `docs/79-v0.1-credential-broker-and-secret-mediation.md`
- `docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md`
- `docs/82-stage1-core-substrate-codex-runbook.md`

## Independent architecture review

`docs/83-pre-implementation-red-team-and-astra-review-packet.md` is the adversarial review packet.

A reviewer should try to falsify the architecture rather than continue it. Do not treat a positive review as a substitute for tests.


## Agent orchestration and human-handoff rule

The project owner should **not** be used as a manual router between model-specific chats.

Project-scoped Codex routing is defined in `.codex/config.toml` and `.codex/agents/*.toml`.

The root coordinator should keep one implementation thread and delegate work through subagents:

- `explorer` — GPT-6 Luna / medium / read-only for codebase mapping and evidence gathering;
- `implementer` — GPT-6 Sol / high / workspace-write for bounded implementation and fixes;
- `reviewer` — GPT-6 Sol / high / read-only for ordinary correctness review;
- `test_auditor` — GPT-6 Sol / high / read-only for adversarial test/evidence review;
- `astra_reviewer` — GPT-6 Astra / medium / read-only for trusted-boundary architecture/security gates;
- `astra_deep_review` — GPT-6 Astra / high / read-only only when a normal review leaves a genuinely difficult architecture/security question unresolved.

The project-level root coordinator is GPT-6 Sol with `ultra` reasoning. In the current Codex model catalog, `ultra` is the maximum GPT-6 Sol reasoning profile with automatic task delegation, which matches this repository's coordinator role. GPT-6 Astra remains the independent review model. The current GPT-6 catalog has no Terra model; former Terra review/test roles migrate to GPT-6 Sol.

**GPT-6 runtime compatibility:** GPT-6 Sol/Luna require Codex 0.155.0+ in the current catalog; GPT-6 Astra requires 0.153.0+. If a configured GPT-6 model is unavailable, do not silently substitute a 5.6 model. Record the runtime/client mismatch in the GitHub handoff and update the Codex runtime before continuing unless the owner explicitly authorizes a temporary fallback.

### Delegation policy

Use subagents proactively when work can be separated without weakening evidence:

1. explorer maps the relevant code/contracts;
2. implementer owns the bounded code change;
3. test_auditor challenges the evidence;
4. reviewer checks ordinary correctness;
5. astra_reviewer is required for trusted-boundary/security milestones or when the active issue explicitly requires independent architecture review;
6. astra_deep_review is escalation-only.

The root coordinator integrates the work and remains accountable for the final result. Subagent conclusions do not merge code by themselves.

**Continuation rule:** a subagent returning is not a reason to stop. The root coordinator must consume the result, route any repair/re-review automatically, update the GitHub handoff, and continue until the issue reaches its defined gate or a genuine owner decision/tool limitation blocks progress.

### Review efficiency

Before implementing a substantial change, map its public contract, trust boundaries, migration/recovery paths, and likely adversarial cases with the implementer and test auditor. Prefer smaller reviewable increments where the roadmap permits, while retaining every issue requirement and stage gate.

For a change to authority, revocation, persistence, or retained handles, write a short evidence map before coding: the actual public admission and use entry points, each required state transition, the adversarial action, the observable denial, and the test that exercises that path. A helper-only assertion cannot stand in for a public-path claim. The test auditor challenges this map before the first full gate, and the implementer adds missing executable coverage before asking for a stable-head review.

Keep schema-only authority groundwork inside the draft workstream until it is paired with the coordinator's public admission and point-of-use checks. Use focused schema and migration tests while iterating; run the full exact-head gates and request GitHub-native review on a complete executable slice. A schema migration may ship separately only when its standalone behavior and recovery contract are independently useful and fully reviewable. Never describe a dormant table or trigger as proven authorization behavior.

If two successive pushed heads reveal different substantive failures in the same trust boundary, pause that repair loop for one `astra_deep_review` high-reasoning boundary challenge. Ask whether the current design or PR scope is causing the churn, consolidate the resulting repair plan, and then resume. Do not treat a new review finding as proof that the previous fix caused it; record whether it is newly introduced, previously latent, or still uncertain.

Collect local correctness, test-audit, and required Astra findings into one repair plan. Have the implementer apply substantive repairs and obtain required local re-review before pushing a stable candidate. Run every required exact-head check after changes. Request GitHub-native review on that candidate, then repair and re-review if it finds a substantive issue. Do not trigger duplicate reviews or repeatedly poll an active review when the scheduled review loop is already watching it.

Before the complete exact-head gate, run each new or changed adversarial regression on every required platform with its real filesystem and database behavior. Fix cross-platform fixture and implementation failures first, then freeze the candidate for the full gate. A later edit invalidates that gate; rerun the complete gate on the final source. This ordering avoids spending full-suite runs on failures a focused test can expose.

Record actionable findings by review source, head-changing review cycles, and available root/subagent usage in the durable handoff. Use measured completed-work quality and consumption to tune the workflow; do not infer savings from model labels or skip a required independent review.

### GitHub as the handoff bridge

GitHub is the durable coordination layer between ChatGPT, Codex, reviews, and future sessions.

**Control-plane issue:** GitHub Issue #38 (`[meta] AIOS autonomous development control plane`) is the persistent project-level coordination bus. The root Codex coordinator should read it at the start of every work cycle and update it when the active work item changes state. Current GitHub state outranks stale chat context.

For active implementation:

- the GitHub issue defines the task and acceptance criteria;
- the branch contains the work;
- the pull request is the review/fix loop;
- Codex review/fix work should be triggered from the PR with GitHub Codex integration where practical;
- one structured `AIOS-HANDOFF` comment should summarize current HEAD, tests, review status, blockers, and the exact next action;
- do not ask the project owner to copy large model-to-model transcripts when the same state can be written to the issue/PR.

When a PR exists, prefer GitHub-native Codex operations (for example review, security review, or a bounded fix request) over asking the project owner to open another model-specific chat.

### Human-interaction rule

The project owner should normally need only:

1. this main ChatGPT project conversation for direction/approval; and
2. one persistent Codex coordinator session when new implementation work must be initiated outside GitHub.

Do **not** instruct the project owner to create separate Sol/Terra/Luna/Astra chats for routine delegation. Spawn the configured subagent instead.

A separate fresh human-visible review session is reserved for exceptional release/security gates where independence from the coordinator context materially matters.

If the runtime cannot spawn the required configured agent, report that limitation explicitly and give one exact fallback action. Do not create a chain of ambiguous session instructions.

See `docs/89-agent-orchestration-and-github-handoff.md`.

## Contract-change rule

If you modify a security/semantic contract:

1. explain why the existing contract fails;
2. update the relevant ADR/design document;
3. update requirement/traceability/maturity entries when affected;
4. update schema(s);
5. update positive + negative fixtures;
6. update acceptance tests/reason codes where applicable;
7. update persistence mapping if the durable shape changes;
8. call out compatibility/migration impact.

Follow `docs/65-contract-maturity-and-architecture-change-control.md` for maturity/version/change rules.

Do not make a schema-only change that silently changes authority semantics.

## Code boundaries

Trusted-core code should prefer strongly typed data and explicit enums over generic unvalidated JSON after parsing.

Untrusted/provider/model/legacy execution must stay behind bounded process/component/container/VM interfaces appropriate to the issue.

Avoid arbitrary `eval`, shell execution, dynamic code loading, unrestricted host paths, unrestricted sockets, environment-secret inheritance, raw credential propagation, or blanket user permissions in core runtime paths.

Providers never open the control-plane database directly.

## Testing expectations

For any implementation task, run every repository-defined formatter/linter/unit/fixture/integration check that applies after changes.

Security-sensitive code must include negative/adversarial tests, not success-path tests only.

For parser/validator code, include malformed/random-input robustness and resource-limit tests; no hostile input should panic the validator.

For persistence/Artifact/provider/authority work, include crash/response-loss/idempotency/revocation tests relevant to the contract.

If exact build/test commands are not yet present in the repository, do not invent architecture by choosing a permanent toolchain convention without documenting the decision.

## Completion report

A PR/task completion summary should state:

- issue addressed;
- roadmap stage;
- architecture docs/contracts followed;
- invariants preserved or intentionally changed;
- files/modules changed;
- tests/checks run and results;
- network/model/provider/secret behavior exercised;
- known limitations/non-goals;
- any contract/ADR follow-up required.

## Secrets and personal data

Never commit credentials, bearer tokens, private keys, passwords, refresh tokens, session cookies, real personal documents, production provider responses, or user-private datasets. Use synthetic fixtures.

Never place raw secret material into AIOS IR, Task records, provenance, provider manifests, normal logs, or ordinary fixture JSON.

## Governance / licensing

Until a final project license is selected, treat `docs/84-open-source-license-and-governance-decision-framework.md` as decision scaffolding only. Do not add or imply a final license without an explicit project-owner decision.

## Governing principle

> Implement the smallest testable component that preserves the architecture and makes the next layer easier.
