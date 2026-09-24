# 89 — Agent Orchestration and GitHub Handoff

## Purpose

The project must not require the owner to act as a clipboard/router between many model-specific chats.

The operating model is:

```text
Project owner
    ↓
main ChatGPT project conversation
    ↓
GitHub issue / PR / handoff state
    ↓
one persistent Codex coordinator
    ↓
configured subagents with model + reasoning routing
    ↓
GitHub review / fix loop
```

The architecture remains ambitious; the operating workflow should be simple.

## Human-visible surfaces

The project owner should normally interact with only two surfaces:

1. **Main ChatGPT project conversation** — project direction, architecture decisions, approvals, and high-level status.
2. **One persistent Codex coordinator session** — only when new implementation work must be initiated outside a GitHub PR/issue automation path.

Routine exploration, implementation, ordinary review, test auditing, and Astra review are delegated inside Codex through project-configured subagents.

The owner should not be asked to create a separate chat for each model.

**Default operator rule:** once the repository is trusted, the owner starts/continues one Codex coordinator session and does not manually choose child-agent models. Project configuration selects the root and named subagent models/reasoning levels. The coordinator must spawn those roles itself.

## Project-scoped Codex configuration

The repository carries:

```text
.codex/config.toml
.codex/agents/explorer.toml
.codex/agents/implementer.toml
.codex/agents/reviewer.toml
.codex/agents/test-auditor.toml
.codex/agents/astra-reviewer.toml
.codex/agents/astra-deep-review.toml
```

Codex loads project-scoped configuration only when the repository is trusted.

### Root coordinator

Fallback project configuration:

```text
GPT-6 Sol
ultra reasoning
```

The current GPT-6 Codex catalog supports `ultra` for GPT-6 Sol; this repository uses it for the root coordinator because `ultra` is the maximum reasoning profile with automatic task delegation. GPT-6 Luna is used for fast repository exploration, GPT-6 Sol for implementation and ordinary review/test-audit work, and GPT-6 Astra for independent trusted-boundary review. The current GPT-6 catalog has no Terra model; former Terra roles migrate to GPT-6 Sol.

Compatibility guard: the current Codex catalog lists GPT-6 Sol and GPT-6 Luna as requiring Codex 0.155.0 or newer, while GPT-6 Astra requires 0.153.0 or newer. A missing configured GPT-6 model is treated as an environment/version blocker, not permission to silently fall back to an older model family.

The root coordinator plans, delegates, integrates, commits, and writes the final handoff. It should not waste its highest reasoning budget on file inventory or mechanical test inspection when a lower-cost subagent can do that safely.

## Agent routing

| Work | Agent | Model | Reasoning | Sandbox |
| --- | --- | --- | --- | --- |
| codebase mapping / evidence | `explorer` | GPT-6 Luna | medium | read-only |
| implementation / repairs | `implementer` | GPT-6 Sol | high | workspace-write |
| ordinary correctness review | `reviewer` | GPT-6 Sol | high | read-only |
| test/adversarial evidence audit | `test_auditor` | GPT-6 Sol | high | read-only |
| trusted-boundary/security review | `astra_reviewer` | GPT-6 Astra | medium | read-only |
| unresolved hard escalation | `astra_deep_review` | GPT-6 Astra | high | read-only |

The parent coordinator may run independent agents in parallel when their work does not depend on one another, but must wait for required review agents before declaring a gate passed.

## Efficient review cadence

The agent roles and required gates stay fixed. Improve the timing of feedback:

1. Before a substantial implementation, map public contracts, trust boundaries, migration/recovery paths, and likely adversarial cases. Give the implementer and test auditor the same bounded acceptance criteria.
2. Prefer smaller reviewable PRs or increments where the stage runbook permits. This changes packaging, not issue scope: every requirement and gate still needs evidence before the issue closes.
3. Consolidate local correctness, test-audit, and required Astra findings into one repair plan. Have the implementer apply substantive repairs and run each changed adversarial regression on every required platform before the complete gate. Obtain required local re-review, run the complete required gate on the frozen candidate, and request GitHub-native review on a stable exact HEAD. Any later edit requires a new exact-head gate.
4. Use the scheduled review loop while an external review is running. Do not request duplicate reviews or spend interactive turns polling an unchanged status. For substantive new findings, have the implementer repair them, obtain local correctness and test-audit re-review plus Astra re-review when that gate is required, rerun the complete required gate on the repaired exact HEAD, then request another GitHub-native review.
5. Record actionable findings by source, head-changing review cycles, and available root/subagent usage in the handoff. Compare quality and consumption of completed work before changing model/reasoning routing; model names alone do not prove savings.

For durable authority, revocation, immutable-history, or migration/recovery changes, map the complete admission-to-use path and the supported persisted-state shapes before implementation. Use Luna for read-only inventory, Sol for bounded implementation and adversarial tests, and Astra for an independent design challenge before the next stable push. Escalate to `astra_deep_review` at high reasoning when multiple review heads expose distinct failures in the same trust boundary or when recovery must infer missing historical facts. The root coordinator integrates those findings before requesting GitHub review. Prefer an explicit set of supported schema fingerprints and fail-closed handling of unprovable history over an expanding collection of automatic repair exceptions. Keep ordinary work on its existing routing; measure whether this targeted escalation reduces review cycles before changing the whole project default.

Keep full end-to-end roadmap evidence, including Demonstration A integration, visible alongside issue and test counts. Passing a component gate is progress toward the system, not proof that the whole system works.

## Independence levels

Not every review needs a fresh human-visible chat.

### Level A — ordinary review

Use `reviewer` and/or `test_auditor` inside the coordinator session.

### Level B — trusted-boundary review

Use `astra_reviewer` as a read-only subagent with explicit instructions to falsify the implementation rather than continue it.

### Level C — exceptional independent review

Create a fresh external Astra session only when one of these is true:

- release/security gate explicitly requires context independence;
- reviewer/implementer disagreement remains unresolved;
- a change alters an accepted security or semantic invariant;
- a prior review found a high-severity issue whose repair needs independent confirmation;
- the configured Astra subagent is unavailable or cannot provide the required isolation.

Level C should be uncommon. It is not the routine workflow.

## GitHub is the durable bridge

GitHub is the system of record for cross-session handoff.

### Permanent control-plane issue

Issue #38 (`[meta] AIOS autonomous development control plane`) is the project-level queue and handoff bus. ChatGPT and the persistent Codex coordinator should use it to identify the active work item, current gate, blockers, and next action. Update it when work moves between issues/PRs; do not make the owner reconstruct state from chat history.

### Issue

The issue owns:

- bounded goal;
- stage;
- architecture inputs;
- acceptance tests;
- non-goals;
- dependencies.

### Branch

The branch owns implementation history.

### Pull request

The PR owns:

- current reviewable diff;
- CI;
- Codex code/security reviews;
- repair comments;
- merge readiness.

### Handoff comment

The coordinator writes one concise structured handoff whenever ownership changes or a gate completes:

```text
AIOS-HANDOFF

Issue:
PR:
Branch:
HEAD:
Stage:

Completed:
Tests:
Reviews:
Known blockers:

Next action:
Owner:
Required agent/model:
Stop condition:
```

Do not copy an entire prior chat into GitHub. Store only the durable state needed to resume correctly.

## GitHub-native Codex loop

When a PR exists and Codex Cloud is connected, prefer GitHub-native delegation.

Examples:

```text
@codex review
@codex security review
@codex fix the P1 issue
@codex fix the CI failures, preserve the current architecture contracts, run the required offline gate, and post a handoff
```

A non-`review` `@codex` PR comment starts a Codex Cloud task with the PR as context and may push a fix when permissions allow.

This means the project owner should not have to open a new implementation chat simply to relay a PR finding back to Codex.

## Main ChatGPT responsibilities

The main ChatGPT project conversation should:

- maintain architecture direction;
- inspect GitHub issues/PRs/results;
- write or refine bounded implementation instructions;
- decide whether a finding is implementation vs architecture;
- update the GitHub control state;
- trigger GitHub-native Codex review/fix work when supported;
- tell the owner only when a decision or manual action is actually required.

It should not ask the owner to shuttle large scripts among routine model sessions when GitHub or configured subagents can carry the state.

## Codex coordinator responsibilities

At the beginning of a work cycle:

1. read `AGENTS.md`;
2. read this document;
3. read the active GitHub issue/PR;
4. inspect current branch/HEAD;
5. delegate exploration/review/test work to configured agents;
6. implement only after the task is bounded;
7. run required tests;
8. obtain required review;
9. update GitHub with `AIOS-HANDOFF` and keep Issue #38 current;
10. continue automatically through repair/re-review while the next action is agent-resolvable;
11. stop only at the defined gate, a tool/runtime limitation, or a genuine owner decision.

## Project owner notification policy

Do not interrupt the owner for normal internal progress.

Notify/ask only for:

- architecture decision with real alternatives;
- permission/credential/environment requirement;
- merge/release approval when policy requires the owner;
- external dependency or service choice;
- blocker that cannot be resolved under existing contracts;
- high-severity review finding that requires project-direction input.

Routine test passes, subagent completion, and no-change monitoring remain quiet.

## Failure mode: required agent unavailable

If a configured subagent/model cannot be spawned:

1. do not silently substitute a materially weaker review for a security gate;
2. state exactly which agent/model was unavailable;
3. use the safest available local fallback for non-security work;
4. write the limitation into the GitHub handoff;
5. request one explicit owner action only if the gate cannot otherwise be satisfied.

## Current transition

Issue #17 is closed and Stage 1 uses this orchestration model:

```text
owner gives direction once
→ coordinator reads GitHub
→ coordinator delegates internally
→ PR opens
→ GitHub/Codex review loop
→ coordinator repairs through subagents or @codex
→ gate passes
→ owner is asked only for decisions that genuinely require them
```

## Principle

> **Models should hand work to models; GitHub should carry durable state; the project owner should make project decisions, not operate the routing layer.**
