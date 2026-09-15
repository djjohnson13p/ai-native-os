# 22 — End-to-End Reference Flow

## Purpose

This document walks one v0.1 task through the architecture so that the services and schemas can be tested against the same concrete story.

Reference request:

> **Understand these numbers, identify important changes, create a chart and a concise report, and save the result.**

Input: a user-selected spreadsheet or CSV artifact.

The important part is not the exact analysis. The reference flow demonstrates how intent, AI reasoning, deterministic capabilities, authorization, resource selection, artifacts, verification, and provenance cooperate without putting an application at the center.

## Actors and services

```text
User / task shell
Task Manager
Artifact Broker
Intent Service
Planner / Model Adapter
Capability Registry
Policy Engine / Authority Service
Resource Broker
Provider Runner / Sandbox Manager
Deterministic Capability Providers
Verifier
Provenance Service
Skill Compiler / Skill Catalog
```

## Phase 0 — Input selection

The user selects `numbers.xlsx` or drops it into the task shell.

The shell does not pass an arbitrary host path into a model.

### Artifact import

The Artifact Broker creates something conceptually like:

```json
{
  "artifact_id": "A17",
  "uri": "artifact://A17",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "format": "xlsx",
  "sensitivity": "private",
  "origin": {"kind": "user"}
}
```

The artifact may retain a broker-owned reference to the actual local file/object.

### Provenance

Record:

```text
artifact.imported A17
```

No AI invocation is required merely to attach a file.

## Phase 1 — Task creation

The Task Manager creates `T91` containing:

- original user intent text;
- initiating user/principal;
- input artifact `A17`;
- default workspace/context, if any;
- task policy context;
- state `CREATED`.

Provenance records `task.created`.

Task state becomes `PLANNING`.

## Phase 2 — Intent normalization

The Intent Service extracts an outcome-oriented representation rather than an application procedure.

Example:

```json
{
  "goal": "analyze tabular numeric data and explain significant changes",
  "required_outputs": [
    "machine-readable-analysis",
    "chart",
    "concise-report"
  ],
  "input_artifacts": ["A17"],
  "constraints": {
    "preserve_input": true,
    "portable_outputs": true
  }
}
```

The normalized intent does **not** say "open Excel" or "open Word."

If the intent is sufficiently clear, no user clarification is needed.

## Phase 3 — Planning

### Model request

If a model is used for planning, the Task Manager/Planner creates a constrained `ModelRequest` associated with `T91` and a planning step.

The request asks for a typed plan conforming to the current task-plan schema.

### Data minimization

The planner does not automatically receive the full spreadsheet content.

Possible strategy:

1. use deterministic metadata inspection first;
2. expose sheet/column/type summaries;
3. request only the necessary authorized sample/derived statistics if the planner needs them;
4. use the full artifact only in deterministic table-analysis providers unless content-level reasoning is required.

This allows private raw data to remain local even if remote planning is permitted.

### Candidate plan

Conceptually:

```text
S1 table.import(A17)                  -> A18 table
S2 table.profile(A18)                 -> A19 profile
S3 stats.compare_or_detect(A18)       -> A20 findings
S4 chart.render(A18, A20)             -> A21 chart
S5 report.compose(A19, A20, A21)      -> A22 draft report
S6 analysis.verify(A18, A20, A22)     -> verification
S7 artifact.export(A22)               -> A23 report
```

Each step names a **capability**, not an executable path.

### Plan validation

Before authorization/execution:

- validate schema;
- validate unique step IDs;
- validate dependency graph;
- reject cycles unless explicitly modeled;
- ensure every capability exists in the registry;
- reject arbitrary free-form execution instructions;
- place bounds on replanning.

A valid plan is still only a proposal.

## Phase 4 — Capability resolution

The Capability Registry returns eligible providers for each step.

Example:

```text
table.import
  provider: builtin-xlsx
  provider: python-openpyxl-sandbox

chart.render
  provider: native-chart
  provider: python-matplotlib-sandbox

report.compose
  provider: template-report
  provider: local-model-report-writer
```

Provider manifests declare:

- supported types;
- side effects;
- resource requirements;
- determinism characteristics;
- isolation requirements;
- version/trust information.

## Phase 5 — Resource placement

The Resource Broker combines:

- hardware profile;
- privacy policy;
- task latency requirement;
- provider availability;
- model/runtime availability;
- resource limits;
- monetary/energy preference;
- required isolation.

Example on an ordinary laptop:

```text
table import      → deterministic local CPU
statistics        → deterministic local CPU
chart              → local CPU/GPU
report composition → small local model or deterministic template
verification       → deterministic local CPU
```

On a constrained machine with remote reasoning permitted, only the report-composition reasoning may be routed remotely after data minimization.

Placement does not grant access.

## Phase 6 — Authority planning

For each executable step, determine the minimum required authority.

Example:

```text
S1 provider:builtin-xlsx
  read artifact:A17
  write task-output:T91
  network:none

S4 provider:native-chart
  read artifact:A18
  read artifact:A20
  write task-output:T91
  network:none

S5 provider:remote-report-model
  read derived artifact:A19
  read derived artifact:A20
  network:service:model-provider-X
  egress only A19 + A20
  write task-output:T91
```

The raw spreadsheet `A17` is not included in the remote grant unless explicitly needed and permitted.

## Phase 7 — Policy decisions

The Policy Engine evaluates each request.

Possible outcomes:

```text
ALLOW
DENY
REQUIRE_APPROVAL
ALLOW_WITH_NARROWER_SCOPE
```

### Example

Reading the user-selected input and writing task-local outputs may be allowed by existing policy.

Sending private derived data to a remote provider may require explicit approval.

If approval is required, task state becomes `WAITING_FOR_AUTH` and the shell presents something like:

```text
This task wants to send:
  - column/profile summary A19
  - detected changes A20

to:
  model-provider-X

Purpose:
  write the natural-language report

The original spreadsheet A17 will not be sent.
```

If the user denies, the resource/planner layer may attempt a local alternative without changing the user's privacy policy.

## Phase 8 — Execution-profile construction

Once authority exists, the Provider Runner creates the execution environment.

For a sandboxed local provider:

```text
isolation class: P2
input A17: read-only mount/descriptor
output area: read-write task-local mount
network: none
memory: bounded
pids: bounded
no-new-privileges: true
namespaces: enabled
Landlock/seccomp: applied where available
```

The provider never receives the user's general home directory just because the original file came from there.

## Phase 9 — Step execution

For every step:

1. revalidate task state;
2. validate provider availability/version;
3. validate authority token/grant;
4. construct/verify execution profile;
5. resolve artifact handles into sandbox-visible resources;
6. record `execution.started`;
7. run provider;
8. capture stdout/logs/structured result as appropriate;
9. collect produced files/data;
10. create output artifact identities;
11. record hashes/lineage;
12. record `execution.completed` or `execution.failed`.

A provider crash is a task event, not an OS-wide failure.

## Phase 10 — Verification

The report must not turn model-generated numeric claims directly into facts.

The Verifier checks claimed quantities and important comparisons against deterministic calculations.

Example:

```text
Report claim:
  "August cost increased 17.4% from July."

Deterministic verifier:
  July = 82,410.00
  August = 96,749.34
  computed change = 17.399...
  result = verified
```

If the draft says `27.4%`, verification fails.

The system may:

- regenerate only the affected report step;
- repair the deterministic substitution itself if policy allows;
- surface a failure rather than publish a false final report.

Task state is `VERIFYING` during this stage.

## Phase 11 — Final artifact publication

Verified outputs are promoted from temporary task outputs into user-visible artifacts.

Example:

```text
A21 chart.png
A23 analysis-report.md
A24 analysis-report.pdf
A20 findings.json
```

The Artifact Broker records:

- content hashes;
- semantic/media types;
- origin task/step/provider;
- source-artifact lineage;
- sensitivity/retention metadata;
- representations of the same logical report where applicable.

Task becomes `COMPLETED`.

## Phase 12 — User presentation

The shell shows the **task result**, not a stack of applications.

Suggested default summary:

```text
Completed

Key findings
  • …
  • …

Outputs
  [View chart]
  [Open report]
  [Open machine-readable findings]

Execution
  7 steps · all verified · local-only
  [Details]
```

The Details view exposes:

- plan revisions;
- provider selections;
- authority decisions;
- model/runtime use;
- egress;
- resource placement;
- provenance;
- verification;
- costs/timing where known.

If the user wants Excel, LibreOffice, or another traditional application, the artifact can still be opened through the explicit application/legacy route.

## Phase 13 — Skill extraction

After repeated successful tasks of the same structure, the Skill Compiler may identify a stable pattern.

It does **not** silently make a new privileged autonomous agent.

A proposed reusable skill might be:

```text
monthly-table-change-report v1

stable deterministic steps:
  import
  profile
  calculate comparisons
  chart
  numerical verification

model-assisted step:
  prose summary
```

The skill records:

- source task patterns;
- input/output contract;
- version;
- test results;
- authority requirements;
- model requirements if any;
- privacy/sensitivity behavior.

Each future execution receives fresh task authority and current provider selection.

## Failure branch examples

### Planner returns invalid output

- schema validation fails;
- no provider executes;
- bounded retry/alternate planner may run;
- task records failure/replan event.

### Provider requests `/home/user/.ssh`

- resource absent from task grant;
- policy/runner denies;
- event recorded;
- provider may be marked suspect depending on manifest/behavior.

### Remote provider unavailable

- resource broker tries eligible local/alternate provider;
- if none satisfies quality/policy, task pauses/fails clearly;
- no privacy rule is relaxed automatically.

### User closes task window

- view closes;
- durable task continues or pauses according to user policy;
- state does not disappear with the UI process.

### Control plane restarts

- recover task record/provenance;
- inspect last durable step event;
- reconcile provider/process state;
- resume, retry, or mark recoverable failure deterministically.

## Why this flow matters

A conventional AI desktop could superficially produce the same report by clicking through spreadsheet and document applications.

The architectural difference here is observable:

- task has stable identity;
- providers are interchangeable capabilities;
- model reasoning is constrained/proposed rather than authoritative;
- resources are task-scoped;
- egress is explicit;
- execution is isolated;
- artifacts have lineage;
- deterministic verification checks important facts;
- provenance spans all components;
- repeated work can compile into a reusable procedure.

Those are the properties the v0.1 prototype must prove.
