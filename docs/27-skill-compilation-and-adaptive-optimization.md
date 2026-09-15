# 27 — Skill Compilation and Adaptive Optimization

## Purpose

One of the project's core efficiency principles is:

> **Reason once, compile when stable, reuse thereafter.**

This document defines what that means operationally without allowing learned/reused procedures to become a back door around policy, verification, or user control.

A **Skill** is a versioned reusable task procedure derived from validated AIOS IR and evidence from prior successful executions.

A Skill is not an AI personality, not a model prompt bundle, and not a permanent permission grant.

## Why skills exist

A first execution of a novel task may require expensive reasoning:

```text
intent
  ↓
model-assisted planning
  ↓
validation
  ↓
execution
  ↓
verification
```

If the same structure recurs, paying the full planning/model cost every time is wasteful and potentially less reliable.

The system should progressively move stable work toward ordinary deterministic computation:

```text
repeated intent pattern
  ↓
validated repeated AIOS IR
  ↓
parameterized skill candidate
  ↓
conformance + privacy + regression tests
  ↓
validated skill
  ↓
optional compiled deterministic subgraphs
  ↓
fast future execution with fresh policy checks
```

## Skill lifecycle

### 1. Observed

The system notices structurally similar successful task graphs.

No reusable executable artifact is created yet.

Observation metadata may include:

- semantic IR hashes;
- task families/intents;
- repeated capability sequences;
- stable parameter locations;
- provider-independent success characteristics;
- verification outcomes;
- failure/retry history.

Private user content is not automatically copied into a shareable skill.

### 2. Candidate

A candidate skill is created explicitly by system suggestion, developer action, or user approval.

The candidate contains:

- a parameterized AIOS IR template;
- input/output contract;
- authority request template;
- capability/version requirements;
- expected verification gates;
- origin/provenance references;
- privacy review status;
- test fixtures.

A candidate is not considered safe for automatic reuse merely because it came from successful tasks.

### 3. Validated

A candidate becomes validated after defined tests pass.

Validation should include:

- structural/schema checks;
- semantic IR validation;
- parameter-boundary tests;
- authority-scope tests;
- negative/adversarial tests;
- provider substitution where the skill claims portability;
- verification-gate preservation;
- privacy scrubbing checks;
- representative fixture replays;
- invalidation-condition tests.

### 4. Compiled

Deterministic portions may be lowered into a more efficient target.

Potential targets include:

- optimized native provider pipeline;
- WASM component/module;
- fused Rust/native helper;
- SQL/query plan;
- GPU/accelerator graph;
- provider-native batch request;
- cached immutable artifact/result where semantically valid.

Probabilistic nodes do not magically become deterministic merely because the skill is compiled.

A compiled skill can remain hybrid:

```text
compiled deterministic preprocessing
          ↓
probabilistic reasoning node
          ↓
compiled deterministic verification/export
```

### 5. Deprecated/invalidated

A skill may stop being eligible due to:

- input contract change;
- capability major-version change;
- revoked provider trust;
- policy semantics change;
- failed regression test;
- security advisory;
- model-behavior change affecting a probabilistic node;
- base-system incompatibility;
- user disable/delete;
- changed verification requirements.

Invalidation must not rely on a model deciding that the skill still 'looks okay.'

## What gets parameterized

A reusable skill should preserve structure while turning task-specific values into explicit parameters.

Example repeated tasks:

```text
Analyze August payroll.csv and create the weekly report.
Analyze September payroll.csv and create the weekly report.
```

Possible skill inputs:

```text
input_table: Artifact<Table>
report_period: DateRange
output_format: ReportFormat = PDF
```

The skill should not accidentally preserve:

- absolute private paths;
- a user's email address unless genuinely part of the declared contract;
- task-specific capability tokens;
- API keys;
- old artifact IDs;
- hidden model conversation state;
- provider IDs unless required by policy/compatibility;
- approval decisions from a prior run.

## Authority semantics

A Skill contains **authority requirements**, never authority grants.

Example:

```text
requires:
  - read(input_table)
  - write(task.output)
```

On every invocation:

1. create a new task identity;
2. bind current input artifacts;
3. evaluate current policy;
4. request any required approval;
5. issue fresh task-scoped grants;
6. bind current providers/hardware;
7. execute;
8. record new provenance.

Therefore:

> Skill reuse can remove repeated reasoning, but cannot remove repeated authorization.

## Deterministic compilation eligibility

A subgraph is a strong compilation candidate when:

- all nodes are deterministic under their declared contracts;
- all capability versions are pinned to compatible semantic ranges;
- data dependencies are explicit;
- side effects are bounded and represented;
- required verifiers remain present;
- no runtime model reasoning is required inside the subgraph;
- no provider-specific hidden state is required;
- conformance tests pass for the selected lowering target.

## Probabilistic-node optimization

Probabilistic work can still become cheaper without pretending it is deterministic.

Possible optimizations:

- route to a smaller local model after demonstrated quality thresholds;
- reduce context to only typed relevant artifacts;
- cache stable embeddings/features where policy permits;
- replace model planning with a parameterized skill template;
- use constrained structured output rather than free-form reasoning;
- use a deterministic verifier to avoid a second large-model pass;
- skip probabilistic nodes when inputs prove they are unnecessary.

The optimization record must preserve that the remaining node is probabilistic.

## Skill identity

A Skill should have:

- stable logical skill ID;
- semantic version;
- source AIOS IR version;
- source/template semantic hash;
- skill-manifest hash;
- optional compiled-target hashes;
- publisher/origin identity where applicable.

Example:

```text
skill://local/analyze-periodic-table@1.2.0
```

The exact URI form is not yet normative.

## Skill packages

A future skill package may contain:

```text
manifest.json
program.ir.json
tests/
compiled/
  x86_64-linux-wasm32-wasi/...
  aarch64-linux-wasm32-wasi/...
provenance.json
SIGNATURES/
```

The semantic source IR remains the reference for understanding what a compiled target is supposed to do.

## Skill manifest

`specs/skill-manifest.schema.json` defines the first draft.

Important fields include:

- identity/version;
- source IR hash/version;
- input/output contract;
- authority request template;
- capability dependencies;
- verification requirements;
- compilation targets;
- validation evidence;
- privacy/scrubbing declaration;
- invalidation conditions.

## Privacy boundary

The project must separate:

### Private learned convenience

A user may choose to retain local procedures that reference their own local conventions.

These remain device/account scoped according to policy.

### Shareable skill

A skill intended for publication must pass a scrubbing process proving that private task context has not been embedded accidentally.

A shareable skill should prefer:

- semantic parameter names;
- synthetic/public tests;
- no historical user artifact IDs;
- no private prompt transcripts;
- no secret values;
- no organization-specific identifiers unless explicitly part of the package's stated purpose.

## Verification preservation

Compilation cannot optimize away a verifier simply because previous runs passed.

For example:

```text
calculate metrics
→ generate narrative
→ verify numeric claims
→ compose report
```

must not become:

```text
generate cached-looking narrative
→ compose report
```

unless an explicit semantic transformation proves an equivalent or stronger verification contract.

## Data-change correctness

A reusable skill is structure reuse, not output reuse.

Changing input data MUST invalidate downstream content-addressed results whose input hashes changed.

A new run may reuse:

- compiled code;
- validated plan structure;
- static templates;
- provider conformance knowledge;
- immutable constants.

It must not reuse:

- previous totals;
- previous narrative claims;
- previous approvals;
- previous output artifacts

unless the content-addressing rules prove the relevant inputs and semantic environment are identical.

## Benchmarking adaptive efficiency

The project should measure whether skill compilation actually improves the system.

For each representative task, record:

- planner/model invocations;
- input/output model tokens where applicable;
- elapsed latency;
- CPU time;
- peak RAM;
- GPU/NPU time and memory;
- network bytes/egress;
- monetary model/provider cost;
- energy estimate where practical;
- number of policy decisions;
- number of provider launches;
- verification time;
- success/failure rate.

Compare at least:

1. fresh model-assisted planning;
2. validated IR reuse without compiled subgraphs;
3. compiled-skill execution;
4. constrained/older hardware profile.

The claim that the system 'learns to become more efficient' should eventually be supported by these measurements rather than assumed.

## Promotion threshold

v0.1 should use a conservative, explicit threshold.

A skill may become a compile candidate only after:

- at least 3 successful structurally equivalent executions on synthetic/test workloads or an explicit developer override;
- all required verifiers passed;
- no authority violation occurred;
- parameterization was reviewed/validated;
- regression fixtures exist;
- a semantic hash/template has been produced.

This number is provisional and may be changed by ADR after empirical testing.

Production-scale automatic promotion would require substantially stronger evidence than the prototype threshold.

## Self-improvement boundary

Skill compilation is deliberately **not** unrestricted self-modifying operating-system code.

The runtime may generate optimized artifacts, but:

- the trusted policy engine is not rewritten by a skill;
- secure boot/update/recovery are not rewritten by a skill;
- kernel/driver code is not generated and installed autonomously through this path;
- compiled output executes inside the same or stricter sandbox/authority envelope;
- every generated target is traceable to source semantic IR;
- generated code can be discarded and regenerated.

This gives the project adaptation without surrendering the deterministic base.

## User control

Users/developers must be able to inspect:

- what skills exist;
- what task pattern each represents;
- what inputs it expects;
- what authority it normally requests;
- whether it contains probabilistic steps;
- what compiled targets exist;
- when it last passed validation;
- which tasks used it.

They must also be able to disable or delete locally learned skills.

## v0.1 demonstration

For Demonstration A:

1. run the task via fresh plan/IR validation;
2. repeat with equivalent synthetic input structures;
3. create a parameterized skill candidate;
4. validate its input/output and authority template;
5. compile at least one deterministic subgraph or replace repeated planner work with the validated IR template;
6. run the task again with fresh data;
7. prove that policy is evaluated again;
8. prove that outputs change with inputs;
9. measure reduced planning/model work;
10. show provenance identifying skill/template and compiled target used.

## Architectural principle

> **Learning should progressively replace unnecessary reasoning with validated computation, not progressively remove safeguards.**
