# 32 — AIOS IR and Skill Efficiency Benchmark Plan

## Purpose

The architecture assumes that an AI-native computer can become more efficient over time by replacing repeated reasoning with validated reusable computation.

That is a hypothesis to measure, not a marketing claim to assume.

This benchmark plan defines how v0.1 should compare:

1. fresh model-assisted planning;
2. reuse of validated semantic AIOS IR;
3. reuse of a validated Skill template;
4. execution with compiled deterministic Skill subgraphs.

## Questions

The benchmark should answer:

- How much planning/model work disappears after a task pattern stabilizes?
- Does reuse reduce latency and memory rather than merely model tokens?
- What overhead does AIOS IR validation/policy/provenance add?
- When is compilation worthwhile?
- How much benefit remains on older/constrained hardware?
- Does provider substitution materially change the result?
- Does optimization preserve security and verification?

## Reference workload

Start with Demonstration A:

> Understand these numbers, identify important changes, create a chart and a concise report, and save the result.

Use synthetic datasets with controlled variation:

- small: ~1,000 rows;
- medium: ~100,000 rows;
- large: size selected to pressure memory without swapping the reference machine uncontrollably;
- same schema / changed values;
- compatible schema variation;
- incompatible schema variation requiring replan/clarification.

Exact sizes should be adjusted after the first implementation baseline.

## Execution modes

### M0 — Deterministic baseline

No model planner.

Load a known validated AIOS IR program and execute deterministic providers plus a stub/fixed narrative where needed.

Purpose:

- measure control-plane/IR/policy/provenance overhead;
- establish the minimum architecture cost.

### M1 — Fresh planning

Start from natural-language intent and input artifacts.

Use the selected model planner to generate a proposal, validate/repair if needed, bind providers, execute, verify, and produce output.

Purpose:

- measure full first-run cost.

### M2 — Validated IR reuse

Skip model planning and reuse a previously validated parameterized IR structure with new input artifacts.

Still perform:

- current IR/contract compatibility checks as designed;
- current policy evaluation;
- current provider/resource selection;
- fresh execution;
- fresh verification;
- fresh provenance.

Purpose:

- isolate the value of semantic-plan reuse.

### M3 — Validated Skill reuse

Invoke a Skill manifest/template derived from the task family.

Measure additional Skill lookup/parameter binding overhead and planner work avoided.

### M4 — Compiled Skill

Execute a Skill where eligible deterministic subgraphs have been lowered/fused to a compiled target.

Any probabilistic node remains explicit and separately measured.

Purpose:

- measure computational benefit beyond merely skipping planning.

## Hardware profiles

At minimum test:

### H0 — Development workstation

Enough RAM/CPU/GPU for comfortable local experimentation.

### H1 — Ordinary laptop

Representative CPU, moderate RAM, integrated or modest accelerator.

### H2 — Constrained/older profile

Use either physical older hardware or controlled cgroup/VM limits to simulate:

- low RAM;
- fewer CPU cores;
- no usable GPU/NPU;
- slower storage.

### H3 — Offline mode

No network route to remote model/provider services.

The purpose is not to crown one hardware class; it is to prove that semantic task identity survives placement changes.

## Metrics

Collect per task and per node where practical.

### AI/model metrics

- planner model invocations;
- execution model invocations;
- verifier model invocations, if any;
- input tokens;
- output tokens;
- cached tokens where the provider reports them;
- model wall time;
- model monetary cost.

### Control-plane metrics

- parse/schema time;
- semantic validation time;
- registry resolution time;
- policy evaluation time;
- provider/resource resolution time;
- execution-binding creation time;
- provenance write time;
- total control-plane CPU time;
- peak control-plane RSS.

### Provider metrics

- wall time;
- CPU time;
- peak RSS;
- accelerator utilization/time where available;
- bytes read/written;
- provider startup overhead;
- conversion/copy overhead between representations.

### System metrics

- end-to-end latency;
- peak total memory;
- disk I/O;
- local network bytes;
- external egress bytes;
- energy estimate where platform telemetry is trustworthy;
- failures/retries;
- output artifact sizes.

### Correctness/safety metrics

- deterministic calculation correctness;
- verification pass/fail;
- IR validation failures;
- policy denials;
- unexpected authority requests;
- unexpected egress;
- stale-output reuse incidents (target: zero);
- provenance completeness.

## Primary comparisons

For equivalent successful workloads calculate:

```text
planning reduction = M1 planner work - M2/M3 planner work
latency reduction  = (M1 latency - Mx latency) / M1 latency
token reduction    = (M1 tokens - Mx tokens) / M1 tokens
memory reduction   = (M1 peak RAM - Mx peak RAM) / M1 peak RAM
cost reduction     = (M1 cost - Mx cost) / M1 cost
```

Do not report a percentage when the baseline is too small or unstable to make the result meaningful.

## Correctness gate before performance claims

A faster execution is invalid as a benchmark result if it:

- skips required verification;
- uses stale data;
- broadens authority;
- changes egress policy;
- produces semantically incorrect metrics;
- loses required provenance;
- changes task output contract unexpectedly.

Correctness/security gates are evaluated before performance comparisons.

## Warm/cold runs

Separate:

- cold daemon/process startup;
- warm service/provider reuse;
- cold filesystem/page cache where practical;
- warm content-addressed cache;
- compiled target already present vs first compilation.

Otherwise the benchmark may incorrectly attribute operating-system cache behavior to AIOS optimization.

## Compilation cost accounting

M4 must account for compilation cost.

Record:

- time/CPU/RAM used to compile;
- model use involved in candidate creation (if any);
- number of future runs required to amortize compilation;
- compiled artifact size;
- invalidation/recompile frequency.

A compilation that saves 200 ms per run but costs 30 minutes to produce may be a poor optimization for an infrequent task.

## Model quality and constrained-model substitution

A future benchmark should test whether validated Skill/IR structure allows a smaller model to replace a larger planner for repeated work.

Compare:

- large planner on first run;
- no planner on exact Skill reuse;
- small local model only for remaining narrative/ambiguity work;
- large remote model only when the smaller/local route fails a quality or capability threshold.

The architecture goal is not always to use the smallest model; it is to use no more intelligence than the task genuinely requires.

## Provider substitution test

For at least one deterministic capability, benchmark two conforming implementations.

Keep semantic AIOS IR identical.

Record:

- provider selection reason;
- execution binding difference;
- output semantic equivalence;
- resource/latency differences.

This tests whether provider independence is real rather than documentation.

## Data-movement benchmark

Because heterogeneous AI workloads can become memory-bandwidth/copy bound, explicitly measure:

- bytes serialized between providers;
- number of full data copies;
- conversion time;
- shared-memory/zero-copy path where available;
- sandbox boundary cost.

This measurement should inform future representation negotiation and whether a lower-level custom runtime/language would provide real benefit.

## Evidence for a future custom language/runtime

Issue #16 should use benchmark evidence when deciding whether AIOS IR should grow into a custom language/runtime.

Evidence in favor could include:

- repeated serialization/FFI overhead dominates useful execution;
- current languages make authority/effect enforcement difficult to prove;
- AI generates structural IR significantly more reliably than implementation code;
- cross-provider graph optimization yields meaningful gains unavailable to ordinary binaries;
- custom compiled representations materially reduce memory/data movement;
- debugging/provenance becomes substantially stronger.

Evidence against could include:

- Rust/WASM/provider interfaces are already a small fraction of end-to-end cost;
- most cost is model inference, I/O, or legacy compatibility;
- tooling/ecosystem cost would outweigh measured gains;
- the semantic IR already captures the important AI-native advantages.

## Results format

Benchmark output should be machine-readable plus a generated human summary.

Candidate record:

```text
benchmark_run_id
commit_sha
IR hash
registry snapshot
Skill hash/version if used
hardware profile hash
provider bindings
model descriptors
policy profile
mode (M0..M4)
input fixture/hash
metrics
verification result
```

Never include production private content in public benchmark artifacts.

## v0.1 success threshold

Do not set arbitrary performance targets before a baseline exists.

For v0.1, success is demonstrated if:

1. M2/M3 measurably reduce planning/model work on repeated equivalent tasks;
2. outputs remain correct and newly derived from new inputs;
3. policy and verification still run;
4. M4 shows either a measurable benefit or provides evidence that compilation is not yet worthwhile;
5. the system can explain where time/memory/model cost went.

A null result is useful architecture evidence. We should prefer discovering that an optimization does not matter over designing the system around an unmeasured assumption.

## Architectural principle

> **Optimize what the measurements say is expensive, while treating safety and semantic correctness as constraints rather than benchmark variables.**
