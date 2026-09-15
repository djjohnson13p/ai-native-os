# 33 — Bootstrap Implementation Language Boundary

## Purpose

The project needs mature implementation languages immediately, but it should not accidentally make Rust, Python, C++, or any other host language the permanent computational model of an AI-native operating system.

This document defines a boundary:

> **Mature languages bootstrap the implementation. AIOS IR and semantic contracts define the operating model.**

That lets the project benefit from existing compilers, debuggers, libraries, drivers, runtimes, and security tooling while preserving the option to evolve a purpose-built AI-oriented language/runtime later.

## Layer model

```text
Human / agent intent
        ↓
Planner / Skill
        ↓
AIOS IR + semantic contracts
        ↓
Trusted validator + deterministic policy
        ↓
Execution binding / capability ABI
        ↓
┌──────────┬──────────┬──────────┬──────────┬─────────────┐
│ Rust     │ WASM     │ Python   │ C/C++    │ Legacy/VM  │
│ core     │ provider │ adapter  │ bridge   │ providers  │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
        ↓
Linux kernel / drivers / hardware
```

The upper semantic model should survive replacement of any lower implementation technology.

## Proposed bootstrap roles

### Rust — trusted control-plane implementation

Use Rust first for components whose correctness/security boundary matters:

- AIOS IR parser/normalizer/validator;
- task state machine;
- authority/policy coordinator;
- capability/type registry core;
- execution binding;
- artifact/provenance core;
- resource broker core;
- sandbox launch/supervision glue where practical.

Reasons:

- memory safety without a garbage collector;
- strong type system;
- predictable native deployment;
- good C interoperability;
- mature async/concurrency ecosystem;
- appropriate for long-running system services.

Rust is an implementation choice, not a semantic ABI.

### Python — rapid experimental/provider layer

Python is appropriate initially for:

- model provider adapters;
- data/ML experiments;
- prototype deterministic capability providers;
- benchmark tooling;
- dataset/test generation;
- fast experiments with planner behavior.

Python should remain outside the most sensitive enforcement boundary unless an explicit ADR justifies otherwise.

A Python provider receives the same constrained capability contract and runtime authority as any other provider. It does not receive extra privilege because it is easy to prototype in.

### C/C++ — existing ecosystem bridge

Use C/C++ where existing high-value libraries/drivers/runtimes require it.

Examples may include:

- graphics/media libraries;
- model inference runtimes;
- GPU toolchains;
- Wine/compatibility components;
- existing high-performance native libraries.

C/C++ code should be treated as a bounded dependency behind Rust/WASM/process/container boundaries where practical, not as ambient trusted logic.

### WASM — portable compiled provider/Skill target

WASM is a strong candidate for:

- portable deterministic capabilities;
- generated/compiled Skill subgraphs;
- third-party extensions;
- constrained cross-architecture execution;
- reproducible conformance fixtures.

WASM is an execution target, not the full AIOS semantic model. Authority and data handles still come from the OS/runtime.

### Shell — development/bootstrap only

Shell scripts are useful for:

- development setup;
- packaging/build orchestration;
- CI;
- deterministic maintenance glue.

Arbitrary shell execution must not become the normal escape hatch for AIOS IR or model-generated plans.

## Semantic ABI rule

No core semantic contract should require another component to know a Rust struct layout, Python class, C++ object, or provider-specific SDK object.

Stable boundaries should use:

- AIOS IR;
- semantic type/capability contracts;
- artifact/resource handles;
- policy decisions/grants;
- execution-binding contracts;
- versioned language-neutral IPC/serialization.

Language-specific representations are adapters behind those boundaries.

## Host-language leakage tests

Architecture review should flag cases where the semantic model begins to contain fields such as:

```text
python_module
rust_crate
cpp_class
pandas_dataframe
cuda_device_ptr
posix_fd
windows_handle
```

unless that value belongs explicitly to an implementation/runtime binding rather than semantic IR.

A semantic type may have a physical representation compatible with one of these technologies, but the type meaning must not depend on it.

## FFI containment

Native foreign-function interfaces are unavoidable in a systems project.

Rules:

1. unsafe/native FFI should be concentrated in small adapters;
2. inputs crossing FFI boundaries should be validated;
3. ownership/lifetime rules should be explicit;
4. untrusted data should not be passed to privileged native parsers without isolation where feasible;
5. crashes in optional providers should not crash the whole control plane;
6. a provider requiring broad in-process unsafe access should carry a higher trust/isolation requirement.

## Provider process model

For early v0.1, prefer out-of-process provider boundaries for code that is:

- experimental;
- Python-based;
- third party;
- legacy;
- native/unsafe;
- model-serving;
- network-facing;
- complex file/media parsing.

This costs IPC/data movement, so benchmarks should determine when in-process or compiled paths are worthwhile.

Optimization may reduce isolation overhead only after the semantic/security contract is preserved.

## Data-plane efficiency

A major risk in a multi-language architecture is unnecessary serialization/copying.

The solution should not be to abandon semantic boundaries prematurely.

Instead, measure and progressively optimize:

```text
semantic type
   ↓
representation negotiation
   ↓
shared memory / zero-copy / Arrow / mmap / GPU buffer where safe
   ↓
provider adapter
```

The semantic graph remains the same while execution bindings select efficient representations.

This gives us evidence about whether a custom lower-level runtime would actually help.

## Evolution ladder toward a custom language/runtime

### Stage 0 — Mature-language bootstrap

```text
Rust core + Python/native providers + JSON AIOS IR
```

Goal: prove semantics and security boundaries.

### Stage 1 — Typed structural IR toolchain

Add:

- strict validator;
- canonicalizer/hash;
- registry snapshots;
- diagnostics;
- graph optimizer;
- execution binding;
- conformance tools.

Goal: prove that AIOS IR is a useful computational boundary.

### Stage 2 — Compiled deterministic IR subgraphs

Lower eligible subgraphs to:

- WASM;
- fused native provider pipelines;
- query/GPU plans;
- other measured targets.

Goal: prove adaptive efficiency without inventing syntax.

### Stage 3 — AI/human authoring language experiment

Only if evidence supports it, build a thin source syntax that compiles to the same AIOS IR.

The language might emphasize:

- capabilities;
- effects/authority requests;
- semantic types;
- locality/privacy;
- verification;
- bounded fallback;
- typed task composition.

It should not bypass AIOS IR validation.

### Stage 4 — Dedicated compiler/runtime

Only if benchmarks show material benefit, implement deeper runtime/compiler ownership such as:

- optimized binary IR;
- specialized scheduler;
- ahead-of-time Skill compilation;
- effect/authority-aware optimizer;
- cross-device graph partitioner;
- accelerator-target lowering.

### Stage 5 — Self-hosting consideration

A future custom language could eventually implement some of its own toolchain/runtime.

This is a long-term option, not an objective for v0.1.

Self-hosting is worthwhile only if it improves maintainability/performance/security; it is not a badge of legitimacy.

## Evidence required before replacing Rust in trusted core

A future proposal to replace substantial Rust core code with a custom language/runtime should demonstrate at least one strong measurable advantage:

- materially stronger authority/effect guarantees;
- significant memory/CPU/data-movement reduction;
- better cross-device portability;
- safer generated-code execution;
- substantially better AI code-generation correctness;
- easier formal verification;
- lower trusted computing base;
- a runtime/compiler architecture not practical to express efficiently in Rust.

It must also compare ecosystem costs:

- compiler maintenance;
- debugger/profiler tooling;
- security audits;
- architecture backends;
- package/build system;
- IDE/editor tooling;
- contributor learning curve;
- FFI burden.

## AI-generated implementation rule

AI tools may generate Rust, Python, tests, adapters, and provider code during bootstrap.

Generated code receives no architectural authority merely because AI wrote it.

The same review boundary applies:

```text
architecture contract
      ↓
generated implementation
      ↓
compiler/static checks
      ↓
tests/fuzzing/conformance
      ↓
review/merge
```

AIOS should eventually make generation safer by giving agents constrained semantic targets rather than unrestricted implementation access for ordinary tasks.

## Dependency rule

Prefer dependencies that are:

- mature;
- actively maintained;
- well licensed;
- portable;
- replaceable behind project contracts;
- reproducibly buildable where practical;
- security-auditable.

Avoid rewriting mature infrastructure solely for ideological purity.

The project should spend originality where its architecture is novel.

## Performance rule

Do not infer that a custom language is faster merely because it is custom.

End-to-end AIOS performance may be dominated by:

- model inference;
- memory bandwidth;
- file parsing;
- GPU transfer;
- legacy translation;
- network latency;
- storage;
- sandbox startup.

`docs/32-aios-ir-and-skill-benchmark-plan.md` exists specifically to identify the actual bottlenecks.

## Long-term architectural freedom

The bootstrap stack is intentionally replaceable.

If, years later, the system uses:

- a custom source language;
- a custom binary AIOS IR;
- a dedicated graph VM;
- a different kernel;
- non-Rust trusted services;

then tasks, Skills, semantic contracts, authority rules, and provenance should migrate through explicit versioned transformations rather than a ground-up conceptual rewrite.

That is the payoff for putting semantic ownership above implementation-language choice now.

## Architectural principle

> **Use existing languages to build the machine; design AIOS semantics so the machine is never trapped inside those languages.**
