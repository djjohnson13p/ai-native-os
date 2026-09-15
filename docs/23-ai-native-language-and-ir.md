# 23 — AI-Native Language and Intermediate Representation Strategy

## Question

Should the system be implemented entirely in existing languages such as Rust, Python, C, and C++, or should the project create a new programming language designed specifically for AI-native computing?

## Working conclusion

The project **should eventually own an AI-native execution language/IR**, but it should **not begin by replacing general-purpose implementation languages**.

The most valuable new abstraction is not initially a human-facing source language. It is a **typed, policy-aware, provider-independent intermediate representation (IR)** that represents what an AI-native system means to do.

Existing languages should bootstrap the trusted runtime, compiler/interpreter, compatibility layers, drivers, and tooling. The AI-native IR should become the stable semantic layer above them.

This avoids two opposite failure modes:

1. building a conventional operating system in Rust/Python and merely attaching an AI assistant; and
2. spending years building a compiler, debugger, package manager, runtime, standard library, FFI, optimizer, and tooling before proving the operating model.

## Why a new source language is not the first priority

Performance and adaptability will be dominated more by:

- task representation;
- capability composition;
- data movement;
- scheduling and placement;
- deterministic versus probabilistic execution boundaries;
- sandboxing and authority checks;
- model selection;
- caching and compiled-skill reuse;
- compatibility overhead;
- memory ownership and zero-copy data handling;
- concurrency and cancellation;
- hardware specialization;
- and compiler/runtime optimization.

A new surface syntax does not automatically improve any of those.

A custom language introduced too early also creates a bootstrap burden:

- parser and compiler;
- optimizer;
- debugger;
- profiler;
- formatter and language server;
- package/module system;
- ABI/FFI rules;
- standard library;
- build system;
- security model;
- dependency tooling;
- architecture backends;
- and ecosystem documentation.

Those costs are justified only if the language expresses semantics that existing languages cannot represent cleanly enough.

## The layer we should invent now: AIOS IR

Working name: **AIOS IR**. This is not a final project or language name.

AIOS IR is the canonical representation between intent/planning and execution.

It should be:

- strongly typed;
- declarative where possible;
- capability-oriented rather than application-oriented;
- explicit about side effects;
- explicit about authority;
- explicit about data sensitivity and egress;
- explicit about deterministic versus probabilistic operations;
- explicit about verification requirements;
- explicit about resource/locality constraints;
- inspectable and serializable;
- model/provider independent;
- versioned;
- executable only after deterministic validation;
- suitable for optimization and compilation;
- and capable of lowering to existing runtimes such as native code, WASM, containers, model adapters, and legacy habitats.

## Example semantic form

The exact syntax is intentionally undecided. A future human-readable form might resemble:

```text
task analyze_numbers(input: Artifact<Table>) -> Artifact<Report> {
    data = call table.import(input)
        requires read(input)
        deterministic;

    metrics = call stats.compare(data)
        deterministic
        prefer local;

    chart = call chart.render(metrics)
        deterministic
        writes task.output;

    narrative = reason report.summarize(metrics)
        egress none
        confidence >= 0.90;

    verify narrative.numeric_claims against metrics;

    report = call document.compose(chart, narrative)
        writes task.output;

    return report;
}
```

This is illustrative, not a syntax commitment.

The important point is that the representation contains concepts that conventional source code normally scatters across libraries, configuration, operating-system permissions, deployment files, and application logic.

## First-class semantics

### Capability invocation

The fundamental executable operation should identify a semantic capability, not a binary or application.

```text
call image.remove_background
```

The runtime resolves an eligible provider later.

### Authority/effects

Authority should be part of the executable contract.

Examples:

```text
requires read(artifact://input/1)
requires write(artifact://task/output/*)
requires network(api.example.com)
```

A planner cannot create authority merely by emitting one of these declarations. The declaration is a request that deterministic policy evaluates.

### Determinism class

Operations should declare or infer whether they are:

- deterministic;
- bounded nondeterministic;
- probabilistic/model-assisted;
- external/opaque.

This allows verification, caching, replay, and skill compilation to behave differently by class.

### Data semantics

Inputs and outputs should use typed artifact/data handles rather than arbitrary filesystem paths whenever possible.

The IR should carry or reference:

- type;
- content identity/hash;
- sensitivity;
- retention;
- lineage;
- locality;
- and allowed transformations.

### Resource constraints

Execution semantics may include constraints such as:

```text
prefer local
require gpu.memory >= 8GiB
allow remote if sensitivity <= internal
max_cost 0.10 USD
max_latency 2s
```

These are interpreted by the Resource Broker rather than hard-coded into the provider.

### Verification

Verification is part of the graph, not an afterthought.

Examples:

```text
verify output.schema == ReportV1
verify narrative.numeric_claims against metrics
verify artifact.hash after write
```

### Failure and fallback

Fallback should be typed and bounded, not arbitrary model improvisation.

```text
try provider.class A
fallback provider.class B
on authority_denied stop
on malformed_output replan max 1
```

### Provenance

Execution of the IR should naturally produce provenance because every node already identifies:

- requested capability;
- provider chosen;
- authority requested/granted;
- inputs;
- outputs;
- placement;
- verification;
- and result.

## Why this is AI-oriented

Human-oriented languages optimize heavily for developers reading and writing algorithms.

An AI-native execution representation can optimize for different properties:

- unambiguous machine generation;
- small constrained grammar;
- schema-valid output;
- explicit effects and authority;
- composability;
- introspection;
- automatic verification;
- safe optimization;
- provenance;
- and transformation between high-level intent and deterministic procedures.

The canonical form may ultimately be binary or structural rather than textual. A textual representation can exist primarily for debugging, reviews, source control, and human authorship.

## "Reason once, compile when stable"

AIOS IR is also the bridge between reasoning and ordinary computation.

A new or ambiguous task may initially contain probabilistic planning/model nodes.

After repeated successful execution and verification, stable portions can be transformed:

```text
intent
  -> model-assisted plan
  -> validated AIOS IR
  -> repeated successful IR graph
  -> optimized/compiled skill
  -> deterministic native/WASM/provider execution
```

This is where a major long-term efficiency gain can come from.

The system should stop paying model cost for decisions that have become stable algorithms.

## Relationship to implementation languages

### Rust

Strong candidate for:

- trusted control-plane components;
- policy enforcement;
- task runtime;
- resource broker;
- artifact/provenance services;
- IR validator/compiler/interpreter;
- sandbox supervision;
- and other long-running security-sensitive services.

Rust is an implementation tool, not the semantic identity of the OS.

### Python

Useful for:

- early capability providers;
- model adapters;
- data/scientific experimentation;
- prototype planners;
- test fixtures;
- and rapid research.

Python providers should remain behind typed contracts so they can later be replaced without changing task semantics.

### C/C++

Remain necessary where existing libraries, kernels, drivers, graphics stacks, compatibility projects, and performance-critical ecosystems already use them.

The project should integrate rather than needlessly rewrite mature components.

### WebAssembly

WASM is a strong candidate as one portable sandboxed compilation target for capability providers and compiled skills. It should be evaluated as an execution target, not assumed to be the only runtime.

## Long-term language path

### Stage 0 — Bootstrap

Implement the first runtime and contracts in mature existing languages.

### Stage 1 — Formal AIOS IR

Define the semantic model, verifier, serialization, versioning, and interpreter.

### Stage 2 — Compilation and optimization

Compile validated IR or stable subgraphs to WASM/native provider calls and optimize data movement, caching, concurrency, and placement.

### Stage 3 — AI-oriented textual language

If useful, provide a compact source language that lowers to AIOS IR. It should exist because it improves composition, safety, and machine generation—not merely because creating a new language is interesting.

### Stage 4 — Self-hosting

Move more system logic into the new representation only after it has stronger correctness, observability, and performance than the bootstrap implementation.

### Stage 5 — Re-evaluate lower layers

Only if profiling shows material gains should the project consider a deeper custom systems language/runtime for portions currently implemented in Rust/C/C++.

## Decision test for creating a full new language

A full language should proceed only if we can demonstrate several of the following:

1. important AI-native semantics cannot be represented safely/ergonomically in existing languages plus the IR;
2. compile-time authority/effect analysis prevents real classes of vulnerabilities;
3. AI generation error rate is substantially lower with the constrained language;
4. IR/source programs can be optimized across capability/provider boundaries in ways normal binaries cannot;
5. compiled stable workflows materially reduce compute, latency, memory, or model use;
6. portability across heterogeneous hardware improves;
7. debugging/provenance becomes materially better;
8. the toolchain can bootstrap without becoming the dominant project maintenance burden.

## Architectural principle

> **Own the semantics before owning the syntax.**

The project should invent the representation that an AI-native computer needs, while using proven languages to bootstrap it. If that representation naturally grows into a new programming language, the language will be derived from demonstrated requirements rather than speculation.
