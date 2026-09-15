# ADR 0011 — Own the AI-Native IR Before Building a New General-Purpose Language

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

The project intends to be designed around AI rather than around conventional application boundaries. That raises a fundamental question: should it also be implemented from the programming-language layer upward using a new language designed by and for AI?

A custom language could eventually provide valuable semantics for capability composition, authority, provenance, deterministic/probabilistic boundaries, resource placement, verification, and skill compilation. However, beginning by replacing mature general-purpose systems languages would substantially increase bootstrap cost before the architecture has proven which semantics actually require a new language.

## Decision

For the initial architecture and v0.1 implementation:

1. Use mature implementation languages for the bootstrap runtime and integrations.
2. Design and own a provider-independent, typed **AIOS IR** as the canonical execution representation between planning and execution.
3. Make authority, effects, data handles, determinism class, verification, placement constraints, fallback, and provenance first-class IR semantics.
4. Treat human-readable syntax as secondary to the semantic model.
5. Evaluate WASM and native code as compilation targets for safe portable providers and compiled skills.
6. Defer creation of a new general-purpose systems language until measurements show that AIOS IR plus existing implementation languages cannot meet safety, adaptability, portability, or efficiency requirements.
7. Allow the IR to evolve into an AI-oriented source language if demonstrated requirements justify it.

## Rationale

The principal expected efficiency gains come from eliminating repeated reasoning, minimizing data movement, selecting appropriate compute, compiling stable task graphs, explicit concurrency, provider substitution, and using deterministic execution wherever possible. Those benefits depend primarily on runtime semantics and representation rather than source-code syntax.

A purpose-built IR can capture the novel aspects of AI-native computing without forcing the project to simultaneously build and maintain a full compiler ecosystem.

This also creates a clean migration path:

```text
human intent
  -> model/deterministic planning
  -> validated AIOS IR
  -> policy authorization
  -> interpreted execution
  -> optimized repeated graph
  -> compiled skill (WASM/native/provider graph)
```

## Consequences

### Positive

- v0.1 can use mature compilers, libraries, debuggers, and platform integrations;
- the project still controls its core AI-native semantics;
- AI-generated plans target a constrained representation rather than privileged arbitrary source code;
- stable workflows can be optimized independently of the model that originally produced them;
- implementation languages remain replaceable behind contracts;
- the future language design can be informed by real traces, benchmarks, and failure modes.

### Negative

- the system temporarily spans conventional implementation code and a new IR;
- IR design and versioning become critical architecture work;
- FFI/provider boundaries must be carefully specified;
- some opportunities for whole-program optimization may remain unavailable until later compilation stages.

## Revisit criteria

Revisit the decision to create a full custom programming language when evidence demonstrates multiple material benefits, including some combination of:

- safer compile-time effect/authority analysis;
- materially lower AI code-generation error rates;
- substantial runtime or memory gains;
- superior heterogeneous-hardware portability;
- cross-provider graph optimization not practical through existing languages;
- significantly improved verification/provenance;
- or inability of existing systems languages to express required semantics without unacceptable complexity.

## Related

See `docs/23-ai-native-language-and-ir.md`.
