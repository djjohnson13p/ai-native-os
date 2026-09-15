# ADR 0016 — Bootstrap Languages Are Not the Semantic ABI

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

The project needs to implement a real prototype before it has evidence for a purpose-built AI-oriented programming language/runtime.

Mature languages provide essential toolchains and ecosystems, but making Rust/Python/C/C++ object models the permanent OS contract would couple the AI-native architecture to implementation convenience.

## Decision

Use mature languages as bootstrap implementation tools while defining the stable architecture at language-neutral semantic boundaries.

Initial roles:

- **Rust** — preferred trusted control-plane implementation;
- **Python** — rapid model/provider/data experimentation outside critical enforcement paths;
- **C/C++** — existing native ecosystem/compatibility bridge behind bounded adapters;
- **WASM** — candidate portable provider and compiled-Skill target;
- **Shell** — development/build/maintenance glue, not an AIOS IR escape hatch.

Core semantic boundaries are AIOS IR, semantic type/capability contracts, task/artifact/authority/provenance contracts, and versioned IPC/runtime bindings.

No core semantic contract should require a consumer to understand a Rust struct, Python class, C++ object, or provider-specific SDK object.

## Rationale

This approach avoids spending the early project on compiler/toolchain construction while preserving the possibility of a custom language/runtime once real workloads demonstrate where existing technology is limiting.

It also lets the project replace lower implementation layers without redefining task meaning.

## Consequences

### Positive

- immediate access to mature compilers/debuggers/libraries;
- safer/faster path to v0.1;
- semantic architecture remains language neutral;
- future custom-language work can be measured against a working baseline;
- existing C/C++ ecosystems remain usable without controlling the OS model;
- WASM/native compilation can optimize stable Skills incrementally.

### Negative

- multiple languages/runtimes create IPC/FFI/data-movement overhead;
- adapters and representation negotiation are required;
- early implementation may temporarily contain duplicated type representations;
- contributors must respect the semantic/runtime boundary to avoid host-language leakage.

## Replacement criterion

A future proposal to replace substantial trusted-core Rust or create a dedicated lower-level runtime should present measured evidence such as stronger authority/effect guarantees, meaningful resource reduction, safer AI generation, lower TCB, or cross-device/compiler advantages that justify the new toolchain cost.

## Non-goal

This ADR does not prohibit a future custom AIOS language.

It establishes that such a language should compile to/preserve AIOS semantic contracts rather than precede them.

## Related

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/32-aios-ir-and-skill-benchmark-plan.md`
- `docs/33-bootstrap-language-boundary.md`
- ADR 0011
- Issue #16
