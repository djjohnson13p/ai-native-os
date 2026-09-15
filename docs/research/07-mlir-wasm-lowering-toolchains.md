# Research 07 — MLIR and WebAssembly Component Model as AIOS Lowering/Provider Infrastructure

**Status:** research note / no binding architecture decision

**Date reviewed:** 2026-09-15

## Question

If AIOS owns a high-level semantic IR, should the project also build all compiler optimization/lowering infrastructure from scratch?

Likewise, should AIOS invent a new cross-language binary/plugin ABI, or can existing component technology implement lower layers without becoming the OS semantic model?

## Short conclusion

Two existing ecosystems appear highly complementary to the current architecture:

- **MLIR** is a strong candidate for an *internal compiler/lowering toolbox* for deterministic subgraphs, custom lower-level dialects, and target conversion.
- **WebAssembly Component Model + WIT/WASI** is a strong candidate for a *portable provider/compiled-Skill execution and interface layer*.

Neither should replace AIOS IR as the semantic/security boundary.

The proposed layered relationship is:

```text
AIOS IR
  authoritative task/capability/authority/verification semantics
      ↓
AIOS optimizer / lowering selection
      ↓
optional internal MLIR representation/passes
      ↓
LLVM/native/GPU/etc target

and/or

AIOS IR / Semantic Capability Contract
      ↓
WIT provider/runtime ABI
      ↓
WebAssembly Component
      ↓
AIOS host grants narrow runtime capabilities
```

## MLIR findings

Official documentation describes MLIR as a multi-level IR compiler framework with reusable dialect, canonicalization, pass, pattern-rewrite, type-conversion, and dialect-conversion infrastructure.

Sources:

- https://mlir.llvm.org/docs/
- https://mlir.llvm.org/docs/DefiningDialects/
- https://mlir.llvm.org/docs/DialectConversion/
- https://mlir.llvm.org/docs/Canonicalization/
- https://mlir.llvm.org/docs/PassManagement/
- https://mlir.llvm.org/docs/TargetLLVMIR/

### Custom dialects

MLIR supports domain-specific dialects with custom operations/types/attributes and dialect-specific canonicalization behavior.

That creates a possible future path where AIOS deterministic lowering uses one or more internal dialects such as conceptually:

```text
aios.data
aios.verify
aios.artifact
```

or, preferably, an even lower implementation dialect produced *after* AIOS security semantics have already been checked.

We should not rush to duplicate the complete AIOS semantic layer in MLIR before measuring the value.

### Dialect conversion

MLIR's dialect-conversion framework supports conversion targets, rewrite patterns, and type conversion. This is attractive for progressive lowering from domain-specific operations toward hardware/runtime-level operations.

Potential AIOS use:

```text
validated deterministic AIOS subgraph
      ↓
AIOS lowering representation
      ↓
MLIR data/tensor/vector/GPU/LLVM dialects as appropriate
      ↓
native / accelerator target
```

### Existing target paths

MLIR includes conversion infrastructure for LLVM and multiple hardware/domain dialects. The LLVM target documentation describes progressive conversion to the LLVM dialect and then translation to LLVM IR.

This could save AIOS from owning instruction selection/register allocation/native-code generation merely to prove Skill compilation.

### Important warning: MLIR canonicalization is not AIOS semantic identity

The official MLIR canonicalization documentation explicitly notes that there is **no formally defined canonical form** and that the de-facto canonical form evolves as patterns/folders change.

Therefore:

> AIOS semantic hashing must not depend on `mlir-opt --canonicalize` or an evolving MLIR canonical form.

AIOS keeps its own versioned semantic normalization/canonicalization before lowering.

MLIR optimization happens *after* the authoritative source semantic hash exists.

### Proposed MLIR role

**Good candidate roles:**

- experimental lowering of deterministic computation;
- graph/tensor/data transforms where suitable;
- native/GPU optimization;
- compiler pass infrastructure;
- differential target experiments.

**Do not use MLIR for:**

- task authorization;
- user approval semantics;
- secret/grant transport;
- authoritative task identity;
- mutable provider selection;
- AIOS semantic hash/canonical identity;
- replacing the task/provenance model.

## WebAssembly Component Model findings

The Component Model defines interoperable/self-describing components with rich typed imports/exports. WIT (Wasm Interface Type) defines interface contracts and worlds.

Sources:

- https://component-model.bytecodealliance.org/
- https://component-model.bytecodealliance.org/design/wit.html
- https://component-model.bytecodealliance.org/design/components.html
- https://component-model.bytecodealliance.org/design/component-model-concepts.html
- https://wasi.dev/
- https://wasi.dev/releases

### WIT is an interface language, not behavior semantics

The Component Model documentation describes WIT as an interface definition language for types/functions/worlds, not a general-purpose language that defines behavior.

That is useful for AIOS.

A Semantic Capability Contract can define *meaning*, while a WIT interface can define a concrete cross-language call boundary.

Conceptually:

```text
Semantic Capability Contract
  table.normalize@1
        ↓
provider ABI generated/represented in WIT
        ↓
Rust/Go/Python/C/etc component implementation
```

We should not pretend WIT alone proves semantic conformance.

### Self-describing component boundaries

Component Model documentation describes components as self-describing binaries with typed imports/exports and composition through interfaces.

That could fit AIOS Provider Manifest/conformance architecture well:

- inspect declared imports/exports;
- map imports to host capabilities;
- refuse undeclared/unapproved host functionality;
- compose language-independent providers.

### Capability-oriented host model

WASI documentation describes applications/components as starting without ambient authority and receiving capabilities exposed by the host.

This strongly aligns with AIOS invariant I1: no ambient AI/provider authority.

AIOS still owns the authorization decision. A WASI/Wasm runtime is an enforcement substrate, not the policy source.

### Rich cross-language types

Component Model/WIT provides language-agnostic richer interface types and a Canonical ABI for interoperable components.

Potential benefit:

- reduce custom Rust/Python/C ABI glue;
- language-neutral provider SDKs;
- provider imports map cleanly to allowed host services;
- portable compiled Skill targets;
- self-describing compatibility/conformance tests.

### WASI version state

As of the review date, official WASI documentation lists **WASI 0.3 as the current stable release**, with native Component Model async primitives including async functions, streams, and futures. The same official release page notes toolchain support varies and many toolchains still target WASI 0.2.

We should therefore avoid making a premature permanent ABI version commitment.

A v0.1 spike should select a concrete Wasmtime/toolchain combination and pin versions reproducibly.

## Proposed experiment A — language-neutral deterministic provider

Build one tiny semantic capability, for example:

```text
text.uppercase@1
```

or:

```text
artifact.hash@1
```

Implement two providers from different source languages that target the same WIT interface.

Test:

1. both pass the same Semantic Capability Contract conformance suite;
2. both execute in a Wasm Component runtime;
3. host exposes only required artifact/log/progress interfaces;
4. no ambient filesystem/network/secret authority exists;
5. provider substitution does not change AIOS IR semantic hash;
6. execution binding/provenance identifies actual provider.

## Proposed experiment B — AIOS-specific WIT host world

Prototype a small `aios:provider` world with interfaces conceptually like:

```text
artifact-input
artifact-output
progress
structured-log
clock (only if explicitly granted)
random (only if explicitly granted)
```

Do **not** initially expose broad generic WASI filesystem/network interfaces unless a capability genuinely requires them and policy authorizes them.

The goal is capability-safe host mediation, not POSIX emulation inside every provider.

## Proposed experiment C — MLIR deterministic lowering

After the reference AIOS IR validator exists:

1. choose a deterministic pure subgraph from Demonstration A;
2. translate only that subgraph into an internal MLIR representation;
3. apply controlled MLIR transformations;
4. lower toward native code or another appropriate target;
5. run differential conformance against the ordinary reference provider path;
6. benchmark compile cost, execution latency, memory, and data movement;
7. confirm semantic source hash and verification/effect boundaries remain intact.

## MLIR vs a custom AIOS compiler infrastructure

A custom AIOS semantic IR remains justified because it captures concepts MLIR is not responsible for:

- task identity;
- authorization requests;
- data sensitivity/egress;
- provider independence;
- semantic capability contracts;
- verification barriers;
- task artifacts/lineage;
- Skill/provenance semantics.

But reusing MLIR later may avoid rebuilding generic compiler mechanisms such as:

- operation rewrite infrastructure;
- type conversion;
- pass management;
- native target lowering;
- hardware-specific optimization.

This fits the project's broader philosophy:

> Build from scratch where our semantics are novel; reuse mature infrastructure where the problem is already solved.

## WebAssembly vs a custom provider VM

The Component Model/WASI already tackles several hard problems AIOS would otherwise need to recreate:

- portable binaries;
- typed language-neutral interfaces;
- composition;
- host imports;
- sandbox-friendly execution;
- multi-language toolchains.

A custom AIOS VM should therefore require evidence that Wasm's execution/security/performance model materially blocks our workloads.

That evidence might appear later for extremely low-overhead graphs, GPU-heavy pipelines, or special device execution—but should be measured first.

## Recommendation

### Near term

1. Keep AIOS IR as the authoritative semantic representation.
2. Implement the Rust validator without depending on MLIR.
3. Evaluate WIT/Component Model for portable provider ABI once the first provider contract is executable.
4. Keep WASI imports much narrower than an ordinary command environment where possible.

### After deterministic substrate works

5. Run the two-language Wasm provider spike.
6. Run an MLIR lowering spike for one deterministic subgraph.
7. Compare both against direct Rust/provider execution using `docs/32-aios-ir-and-skill-benchmark-plan.md`.
8. Decide by evidence whether either technology becomes a standard layer.

## Decision implications

This research strengthens, rather than weakens, ADR 0016:

- existing languages/tools remain implementation mechanisms;
- AIOS owns semantic meaning;
- mature compiler/component infrastructure can be used below that semantic boundary;
- a custom compiler VM/language remains possible later if measured limitations justify it.
