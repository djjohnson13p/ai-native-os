# 36 — AIOS IR Compiler and Lowering Boundary

## Purpose

AIOS IR is intentionally higher level than machine code, WASM, Python bytecode, LLVM IR, SQL plans, or GPU graphs.

The compiler/lowering layer exists to make validated stable work faster **without losing the AI-native semantics that made it safe and inspectable**.

The most important compiler rule is:

> **Compiled code performs work; the operating system still supplies authority.**

A compiled artifact never becomes a portable permission token.

## Pipeline

```text
Validated AIOS Semantic IR
       │
       ├─ semantic hash + registry snapshot
       │
       ▼
Effect/verification-preserving optimizer
       │
       ▼
Lowering plan
       │
       ├─ interpreted/provider graph
       ├─ fused provider pipeline
       ├─ WASM target
       ├─ native target
       ├─ SQL/query target
       └─ GPU/accelerator graph
       │
       ▼
Compiled Target Artifact
       │
       │ task invocation creates fresh policy/grants
       ▼
Execution Binding + Host-Mediated Authority
```

## What may be compiled

Strong v0.1/v0.2 candidates are deterministic subgraphs whose semantics are stable and whose effects are explicit.

Example:

```text
normalize table
    ↓
calculate metrics
    ↓
transform metric representation
```

may be fused/compiled while:

```text
report.summarize (probabilistic model)
```

remains a separate capability invocation.

A hybrid Skill is expected to be normal.

## Compilation eligibility

A subgraph is eligible only when the compiler can identify:

- exact source semantic program/subgraph hash;
- semantic type contracts;
- capability contracts;
- execution classes;
- authority request upper bound;
- egress restrictions;
- verification requirements;
- deterministic/environment assumptions;
- finite failure behavior;
- explicit inputs/outputs.

If an operation depends on hidden provider state or ambient host behavior that cannot be represented, it should remain an ordinary provider invocation.

## Lowered code must not contain authority

A compiled target MUST NOT embed:

- capability tokens;
- API keys/passwords;
- old approval IDs as permissions;
- unrestricted host paths;
- long-lived bearer credentials;
- user-specific secret data;
- a hard-coded bypass of policy checks.

At invocation time, the runtime creates a new Execution Binding and exposes only approved host capabilities/resources.

## Host-call model

Portable compiled targets should interact with the OS through narrow host interfaces conceptually like:

```text
read_input(handle)
create_output(allocation)
write_output(handle, bytes/typed buffer)
emit_progress(...)
emit_metric(...)
request_declared_capability(...)
```

Not:

```text
open("/home/user/*")
connect_any_socket()
read_environment_secrets()
spawn_arbitrary_shell()
```

The exact ABI is future work. The principle is that host mediation preserves task-scoped authority.

## Pure vs effectful lowering

### Pure deterministic region

No external side effects.

Examples:

- math;
- normalization;
- data transforms;
- hashing;
- deterministic validation.

These are the easiest to fuse/cache/compile.

### Task-local effect region

May create task-scoped artifacts but no external communication.

Examples:

- render chart into allocated output;
- compose document into task output.

These can compile if output creation remains host mediated.

### External effect region

Examples:

- send message;
- call transaction API;
- control device;
- modify external account.

These should generally remain explicit capability boundaries so authorization/idempotency/provenance are not optimized away.

A compiler may optimize deterministic preparation around them, not hide the effect itself.

## Compiler-visible effects

The optimizer should reason about an effect summary derived from semantic contracts:

```text
PURE
ARTIFACT_READ
ARTIFACT_WRITE
NETWORK
EXTERNAL_MESSAGE
SECRET_ACCESS
PERSISTENT_STATE
DEVICE_ACCESS
SYSTEM_CHANGE
```

This is not a permission system by itself. It prevents unsafe transformations and helps choose isolation/compilation targets.

## Verification barriers

A required verifier is a semantic barrier.

Example:

```text
probabilistic narrative
      ↓
verify numeric claims
      ↓
compose final report
```

The compiler may optimize inside each region but cannot move final composition before the verifier or delete the verifier because previous runs succeeded.

## Determinism and ambient inputs

Deterministic compilation requires controlling/representing ambient state.

Values such as:

- current time;
- random numbers;
- locale;
- timezone;
- filesystem order;
- environment variables;
- network state;
- hardware floating-point mode

must not be silently treated as stable inputs.

If a task semantically needs time/randomness/location, those values should enter through explicit capabilities/typed inputs so provenance and replay can explain them.

## WASM target

WASM is a promising portable target for deterministic Skills/providers because it can offer:

- architecture-neutral code;
- bounded linear memory;
- explicit imports/exports;
- reproducible packaging;
- strong process/runtime isolation options;
- broad tooling.

AIOS should still expose a restricted host ABI rather than granting a WASM module generic filesystem/network access.

Whether to use the WASM Component Model/WASI interfaces directly or a smaller AIOS-specific host interface should be decided by implementation experiments.

## Native target

Native AOT code may be justified for:

- very hot stable loops;
- SIMD/accelerator integration;
- lower startup/IPC overhead;
- hardware-specialized code.

Native generated code increases risk and compatibility burden.

Requirements should include:

- content-addressed target identity;
- source semantic hash linkage;
- compiler version/target metadata;
- sandbox/least privilege;
- reproducible/differential tests where practical;
- regeneration path;
- never installing generated native code as privileged kernel/boot code through ordinary Skill compilation.

## Provider-pipeline target

Sometimes the best 'compiler' is a fused pipeline inside an existing conforming provider.

Example:

```text
normalize → aggregate → compare
```

could lower to one local data-engine query plan.

This avoids IPC/copies while preserving semantic source traceability.

The provider must prove that the fused operation conforms to the same observable semantics and effect bounds.

## SQL/query target

Structured deterministic data operations may lower to SQL or a query-engine plan.

The lowered query is an implementation artifact, not the semantic program.

Data-access authority remains mediated by handles/approved data sources rather than arbitrary database credentials embedded in generated SQL.

## GPU/accelerator target

Eligible numerical/image/3D subgraphs may lower to an accelerator graph.

Resource Broker decides whether the target is usable on the current hardware.

A Skill may contain multiple compiled targets plus a provider/interpreted fallback.

Example:

```text
x86_64-cpu target
aarch64-cpu target
GPU target
portable WASM fallback
semantic IR source
```

## Compilation cache key

A compiled target cache key should include all semantics that affect correctness.

Candidate inputs:

```text
source semantic IR/subgraph hash
semantic registry snapshot/dependency hashes
compiler ID/version/build
optimization profile
lowering target/target triple
relevant deterministic runtime ABI version
representation assumptions
```

It should NOT include old task-specific authority grants as a way to make them reusable.

## Compiled target manifest

`specs/compiled-target.schema.json` defines a bootstrap metadata contract linking a target to:

- source semantic hash;
- covered node IDs;
- compiler identity;
- target format/platform;
- artifact hash;
- semantic contract dependencies;
- required runtime ABI;
- effect/authority upper bound;
- verification-barrier evidence;
- validation/conformance evidence.

## Differential validation

For deterministic compiled regions, compare compiled execution against a reference interpretation/provider path on synthetic fixtures.

Tests should cover:

- normal inputs;
- boundary values;
- malformed inputs;
- different hardware targets where claimed;
- authority denial;
- output semantic equivalence;
- crash/resource limit behavior.

Compilation should not become trusted merely because the compiler completed successfully.

## Compiler trust model

The compiler itself can contain bugs.

v0.1 should therefore keep compiled targets optional and regenerable.

Possible future defenses:

- sandbox compiler process;
- deterministic/reproducible compilation;
- source/target hashing;
- differential testing;
- target verification;
- multiple compiler backends;
- signed released compiler toolchains;
- restricted host ABI limiting damage even if target is incorrect.

## Invalidating compiled targets

Invalidate/revalidate when a relevant assumption changes:

- source IR hash;
- required semantic contract incompatible change;
- runtime ABI incompatible change;
- compiler security advisory;
- target architecture incompatibility;
- failed regression/conformance test;
- security policy marks target/compiler untrusted.

A model-provider version change only invalidates a compiled target if that target actually depends on the provider/model semantics.

## Provenance

When a compiled target executes, provenance should record:

```text
source semantic program hash
subgraph/node coverage
Skill ID/version if applicable
compiled target ID/hash
compiler identity/version
runtime ABI
execution binding
authority grants
input/output artifact hashes
verification results
```

The user does not need to see all of this by default, but the system needs it for inspectability/debugging.

## Measuring whether compilation matters

Use `docs/32-aios-ir-and-skill-benchmark-plan.md`.

Especially measure:

- eliminated model/planner work;
- IPC calls eliminated;
- bytes/copies eliminated;
- memory reduction;
- startup overhead;
- CPU/GPU efficiency;
- compile cost/amortization;
- correctness/security parity.

This evidence directly informs whether a deeper custom runtime/language is justified.

## Architectural principle

> **Compilation may specialize execution, never authority or truth.**
