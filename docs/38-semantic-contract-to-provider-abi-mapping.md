# 38 — Semantic Contract → Provider ABI Mapping

## Purpose

AIOS separates **semantic meaning** from **how an implementation is called**.

That creates a necessary translation layer:

```text
Semantic Capability Contract
       │
       │ provider implementation mapping
       ▼
Concrete Provider ABI
       │
       ▼
Rust process / Varlink / Wasm Component / OCI / model adapter / legacy adapter
```

This document defines what that mapping must preserve so a convenient ABI never becomes the de-facto semantic contract.

## Four identities that must stay distinct

For one invocation, the system may have:

1. **Semantic Capability ID** — e.g. `artifact.hash@1`;
2. **Provider ID/version** — e.g. `org.example.hash-provider@0.4.2`;
3. **Provider ABI/interface version** — e.g. a WIT package/world version or Varlink interface version;
4. **Execution Binding ID** — one concrete attempt under one task/current grant.

Changing #2 or #3 should not change #1 if conformance remains valid.

Changing #4 certainly should not change #1.

## What the semantic contract owns

A Semantic Capability Contract owns:

- operation meaning;
- semantic input/output port names and types;
- allowed execution classes;
- allowed side-effect classes;
- allowed authority classes;
- allowed egress modes;
- stable semantic error classes;
- conformance-suite identity;
- deterministic-equivalence rules where applicable.

The provider ABI must preserve/marshal these concepts; it does not redefine them.

## What the ABI owns

A provider ABI may define:

- concrete function/interface names;
- wire data layout;
- resource/handle representation;
- streaming/chunking mechanics;
- cancellation protocol;
- progress/diagnostic channel;
- ABI-level errors;
- lifecycle/health handshake;
- protocol version negotiation;
- concrete host imports exposed to the provider.

Those details can change without redefining the semantic capability if an adapter preserves the same contract.

## Port mapping

Every semantic port must map explicitly to an ABI parameter/result field or host-mediated resource.

Example:

```text
Semantic contract:
  artifact.hash@1
  input  source : artifact.file@1
  output hash   : data.hash@1

WIT ABI:
  hash(source: borrow<input-artifact>, algorithm: string)
      -> result<digest, hash-error>
```

The WIT `input-artifact` is not itself the semantic type. It is a concrete host-mediated representation/handle for an artifact whose Semantic Type and instance metadata have already been validated/bound.

## Type mapping table

A provider registration should be able to answer:

```text
semantic port
semantic type
physical representation / ABI type
conversion/adapter used (if any)
zero-copy eligible?
```

Example:

```text
metrics
  data.metrics@1
  → canonical-json bytes
  → guest record/bytes adapter
```

or:

```text
table
  data.table@1
  → Arrow IPC shared-memory region
  → read-only handle
```

Representation choices belong to provider registration/execution binding and can be optimized independently.

## Artifact handles vs artifact content

AIOS should prefer opaque task-scoped resources over host paths.

The ABI may give a provider:

```text
input-artifact handle
```

with operations such as:

```text
metadata()
read(offset, length)
```

instead of:

```text
/home/dale/private/report.xlsx
```

Benefits:

- provider cannot invent neighboring paths;
- host can enforce task scope per handle;
- storage backend can change;
- remote/peer/provider adapters can implement the same logical resource;
- provenance can attribute reads to a bound artifact.

For high-performance in-process/local providers, the handle can later negotiate shared memory or another representation without changing semantic identity.

## Authority mapping

Semantic authority declarations are upper-bound/request semantics.

Provider ABI imports determine what actions are even technically reachable in that execution environment.

Example:

```text
Semantic contract allows:
  artifact.read

Wasm provider world imports:
  AIOS artifact input interface only

Execution Binding grants:
  read artifact A42 for Task T91
```

All three layers agree.

A provider ABI exposing generic networking when the semantic contract forbids network is a provider/contract incompatibility even if policy would later deny actual network use.

Defense in depth means unnecessary interfaces should be absent, not merely denied at the final syscall.

## Static imports and dynamic grants

Some ABI technologies, especially the WebAssembly Component Model, have statically declared imports.

AIOS task authority remains dynamic.

Use the distinction:

```text
Static world/import = maximum technical capability the component can ask the host to fulfill
Current Execution Binding = concrete task-scoped resources/actions actually supplied
```

Where a provider imports an interface that can be safely narrowed dynamically (for example an artifact resource), the host supplies only handles for authorized resources.

Where an imported interface is inherently broad (generic outbound networking), consider:

- separate provider variants/worlds;
- stronger sandbox policy;
- narrow destination-bound host interfaces;
- making the provider ineligible under no-egress tasks.

Do not solve dynamic policy by giving every component a universal host API and asking it to behave.

## Narrow network interfaces

A future remote/network-capable provider ABI should prefer host-mediated operations tied to approved destinations rather than a raw socket interface where practical.

Conceptually:

```text
external-call(endpoint-handle, request)
```

where the host created `endpoint-handle` only after policy approved a destination class/endpoint.

For workloads genuinely needing generic networking, stronger isolation and explicit network policy are required.

## Clock/random/environment

Clock, randomness, environment variables, locale, and similar ambient data can affect determinism and replay.

Therefore:

- deterministic providers should not receive them automatically;
- capabilities that need current time/randomness should request explicit semantic capabilities/inputs where the value matters to task meaning;
- an ABI may expose a clock/random source only when its presence is compatible with semantic contract/execution class;
- sensitive host environment values are never inherited by default.

## Error mapping

Provider ABI errors must map into semantic error classes.

Example:

```text
WIT error:
  read-failed("host returned access-denied")

Provider adapter/runtime maps to:
  ARTIFACT_HASH_READ_FAILED

Policy denial is NOT remapped to provider failure.
```

Keep separate:

- authorization denial;
- ABI transport failure;
- provider semantic failure;
- provider crash;
- output verification failure.

This lets bounded fallback/retry behave correctly.

## Cancellation

A provider ABI should eventually support cooperative cancellation.

Requirements:

- cancellation carries Task/Binding context implicitly through the runtime, not a reusable token;
- cancellation does not mean rollback succeeded;
- external side effects may require reconciliation;
- the control plane records requested/observed cancellation separately;
- uncooperative providers can be terminated by the supervisor/sandbox according to execution class/effect risk.

v0.1 may implement process termination before a fully general ABI-level cancellation protocol.

## Progress and logs

Progress/logging channels are non-authoritative.

A provider saying:

> "done"

in a log does not complete the task.

Completion comes from protocol/runtime outcome, expected outputs, verification, and control-plane state transition.

Logs should be treated as potentially untrusted content and subject to size/privacy limits.

## Health interface

Provider health/readiness should be a minimal operation separate from task execution.

It should not require:

- arbitrary task artifacts;
- secrets unrelated to startup;
- broad network;
- user authority.

Possible states:

```text
ready
degraded
unavailable
blocked
```

Health is current runtime availability, not semantic conformance.

## ABI versioning

Provider ABI versions should evolve independently from capability semantic versions.

Example:

```text
artifact.hash semantic contract: 1.0
WIT ABI package:                 0.1 → 0.2
provider implementation:        3.7 → 4.0
```

If the ABI changes but an adapter preserves `artifact.hash@1.0` semantics, the AIOS IR program does not change.

## Cross-language requirement

A provider ABI is successful only if implementations from different languages can satisfy the same semantic contract without language-specific behavior leaking upward.

Issue #18 should test at least two guest languages where current toolchains permit.

Conformance should catch differences such as:

- integer overflow behavior;
- Unicode normalization;
- floating-point tolerances;
- missing/null conventions;
- filesystem path assumptions;
- exception/panic behavior.

## Model adapter ABI

Model providers need a different concrete ABI from artifact hashing, but the same layering applies.

Semantic capability might be:

```text
report.summarize@1
```

Concrete adapter ABI handles:

- model descriptor;
- structured request/context representation;
- local/remote invocation;
- token/usage metadata;
- structured output;
- transport errors.

The semantic contract still owns output type, allowed execution class, egress modes, and conformance expectations.

## Legacy adapter ABI

Legacy application adapters may need:

- launch/habitat interface;
- file/artifact projection;
- UI automation/accessibility adapter;
- lifecycle observation;
- output capture.

Because behavior is often opaque, the adapter should advertise only semantic capabilities it can reliably enforce/verify.

## Security validation

Before registration, compare:

```text
semantic contract allowed effects/authority
        vs
provider manifest declared effects/authority
        vs
ABI static imports/reachable host functions
        vs
minimum sandbox profile
```

Any unexplained broadening should reject registration or raise isolation requirements.

This creates a useful future tool:

```text
aios-provider inspect component.wasm
```

which could show:

```text
implements: artifact.hash@1
imports: artifact-read, progress, log
network: none
filesystem: none
secrets: none
conformance: tested
```

## Relationship to future custom language

If AIOS later gains a custom source language/compiler, provider ABI boundaries should remain useful.

A new compiler could target:

- Wasm Component ABI;
- native provider ABI;
- compiled Skill ABI;

without forcing third-party providers to be rewritten in the new language.

This is another reason to keep semantics above implementation language.

## Architectural principle

> **Semantic contracts tell AIOS what a capability means; ABIs tell one implementation how to participate without inheriting more authority than it needs.**
