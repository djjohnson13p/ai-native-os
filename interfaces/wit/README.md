# WIT / WebAssembly Component Model Provider ABI Spike

**Status:** architecture/research fixture — not a stable ABI.

This directory explores the WebAssembly Component Model as a language-neutral provider boundary **below** AIOS semantic contracts.

The intended layering is:

```text
AIOS IR
   ↓
Semantic Capability Contract
   ↓
Provider Manifest + conformance
   ↓
WIT world/interface (one possible concrete provider ABI)
   ↓
WebAssembly Component
   ↓
AIOS host supplies only current task-scoped capabilities
```

## Files

- `provider-host/world.wit` — narrow host-side artifact/progress/log interfaces a provider may import.
- `artifact-hash/world.wit` — example capability component that exports a hashing interface and imports the narrow AIOS host interfaces.

## Design goals

1. **No ambient filesystem.** The fixture receives an opaque `input-artifact` resource instead of `/home/...` paths.
2. **No ambient network.** The world imports no socket/HTTP interface.
3. **No ambient secrets/environment.** The world imports no environment or secret-store interface.
4. **Language-neutral.** Rust and another supported guest language should be able to implement the same exported WIT interface.
5. **Current authority remains host-side.** Possessing a WIT resource handle only means the host chose to expose that task-scoped resource to this invocation.
6. **WIT does not define semantics.** `artifact.hash@1` meaning/conformance remains in the Semantic Capability Contract.

## Why artifact handles are resources

Passing a host path/string would let guest code invent or probe identifiers the host did not explicitly hand it.

The `input-artifact` resource is host-implemented and gives the component a narrow object with only metadata/read methods. The component does not learn the underlying filesystem path.

Likewise, output creation is mediated through `allocate-output`; the component cannot choose an arbitrary host destination.

## Why no generic WASI command world

A generic command environment commonly expects filesystem, environment, clocks, stdio, and sometimes network capabilities. That is useful for ordinary applications but broader than many AIOS capability providers need.

The spike intentionally starts from an almost-empty world and adds imports according to semantic/provider requirements.

A provider that genuinely requires time/random/network should receive an explicit AIOS host interface or explicitly authorized WASI interface in its concrete execution profile.

## Compatibility/toolchain note

The Component Model/WASI ecosystem is evolving. This WIT is an architecture sketch and must be validated against the exact Wasmtime/component toolchain selected for Issue #18 before becoming executable.

Pin toolchain/runtime versions in the experiment rather than treating today's syntax/runtime support as a permanent AIOS ABI.

## Conformance experiment

Issue #18 should implement `artifact-hash` in two guest languages if practical and prove:

- both components export the same WIT contract;
- both map to the same `artifact.hash@1` Semantic Capability Contract;
- both pass the same semantic conformance suite;
- neither can access filesystem/network/secrets unless the host explicitly adds imports;
- provider switching changes Execution Binding/provenance only, not AIOS IR semantic hash.

## Security note

Component imports are a useful enforcement mechanism, but they do not replace:

- package/publisher trust;
- semantic provider conformance;
- deterministic task policy;
- artifact sensitivity policy;
- runtime resource limits;
- provenance;
- verification.
