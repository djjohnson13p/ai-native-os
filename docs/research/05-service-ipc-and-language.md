# Research 05 — Service Boundaries, IPC, and Implementation Languages

**Research date:** 2026-09-15  
**Status:** provisional v0.1 recommendation; intended to resolve issue #15 after review.

## Question

How much of the v0.1 control plane should be split into services, what IPC should connect components, and where should Rust versus Python be used?

The project should avoid two opposite mistakes:

1. building a fragile single process in which third-party/model code runs with control-plane authority;
2. turning a prototype into a distributed microservice system before the contracts are proven.

## Recommendation in one sentence

> **Use one modular Rust control-plane daemon for trusted task/policy/artifact/provenance coordination, run capability/model/legacy providers out-of-process, use Varlink over Unix sockets for the first provider/control interfaces, reserve D-Bus for Linux desktop/portal integration, and keep gRPC or another network-oriented protocol for future remote/peer execution.**

## Proposed v0.1 process model

```text
┌───────────────────────────────────────────────────────────┐
│ task shell / CLI                                          │
└────────────────────────────┬──────────────────────────────┘
                             │ local typed IPC
                             ▼
┌───────────────────────────────────────────────────────────┐
│ aiosd — Rust, unprivileged per-user daemon                │
│                                                           │
│  task manager                                             │
│  intent/task state                                        │
│  capability registry                                      │
│  policy/authority                                         │
│  artifact broker                                          │
│  provenance store                                         │
│  resource broker                                          │
│  planner coordinator                                      │
│  verifier coordinator                                     │
│  provider supervisor                                      │
└───────┬─────────────────┬───────────────────┬─────────────┘
        │ Varlink/UDS     │ Varlink/UDS       │ habitat ctrl
        ▼                 ▼                   ▼
┌──────────────┐   ┌────────────────┐   ┌──────────────────┐
│ capability   │   │ model adapters │   │ legacy habitats  │
│ providers    │   │ llama.cpp/etc. │   │ Wine/etc.        │
│ Rust/Python  │   │ out-of-process │   │ out-of-process   │
└──────────────┘   └────────────────┘   └──────────────────┘

Optional later:

┌───────────────────────────────────────────────────────────┐
│ minimal privileged system broker                          │
│ system update · privileged devices · machine-wide config  │
└───────────────────────────────────────────────────────────┘
```

## Why one core daemon first

The initial architecture diagram names many logical services. They do not all need to be separate OS processes in v0.1.

Keeping task state, artifact metadata, authority state, and provenance coordination inside one daemon initially provides:

- simpler transactions;
- fewer partial-failure modes;
- easier debugging;
- lower resource use on older hardware;
- less serialization/IPC boilerplate;
- faster evolution while contracts are still changing.

The code should still use explicit Rust modules/interfaces so any component can be split later without rewriting semantics.

### What must remain out-of-process

At minimum:

- third-party capability providers;
- complex parsers/renderers that process hostile files;
- AI/model runtimes;
- legacy applications/habitats;
- any generated/untrusted code executor;
- future privileged system broker.

Those boundaries are security boundaries, not microservice style preferences.

## IPC options reviewed

### Varlink

Varlink provides a small typed interface-description format and a JSON-based protocol. Its current documentation emphasizes discoverability, self-documentation, testability, Unix-socket transport, simple debugging, socket activation, and language bindings including Rust and Python.

Why it fits the v0.1 provider/control interface well:

- typed interfaces without a large code-generation stack;
- plain JSON messages are easy to inspect in early development;
- Unix socket support matches local process isolation;
- service discovery/introspection can help capability/provider diagnostics;
- Rust and Python bindings exist;
- systemd-style socket activation aligns with a Linux service substrate;
- multiple replies can support task/provider progress streams.

Important limitation:

Varlink intentionally focuses on message interfaces rather than passing local file descriptors/references. That is acceptable for the provider protocol if artifact resources are prepared by the trusted runner and mounted/exposed to the sandbox **before** provider execution.

Primary sources:

- https://varlink.org/
- https://varlink.org/Interface-Definition.html
- https://varlink.org/FAQ
- https://varlink.org/Language-Bindings

### D-Bus

D-Bus is mature Linux desktop/system IPC and supports Unix file-descriptor transfer and authenticated bus identities.

It is attractive for:

- Linux desktop shell integration;
- portals/file pickers;
- notifications;
- session services;
- interoperability with existing desktop components.

Why not make it the universal AI-OS provider ABI initially:

- its bus/object model is more coupled to the Linux desktop/system environment;
- the long-term provider interface may need to work identically in containers, remote nodes, non-Linux hosts, or future mobile targets;
- providers normally need semantic artifact handles rather than unrestricted local FDs anyway.

Primary source:

- https://dbus.freedesktop.org/doc/dbus-specification.html

### gRPC / Protocol Buffers

gRPC provides strongly typed service definitions, generated clients/servers, streaming RPCs, and mature multi-language/network support.

It is a strong future candidate for:

- peer compute;
- organizational nodes;
- remote resource brokers;
- high-volume model/compute services.

Why not start with it everywhere:

- HTTP/2 and code generation are unnecessary complexity for small local v0.1 providers;
- it encourages treating every logical module as a network service;
- it adds dependencies/build tooling before the local contracts stabilize.

Primary sources:

- https://grpc.io/docs/what-is-grpc/introduction/
- https://grpc.io/docs/what-is-grpc/core-concepts/

### Raw JSON-RPC over Unix sockets

JSON-RPC 2.0 is lightweight and transport-agnostic. It would be easy to implement.

Why Varlink is preferable for the first project-owned local API:

- Varlink includes a simple IDL and documented type system;
- service introspection is built into the model;
- interface documentation lives with the machine-readable contract;
- standard socket-activation patterns already exist.

JSON-RPC remains a reasonable fallback if Varlink tooling proves insufficient.

Primary source:

- https://www.jsonrpc.org/specification

## Language split

### Rust — deterministic control plane

Use Rust for `aiosd` and security-sensitive local brokers because:

- memory safety is valuable in code parsing authority/artifact/task state;
- good control over Unix process/socket/sandbox primitives;
- static binaries/dependency control are useful for system services;
- strong type modeling helps state machines and capability contracts;
- lower idle/runtime overhead than a large interpreted control-plane stack is useful on older devices.

Do **not** require every provider to be written in Rust.

### Python — prototype providers, analysis, and adapters

Use Python where rapid iteration matters and isolation provides the security boundary:

- Demonstration A table/chart/report providers;
- fixture generators;
- model/provider adapters during experimentation;
- compatibility-profile tooling;
- test harnesses;
- architecture experiments.

Python providers must still run out-of-process under explicit execution profiles. "It's only Python" is not a trust designation.

### Other languages

The provider protocol is intentionally language-neutral. Future providers may be C/C++, Go, JavaScript, Zig, JVM/.NET, or others if they conform to capability interfaces and isolation rules.

The OS must not equate one language with one capability class.

## Data transport rule

Do **not** send large user files through IPC JSON messages.

IPC messages should carry:

- task IDs;
- artifact handles;
- metadata;
- capability requests/results;
- progress/events;
- small structured values;
- policy decisions;
- error/status information.

Bulk data stays in:

- broker-managed files/objects;
- sandbox mounts;
- streams explicitly negotiated by a specialized transport when needed.

This keeps the control protocol inspectable and prevents base64-encoded multi-gigabyte artifacts from becoming an accidental ABI.

## Persistence recommendation

Use SQLite for v0.1 control-plane metadata because task, artifact, grant, and provenance state require transactions but not a remote database server.

Candidate logical tables:

```text
tasks
intent_revisions
plan_revisions
artifacts
artifact_lineage
providers
capabilities
policy_rules
authority_grants
approvals
provenance_events
skills
model_invocations
```

Large artifacts and model files should not be stored as SQLite blobs by default; store identities/metadata and broker-managed object paths/content-addressed references.

## Interface versioning

No prototype IPC shape should become the permanent ABI accidentally.

Every project-owned interface should carry:

- reverse-domain/stable interface name;
- explicit version or compatibility contract;
- documented optional-field behavior;
- declared errors;
- conformance tests;
- architecture requirement references.

Breaking protocol changes are acceptable before v1.0 but must be explicit.

## Suggested initial interfaces

```text
org.ainative.Task
org.ainative.Artifact
org.ainative.CapabilityRegistry
org.ainative.Authority
org.ainative.Provider
org.ainative.Provenance
org.ainative.Resource
org.ainative.Model
org.ainative.LegacyBroker
```

`org.ainative` is a placeholder namespace until the project has a final name/domain.

## Provider lifecycle

Preferred v0.1 flow:

1. provider package/manifest is registered;
2. provider remains stopped when unused where practical;
3. supervisor creates execution profile;
4. sandbox/process is started or activated;
5. provider exposes its typed interface through a private Unix socket;
6. control plane performs capability call(s);
7. provider emits bounded progress/result information;
8. artifacts are collected through the artifact broker;
9. provider exits/returns idle according to policy;
10. resource/accounting/provenance is finalized.

A provider cannot decide its own sandbox mounts or network grants after launch.

## Privileged operations

Do not run the entire `aiosd` as root.

If later tasks require machine-level actions, create a deliberately small privileged broker with a narrow interface such as:

```text
system.update.stage
system.update.activate
system.rollback
system.device.grant
system.power.request
```

That broker independently validates deterministic authorization and never accepts arbitrary shell commands from the planner.

## Decision matrix

| Option | Local simplicity | Types | Introspection | Rust/Python | FD passing | Remote suitability | v0.1 role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Varlink/UDS | High | Yes | Yes | Yes | No/by design | Moderate | **Core/provider local IPC** |
| D-Bus | Moderate | Yes | Yes | Yes | Yes | Low/desktop-oriented | Desktop/portal integration |
| gRPC | Lower | Strong | Via descriptors/tooling | Yes | Not native local FD model | High | Future peer/remote |
| JSON-RPC/UDS | High | External schemas | Minimal | Yes | Custom | Moderate | Fallback/prototyping |

## Provisional v0.1 decision

- `aiosd`: Rust, modular single process, per-user/unprivileged.
- provider/model/legacy execution: separate sandboxed processes.
- primary project-owned local IPC: Varlink over Unix-domain sockets.
- Linux desktop integration: D-Bus/portal APIs where they solve an existing problem.
- remote/peer protocol: explicitly deferred; do not assume local Varlink protocol is the internet security layer.
- Python: first-party prototype providers and tooling.
- persistence: SQLite plus broker-managed artifact/object storage.
- privileged system broker: deferred until a v0.1 use case actually requires it.

## Validation before accepting ADR

1. implement one tiny Rust Varlink service and Python client;
2. implement one Python provider and Rust client/supervisor;
3. measure startup/idle overhead on a constrained machine/profile;
4. test socket activation/restart behavior;
5. test schema/type evolution with optional fields;
6. confirm sandbox construction does not require protocol-level file-descriptor transfer.

If these experiments reveal poor tooling or maintenance risk, fall back to a simple framed JSON-RPC protocol while preserving the higher-level contracts.
