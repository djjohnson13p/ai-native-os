# ADR 0009 — Modular Rust Core and Varlink Provider IPC

- **Status:** Proposed — requires IPC spike
- **Date:** 2026-09-15

## Context

The architecture describes several logical services, but implementing every logical boundary as a separate network-style daemon would add unnecessary distributed-system complexity to v0.1. At the same time, third-party providers, AI runtimes, parsers, and legacy applications must not execute inside the trusted control-plane process.

## Proposed decision

For v0.1:

- implement one modular unprivileged per-user Rust daemon, `aiosd`, containing the trusted task/artifact/policy/provenance/resource coordination modules;
- keep capability providers, model runtimes/adapters, and legacy habitats out-of-process under execution profiles;
- use Varlink over Unix-domain sockets as the first project-owned local provider/control IPC;
- use D-Bus/portal APIs only where integrating with existing Linux desktop facilities provides clear value;
- defer a remote/peer protocol rather than assuming the local IPC is also the internet transport;
- use Python freely for prototype providers, adapters, fixtures, and test tooling;
- use SQLite for v0.1 transactional control-plane metadata and keep large artifacts/model weights outside database blobs by default;
- introduce a separate narrow privileged system broker only when a real privileged operation is required.

## Validation required

Before acceptance:

1. Rust Varlink service ↔ Python client spike;
2. Python provider ↔ Rust supervisor/client spike;
3. socket activation/restart test;
4. optional-field/interface evolution test;
5. constrained-resource startup/idle measurement;
6. proof that artifact sandbox mounts/handles remove the need to transfer broad raw paths or bulk data over IPC.

If Varlink tooling proves brittle, use a small framed JSON-RPC/Unix-socket protocol while preserving the same service boundaries and typed contracts.

## Consequences

### Positive

- avoids premature microservices;
- creates real isolation around high-risk providers;
- keeps contracts human-inspectable during the prototype;
- supports Rust/Python collaboration;
- gives long-running state a simple transactional home;
- retains a path to split modules into processes later.

### Costs/risks

- `aiosd` becomes an important trusted process and must remain modular/testable;
- Varlink has a smaller ecosystem than gRPC/D-Bus;
- a future remote compute protocol will be a separate design effort;
- IPC and provider SDK conformance tests become project responsibilities.

## Related

- `docs/research/05-service-ipc-and-language.md`
- `docs/21-trust-boundaries.md`
- issue #15
