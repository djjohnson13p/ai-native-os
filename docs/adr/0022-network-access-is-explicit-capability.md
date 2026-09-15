# ADR 0022 — Network Access Is an Explicit Task-Scoped Capability

- Status: **Proposed**
- Date: 2026-09-15

## Context

Conventional applications commonly inherit ambient network access. In an AI-native platform, that would make it difficult to prove what data left a device, prevent model/provider exfiltration, or enforce local-only operation.

AIOS also needs peer, local-service, cloud, relay, and public-internet connectivity without coupling semantic programs to IP addresses or one transport.

## Decision

Providers/agents do not receive unrestricted network access by default.

Network communication is requested as bounded authority to a semantic service/destination class and is mediated by the Network Fabric.

Discovery does not imply authorization. Reachability does not imply trust.

Network paths/endpoints/addresses belong to runtime binding and may change without changing semantic program identity.

## Required properties

- explicit egress policy;
- stable service identity where practical;
- authenticated/encrypted transport for trusted services;
- provenance for material external transfer;
- destination/data-sensitivity constraints;
- inbound exposure closed by default;
- network-loss/retry semantics coordinated with operation idempotency/outcome certainty.

## Consequences

### Positive

- local-only mode is enforceable;
- data egress is inspectable;
- peer/cloud/service connectivity can use one policy model;
- transport/address changes do not rewrite AIOS IR;
- compromised providers have smaller exfiltration surface.

### Costs

- legacy apps may require broader habitat-specific network mediation;
- Network Broker/service identity infrastructure is required;
- some developer workflows need explicit network grants that conventional OSes grant implicitly.

## Related

- `docs/51-network-fabric-and-service-connectivity.md`
- `specs/network-service-descriptor.schema.json`
- `specs/network-transfer.schema.json`
- ADR 0006
