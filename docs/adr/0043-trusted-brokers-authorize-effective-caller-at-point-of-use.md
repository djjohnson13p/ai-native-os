# ADR 0043 — Trusted Brokers Authorize the Effective Caller at Point of Use

- Status: **Proposed / controlling for Stage-1 protected resource brokers**
- Date: 2026-09-15

## Context

AIOS intentionally moves protected resources behind trusted brokers such as the Artifact Store, Credential Broker, Network Broker, Object Store, and Device Broker.

Those services may have broad OS-level mechanism privilege. If they authorize requests merely because the broker process itself is privileged, they become confused deputies and collapse the no-ambient-authority model.

## Decision

Every protected broker operation is authorized as the effective caller/workload acting through the broker, not as the broker's own service principal.

At point of use, trusted code validates:

```text
authenticated caller/workload identity
+ immutable Execution Binding / attempt
+ Task / semantic program / node
+ exact action
+ concrete resource
+ current durable Authority Grant(s)
+ current Task/grant/resource state
+ broker-specific invariants
```

Provider-supplied identifiers are claims until they match authenticated channel and trusted durable state.

The broker's OS privilege supplies mechanism access only; it is not delegated authority.

## Consequences

### Positive

- trusted services do not become universal privilege proxies;
- provider compromise remains scoped to current Task/resource/grant;
- cancellation/revocation can be enforced after provider launch;
- one-shot grant use can be serialized at the actual resource boundary;
- transport can evolve without changing authority semantics.

### Costs

- protected broker calls require more context/state lookups;
- IPC/workload identity must be authenticated strongly enough for the trust boundary;
- high-volume interfaces need efficient session/batched validation without weakening grant scope;
- resource services must integrate with Authority Grant state rather than rely on process identity alone.

## Security impact

This ADR closes the confused-deputy path where a system service's own filesystem/network/credential privileges could otherwise be borrowed by an untrusted provider.

Sandboxing remains complementary: providers must also be unable to bypass the trusted broker and access the raw resource directly.

## Compatibility impact

Legacy/provider adapters that require broader raw access must run in explicitly stronger compatibility/isolation profiles and cannot claim the narrow brokered capability contract unless they actually satisfy it.

## Related

- `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`
- `docs/78-v0.1-execution-binding-and-provider-supervisor.md`
- `docs/79-v0.1-credential-broker-and-secret-mediation.md`
- `docs/91-v0.1-protected-operation-point-of-use-contract.md`
- `specs/protected-operation-context.schema.json`
- ADR 0006
- ADR 0039
- ADR 0040
- ADR 0041

## Principle

> **Broad service privilege is implementation machinery, never ambient delegated authority.**
