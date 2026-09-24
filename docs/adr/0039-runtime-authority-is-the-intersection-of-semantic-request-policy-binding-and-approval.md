# ADR 0039 — Runtime Authority Is the Intersection of Semantic Request, Policy, Binding, Resource, and Approval

- Status: **Accepted for the v0.1 / Phase-I substrate**
- Date: 2026-09-15

## Context

AIOS must let AI-generated plans and interchangeable providers request useful side effects without turning the AI, provider, or logged-in user session into a superuser.

A semantic authority request in AIOS IR describes what the program may need, but it is not a permission grant. Likewise, provider conformance, signatures, user approval, or policy allow decisions should not independently create broader authority than the validated Task semantics and concrete runtime binding permit.

## Decision

For v0.1, concrete runtime authority is the strict intersection of:

```text
validated semantic authority request
∩ deterministic current policy
∩ exact Task + semantic node
∩ exact provider/workload principal + Execution Binding
∩ exact resolved concrete resource
∩ valid approval state when policy requires it
∩ current time/usage/revocation constraints
```

The Authority Coordinator owns this intersection, produces stable decisions/grants, and validates/revokes grants at point of use through resource mediators.

Policy-engine syntax/implementation is not part of the AIOS semantic ABI. Cedar may serve as the reference backend under ADR 0010/spike evidence, but AIOS authority contracts remain engine-neutral.

User approval satisfies a policy condition; it cannot override architecture invariants or explicit hard deny.

v0.1 prefers opaque random grant handles with server-side grant records rather than complex self-contained bearer/JWT semantics.

Detailed semantics are in `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`.

## Consequences

### Positive

- no ambient AI/provider/user-session authority;
- provider substitution does not reuse another provider's grant automatically;
- approvals cannot become blanket superuser bypasses;
- revocation/expiry/one-shot consumption are straightforward;
- secret/resource mediation stays outside planner/model context;
- policy backend can evolve without redefining Task/IR contracts.

### Costs

- runtime action requires deterministic request/resource/principal normalization;
- point-of-use grant validation is needed;
- provider rebinding often requires a new policy/grant evaluation;
- trusted approval UI and policy snapshot attribution add control-plane machinery.

## Security impact

This ADR is a core enforcement boundary. Any implementation shortcut that allows a provider/model to act under broader logged-in user credentials violates I1/I2/I10/I14/I33/I35.

The Stage-1 `0015_authority_issuance_fence` migration preserves preexisting grants as historical records but denies their use without a matching issuance receipt. It does not infer missing token or Execution Binding facts, and it does not treat a SQL row alone as proof of coordinator issuance. A later private Authority Coordinator writer must own receipt creation; the additive fence does not claim resistance to arbitrary privileged database modification.

## Related

- ADR 0006
- ADR 0010
- ADR 0031/0033
- `docs/19-principal-and-authority-model.md`
- `docs/45-cross-domain-transactions-and-compensation.md`
- `docs/57-component-distribution-supply-chain-update-trust.md`
- `docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md`
- GitHub Issue #3
