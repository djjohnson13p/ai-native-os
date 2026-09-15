# ADR 0033 — Capability Contracts Declare Required and Allowed Effects/Authority

- Status: **Accepted for the v0.1 / Issue #17 spike**
- Date: 2026-09-15

## Context

The initial Semantic Capability Contract exposed only `allowed_effect_classes` and `allowed_authority_classes`.

That defines an upper bound but cannot detect an IR node that omits authority/effects every valid implementation of the capability inherently requires.

Examples such as `artifact.hash@1`, `table.import@1`, and `chart.render@1` have semantic resource effects that should not be optional planner guesses.

## Decision

Semantic Capability Contracts v0.1 declare both:

```text
required_effect_classes
allowed_effect_classes
required_authority_classes
allowed_authority_classes
```

Required sets are semantic lower bounds. Allowed sets are semantic upper bounds.

Required sets must be subsets of allowed sets.

`PURE` is mutually exclusive with non-PURE derived effects. A capability that is always pure declares required/allowed `[PURE]`; a capability that can be either pure/local or externally effectful may use an empty required-effect set and an allowed set containing `PURE` plus optional effects.

The full profile is `docs/69-v0.1-capability-effect-and-authority-contract-profile.md`.

## Consequences

### Positive

- validator can detect missing required authority;
- static effect summaries have a semantic lower bound;
- provider conformance can reject implementations that need undeclared privileges;
- fallback compatibility can detect authority/effect broadening;
- local-vs-remote provider variants can share one semantic capability when the optional envelope is explicit.

### Costs

- capability contract fixtures/schemas need another pair of fields;
- authority-class-to-effect mapping becomes explicit trusted semantic infrastructure;
- domain extensions must define new authority/effect mappings deliberately rather than by naming convention.

## Security impact

This closes an under-declaration failure mode in which a model/planner could omit authority required by a capability and rely on provider runtime behavior to acquire it later.

Concrete grants remain runtime policy decisions. Required authority in a semantic contract is still a request requirement, not permission.

## Related

- ADR 0032
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/69-v0.1-capability-effect-and-authority-contract-profile.md`
- `specs/capability-contract.schema.json`
- `specs/effect-summary.schema.json`
