# ADR 0020 — Resource Placement Does Not Change Semantic Program Identity

- Status: **Proposed**
- Date: 2026-09-15

## Context

AIOS is intended to run the same Task model across heterogeneous hardware and provider environments.

A semantic capability may execute on the current CPU, a local GPU/NPU, a sandboxed process, a trusted peer device, or a policy-approved remote provider.

If placement/provider identity becomes part of the semantic program, hardware adaptation would continuously rewrite Task meaning and invalidate reusable Skills, provenance comparisons, caches, and provider substitution.

## Decision

AIOS IR semantic identity will exclude concrete provider, device, accelerator, endpoint, execution grant, and transient resource-selection information.

Placement occurs after semantic validation and policy eligibility.

A concrete attempt creates an `Execution Binding` and `Placement Decision` linked to the stable semantic node/program hash.

Changing placement/provider creates a new binding/attempt but does not change semantic program identity unless the requested semantic capability/constraints themselves change.

## Hard constraints

Placement MUST NOT weaken:

- semantic capability/version requirements;
- authority/policy restrictions;
- data sensitivity/egress rules;
- required isolation;
- verification requirements;
- correctness/conformance minimums.

## Consequences

### Positive

- the same Skill/program can run across old and new hardware;
- hardware upgrades do not require semantic rewrites;
- provider/peer/remote substitution remains inspectable;
- caching/compilation can key on semantic identity separately from target-specific artifacts;
- resource decisions can be re-evaluated dynamically.

### Costs

- runtime needs explicit binding/placement records;
- provider-specific results must be checked against the same semantic contract;
- target-specific compiled artifacts require separate identity/version metadata;
- stateful migration/recovery becomes a distinct subsystem.

## Related

- `docs/06-resource-broker.md`
- `docs/10-hardware-adaptation.md`
- `docs/48-resource-placement-and-personal-compute-fabric.md`
- `specs/execution-binding.schema.json`
- `specs/resource-snapshot.schema.json`
- `specs/placement-decision.schema.json`
