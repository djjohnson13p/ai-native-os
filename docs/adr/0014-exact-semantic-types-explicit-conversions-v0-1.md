# ADR 0014 — Exact Semantic Types and Explicit Conversions for v0.1

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

AIOS IR composes capabilities from multiple providers and implementation languages. Implicit coercion rules copied from Python, JavaScript, C/C++, dataframe libraries, or model guesses would make task behavior difficult to validate and would create ambiguity at trust boundaries.

## Decision

For AIOS IR v0.1:

1. capability ports use versioned semantic type identifiers;
2. port compatibility requires an exact compatible semantic type under the type registry;
3. semantic conversion must be represented by an explicit capability node;
4. missing values and null are distinct;
5. artifact semantic type and physical media representation are distinct;
6. language-specific coercion/sentinel behavior is not part of the operating-system contract;
7. representation conversion may be optimized/fused later, but the semantic conversion must remain reconstructable in provenance.

## Examples

`artifact.table@1` does not implicitly become `data.table@1`; a `table.import@1` operation performs that semantic conversion.

`data.metrics@1` does not implicitly become narrative text; a capability such as `report.summarize@1` is explicit in the graph.

## Rationale

Explicit conversion improves:

- model generation reliability;
- deterministic validation;
- provider interchangeability;
- provenance;
- security review;
- optimization safety;
- debugging.

The runtime may later support formally defined subtyping/compatibility rules, but they should be added only when real workloads justify the added complexity.

## Consequences

### Positive

- no hidden cast semantics;
- validator errors are local and explainable;
- conversions can carry their own authority/resource requirements;
- physical representations can evolve independently;
- planners can learn a small stable type graph.

### Negative

- early IR graphs are more verbose;
- adapters/conversion capabilities must be written explicitly;
- some ergonomics available in general-purpose languages are intentionally deferred.

## Acceptance criteria

- Demonstration A validates using only explicit type transitions;
- invalid fixtures detect a mismatched port type;
- a representation change can occur without changing semantic IR where no semantic conversion is required;
- semantic conversion remains visible even if an optimizer fuses its physical implementation.

## Related

- `docs/29-semantic-type-system.md`
- `specs/type-contract.schema.json`
- `specs/capability-contract.schema.json`
- `specs/aios-ir.schema.json`
