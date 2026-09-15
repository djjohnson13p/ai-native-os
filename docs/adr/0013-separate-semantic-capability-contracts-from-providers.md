# ADR 0013 — Separate Semantic Capability Contracts from Provider Manifests

- **Status:** Proposed
- **Date:** 2026-09-15

## Context

AIOS IR plans against semantic capabilities so the operating environment can choose among multiple implementations without changing task meaning.

If the provider manifest itself defines what a capability means, two providers can silently disagree about types, effects, determinism, or failure semantics while using the same capability name.

That would make provider substitution unreliable and would cause implementation detail to leak into the semantic layer.

## Decision

Define a first-class **Semantic Capability Contract** independent of any provider implementation.

The contract defines:

- capability identity/version;
- named typed inputs and outputs;
- allowed execution classes;
- allowed effect/authority classes;
- allowed egress modes;
- semantic error classes;
- determinism/equivalence rules where applicable;
- conformance-suite identity.

Provider manifests declare that they implement a particular semantic contract and later should record the contract hash/conformance status.

AIOS IR validates against semantic capability contracts, not against arbitrary provider behavior.

## Resulting layer model

```text
AIOS IR
   ↓
Semantic Capability Contract
   ↓
Provider Manifest / Implementation
   ↓
Runtime binding + sandbox + authority grant
```

## Consequences

### Positive

- provider interchangeability has a testable meaning;
- planner/IR semantics remain provider neutral;
- providers cannot silently broaden capability authority;
- conformance testing can be shared across implementations;
- capability contracts can survive provider upgrades/replacements;
- compiled skills can depend on semantic contracts rather than vendor identities.

### Negative

- the project must maintain a semantic capability/type registry;
- provider integration requires an extra contract/conformance step;
- capability ontology/versioning becomes a real governance concern;
- some legacy applications may only honestly implement broad opaque capabilities until reliable adapters exist.

## Alternatives considered

### Let every provider define its own signature

Rejected because a shared capability name would not guarantee shared semantics.

### Pin every task to one provider

Rejected because this defeats model/provider/application independence and prevents hardware-adaptive substitution.

### Put all implementation behavior into AIOS IR

Rejected because it would make semantic programs hardware/provider specific and harm reuse/compilation.

## Acceptance criteria

This ADR should be accepted when:

- the v0.1 capability-contract schema can describe every Demonstration A operation;
- two fixture providers can implement at least one shared contract;
- the validator rejects a provider whose ports/effects conflict with the semantic contract;
- provider substitution passes one shared conformance suite without changing AIOS IR.

## Related

- `docs/04-capability-model.md`
- `docs/25-aios-ir-semantics.md`
- `docs/28-capability-contracts-and-conformance.md`
- `specs/capability-contract.schema.json`
- Issue #2
- Issue #16
