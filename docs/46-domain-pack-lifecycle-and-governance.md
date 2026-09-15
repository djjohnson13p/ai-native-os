# 46 — Domain Pack Lifecycle and Governance

## Purpose

If AIOS is intended to absorb software capability continuously, it needs a way for hundreds or thousands of Domain Packs to evolve without turning the semantic layer into an unreviewable collection of incompatible schemas.

A Domain Pack is therefore a governed semantic package, not merely a folder of plugins.

## Pack lifecycle

Proposed lifecycle states:

```text
EXPERIMENTAL
DRAFT
CANDIDATE
STABLE
DEPRECATED
RETIRED
REVOKED
```

### EXPERIMENTAL

Research/prototyping. Breaking changes are expected. Not suitable as a durable external contract.

### DRAFT

Semantic object/capability contracts are documented and have initial fixtures, but compatibility is not promised.

### CANDIDATE

Contracts are believed ready for stabilization and have:

- object/type definitions;
- capability definitions;
- invariants;
- positive/negative fixtures;
- at least one provider path;
- security/effect review;
- import/export/federation strategy where applicable.

### STABLE

The major-version semantic contract is maintained under compatibility rules and has a conformance suite.

### DEPRECATED

Still supported but replacement/migration is defined.

### RETIRED

No new use should begin; historical objects/programs remain interpretable where possible.

### REVOKED

Used only for a security/integrity condition where continued use is unsafe. Revocation does not erase historical provenance.

## Semantic versioning

A Domain Pack version and its contained semantic contracts are related but distinct.

A pack release can add new compatible contracts without changing existing contract major versions.

Example:

```text
pack business.core 2.4.0
  core.party@1
  crm.opportunity@2
  commerce.quote@1
  commerce.invoice@1
```

The pack release version describes the bundle. The semantic identifiers describe meaning.

## Breaking-change rule

A breaking semantic change MUST create a new major semantic contract.

Do not silently redefine:

```text
commerce.invoice@1
```

because a new tax model or provider became convenient.

Instead create/migrate to a new version or a separate capability/type where the meaning is genuinely different.

## Domain namespaces

Namespaces should describe domain semantics, not vendor ownership.

Examples:

```text
core.*
knowledge.*
data.*
commerce.*
crm.*
accounting.*
project.*
media.*
cad.*
eda.*
manufacturing.*
software.*
communication.*
```

A community/project may publish implementations under its own provider namespace while still implementing shared semantic contracts.

## Contract ownership

Semantic contracts should have explicit maintainership metadata separate from provider publisher identity.

The maintainers of `cad.feature.extrude@1` do not need to maintain every CAD engine that implements it.

This separation is essential to avoiding provider capture of platform semantics.

## Conformance

A stable capability should have a versioned conformance suite containing:

- minimal valid operations;
- realistic operations;
- boundary cases;
- invalid inputs;
- deterministic expected invariants where applicable;
- tolerance rules for geometry/media/numerical domains;
- side-effect/authority tests;
- round-trip tests when import/export is part of the contract;
- performance classes only when performance is part of a support claim.

Conformance means the provider satisfies the semantic contract. It does not mean every provider has equal performance or quality.

## Quality profiles

Some domains need quality dimensions beyond pass/fail conformance.

Examples:

```text
CAD geometry tolerance
renderer fidelity
OCR accuracy
speech latency
model reasoning quality
solver convergence
video encoding efficiency
```

These should be declared as measurable provider capabilities/quality profiles rather than embedded into the core semantic meaning unless the semantic result itself depends on them.

## Pack dependencies

Domain Packs may depend on other packs/contracts, but dependencies should remain acyclic at the pack layer where practical.

Example:

```text
billing
  depends on core.party
  depends on commerce.product/line_item
  depends on data.currency
```

Avoid requiring the entire CRM pack merely to issue an invoice.

## Extension vs fork

A new domain requirement should prefer extension when core meaning remains intact.

Example:

```text
commerce.invoice@1
+ healthcare.claim-extension@1
```

rather than redefining `invoice` globally for one industry.

Forking a semantic contract is acceptable when the semantics truly diverge, but bridges/conversions should be explicit.

## Governance levels

Not every contract needs the same review burden.

Suggested classes:

### Core semantic primitives

Examples: Party, Document, Dataset, Artifact, Message, Project.

Require broad architecture review because many packs depend on them.

### High-consequence domain contracts

Examples: accounting, payroll, payments, medical, legal filing, safety-critical engineering.

Require stronger domain expertise, security review, jurisdiction/version metadata, and conservative automation rules.

### Specialist but lower-consequence contracts

Examples: image transforms, creative effects, layout, many media operations.

May evolve faster with conformance and compatibility tests.

## Trust and signatures

Published pack manifests/contracts SHOULD be content-addressed and signed once the registry/distribution system exists.

Trust dimensions should remain separate:

```text
cryptographic identity
semantic review status
security review status
provider conformance
publisher reputation
```

A valid signature proves origin/integrity, not correctness.

## Deprecation and migration

Stable object/capability versions should declare migration paths when replaced.

Migration may be:

- lossless deterministic conversion;
- lossy explicit conversion;
- manual/domain-assisted transformation;
- federation adapter compatibility;
- no safe automatic migration.

AI may assist with migration planning, but deterministic validation must identify which transformations are guaranteed versus heuristic.

## Domain Pack distribution

A future registry should distribute:

- pack manifest;
- semantic object/type/capability contracts;
- relationship contracts;
- conformance suites;
- policy profiles;
- optional reference providers;
- optional views;
- Skills/examples;
- migration definitions;
- signing/provenance metadata.

The registry should not require one central vendor to provide every implementation.

## Long-term scaling principle

The platform should be able to add an entirely new software field without changing the core OS architecture.

For example, adding a future robotics Domain Pack should primarily mean introducing:

```text
new semantic objects
new capabilities
new effects/devices
new conformance suites
new providers/views
```

—not redesigning Tasks, authority, provenance, AIOS IR, or object identity from scratch.

## Principle

> **AIOS can expand indefinitely only if semantic evolution is slower, more disciplined, and more interoperable than provider/application evolution.**
