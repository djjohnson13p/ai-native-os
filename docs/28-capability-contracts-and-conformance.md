# 28 — Semantic Capability Contracts and Conformance

## Purpose

AIOS IR invokes **semantic capabilities**, not providers, executables, libraries, or applications.

That only works if the meaning of a capability is defined independently from any one provider that implements it.

Therefore the architecture separates:

```text
Capability Contract
    = what an operation means

Provider Manifest
    = who implements it and under what execution requirements
```

A provider must conform to a semantic contract rather than silently redefining the capability.

## Why provider manifests alone are insufficient

If two providers both claim to implement `stats.compare_periods@1` but disagree on:

- input port names;
- input types;
- output types;
- null handling;
- numerical precision;
- side effects;
- determinism;
- error semantics;

then provider substitution is not real.

The semantic contract is the stable interface that the AIOS IR validator reasons about.

## Contract identity and v0.1 references

A capability contract record has:

- semantic identifier, e.g. `stats.compare_periods`;
- full contract version, e.g. `1.0` or `1.1.2`;
- immutable contract content identity/hash once generated;
- named typed input/output ports;
- execution-class constraints;
- allowed effect categories;
- allowed authority classes;
- allowed egress modes;
- error/failure contract;
- conformance suite identity;
- optional verifier semantics.

AIOS IR v0.1 does **not** embed the full contract version. It references a semantic compatibility family using exactly:

```text
stats.compare_periods@1
```

The immutable Registry Snapshot selects the exact full contract version/content for `(stats.compare_periods, major 1)`.

Unversioned references and selectors such as `@1.0` are invalid in AIOS IR v0.1.

The controlling rules are ADR 0030 and `docs/67-v0.1-semantic-reference-and-version-resolution.md`.

## Why the reference and contract version are separate

The IR says:

> I require semantic capability family `stats.compare_periods` major 1.

The validation result says exactly which Registry Snapshot supplied that meaning.

Therefore reproducible validation is attributable through:

```text
semantic program hash
+ registry snapshot ID
+ IR/hash profile
```

The validator does not run a package-manager-style "highest compatible version" solver while validating IR.

## Named ports

Capability contracts use named ports rather than positional arguments.

Example:

```text
stats.compare_periods@1

inputs:
  table: data.table@1

outputs:
  metrics: data.metrics@1
```

This improves model generation, inspection, schema validation, and future additive evolution.

Port type references use the same v0.1 semantic major-selector rule.

## Effects and authority

The contract declares **categories the capability is allowed to require**, not actual permission grants.

Example:

```text
allowed_authority_classes:
  - artifact.read
  - artifact.write
```

A provider claiming `table.import@1` cannot legitimately request `system.install_kernel_module` merely because its implementation wants to.

The semantic validator/provider-conformance boundary can reject such a mismatch before user policy considers execution.

Actual runtime permission is still decided later by deterministic policy/current grants.

## Execution class constraints

A capability declares allowed execution classes.

For example:

```text
artifact.hash@1 -> deterministic only
report.summarize@1 -> probabilistic or bounded_nondeterministic
legacy.app.invoke@1 -> opaque_external
```

A provider may offer a stronger guarantee than required if the semantics permit it, but may not silently downgrade a deterministic capability into probabilistic behavior.

## Egress semantics

Capabilities declare allowed egress modes.

Examples:

- a pure local hash capability may permit only `deny`;
- a web-research capability necessarily permits `policy`;
- a model reasoning capability may permit both when local and remote providers exist.

Concrete external destinations remain runtime/policy concerns.

## Error semantics

A semantic contract should define stable error classes meaningful to callers.

Example:

```text
TABLE_PARSE_UNSUPPORTED_FORMAT
TABLE_PARSE_MALFORMED_INPUT
TABLE_PARSE_SIZE_LIMIT
```

Provider-specific errors may appear in diagnostics, but the provider adapter should map them to the semantic contract where possible.

This is important for bounded fallback and Skill portability.

## Conformance suites

A capability should not be called interchangeable until providers pass the same semantic conformance suite.

A conformance suite may test:

- valid inputs;
- boundary values;
- invalid inputs;
- type behavior;
- deterministic output expectations;
- permitted tolerances;
- declared side effects;
- denial under insufficient authority;
- sandbox behavior;
- error mapping;
- performance/resource envelopes where part of the contract.

## Conformance levels

Early project terminology:

### `declared`

Provider claims implementation but has not passed project conformance.

### `tested`

Provider passes the referenced conformance suite in at least one supported environment.

### `certified`

Reserved for a future governance/security process. v0.1 should not imply formal certification.

Provider ranking may use conformance status, but cryptographic publisher identity and community reputation remain separate concepts.

## Deterministic capability conformance

For deterministic capabilities, conformance should be especially strict.

The contract should define whether output equality means:

- byte-identical;
- canonical-value identical;
- numerically equivalent within explicit tolerance;
- semantically equivalent after normalization.

For example, two chart renderers need not produce byte-identical SVG if `chart.render@1` defines semantic rather than pixel identity.

## Probabilistic capability conformance

Probabilistic providers cannot be tested by exact output equality.

Their contract may instead validate:

- output schema;
- prohibited behavior;
- maximum authority/effects;
- egress behavior;
- bounded resource usage;
- required evidence/citations fields where applicable;
- quality benchmark thresholds;
- verification compatibility.

Quality scoring must not become hidden authority.

## Contract registry

The runtime maintains a versioned registry of semantic capability contracts.

The IR validator reads one immutable Registry Snapshot so validation is reproducible.

For v0.1, one snapshot contains at most one active full contract version for each `(semantic capability ID, major version)` pair.

Changing a contract after publication creates a new contract content identity/version/snapshot rather than mutating historical meaning invisibly.

See `docs/31-semantic-registry-snapshots.md`.

## Provider implementation declaration

A provider manifest/registration should eventually identify the exact semantic contract it was tested against, conceptually:

```text
implements:
  semantic_ref: stats.compare_periods@1
  contract_version: 1.1
  contract_hash: sha256:...
  conformance_suite: conformance://stats.compare_periods/1
  conformance_status: tested
```

The runtime can then distinguish:

- semantic contract compatibility;
- provider availability;
- provider trust;
- provider conformance;
- runtime resource suitability.

A provider cannot privately redefine what major family `@1` means.

## Type contracts

Capability contracts depend on semantic types.

Type IDs are referenced in v0.1 by major family, for example:

```text
data.table@1
data.metrics@1
text.narrative@1
artifact.report@1
```

The exact full type-contract version is selected by the same immutable Registry Snapshot.

The type registry remains separate from language-specific Rust/Python classes.

## Universal App Broker relationship

Legacy applications can be wrapped as providers, but opaque application behavior should not be misrepresented as a strong semantic capability unless the adapter actually enforces the contract.

For example:

```text
legacy.launch@1
```

may be an honest opaque capability.

A legacy image editor adapter could later expose narrower capabilities such as:

```text
image.resize@1
image.export@1
```

only if the adapter can reliably satisfy those contracts and sandbox boundaries.

## Capability granularity

Capabilities should be large enough to represent meaningful semantic operations but small enough to compose.

Bad extremes:

```text
cpu.add_two_ints
```

is too low-level for most orchestration, while:

```text
do_everything_an_image_editor_can_do
```

is too broad to type, authorize, substitute, and verify.

Candidate granularity examples:

```text
table.import
stats.compare_periods
chart.render
image.resize
image.remove_background
document.compose
mail.draft
mail.send
3d.render_scene
```

Exact ontology will evolve through real workloads.

## Capability discovery

The planner may discover available capability semantics, but should generally plan against semantic needs rather than concrete provider inventory.

The broker later determines whether the current machine/fabric can satisfy them.

This preserves a Task across hardware/provider changes.

## Security rules

1. A capability contract does not grant authority.
2. A provider manifest does not grant authority.
3. Passing conformance does not grant authority.
4. Publisher reputation/signature does not grant authority.
5. Runtime policy/grants govern each concrete side effect.
6. A provider cannot extend a contract's allowed authority/effect classes through undocumented behavior.
7. A provider requesting undeclared authority fails closed.
8. A missing semantic reference never means "fetch/latest/execute something with this name."

## v0.1 minimum registry

The initial Demonstration A/test registry defines families including:

```text
table.import@1
table.normalize@1
stats.compare_periods@1
chart.render@1
report.summarize@1
verify.numeric_claims@1
document.compose@1
artifact.hash@1
artifact.copy@1
```

Each should have synthetic fixtures and explicit port types.

## Architectural result

The system has clean layers:

```text
AIOS IR semantic reference
   ↓ resolved by immutable snapshot
Semantic Capability Contract
   ↓ implemented by
One of N Provider Implementations
```

This is the mechanism that lets the operating environment remain application/provider-neutral while still using existing software underneath.

## Principle

> **Programs name stable semantic families; immutable registry snapshots pin the exact meaning; providers conform rather than redefine.**
