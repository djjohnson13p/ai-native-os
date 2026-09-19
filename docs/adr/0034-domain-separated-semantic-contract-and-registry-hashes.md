# ADR 0034 — Domain-Separated Semantic Contract and Registry Hashes

- Status: **Accepted for the v0.1 / Issue #17 spike**
- Date: 2026-09-15
- Clarified: 2026-09-19 (R17-01 structural admission and R17-04 tolerance authoring)

## Context

Issue #17 must identify the exact semantic type/capability Registry Snapshot used for validation. Current fixtures use placeholder hashes, and a raw JSON-file hash would make harmless formatting/prose changes redefine semantic contract identity.

AIOS also has several distinct content identities—IR programs, semantic contracts, registry snapshots, packages, Artifacts—which must not be confused merely because they all use SHA-256.

## Decision

Adopt `docs/72-v0.1-semantic-contract-and-registry-hash-profile.md`.

For v0.1:

- Capability Contract semantic content, Type Contract semantic content, and Registry Snapshot each use a distinct normalized semantic view;
- obvious explanatory prose is excluded while execution/conformance-relevant fields are included;
- semantic-set ordering is normalized;
- RFC 8785 JCS is used over each normalized view;
- each identity uses a distinct domain/version prefix before SHA-256;
- stored IDs are algorithm tagged;
- snapshot identity excludes timestamp/publisher/signature/catalog location;
- contract/snapshot hashing happens only after structural/semantic registry validation;
- placeholder fixture hashes are never accepted as production trust evidence;
- exact validated interpretation retains both AIOS semantic-program hash and Registry Snapshot ID rather than folding one into the other.

R17-01/R17-04 clarification: raw records must satisfy the embedded schemas before
typed interpretation. Optional fields do not implicitly permit null. Registry
tolerances use finite nonnegative binary64 semantics with nearest/ties-even
rounding; exact signed zero becomes zero. Negative nonzero tokens, nonzero-to-zero
underflow, and overflow are rejected before numeric information is lost. Positive
finite subnormals and ordinary finite rounding remain permitted. Docs72 defines
the authoring and migration details. This validation tightening preserves all
valid bootstrap identities and does not introduce arbitrary decimal semantics.

## Consequences

### Positive

- reproducible semantic contract identity independent of formatting/prose;
- exact Registry Snapshot identity survives mirror/publisher/timestamp changes;
- no accidental equivalence between Program/Contract/Registry/Package hash namespaces;
- provider/Skill/compiler/provenance records can bind exact semantic evidence;
- registry hashes can later be signed without signing arbitrary pretty-printed JSON.

### Costs

- trusted implementation needs multiple canonical semantic-view builders;
- schema/fixture prose must be clearly classified as non-semantic;
- changes to conformance/equality/representation contract fields can create new contract/snapshot identities even when AIOS IR major references remain unchanged.

## Security impact

A hash proves content identity/integrity only. It does not grant publisher trust, semantic conformance, provider authority, or execution permission.

The implementation should use distinct strong types for different hash domains where practical.

## Related

- ADR 0029
- ADR 0030
- `docs/31-semantic-registry-snapshots.md`
- `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`
- `docs/67-v0.1-semantic-reference-and-version-resolution.md`
- `docs/72-v0.1-semantic-contract-and-registry-hash-profile.md`
- `specs/registry-snapshot.schema.json`
