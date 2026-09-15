# ADR 0032 — Single v0.1 Semantic Effect Vocabulary

- Status: **Accepted for the v0.1 / Issue #17 spike**
- Date: 2026-09-15

## Context

Early drafts used two machine vocabularies for the same concept:

- lower-case provider/capability effect names such as `artifact_read` / `none`;
- upper-case static effect-summary names such as `ARTIFACT_READ` / `PURE`.

That would force the trusted validator/provider-conformance layer to maintain an unnecessary translation table and creates room for effect omissions during comparison.

## Decision

AIOS v0.1 semantic effect analysis uses one canonical machine vocabulary everywhere semantic effect classes are compared:

```text
PURE
ARTIFACT_READ
ARTIFACT_WRITE
NETWORK
DATA_EGRESS
EXTERNAL_MESSAGE
SECRET_ACCESS
PERSISTENT_STATE
DEVICE_ACCESS
SYSTEM_CHANGE
LEGACY_OPAQUE
```

This vocabulary is used by:

- Semantic Capability Contract `allowed_effect_classes`;
- derived node/program Effect Summary;
- fallback effect-broadening checks;
- provider-conformance normalization where semantic effect classes are declared;
- policy/compiler/static-analysis inputs that consume semantic effects.

`PURE` means no externally relevant side effect under the semantic contract. It is not combined with another effect class in a derived node summary when any non-pure effect applies.

## Provider-runtime side-effect fields

Provider manifests may retain separate runtime declarations such as `read`, `write`, `network`, `device`, or sandbox requirements when they describe implementation/sandbox mechanics rather than semantic effects.

Those runtime declarations do not replace the semantic effect vocabulary. Provider conformance maps/checks them against the semantic capability contract conservatively.

## Consequences

### Positive

- one comparison vocabulary in trusted validation;
- less effect-translation ambiguity;
- effect-summary fixtures and capability contracts align directly;
- fallback/provider checks are simpler and safer.

### Costs

- pre-implementation fixtures using lower-case semantic effect aliases must be updated;
- provider runtime side-effect terminology remains a separate layer and must not be confused with semantic effect classes.

## Revisit condition

Adding a new semantic effect class requires an explicit architecture/schema/test update because effect classes influence policy, fallback compatibility, compilation, provenance, and security review.

## Related

- `docs/39-static-effect-and-authority-analysis.md`
- `specs/capability-contract.schema.json`
- `specs/effect-summary.schema.json`
- `examples/aios-ir/capability-contracts.json`
