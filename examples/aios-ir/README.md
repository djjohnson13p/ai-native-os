# AIOS IR Examples and Validation Fixtures

This directory exercises the semantic IR and adaptive-execution model described in:

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/27-skill-compilation-and-adaptive-optimization.md`
- `docs/28-capability-contracts-and-conformance.md`
- `docs/29-semantic-type-system.md`
- `docs/31-semantic-registry-snapshots.md`
- `specs/aios-ir.schema.json`

## Files

- `demonstration-a.ir.json` — realistic end-to-end semantic program for the v0.1 data-analysis demonstration.
- `capability-contracts.json` — bootstrap semantic capability registry records.
- `type-contracts.json` — bootstrap semantic type registry records.
- `registry-snapshot.json` — structural fixture identifying the contract set used for validation.
- `validation-result.json` — example of a successful deterministic IR validation result.
- `execution-binding-import-table.json` — example showing how one semantic IR node becomes bound to a provider, authority grants, sandbox, and hardware only after validation/policy.
- `skill-manifest-analyze-numbers.json` — candidate reusable Skill derived from the Demonstration A semantic graph without carrying old grants.
- `valid-cases.json` — compact structurally/semantically valid IR programs.
- `invalid-cases.json` — parser/schema/graph/reference/egress/failure adversarial IR cases.
- `invalid-semantic-cases.json` — registry-aware type/capability/execution-class/authority/egress failure cases.
- `provider-conformance-cases.json` — provider declarations tested against provider-independent semantic capability contracts.

## Placeholder hashes

Files such as `registry-snapshot.json`, `validation-result.json`, and the execution/Skill examples currently contain obvious synthetic placeholder hashes.

They are **not** claims that canonical hashing has been implemented.

The first reference validator/canonicalizer must replace these values with computed hashes and tests that prove stable canonical identity.

## Important distinction

JSON Schema catches only structural invalidity.

The reference validator must also perform semantic checks such as:

- duplicate node IDs;
- dangling references;
- missing output ports;
- graph cycles;
- capability/type compatibility;
- execution-class compatibility;
- egress/authority contradictions;
- fallback compatibility;
- bounded retry/replan behavior;
- prohibition on provider/grant/secret embedding in semantic IR;
- provider declarations that exceed their semantic capability contracts;
- registry snapshot compatibility.

## Test convention — IR cases

A valid case contains:

```json
{
  "name": "short-test-name",
  "expected": "valid",
  "program": {}
}
```

An invalid IR case contains:

```json
{
  "name": "short-test-name",
  "expected": "invalid",
  "reason_code": "IR_GRAPH_CYCLE",
  "validation_stage": "semantic",
  "program": {}
}
```

`invalid-semantic-cases.json` may additionally state a `registry_assumption` explaining which fixture contract makes the case invalid.

## Test convention — provider cases

Provider conformance cases use:

```json
{
  "name": "provider-authority-exceeds-contract",
  "expected": "invalid",
  "reason_code": "PROVIDER_AUTHORITY_NOT_ALLOWED",
  "provider": {}
}
```

Provider validation is separate from task authorization. A conforming provider can still be denied by task policy, and an allowed task operation cannot make a non-conforming provider acceptable.

## Registry assumptions for fixtures

The checked-in capability/type fixtures are the initial semantic registry seed for Demonstration A.

Some compact tests additionally assume compatible test-only contracts for:

```text
artifact.copy@1
artifact.copy.compat@1
artifact.hash@1
text.uppercase@1
```

If those contracts are not in the production Demonstration A snapshot, validator tests may extend an isolated test registry explicitly. They must not silently invent an unknown capability.

Tests that intentionally reference `unknown.*` must fail closed.

## Semantic IR vs execution binding

The files intentionally show this separation:

```text
demonstration-a.ir.json
       │
       │ deterministic validation against registry-snapshot.json
       ▼
validation-result.json
       │
       │ policy + provider + resource selection
       ▼
execution-binding-import-table.json
```

Changing the bound provider/hardware/grant should not alter the semantic program hash.

## Skill fixture

The Skill fixture is `candidate`, not validated/compiled production state.

It demonstrates that reusable structure contains:

- semantic source IR identity;
- parameters;
- capability dependencies;
- authority **requests**;
- verification requirements;
- privacy/invalidation metadata.

It does not contain task-specific approval or capability grants.

## No real user data

All fixtures are architecture/test data and must remain synthetic. Do not commit credentials, private documents, real capability tokens, or production provider responses here.
