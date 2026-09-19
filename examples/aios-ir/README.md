# AIOS IR Examples and Validation Fixtures

This directory exercises the semantic IR and adaptive-execution model described in:

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `docs/27-skill-compilation-and-adaptive-optimization.md`
- `docs/28-capability-contracts-and-conformance.md`
- `docs/29-semantic-type-system.md`
- `docs/31-semantic-registry-snapshots.md`
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/61-validator-test-fuzz-and-resource-limit-matrix.md`
- `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md`
- ADR 0029
- `specs/aios-ir.schema.json`

## Files

- `demonstration-a.ir.json` — realistic end-to-end semantic program for the v0.1 data-analysis demonstration.
- `capability-contracts.json` — bootstrap semantic capability registry records.
- `type-contracts.json` — bootstrap semantic type registry records.
- `registry-snapshot.json` — structural fixture identifying the contract set used for validation.
- `validation-result.json` — example of a successful deterministic IR validation result.
- `demonstration-a.effect-summary.json` — derived-effect-summary fixture for Demonstration A.
- `execution-binding-import-table.json` — example showing how one semantic IR node becomes bound to a provider, authority grants, sandbox, and hardware only after validation/policy.
- `skill-manifest-analyze-numbers.json` — candidate reusable Skill derived from Demonstration A without carrying old grants.
- `valid-cases.json` — compact structurally/semantically valid IR programs.
- `invalid-cases.json` — parser/schema/graph/reference/egress/failure adversarial IR cases.
- `invalid-semantic-cases.json` — registry-aware type/capability/execution-class/authority/egress failure cases.
- `provider-conformance-cases.json` — provider declarations tested against provider-independent semantic capability contracts.
- `canonicalization-cases.json` — paired valid programs that MUST hash equal/different under ADR 0029 plus structural invalidity for forbidden Task identity in semantic IR.

## Generated identities

`registry-snapshot.json`, `validation-result.json`, the derived effect summary, and the
semantic identity fields in the binding/Skill examples contain generated v0.1 identities
locked by the reference implementation tests. Obvious repeated-digit hashes that remain in
explicitly synthetic cross-snapshot or runtime-artifact examples are test data, not registry or
AIOS IR semantic identities.

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
- prohibition on provider/grant/secret/runtime binding embedding in semantic IR;
- provider declarations that exceed their semantic capability contracts;
- registry snapshot compatibility;
- static effect-summary consistency;
- semantic normalization/hash invariants.

## Task identity is outside semantic IR

Under ADR 0029, AIOS IR v0.1 no longer contains `task_id`.

A Task references a validated semantic program through control-plane Task/program/binding records.

This allows the same semantic graph to execute for many Tasks without changing semantic hash.

## Program ID vs semantic hash

`program_id` remains a required logical/diagnostic identifier, but it is **excluded** from the semantic hash.

Therefore:

```text
program_id A + semantics X -> semantic hash H
program_id B + semantics X -> semantic hash H
program_id A + semantics Y -> semantic hash H2
```

Exact executable identity is the semantic hash/profile, not `program_id` alone.

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

## Test convention — canonicalization/hash pairs

`canonicalization-cases.json` contains pairs such as:

```json
{
  "name": "program-id-is-nonsemantic",
  "expected_relation": "equal",
  "left": {},
  "right": {}
}
```

or:

```json
{
  "name": "retry-budget-is-semantic",
  "expected_relation": "different",
  "left": {},
  "right": {}
}
```

Both sides of an equality/difference pair must be fully valid before comparing semantic hashes.

The file also carries explicitly invalid hash-profile/schema cases under `invalid_cases`.

## Semantic hash profile summary

For v0.1:

Excluded from semantic hash:

```text
program_id
metadata
descriptions
authority reason prose
Task identity
runtime/provider/grant/device/path/network/cloud binding state
```

Included:

```text
IR version
kind
typed inputs
node identity/operations/data flow/output types
execution classes
authority action/resource
egress
constraints
failure behavior
cache policy
program outputs
```

Unordered semantic sets and node authoring order are normalized; fallback order remains significant.

See `docs/66-aios-ir-v0.1-canonicalization-and-semantic-hash-profile.md` for the controlling details.

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

The checked-in capability/type fixtures are the initial semantic registry seed for Demonstration A and validator tests.

Compact tests may use compatible fixture contracts such as:

```text
artifact.copy@1
artifact.copy.compat@1
artifact.hash@1
text.uppercase@1
```

If a test requires a contract not present in the production Demonstration A snapshot, validator tests may extend an isolated test registry explicitly. They must not silently invent an unknown capability.

Tests that intentionally reference `unknown.*` must fail closed.

## Semantic IR vs execution binding

The files intentionally show this separation:

```text
demonstration-a.ir.json
       │
       │ deterministic validation against registry snapshot
       ▼
validation-result.json
       │
       │ policy + provider + resource selection
       ▼
execution-binding-import-table.json
```

Changing Task ID, bound provider/hardware/grant/path/network/cloud placement must not alter the semantic program hash.

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

## Independent-review repair regressions

`registry-structure-repair-cases.json` covers R17-01 optional-value structural
admission. `review-repair-cases.json` covers R17-02 exact integer spellings,
R17-03 diagnostic key attacks, R17-04 tolerance numeric bounds and R17-05 verifier
inventory versus output assurance, plus R17-06 nested discriminated-union diagnostic
classification. Numeric tokens are stored as strings on purpose:
tests inject their original bytes rather than rounding them while loading fixtures.
Both corpora are executed by the offline Rust test gate.

## No real user data

All fixtures are architecture/test data and must remain synthetic. Do not commit credentials, private documents, real capability tokens, or production provider responses here.
