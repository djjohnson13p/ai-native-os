# AIOS IR Examples and Validation Fixtures

This directory exercises the semantic IR described in:

- `docs/23-ai-native-language-and-ir.md`
- `docs/25-aios-ir-semantics.md`
- `docs/26-aios-ir-validation-and-lowering.md`
- `specs/aios-ir.schema.json`

## Files

- `demonstration-a.ir.json` — realistic end-to-end semantic program for the v0.1 data-analysis demonstration.
- `valid-cases.json` — compact programs that should pass structural validation and the stated semantic checks.
- `invalid-cases.json` — structural and semantic adversarial cases with expected validator reason codes.

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
- prohibition on provider/grant/secret embedding in semantic IR.

## Test convention

Each case in the fixture collections contains:

```json
{
  "name": "short-test-name",
  "expected": "valid",
  "program": {}
}
```

or:

```json
{
  "name": "short-test-name",
  "expected": "invalid",
  "reason_code": "IR_GRAPH_CYCLE",
  "validation_stage": "semantic",
  "program": {}
}
```

The program objects are intended to be fed individually to the schema/semantic validator.

## Registry assumptions for fixtures

The semantic test registry should contain compatible mock contracts for:

```text
artifact.copy@1
artifact.hash@1
table.import@1
table.normalize@1
stats.compare_periods@1
chart.render@1
report.summarize@1
verify.numeric_claims@1
document.compose@1
text.uppercase@1
text.concat@1
```

Tests that intentionally reference `unknown.*` must fail closed.

## No real user data

All fixtures are architecture/test data and must remain synthetic. Do not commit credentials, private documents, real capability tokens, or production provider responses here.
