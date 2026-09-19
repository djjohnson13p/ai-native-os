# Issue #17 — R17-01–05 repair handoff

Status: repaired and locally verified; **second independent read-only review required**.
Do not merge based solely on this implementation handoff. Issue #17 remains open.

## Reviewed baseline and scope

- Repository: `djjohnson13p/ai-native-os`.
- Branch: `codex/issue-17-aios-ir-validator`.
- Pre-repair HEAD: `848fb7cb1afacbfb23165ae9a5d177699feae2bc`; clean working tree verified.
- Review source: [Issue #17 independent-review comment](https://github.com/djjohnson13p/ai-native-os/issues/17#issuecomment-5745195773).
- Scope: only validator/registry/contract correctness, documentation and regression tests.
- No Task, Artifact, Authority Coordinator, provider runtime, AI/model, network execution,
  or other Stage-1 implementation. No IR redesign, new hash domain or new semantic version.

## Dispositions and change classification

| Finding | Classification | Repair |
| --- | --- | --- |
| R17-01 | Schema/typed-contract mismatch; implementation admission defect | Strict raw Snapshot/Type/Capability schema validation before typed decoding; optional non-null boolean decoder; typed-record structural backstop. |
| R17-02 | Implementation defect; authoring-profile clarification | Exact bounded coefficient/decimal-scale analysis accepts integral decimal/exponent forms; zero includes exact negative zero; no float-to-integer cast. |
| R17-03 | Implementation defect | Structured JSON Schema error-kind mapping, including property-name errors; no message substring heuristics. |
| R17-04 | Numeric architecture clarification with validation tightening | Original-token sign/nonzero checks; finite nonnegative binary64 nearest/ties-even semantics; reject nonzero underflow and overflow; normalize exact signed zero. |
| R17-05 | Documentation/API clarification, not graph semantics change | Explicit verifier inventory wording and a valid graph exposing both verified and unverified outputs. |

The ADR0029/0034, docs31/39/61/64/66/68/70/72, relevant schema descriptions,
fixtures and tests move together under docs65 change control. Existing machine
reason codes are retained. Maturity remains `SPIKE_READY`; no persistence mapping
or authority/effect vocabulary changes are involved.

## Registry optional-value audit

The audit covered all `Option<T>` members in the registry/semantic-contract DTOs:

- Non-null when present: capability description, port description, determinism
  object, determinism equivalence, publisher ID, and unit-required boolean.
  The first five already used the non-null helper; unit-required now does too.
- Nullable when permitted by schema: type logical schema reference, unit-semantics
  container, canonical unit and unit notes; representation media/schema refs;
  equality canonicalizer; both tolerance fields; conformance suite version/hash;
  snapshot generation/publisher container, publisher signature and contract source.
- Adjacent defaulted booleans/arrays remain non-null: nullable, zero-copy,
  role, notes and conversion-capability collections. Omission retains specified defaults.

`{}` is legal for unit-semantics and for determinism where their members are optional;
it is not equivalent to permitting explicit null for a non-null member. No structural
schema was weakened. Hashes cannot substitute for these checks.

Trusted authored JSON enters `SemanticRegistry::load_bundle`. The programmatic
`from_records` API checks typed structure/values/identities but cannot recover original
tokens or duplicate keys already discarded by a caller; its documentation now states
that it is not a replacement raw-JSON admission route.

## Numeric implementation and compatibility

The shared registry `numbers` module is a bounded lexical preparation pass, not a
replacement JSON parser or arithmetic subsystem. It preserves quoted text and
invalid numeric spellings, and strict duplicate-key/JSON parsing remains mandatory.
Exponent accumulation saturates; exponent magnitude never drives allocation or
iteration. Exact integral coefficients reduce to at most 16 digits before bounded
u64 construction. No arbitrary-precision dependency was added.

For IR, only exactly integral nonnegative safe tokens become integer values. Other
numeric forms cannot pass the closed integer fields merely because binary64 rounds
them. Field-specific minima/retry/replan maxima still apply. Excluded metadata never
becomes an executable numeric operand.

For registry tolerances, correctly rounded finite binary64 values are intentional
semantics; positive finite subnormals are supported. Negative nonzero source tokens,
nonzero-to-zero underflow and overflow reject before sign/nonzero information can
be lost. Exact signed zero is accepted as zero. Docs72 records the policy.

Compatibility:

- Previously valid bootstrap/program/contract meanings retain the same hashes.
- Newly accepted integral spellings share their canonical integer's identity.
- Previously admitted schema-invalid nulls now reject.
- Previously admitted nonzero-underflow tolerance spellings now reject. Authors
  must choose an explicit intended zero or a representable positive value and revalidate.
- Existing float rounding/equality is not replaced with decimal arithmetic.
- Verifier summary field names and graph acceptance remain unchanged; there is no
  claim of per-output verification assurance or successful runtime verification.

## Verification evidence

On the repair tree, all commands passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-targets --all-features --locked --offline
```

141 tests passed, including property tests and 16 additional test functions over
the reviewed baseline. The new corpus covers optional-field schema parity, all
semantic integer paths, near-boundary fractions, long exponents, signed zero,
both tolerance fields in both contract classes, binary64 ties-to-even, diagnostic
property-name injection, local bundle fail-closed ordering and verifier inventory.

The original external review harness was also rerun (81 validation probes).
Observed repairs: null unit-required and negative underflow now reject with
`REGISTRY_SCHEMA_INVALID`; integral spellings now share identity; diagnostic-key
attacks now report `IR_SCHEMA_ADDITIONAL_PROPERTY`. Verifier inventory behavior
remains intentionally unchanged. This is an implementer's reproduction, not the
second independent review itself.

The independent JavaScript hash reconstruction still reproduces:

```text
Registry Snapshot:
sha256:5b1e89c974f35a0f3e1e7040bbec8f2e44ea908eb9a12d313ecda40600c6ddbd
Demonstration A:
sha256:beac8904db84998c56eca183c0e979f99746da2cec916f58c600416ee5de3cbf
table.import:
sha256:b6ab9313d952be9ee69e1fa240f17032a7a71b2e15c5d413077ce106570710c6
```

Only the existing locked `jsonschema` dependency was added to the registry crate;
no dependency version changed. Default resolver features remain disabled. The
dependency feature tree confirms no HTTP/file schema retrieval feature activation.
Registry content refs are identifiers, not fetched schemas. Test-generated temporary
bundles contain synthetic fixtures only. No grant, secret resolution, provider or
model execution was exercised.

## Second reviewer checklist

1. Verify the review branch's new HEAD and clean tree; compare to the baseline above.
2. Read the GitHub review comment and ADR/profile amendments; do not trust this handoff.
3. Inspect `numbers.rs`, `schema.rs`, `load_bundle` and `from_records` admission paths.
4. Try invalid numeric grammar, very long coefficients/exponents, exact fractions
   near safe integers, signed/nonzero underflow and metadata/string smuggling.
5. Repeat optional-field omissions/nulls/empty objects and malformed raw local bundles.
6. Check structured diagnostics against attacker-controlled names and nested shapes.
7. Verify that summary wording cannot be mistaken for per-output assurance.
8. Rerun the offline gate and independent hash/probe reconstruction.

This pass does not claim formal correctness, exhaustive fuzzing, cross-platform
binary reproducibility, or production readiness. Review the parser changes as trusted
code, especially the exact-token/binary64 distinction. Do not merge or start Stage 1
until the required follow-up review has resolved any remaining findings.

## R17-06 follow-up after the second review

The [second independent review](https://github.com/djjohnson13p/ai-native-os/issues/17#issuecomment-5745523710)
verified R17-01, R17-02, R17-04 and R17-05, found R17-03 fixed for direct schema
errors, and reported one remaining nested-`oneOf` diagnostic defect as R17-06.

The follow-up repair keeps the schemas, acceptance rules and reason-code vocabulary
unchanged. `classify_schema_failure` now examines structured `OneOfNotValid` branch
contexts. A single const-discriminator-compatible branch supplies a nested code only
when its child failures agree. Missing common discriminators map to required, unknown
discriminators map to enum, and genuine ambiguity or conflicting child families stay
at the conservative type family. No branch is selected by array order, rendered
English text or attacker-controlled property prose.

The permanent corpus contains 19 nested cases across input/node value references,
program outputs and stop/retry/fallback/replan policies. It covers additional-property,
required, pattern, range, missing/unknown discriminator and conflicting-failure cases.
The existing dedicated `IR_FAILURE_POLICY_UNBOUNDED` precheck remains authoritative
for retry/replan policies that omit their finite budget.

On the R17-06 repair tree, formatter, locked/offline Clippy with warnings denied and
the full locked/offline suite pass (142 tests). The existing adversarial harness emits
84 passing result records, and a separate targeted CLI harness passes all 19 R17-06
cases. Registry Snapshot, Demonstration A and `table.import` identities remain the
three values recorded above. These are implementer checks, not the final independent
targeted read-only review. Issue #17 remains open and the branch must not merge until
that review is complete.
