# Provenance Journal Fixtures

These fixtures exercise the v0.1 provenance architecture in:

- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- ADR 0035
- `specs/provenance-event.schema.json`
- `specs/provenance-journal-record.schema.json`
- `specs/provenance-checkpoint.schema.json`
- `specs/provenance-verification-result.schema.json`
- `specs/provenance-projection-manifest.schema.json`
- `specs/provenance-projected-record.schema.json`
- `specs/provenance-projection-verification-result.schema.json`

## Files

- `chain-cases.json` — synthetic append/hash-chain/Task-transaction integrity cases.
- `event-schema-cases.json` — positive and adversarial event payload cases for event-specific detail keys and journal-envelope field exclusion. Run `python examples/provenance/validate_event_schema_cases.py` with the Python `jsonschema` package to check these cases and the array/string shape boundaries.
- `portable-v1/positive/` — a two-record `privacy-redacted-projection-v1` bundle with a manifest and an offline verification result.
- `portable-v1/tampered/` — a valid projected event field changed without updating its record hash; offline verification reports `PROJECTION_HASH_MISMATCH`.
- `portable-v1/wrong-namespace/` — a record and manifest rehashed after an Artifact alias is falsely labeled as a Step alias; offline verification reports `PROJECTION_RECORD_INVALID`.

Each portable case contains `manifest.json`, `records.jsonl`, and
`expected-result.json`. These are static JSON/JSONL interchange fixtures for
implementations in any language. The positive case exercises genesis,
predecessor linkage, descriptor hashing, bundle-local aliasing, and the
limited `exported-projection` verification claim. The negative cases show that
recomputed projection hashes cannot make a wrong alias namespace acceptable.

The exact record hash is SHA-256 over
`AIOS-PROVENANCE-PROJECTION-RECORD\0v1\0` followed by RFC 8785 JCS of the
record without `projection_hash`. The descriptor hash uses
`AIOS-PROVENANCE-PROJECTION-DESCRIPTOR\0v1\0` and the manifest without
`descriptor_hash`. Alias values use
`AIOS-PROVENANCE-PROJECTION-ALIAS\0v1\0`, a 32-byte bundle key, namespace
UTF-8, one zero byte, and source value UTF-8. `portable-v1/generate.py`
reproduces these synthetic fixtures; its public fixed key is only for fixture
repeatability. Real exporters must generate a fresh secret key for each bundle.

Run `python examples/provenance/portable-v1/generate.py` to regenerate the
static files, then `cargo test -p aios-provenance --test projection_fixture_contracts`
to compare every case with the public offline verifier and validate result
shapes against the machine schema.

Run `cargo test --locked --offline -p aios-provenance --test chain_fixture_contracts`
to generate the base chain's hashes and verify its derived stream identity and
records with the public provenance verifier.

## Placeholder hashes

Any repeated-digit or `GENERATE_AT_TEST_TIME` values are test specifications, not trusted cryptographic evidence.

The Phase-I provenance implementation must compute canonical journal hashes using the accepted profile and then test tamper/reorder/delete behavior against generated values.

Production/trusted APIs must never accept placeholder hashes as proof.

## Privacy

Fixtures contain only synthetic IDs and synthetic metadata.

Do not add real prompts, private documents, credentials, API tokens, email bodies, or user data to provenance fixtures.

## Journal envelope vs event payload

The semantic event payload is defined independently from the append-order/hash envelope:

```text
ProvenanceJournalRecord
  stream_id
  sequence
  previous_event_hash
  event: ProvenanceEvent
  event_hash
```

This lets event consumers inspect semantic facts without coupling them to one database implementation while still providing deterministic persisted ordering/integrity.
