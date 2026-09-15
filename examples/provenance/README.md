# Provenance Journal Fixtures

These fixtures exercise the v0.1 provenance architecture in:

- `docs/73-v0.1-provenance-journal-and-hash-chain.md`
- ADR 0035
- `specs/provenance-event.schema.json`
- `specs/provenance-journal-record.schema.json`
- `specs/provenance-checkpoint.schema.json`
- `specs/provenance-verification-result.schema.json`

## Files

- `chain-cases.json` — synthetic append/hash-chain/Task-transaction integrity cases.

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
