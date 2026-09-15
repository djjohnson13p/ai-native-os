# Artifact Store Fixtures

Synthetic fixtures for:

- `docs/75-v0.1-artifact-store-content-identity-and-publication.md`
- ADR 0037
- `specs/artifact-handle.schema.json`
- `specs/artifact-output-allocation.schema.json`
- `specs/artifact-publication-request.schema.json`
- `specs/artifact-publication-result.schema.json`
- `specs/artifact-reason-codes.json`

## Files

- `publication-cases.json` — content deduplication, idempotent finalize, size/type checks, crash windows, and path-independent identity.

Hashes/paths are synthetic. A test harness should create temporary directories/files and compute real SHA-256 values at runtime.
