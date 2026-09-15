# Domain Fabric Examples

This directory contains synthetic fixtures for the Universal Software Fabric / Universal Object Graph architecture.

## Files

- `tier0-object-contracts.json` — draft semantic object contracts for cross-domain foundation objects.
- `tier0-relationship-contracts.json` — draft relationship predicates that connect objects across former application boundaries.
- `reference-object-graph.json` — synthetic object instances for the Acme enclosure cross-domain workflow.

Related architecture:

- `docs/40-universal-software-fabric.md`
- `docs/41-domain-capability-architecture.md`
- `docs/42-universal-object-graph-and-data-federation.md`
- `docs/43-software-coverage-expansion-strategy.md`
- `docs/44-tier0-universal-object-model.md`
- `docs/45-cross-domain-transactions-and-compensation.md`
- `docs/46-domain-pack-lifecycle-and-governance.md`
- `docs/47-cross-domain-reference-workflow.md`

The fixtures are deliberately provider/vendor neutral. External-system IDs shown in examples are synthetic mappings, not canonical AIOS identities.

## Contract validation

Individual object contracts should validate against `specs/semantic-object-contract.schema.json`.

Individual relationship contracts should validate against `specs/relationship-contract.schema.json`.

Object instances should validate against `specs/object-record.schema.json` once every referenced semantic type/relationship contract is present in the active registry snapshot.

## No real data

All names, addresses, IDs, prices, and records in this directory are synthetic test architecture data.
