# Platform Fabric Fixtures

Synthetic examples for the architecture described in:

- `docs/49-identity-resolution-and-object-reconciliation.md`
- `docs/50-adaptive-presentation-and-device-ui.md`
- `docs/51-network-fabric-and-service-connectivity.md`
- `docs/52-cloud-edge-and-service-fabric.md`
- `docs/53-system-of-everything-staged-roadmap.md`
- `docs/54-unified-platform-fabric-architecture.md`

The fixtures are deliberately small and are not claims of implemented runtime behavior.

## Files

- `display-phone.json` — compact touch/voice presentation profile.
- `display-workstation.json` — multi-display workstation profile.
- `peer-service.json` — paired workstation service identity with multiple possible endpoints.
- `remote-service.json` — policy-described remote compute/model service.
- `identity-resolution-acme.json` — synthetic cross-system identity match proposal that is not yet a merge.
- `network-transfer-peer.json` — explicit task-scoped transfer to a paired peer.

## What these demonstrate

The same Task/object/program semantics can be surrounded by different presentation, network, peer, and remote-service context without changing semantic identity.

The identity-resolution example demonstrates that strong evidence may produce a likely-match proposal while still requiring a separate deterministic merge/link decision.

All IDs/domains are synthetic. No credentials, private data, real provider endpoints, or production identities belong in these fixtures.
