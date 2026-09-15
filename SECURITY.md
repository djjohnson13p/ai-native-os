# Security Policy — Architecture / Prototype Phase

This project is currently an architecture/prototype effort and **must not be treated as a production security boundary**.

Security is part of the core architecture rather than a feature added later.

Primary references:

- `docs/08-security-threat-model.md`
- `docs/15-system-invariants.md`
- `docs/19-principal-and-authority-model.md`
- `docs/21-trust-boundaries.md`
- `docs/39-static-effect-and-authority-analysis.md`
- `docs/45-cross-domain-transactions-and-compensation.md`
- `docs/56-cryptographic-identity-trust-and-credential-fabric.md`
- `docs/57-component-distribution-supply-chain-and-update-trust.md`

## Current security posture

Until explicitly stated otherwise:

- no release is approved for production use;
- schemas/ADRs are pre-v1 and may change;
- example hashes/signatures/identities may be synthetic placeholders;
- no real credential/private user data should be committed;
- compatibility/provider/model integrations are not assumed trustworthy merely because they work;
- successful schema validation does not imply authorization, semantic correctness, or component safety.

## Security-critical design rules

Changes must preserve, unless an explicit architecture decision says otherwise:

- no ambient AI/model/agent authority;
- plans/AIOS IR are proposals, not permission;
- deterministic authorization/security enforcement;
- explicit data-egress decisions;
- mediated secrets/credential handles;
- provider/legacy sandboxing;
- stable provenance for material side effects;
- verification barriers surviving optimization/provider substitution;
- authentication separate from authorization;
- package signatures separate from runtime trust;
- updates unable to silently broaden authority;
- irreversible external effects gated/recoverable as far as their semantics permit.

## Security-sensitive contributions

Security-relevant PRs should include:

- affected invariants/ADRs;
- threat/abuse cases;
- negative/adversarial tests;
- failure/recovery behavior;
- authority/egress/secret implications;
- migration/rollback implications;
- provider/compatibility assumptions.

A happy-path demonstration is not sufficient evidence for a trusted-core change.

## Secrets and test data

Never commit:

- passwords;
- API/OAuth tokens;
- private keys;
- production certificates;
- real user secrets;
- real capability grants;
- sensitive/private user documents;
- production service dumps containing private data.

Use synthetic fixtures.

If secret material is committed accidentally, treat it as compromised and rotate/revoke it rather than relying on Git history deletion alone.

## Dependency / supply-chain expectations

Security-sensitive implementation should:

- minimize unnecessary dependency surface;
- pin/lock dependencies for reproducibility;
- preserve package/build/version attribution;
- separate publisher signature from conformance/trust;
- support quarantine/rollback/revocation paths as the component distribution architecture matures.

## Vulnerability reporting

A dedicated private vulnerability-reporting channel has **not yet been established** for a public production release.

While the repository remains in its current prototype/governance phase, do not create a public disclosure process that implies production support that does not exist.

Before the project accepts public security-sensitive production use, establish and document:

- private vulnerability reporting;
- supported-version/security-fix policy;
- response/severity process;
- release signing/key rotation/revocation;
- security-critical code ownership/review rules;
- dependency/SBOM/advisory handling;
- coordinated disclosure expectations.

## Security claims

Do not describe a capability/provider/component as "secure" solely because:

- it is written in a memory-safe language;
- it runs in a container/Wasm/VM;
- it is signed;
- it passed schema validation;
- an AI/model says it is safe;
- it uses encryption;
- it is local/on the same LAN;
- it comes from a known publisher.

Security claims require a concrete threat model and evidence appropriate to the claim.
