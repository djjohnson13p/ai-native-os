# 37 — Provider Registration and Conformance Pipeline

## Purpose

AIOS depends on interchangeable capability providers without trusting a provider merely because it declares a familiar capability name.

This document defines the path from **installed implementation** to **eligible runtime provider**.

The core distinction is:

```text
Semantic Capability Contract = what the operation means
Provider Manifest             = what this implementation claims
Conformance Evidence          = what tests demonstrated
Trust Policy                  = whether this publisher/build may run
Task Policy                   = whether this concrete invocation may act
```

No one layer substitutes for the others.

## Provider lifecycle

```text
Package discovered
      ↓
Static inspection
      ↓
Manifest schema validation
      ↓
Semantic contract resolution
      ↓
Provider/contract compatibility validation
      ↓
Trust/source verification
      ↓
Conformance tests (when required)
      ↓
Registration
      ↓
Health/readiness check
      ↓
Eligible provider pool
      ↓
Task-specific broker selection
      ↓
Policy + Execution Binding
      ↓
Sandboxed invocation
```

## 1 — Package discovery

Possible sources include:

- system-installed built-in provider;
- project package/registry;
- local developer provider;
- WASM component;
- OCI image;
- native executable/service;
- model adapter;
- legacy application adapter;
- organization-managed provider.

Discovery does not execute provider code.

The discovery layer should obtain package/manifest metadata through a controlled path.

## 2 — Static inspection

Before execution, collect where applicable:

- package identity/version;
- content digest;
- publisher/signature metadata;
- runtime kind;
- declared entrypoint/interface;
- declared semantic contracts implemented;
- side effects;
- authority classes requested by implementation;
- isolation floor;
- network default;
- resource requirements;
- physical representation support.

Static inspection should not treat executable self-reporting as trustworthy evidence when the same data can be read from a signed/immutable manifest.

## 3 — Manifest schema validation

Validate against `specs/capability-manifest.schema.json`.

Unknown security-relevant fields fail closed.

Schema-valid means only that the manifest has an understood shape.

## 4 — Semantic contract resolution

For each provided capability:

1. locate the exact Semantic Capability Contract in an identified Registry Snapshot;
2. compare capability ID/version;
3. compare contract hash once generated hashes are mandatory;
4. resolve semantic port/type contracts;
5. locate referenced conformance suite.

A missing or incompatible contract prevents registration for that capability.

## 5 — Provider/contract compatibility validation

Check that implementation claims are a subset/compatible refinement of the semantic contract.

At minimum:

- execution class allowed;
- provider side effects do not exceed contract effects;
- implementation authority actions do not exceed allowed authority classes;
- provider egress/network behavior is compatible;
- physical representations correspond to semantic port types;
- runtime kind can satisfy required isolation;
- semantic ports have an implementation mapping;
- verifier/ordinary role is compatible.

Stable diagnostic families should include:

```text
PROVIDER_SCHEMA_*
PROVIDER_CONTRACT_NOT_FOUND
PROVIDER_CONTRACT_HASH_MISMATCH
PROVIDER_PORT_MISMATCH
PROVIDER_TYPE_REPRESENTATION_MISMATCH
PROVIDER_EXECUTION_CLASS_INCOMPATIBLE
PROVIDER_EFFECT_NOT_ALLOWED
PROVIDER_AUTHORITY_NOT_ALLOWED
PROVIDER_EGRESS_INCOMPATIBLE
PROVIDER_ISOLATION_UNSATISFIABLE
PROVIDER_CONFORMANCE_REQUIRED
PROVIDER_TRUST_DENIED
```

## 6 — Trust/source verification

Conformance and trust are different.

A provider can correctly implement a capability and still come from an untrusted publisher/build.

Trust inputs may eventually include:

- content hash;
- publisher signature;
- repository/source provenance;
- reproducible build evidence;
- project review status;
- organization policy;
- local user trust decision;
- revocation/security advisory state.

v0.1 may use local project-reviewed fixtures while the full signing/governance design remains open.

## 7 — Conformance testing

A provider becomes `tested` only after passing the capability's referenced conformance suite in a declared environment.

Conformance should test both semantic output and boundary behavior.

Examples:

- correct outputs for canonical fixtures;
- expected semantic error classes;
- refuses/does not obtain undeclared resources;
- respects input/output type mapping;
- deterministic equivalence where promised;
- resource limits where part of the contract;
- crash behavior;
- malformed/untrusted input handling.

For a WASM provider, tests should additionally verify that required imports are no broader than expected.

For a native/process provider, tests should verify effective sandbox policy independently from manifest claims.

## 8 — Registration record

Registration should produce an immutable/versioned record conceptually containing:

```text
provider ID/version
provider package/content hash
publisher/trust status
runtime kind
capability contract refs/hashes
conformance status + evidence refs
supported representations
resource requirements
minimum isolation
date registered
revocation/disable state
```

`specs/provider-registration.schema.json` defines the first machine-readable draft.

This is distinct from the package's self-authored Provider Manifest.

## 9 — Health/readiness

Registration means the provider is known. It does not mean it is available now.

Runtime health may include:

- executable/component present;
- runtime dependency available;
- model weights loaded/available;
- remote endpoint reachable;
- license/user prerequisites satisfied;
- required accelerator present;
- provider starts and completes a bounded health handshake.

Health checks must not receive broad user data/authority.

## 10 — Broker eligibility

The Capability Broker builds an eligible pool using:

```text
semantic contract compatibility
AND registration/trust status
AND conformance policy
AND current health
AND hardware/resource eligibility
AND task privacy/egress constraints
AND sandbox capability
```

Ranking happens only after eligibility.

A fast/cheap provider that violates a hard constraint is not a candidate with a bad score; it is ineligible.

## Ranking vs constraints

Separate:

### Hard constraints

Examples:

- local-only data;
- no network;
- deterministic requirement;
- minimum semantic contract version;
- approved publisher/trust level;
- memory ceiling;
- required architecture/accelerator;
- required isolation.

### Soft objectives

Examples:

- latency;
- monetary cost;
- energy;
- historical reliability;
- quality benchmark;
- user preference;
- warm runtime availability.

This prevents scoring weights from accidentally overriding privacy/security requirements.

## Runtime invocation

Once selected, the provider still receives a fresh task-specific Execution Binding.

Registration never grants task authority.

A provider invocation gets only:

- node/capability identity;
- concrete approved input handles;
- output allocations;
- scoped authority/grant interfaces;
- execution profile/sandbox;
- resource limits;
- model descriptor if applicable;
- operation/idempotency identity if effectful.

## Provider updates

A provider update is a new implementation identity/version/digest.

Do not silently transfer `tested` conformance status to a changed binary unless policy explicitly allows evidence reuse and the conformance model supports it.

At minimum:

- rerun manifest/contract compatibility;
- reevaluate trust/signature;
- rerun required conformance suites when binary/runtime semantics change;
- invalidate active cached eligibility record;
- preserve historical registrations referenced by provenance according to retention policy.

## Revocation

A provider may be disabled because of:

- signature/key revocation;
- security advisory;
- failed conformance regression;
- malicious behavior;
- user/admin policy;
- corrupted package;
- incompatible semantic contract change.

Revocation prevents new selection.

Running tasks require a policy-defined response:

- stop immediately for severe compromise;
- allow current non-sensitive deterministic operation to finish;
- pause and rebind another provider;
- quarantine produced output pending verification.

This severity model remains open for later policy design.

## Built-in providers

Built-in code is not exempt from semantic contracts.

It may have a simpler package/registration path, but should still:

- declare which semantic contracts it implements;
- pass conformance tests;
- appear in provenance/provider selection;
- obey task authority boundaries.

This prevents privileged first-party implementations from becoming invisible special cases.

## Legacy application adapters

A legacy adapter may register broad capabilities such as `legacy.launch` before it earns narrower semantic capability claims.

To promote an application adapter to `image.resize@1`, for example, it must:

- expose stable typed inputs/outputs;
- pass the same semantic conformance suite as other implementations;
- define its actual effects/authority requirements;
- run under the appropriate habitat isolation;
- handle application-specific failures predictably.

Brand recognition is not semantic conformance.

## Model providers

Model adapters are ordinary providers at the architecture level but often implement probabilistic capabilities.

Registration should separate:

- adapter implementation identity;
- model descriptor/model version;
- local vs remote locality;
- data-egress behavior;
- structured-output support;
- supported context/modalities;
- quality/evaluation evidence.

A remote model endpoint cannot claim `egress: deny` merely because the adapter runs locally.

## WIT/Wasm component providers

If Issue #18 validates the approach, a Component Model provider can offer useful additional static evidence:

- typed import/export interface;
- required host interfaces;
- self-contained component identity;
- portable runtime target.

WIT interface compatibility still does not replace Semantic Capability conformance.

## Persistence

The control-plane DB should store registration metadata or a content-addressed reference so provenance can later answer:

- which provider binary/component was selected;
- which semantic contract it claimed;
- what conformance/trust status was active;
- whether the provider is now revoked.

Historical provenance must not be rewritten to pretend a revoked provider was never used.

## v0.1 provider-registration tests

1. schema-valid conforming fixture registers;
2. unknown semantic contract rejects;
3. authority class beyond contract rejects;
4. execution class beyond contract rejects;
5. side effect beyond contract rejects;
6. missing required conformance evidence is ineligible when policy requires `tested`;
7. changed binary digest forces new registration/revalidation;
8. revoked provider disappears from new eligibility while historical provenance remains;
9. two conforming providers remain interchangeable at AIOS IR level;
10. unhealthy provider is skipped without changing semantic program;
11. remote provider is ineligible under local-only policy;
12. provider health check cannot read arbitrary task artifacts/secrets.

## Architectural principle

> **Providers earn eligibility through contracts, trust, conformance, and current policy; declaring a capability name is only the beginning.**
