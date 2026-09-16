# 84 — Open-Source License and Governance Decision Framework

## Purpose

AIOS is intended to become an open platform with a large provider/Domain-Pack ecosystem, but the repository should not select a license casually just because implementation is about to begin.

This document defines the decision criteria and a provisional direction. It is **not legal advice** and it deliberately does not add a `LICENSE` file yet.

A final license choice should occur before meaningful outside code contributions are accepted so contributors know the terms under which their work is submitted.

## What the license needs to support

AIOS has several unusually different ecosystem layers:

```text
trusted core/runtime
semantic contracts + schemas
reference providers
third-party providers/adapters
Domain Packs
Views/UI components
legacy compatibility integrations
compiled Skills
models/model adapters
cloud/self-hosted services
documentation/conformance suites
```

The license strategy should maximize the long-term architecture rather than optimize only for the first Rust crate.

## Strategic questions we must answer

### Q1 — How strongly do we want to prevent proprietary forks of the core?

Spectrum:

```text
permissive
  Apache-2.0

file-level copyleft
  MPL-2.0

strong program/library copyleft
  GPLv3

strong copyleft including network-service deployment
  AGPLv3
```

There is no universally correct answer. It is a project-governance choice.

### Q2 — Do we want proprietary/commercial providers to be able to implement open AIOS interfaces?

The architecture benefits from many interchangeable providers.

If provider boundaries are language-neutral/process/component/service contracts, the project may intentionally permit both open and proprietary providers while keeping the **semantic contracts/conformance suites/core runtime open**.

License selection should not accidentally make provider adoption impossible unless that is a deliberate project policy.

### Q3 — How important is an explicit patent grant?

AIOS touches compilers, orchestration, AI runtimes, operating-system infrastructure, compatibility, networking, and domain software—all areas where patents can matter.

An explicit contributor patent license/termination framework is therefore a significant criterion rather than a footnote.

### Q4 — Do we want cloud-hosted modified cores to publish their modifications?

GPLv3 generally focuses on distribution/conveying of software; AGPLv3 adds a network-use source-offer obligation for modified covered programs used to interact with users over a network.

If preventing proprietary hosted forks is a primary project value, AGPL deserves serious consideration for relevant server components.

If broad infrastructure/vendor adoption is the primary goal, AGPL can materially reduce participation.

### Q5 — Can different repository layers use different licenses?

Yes in principle, but every additional license creates contributor/compliance complexity.

Possible intentional split:

```text
core/reference runtime code      one OSI-approved software license
schemas/specifications           same license or a documentation/spec license
examples/conformance code        same software license where practical
documentation                    software license or CC license
third-party bundled components   their upstream compatible licenses
```

Avoid clever multi-license architecture until there is a concrete need.

## Candidate licenses

### Apache License 2.0

Strengths for this project:

- permissive reuse;
- explicit patent license from contributors;
- well understood by commercial/open-source infrastructure ecosystems;
- easy for independent providers/adapters to adopt;
- modifications can be distributed under other terms subject to Apache notices/conditions;
- good fit if our primary moat/value is open semantic standards + conformance + community rather than forcing all downstream code open.

Tradeoff:

- organizations can make proprietary modified forks without publishing their changes.

### Mozilla Public License 2.0

Strengths:

- file-level copyleft keeps modifications to covered files open;
- permits combination with larger works under different terms;
- includes patent provisions;
- can offer a middle ground between Apache and GPL for a modular provider ecosystem.

Tradeoff:

- mixed-license/file-boundary compliance is more complex than a simple permissive license;
- contributors must understand which modifications trigger source obligations.

### GNU GPLv3

Strengths:

- strong copyleft for distributed covered programs/derivatives;
- explicit patent-related protections;
- strong community expectation that improvements to the covered program remain open when distributed.

Tradeoff:

- can reduce willingness of some commercial vendors to link/integrate tightly;
- provider/plugin boundary questions require careful legal analysis rather than architecture assumptions;
- network-only hosted modifications generally are not the same trigger as AGPL.

### GNU AGPLv3

Strengths:

- strong copyleft plus network-interaction source provision for modified covered software;
- useful if keeping hosted/server modifications open is a core goal.

Tradeoff:

- many organizations have restrictive AGPL policies;
- may significantly narrow commercial/cloud participation;
- probably excessive for every AIOS component even if selected for some future server service.

## Provisional architecture recommendation

Do **not** add a final license yet.

Before the repository accepts meaningful third-party code, explicitly choose between these two strategic defaults:

### Path A — ecosystem-first

Use **Apache-2.0** for the core/reference implementation and open machine contracts.

Best when the objective is:

- maximum adoption;
- many independent/open/commercial providers;
- AIOS semantic interfaces becoming a broad standard;
- explicit patent grant;
- competition through conformance and implementation quality.

### Path B — shared-core-first

Use **MPL-2.0** for much/all of the core implementation while keeping public interfaces/specifications broadly usable.

Best when the objective is:

- modifications to core files should normally flow back as source;
- still allow a heterogeneous provider/application ecosystem;
- avoid the full integration implications of strong GPL-family copyleft for every component.

GPLv3/AGPLv3 remain valid choices if the project later decides strong copyleft is a defining value, but that decision should be intentional because it affects ecosystem architecture and commercial participation.

## Current preference pending owner decision

From a purely **platform-adoption and provider-ecosystem** perspective, Apache-2.0 is the simplest provisional fit for AIOS's current architecture.

That is **not yet a project decision**. The counterargument is meaningful: AIOS is explicitly intended to become foundational infrastructure, and a file-level copyleft such as MPL-2.0 may better protect shared improvements without closing the provider ecosystem.

The owner/community should choose that strategic tradeoff explicitly before a `LICENSE` file is committed.

## Third-party engines and “best of software” goal

The Universal Software Fabric must not assume we can copy proprietary implementations merely because their functionality is desirable.

Rules:

1. implement functionality from open standards, original engineering, public behavior where legally appropriate, and compatibly licensed open-source engines;
2. preserve upstream licenses/notices;
3. keep incompatible-license components separated where required;
4. use external/legacy providers when direct incorporation is not permitted;
5. treat proprietary formats/protocol compatibility as a legal + technical review area;
6. never describe AIOS as owning third-party trademarks/products merely because it can provide equivalent capability;
7. maintain a dependency/license inventory once code begins.

The product goal is to absorb **capabilities**, not misappropriate source code or branding.

## AI-generated contributions

Because AI will produce substantial code/docs, contribution governance should require provenance discipline.

At minimum contributors/agents should affirm that submitted material is intended for contribution under the project license and that they are not knowingly submitting proprietary/confidential third-party code.

AI-generated output should be reviewed like any other contribution for:

- suspicious copied headers/comments;
- incompatible dependencies;
- generated vendored code;
- unreviewed snippets from restrictive sources;
- license notice obligations;
- security/correctness.

A model saying “this is original” is not legal provenance evidence by itself.

## DCO vs CLA

### DCO-style sign-off

Pros:

- lightweight;
- familiar open-source contribution flow;
- contributor certifies right to submit;
- no broad copyright reassignment.

Likely good default if project remains community/open-source oriented.

### CLA

Pros:

- can clarify patent/copyright grants;
- can support future relicensing under defined governance.

Costs:

- more contributor friction;
- contributor concern about asymmetric relicensing;
- organizational administration.

Provisional recommendation: prefer a **DCO-style contribution certification** unless a concrete relicensing/commercial governance need justifies a CLA.

## Governance phases

### Phase 0 — founder/architecture phase

Current state.

- repository owner acts as final merger;
- architecture changes use ADRs;
- security/semantic contract changes require change bundles;
- implementation PRs map to GitHub issues/stage gates;
- no implication of broad community governance before a community exists.

### Phase 1 — early contributor phase

Add when outside contributors appear:

- CODEOWNERS by subsystem;
- maintainer/reviewer roles;
- documented merge requirements;
- contribution sign-off;
- security reporting channel;
- dependency/license scanning;
- release/signing process;
- public RFC/ADR path for semantic contracts.

### Phase 2 — ecosystem governance

When third-party Domain Packs/providers depend on stable contracts:

- versioned compatibility policy;
- namespace allocation/governance;
- conformance-suite governance;
- deprecation windows;
- maintainer succession/removal process;
- conflict-of-interest/disclosure rules where needed;
- possibly a neutral foundation/organization if scale warrants it.

Do not create foundation-style bureaucracy before there is an ecosystem to govern.

## Semantic namespace governance

Long-term capability/type/Object namespaces are more strategically important than branding.

The project should eventually distinguish:

```text
core.*                  project-governed stable semantics
org.<owner>.*           third-party/community namespaces
experimental.*          non-stable incubation
```

A project-governed `core.*` capability should require:

- clear semantic contract;
- use across more than one provider/workload where practical;
- conformance fixtures;
- versioning rationale;
- security/effect semantics;
- ADR/RFC review for breaking meaning.

Do not let one vendor acquire semantic authority merely because its provider was first.

## Trademark vs conformance

If AIOS later has a trademark/certification program, keep it conceptually separate from code license.

Possible future claims:

```text
AIOS-compatible
AIOS-conformant provider
AIOS-tested Domain Pack
```

should be backed by public conformance requirements rather than payment/vendor identity.

No trademark policy is needed for v0.1.

## Decision gate before public contribution

Before accepting meaningful outside code, resolve:

1. Apache-2.0 vs MPL-2.0 (or an explicitly chosen stronger-copyleft alternative);
2. DCO vs CLA;
3. documentation license if separate;
4. third-party dependency/license inventory process;
5. contributor AI/provenance declaration;
6. security reporting contact/process.

Then add actual legal files/templates based on the chosen policy.

## Principle

> **Keep the architecture maximally open and interoperable; choose copyleft strength deliberately rather than letting the first dependency or template make that governance decision for us.**
