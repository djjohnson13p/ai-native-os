# 13 — Open Questions and Decision Status

These are architecture decisions that should be made deliberately rather than smuggled into the prototype through implementation convenience.

Status labels:

- **Open** — no preferred architecture yet;
- **Narrowed** — options/recommendations exist but evidence or an ADR spike is still needed;
- **Proposed** — architecture has a documented preferred answer but the relevant ADR remains proposed until implementation/tests support acceptance;
- **Decided** — accepted architecture decision. Pre-v1 decisions can still be superseded through a later ADR.

## Product / interaction

1. **Proposed — canonical user-visible objects.** `Task` is the primary unit of active work; `Artifact` is durable content; `Workspace` organizes context; `Conversation` is an interaction channel; `Application` is a legacy/provider/UI concept; `View` is presentation. See `docs/20-user-object-model.md` and ADR 0007.
2. **Narrowed — planning detail.** Default UX should show outcome/progress/approvals with plan/provenance under progressive disclosure. Exact UI thresholds remain open. See `docs/23-task-shell-ux.md`.
3. **Open — provider override UX.** Need a user-control model that can pin/avoid providers for privacy/cost/quality without making ordinary tasks app-centric.
4. **Proposed — traditional application interface.** Preserve an explicit application-launch escape hatch through the Universal App Broker. See R-UX-002.
5. **Narrowed — long-running autonomous tasks.** Persisted Task state and durable provenance are defined; wake/scheduling/notification semantics remain open. See `docs/24-task-state-machine.md`.

## AI-native language / execution semantics

6. **Proposed — semantic IR before a new general-purpose language.** AIOS IR is a structural typed graph; JSON is the bootstrap representation. See `docs/25-aios-ir-semantics.md`, ADRs 0011–0012.
7. **Proposed — trusted IR validation.** Deterministic Rust validator in the trusted core before policy/provider binding. See `docs/30-aios-ir-reference-validator-plan.md`, ADR 0015, Issue #17.
8. **Proposed — semantic/runtime separation.** Provider, grant, hardware, sandbox, and attempt-specific state belongs to Execution Binding rather than AIOS IR. See `specs/execution-binding.schema.json`.
9. **Proposed — bootstrap language boundary.** Rust/Python/C/C++/WASM are implementation mechanisms below language-neutral semantic contracts. See `docs/33-bootstrap-language-boundary.md`, ADR 0016.
10. **Open — custom source language trigger.** What measured threshold justifies building a dedicated AIOS authoring/general-purpose language instead of structural IR plus existing languages? Use Issue #16 and `docs/32-aios-ir-and-skill-benchmark-plan.md`.
11. **Open — optimized binary IR/runtime.** When do JSON/control-plane representation costs justify a compact binary IR or dedicated graph VM?
12. **Open — richer control flow.** Which real workloads justify loops, conditions, streaming graphs, transactions, or subgraph calls beyond the v0.1 DAG/bounded-failure model?

## Capability and semantic type system

13. **Proposed — stable type system.** Versioned semantic type contracts are independent of physical representations and use explicit conversions for v0.1. See `docs/29-semantic-type-system.md`, ADR 0014.
14. **Proposed — semantic capability versioning.** Provider-independent Capability Contracts own operation semantics and versions; provider manifests claim implementations. See `docs/28-capability-contracts-and-conformance.md`, ADR 0013.
15. **Narrowed — quality/determinism declarations.** Execution class and conformance status are defined; objective quality metrics for probabilistic providers remain workload-specific.
16. **Narrowed — conformance.** Shared conformance suites are required before interchangeability claims; exact governance/test thresholds remain open.
17. **Open — provider ranking.** Define the policy-aware scoring/constraint model across privacy, trust, latency, quality, cost, energy, local hardware, user preference, and availability.
18. **Proposed — registry reproducibility.** Validation uses identifiable semantic Registry Snapshots. Signing/distribution/governance remain open. See `docs/31-semantic-registry-snapshots.md`.

## Security

19. **Proposed — no ambient authority.** AIOS IR contains authority requests only; deterministic policy creates current task-scoped grants. See `docs/19-principal-and-authority-model.md` and ADR 0006.
20. **Narrowed — policy engine.** Cedar is the leading candidate for deterministic authorization, pending a Rust/adversarial spike. See `docs/research/06-authorization-policy-engine.md` and ADR 0010.
21. **Open — capability-token implementation.** Exact cryptographic/OS representation, delegation, attenuation, expiry, and cross-device token format still need a spike.
22. **Open — persistent approvals.** Define which actions may be remembered and which categories can never receive persistent approval.
23. **Open — tamper-evident provenance.** Choose hash chaining/signing/storage/rotation semantics and define the attack model.
24. **Open — signing and revocation.** Models, providers, Skills, registry snapshots, compatibility profiles, and compiled targets need publisher identity/key rotation/revocation rules.
25. **Open — trusted-core minimization.** Continue measuring what must remain inside `aiosd`/trusted Rust vs isolated providers/processes.

## Memory / learning / Skills

26. **Narrowed — local/private memory boundary.** Local-first and explicit egress are invariants; exact per-memory-class retention/sync defaults remain open.
27. **Narrowed — Skill inspection/deletion.** Users must be able to inspect/disable/delete learned Skills; detailed UX/storage retention is open.
28. **Proposed — compilation eligibility.** A Skill is parameterized validated AIOS IR; deterministic subgraphs may compile after tests/validation and fresh policy remains mandatory. See `docs/27-skill-compilation-and-adaptive-optimization.md`.
29. **Open — production promotion threshold.** The v0.1 three-successful-run threshold is only a prototype rule; production confidence/evidence policy needs data.
30. **Open — privacy scrubbing.** Define deterministic/AI-assisted checks proving shareable Skills contain no private task context or secret identifiers.
31. **Open — Skill distribution.** Package/signing/dependency/update/revocation registry design remains open.

## Compatibility

32. **Proposed — first non-native legacy family.** Windows-on-Linux via mature compatibility technology is the first v0.1 proof. See `docs/research/03-legacy-compatibility-fabric.md` and Issue #10.
33. **Open — Android default habitat.** Decide when container-based compatibility is sufficient vs VM isolation/fidelity.
34. **Open — proprietary runtimes/DRM.** Define technical and legal boundaries; do not make unsupported circumvention promises.
35. **Narrowed — translation composition.** OS API translation, CPU architecture translation, containers, VMs, and remote execution are separate composable layers; concrete broker algorithms remain open.
36. **Open — legal compatibility claims.** Establish project wording/process for `supported`, `works with limitations`, `experimental`, and `unsupported` across jurisdictions/components.
37. **Open — application-to-capability promotion.** Define evidence/conformance required before a legacy-app adapter can honestly advertise narrow semantic capabilities rather than only opaque launch/automation.

## Base system and hardware adaptation

38. **Narrowed — Linux reference base.** Image/atomic-update approaches are preferred for rollback/reproducibility, but final v0.1 base selection is still tracked in Issue #14 and `docs/research/01-linux-base-and-updates.md`.
39. **Narrowed — mutable vs image-based root.** Favor immutable/image-based system state plus writable user/task state; exact technology awaits the base-system decision.
40. **Narrowed — service management.** Reuse a standard Linux init/service ecosystem under the AIOS control plane rather than replacing init in v0.1. Exact integration follows base selection.
41. **Open — update/rollback details.** Define system-image, semantic-registry, provider, model, Skill, and compatibility-profile update transactions and cross-version rollback rules.
42. **Open — hardware-profile evolution.** Define device classes, NPU/GPU capability descriptors, hot-plug, thermal/power signals, and stable unknown-field behavior across older/new hardware.
43. **Open — peer compute trust.** If personal devices form a compute fabric, define discovery, mutual identity, authority attenuation, data placement, revocation, and offline reconciliation.

## Performance and adaptive execution

44. **Proposed — benchmark before language/runtime replacement.** Use M0–M4 comparisons in `docs/32-aios-ir-and-skill-benchmark-plan.md`.
45. **Open — zero-copy representation negotiation.** Determine when Arrow/shared memory/mmap/GPU buffers are safe and materially beneficial across isolation boundaries.
46. **Open — compiler targets.** Prioritize WASM/native/provider-pipeline/query/GPU lowering according to measured workloads rather than architecture aesthetics.
47. **Open — scheduling objective.** Define how Resource Broker handles conflicting goals such as privacy vs battery, latency vs monetary cost, and quality vs offline operation.
48. **Open — model escalation/de-escalation.** Define measurable policies for small/local model first, larger/remote escalation, and model-free deterministic execution.

## Open source / governance

49. **Open — license.** Apache-2.0, MPL-2.0, GPL-family, or another model; consider provider/plugin ecosystem, patent grants, distribution, and compatibility with key dependencies.
50. **Open — semantic registry governance.** Namespace allocation, compatibility review, contract ownership, forks/extensions, and security revocation need a governance model.
51. **Open — project name.** Choose a vendor-neutral name after architecture stabilizes enough that branding will not drive design.
52. **Open — security-sensitive provider review.** Define conformance vs trust/review levels without pretending automated tests equal security certification.
53. **Open — contribution/governance model.** Maintainer roles, ADR approval, security response, release authority, and conflict-resolution process will matter before a public contributor community scales.

## Decision discipline

When one of these questions becomes sufficiently resolved:

1. record the rationale/evidence in an ADR;
2. update related schemas/examples/tests in the same architecture change;
3. update this file's status;
4. avoid treating a prototype implementation choice as a permanent decision unless the ADR explicitly says so.
