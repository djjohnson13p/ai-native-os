# ADR 0008 — Fedora Reference Development Environment and Image-Mode Experiment

- **Status:** Proposed — requires prototype validation
- **Date:** 2026-09-15

## Context

The project needs a concrete Linux environment for v0.1 development without turning distribution choice into the AI-native operating-system contract.

The base should offer current hardware support, ordinary developer tooling, container/sandbox support, and a credible path to atomic system composition, rollback, and recovery.

## Proposed decision

For v0.1:

1. Treat **modern x86_64 Linux** as the implementation platform contract.
2. Use **Fedora 44** as the first reference development/test environment.
3. Allow early control-plane development on a conventional Fedora Workstation or Fedora Atomic Desktop; immutable/image packaging is not required for every edit/test cycle.
4. Use **Fedora Atomic/Image Mode/bootc** as the first integrated bootable-system image experiment once the core control plane runs in ordinary userspace.
5. Keep higher-level task/capability/policy/artifact/provider interfaces distribution-neutral.
6. Re-evaluate Fedora Image Mode around Fedora 45 before promoting this proposal to a stable base-system decision.

## Why this is proposed rather than accepted

Current Fedora image-mode work is still actively maturing. The project needs evidence from its own prototype that update, rollback, driver composition, state layout, and recovery meet the architecture requirements.

## Validation required

Before acceptance:

- build a minimal system image containing one AI-OS service;
- perform an image update and known-good rollback;
- verify `/var`/user/task state survives correctly;
- boot/recover with all AI model services disabled;
- test at least Intel/AMD graphics path and separately document NVIDIA behavior;
- confirm ordinary development does not require rebuilding the complete OS image.

## Consequences

### Positive

- gives Codex/developers a concrete environment;
- avoids writing kernel/driver infrastructure;
- aligns with atomic update/rollback goals;
- preserves freedom to support other distributions later.

### Risk

- Fedora's image-mode tooling is evolving;
- rapid Fedora release cadence can increase maintenance;
- GPU/NPU and proprietary driver composition may require special handling;
- project documentation must distinguish reference platform from architecture requirement.

## Related

- `docs/research/01-linux-base-and-updates.md`
- issue #14
- ADR 0001
