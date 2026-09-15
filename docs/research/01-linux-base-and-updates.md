# Research 01 — Linux Base, Image Updates, and Rollback

**Research date:** 2026-09-15  
**Status:** provisional recommendation; intended to inform issue #14 and a later ADR.

## Question

What Linux base should the v0.1 prototype use while preserving broad hardware reach, ordinary developer tooling, reliable rollback, and freedom to move the AI-native control plane across distributions later?

## Options reviewed

### Fedora Atomic Desktops / Fedora Image Mode / bootc

Fedora currently ships Atomic Desktop variants including Silverblue and Kinoite. Fedora's image-mode direction uses OCI container images as operating-system artifacts, with `bootc` intended to manage transactional in-place system deployment/update.

Strengths for this project:

- desktop-oriented variants exist today;
- strong modern kernel/hardware cadence;
- close alignment with Podman/rootless-container workflows;
- OCI-based system images fit a future reproducible AI-OS image pipeline;
- atomic/image concepts align with our rollback invariant;
- Fedora is actively exploring image-mode GPU-driver composition, directly relevant to local AI acceleration.

Caution:

Fedora's own 2026 Image Mode initiative states that the bootc toolchain is still being driven toward a fully production-capable common system, targeting production pipelines around Fedora 45. We should therefore treat Fedora 44 bootc integration as a prototype substrate rather than assume the image-mode ecosystem is already finished.

Primary sources:

- https://www.fedoraproject.org/atomic-desktops/
- https://fedoraproject.org/wiki/Initiatives/Image_Mode%2C_Phase_2_%282026%29
- https://fedoraproject.org/wiki/Changes/DNFAndBootcInImageModeFedora
- https://forge.fedoraproject.org/iot/base-images/

### Ubuntu Core 26

Ubuntu Core 26 is current and explicitly designed as a minimal immutable OS with image composition and transactional/managed update properties. Canonical positions Ubuntu Core primarily for embedded/edge/device deployments rather than as its ordinary general-purpose desktop platform.

Strengths:

- mature immutable/device philosophy;
- strong OTA/update story;
- long security-maintenance option;
- broad silicon/embedded ecosystem.

Concerns for v0.1:

- its strict snap-centric and device-oriented model would impose packaging assumptions unrelated to our core experiment;
- desktop AI-OS prototyping would spend time adapting to Ubuntu Core rather than proving task/capability orchestration;
- we should not make Snap part of the architecture contract.

Primary sources:

- https://documentation.ubuntu.com/core/uc26/
- https://ubuntu.com/core

### NixOS

NixOS creates system generations and supports switching/rolling back between them. Its declarative configuration and reproducible package model are philosophically attractive for a system that wants auditable composition.

Strengths:

- excellent configuration reproducibility;
- explicit generations and rollback;
- strong isolation/composition ideas;
- useful inspiration for our system-manifest and rollback design.

Concerns for v0.1:

- the Nix language/store/dependency model becomes a large architectural commitment if adopted as the base;
- it risks making contributors learn Nix before they can work on the AI-native control plane;
- compatibility and hardware debugging would be entangled with a less conventional filesystem/package model.

Primary sources:

- https://wiki.nixos.org/wiki/NixOS
- https://wiki.nixos.org/wiki/Generation

## Provisional recommendation

### 1. Keep the core control plane distribution-neutral

The first services should target a reasonably modern Linux userspace and avoid depending on Fedora-specific APIs above ordinary Linux facilities.

The architecture contract is **Linux kernel facilities + explicit adapters**, not "Fedora APIs."

### 2. Use Fedora 44 as the initial reference development environment

Fedora provides a current kernel/userspace, strong container tooling, a desktop-oriented test environment, and practical access to modern GPU stacks.

Developers should be able to run the early control plane on ordinary Fedora Workstation or an Atomic Desktop. The code should not require an immutable host to function.

### 3. Use Fedora Atomic/Image Mode as the first integrated system-image experiment

Once task/artifact/policy/provenance services work as ordinary userspace components, create an image-mode/bootc reference image to test:

- deterministic composition;
- system-service integration;
- atomic system update;
- known-good rollback;
- predeclared driver/runtime profiles;
- recovery without AI.

Do **not** make bootc image construction a prerequisite for every early development cycle.

### 4. Re-evaluate Fedora 45 Image Mode before calling the base decision stable

Fedora's 2026 Image Mode initiative targets major production maturation around Fedora 45. Before the project commits to a public bootable image format, repeat this evaluation against the then-current Fedora 45 state.

### 5. Borrow ideas from NixOS without adopting Nix as the OS contract

In particular:

- declarative system composition;
- immutable versioned generations;
- inspectable configuration identity;
- rollback as a normal operation.

Those properties belong in our requirements even if implemented through a different substrate.

## Architecture consequence

The v0.1 base decision should be phrased as:

> **Reference platform: modern x86_64 Linux, initially tested on Fedora 44. First integrated bootable-system packaging experiment: Fedora Atomic/Image Mode/bootc. Higher-level AI-native contracts remain distribution-neutral.**

This is intentionally less restrictive than "the OS is Fedora."

## Rejection triggers

Revisit this provisional choice if:

- required GPU/NPU drivers cannot be composed/recovered reliably;
- bootc/image-mode development prevents ordinary rapid iteration;
- the image-update stack cannot provide the rollback semantics required by the project;
- another base offers materially broader hardware coverage with lower maintenance burden;
- licensing/distribution constraints interfere with an open project;
- ARM/mobile work exposes assumptions that cannot be abstracted cleanly.

## Next research

Before ADR acceptance:

1. prototype the control plane on ordinary Fedora 44;
2. build a trivial bootc image containing one system service and test rollback;
3. test NVIDIA and AMD/Intel graphics/compute-driver strategies separately;
4. document which state lives in the image versus persistent `/var`/home/task storage;
5. test recovery boot with the AI runtime intentionally unavailable.
