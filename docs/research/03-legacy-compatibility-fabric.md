# Research 03 — Legacy Compatibility Fabric

**Research date:** 2026-09-15  
**Status:** architecture recommendation; compatibility claims remain target-specific.

## Question

How can the system make legacy software feel "native" to the user without attempting to reimplement Windows, Android, macOS, Linux, and multiple CPU architectures inside one codebase?

## Core conclusion

Compatibility has at least two independent dimensions:

1. **Operating environment / API / ABI** expected by the application.
2. **CPU instruction-set architecture** expected by the binary.

The Universal App Broker should compose translation layers along those axes rather than maintain one giant universal emulator.

```text
Package / executable
        ↓
Format + OS-family inspection
        ↓
CPU architecture inspection
        ↓
Compatibility profile lookup
        ↓
┌───────────────────────────────────────────────┐
│ OS/API habitat                                │
│ native Linux · Wine · Android · web · VM     │
└──────────────────┬────────────────────────────┘
                   │
           architecture match?
            ┌──────┴──────┐
            │             │
           yes            no
            │             ↓
            │       QEMU-user / FEX / VM
            │             │
            └──────┬──────┘
                   ↓
          sandbox + integration broker
                   ↓
                launch
```

To the user, "native" should mean **transparent launch and integration**, not falsely claiming the binary executes against our kernel/API without translation.

## Windows applications

### Wine

Wine describes itself as a compatibility layer that translates Windows API calls to POSIX calls rather than running a full Windows VM.

This is the correct first general Windows compatibility substrate for an x86_64 Linux v0.1 target.

Current Wine stable release is 11.0, with active 11.x development in 2026.

Primary source:

- https://www.winehq.org/

### Proton

Valve Proton is a compatibility tool for Steam Play built on Wine plus additional components. It is an important proof that compatibility profiles and additional translation/runtime components can make very complex Windows software work well on Linux.

Architectural lesson:

- maintain per-application compatibility profiles;
- version the habitat;
- allow graphics/runtime components to differ by application;
- keep those profiles separate from the application binary.

However, Proton should not be treated as the generic office/application compatibility layer; its product target is Steam/games.

Primary source:

- https://github.com/ValveSoftware/Proton

## CPU architecture translation

### QEMU user-mode

QEMU user-mode can run programs built for one CPU architecture on the same guest operating-system family while translating system calls and instruction execution.

Architectural role:

- broad fallback for foreign-architecture Linux binaries;
- useful component for package inspection/testing;
- potential composition layer under/around compatibility habitats when performance is acceptable.

Primary source:

- https://www.qemu.org/docs/master/user/

### FEX

FEX targets x86/x86-64 applications on ARM64 Linux and explicitly supports use alongside Wine/Proton. It can forward selected host graphics APIs to reduce emulation overhead.

Architectural role:

- preferred technology to evaluate for ARM64 devices that need x86/x64 Linux or Windows application compatibility;
- evidence that API translation and CPU translation can be composed as separate layers.

Primary source:

- https://github.com/FEX-Emu/FEX

## Android applications

### Waydroid

Waydroid runs a full Android system in a Linux container using namespaces and integrates Android applications with a Wayland desktop. It supports ARM, ARM64, x86 and x86_64 hosts, subject to image/application architecture and hardware constraints.

Architectural role:

- strong candidate for the Android habitat on Linux;
- APK install/launch can be wrapped behind the Universal App Broker;
- Android should receive an AI-OS-specific host integration/policy layer rather than exposing all normal Waydroid host integration automatically.

Important caveats:

- Waydroid relies on Linux/Android kernel facilities such as binder support;
- direct hardware access is part of its performance model;
- Nvidia/VM environments can require software rendering or different handling;
- an ARM-only APK will not automatically work on x86_64 merely because Waydroid itself runs.

Primary sources:

- https://docs.waydro.id/
- https://docs.waydro.id/usage/install-and-run-android-applications
- https://waydro.id/

## macOS applications

### Darling

Darling is a Darwin/macOS compatibility layer for Linux. It implements Mach-O loading, Darwin/Mach interfaces, and reimplements a growing set of Apple frameworks. Its own current project description states that many command-line tools are functional while higher-level GUI support is still actively being developed.

Architectural role:

- research/experimental habitat;
- valuable proof that macOS API translation is technically possible for subsets of software;
- **not** a basis for promising general macOS application compatibility today.

Primary source:

- https://github.com/darlinghq/darling

## iOS/iPadOS applications

Do not put iOS application compatibility on the v0.1 or early roadmap as a promised feature.

An `.ipa` package is not simply "another executable format." Practical execution involves Apple platform frameworks, entitlements/signing assumptions, mobile hardware/OS APIs, graphics/media stacks, and proprietary ecosystem dependencies.

This should remain a separate research track with legal/licensing review before any public compatibility claim.

## Full virtual machines

QEMU system emulation plus KVM acceleration where available provides the fallback when shared-kernel/API translation cannot satisfy an application.

Architectural roles:

- high-isolation untrusted applications;
- software requiring a full foreign OS environment;
- compatibility debugging/reference;
- remote/headless habitat where UI can be streamed/integrated.

The tradeoff is higher memory/storage/startup overhead.

Primary source:

- https://www.qemu.org/docs/master/system/

## Proposed Universal App Broker pipeline

### Stage 1 — static inspection

Without executing the file:

- identify container/package/binary format;
- detect executable architecture(s);
- extract application identity/version where possible;
- inspect declared dependencies/signing metadata;
- hash package;
- query known compatibility profile.

### Stage 2 — target classification

Example target classes:

```text
linux.native
linux.foreign-arch
windows.wine
windows.wine+arch-translation
android.waydroid
macos.darling.experimental
web.browser-habitat
vm.full-system
unsupported
```

### Stage 3 — profile resolution

A compatibility profile may specify:

- habitat/runtime version;
- libraries/runtime packages;
- CPU translation layer;
- graphics backend;
- environment/registry settings;
- known command-line options;
- filesystem mappings;
- network policy;
- device needs;
- integration permissions;
- known limitations;
- test status and confidence;
- provenance/source of the profile.

### Stage 4 — policy composition

Compatibility requirements do not override user security policy.

If an application profile requests home-directory access and the user/task granted only one document, the broker should expose only that document through the habitat's integration bridge.

### Stage 5 — launch and health monitoring

Record:

- selected habitat;
- version/image/profile digest;
- architecture translator;
- effective sandbox;
- granted host integrations;
- launch result;
- crashes/errors;
- user-visible compatibility status.

## Compatibility status vocabulary

Avoid one binary "works/doesn't work" flag.

Recommended states:

- **verified** — passes a defined compatibility test on a declared hardware/runtime profile;
- **works-with-limitations** — launches and core use works, documented gaps remain;
- **experimental** — partial/unreliable or insufficiently tested;
- **blocked** — known technical/policy/legal blocker;
- **unsupported** — no viable habitat currently known;
- **unknown** — not yet tested.

Compatibility status must name the profile against which it was measured.

## Community learning model

This is an area where safe collective learning can deliver large value.

When a user/application combination is made to work, a sanitized profile can potentially be shared containing:

- application hash/version;
- habitat version;
- required translation components;
- safe configuration changes;
- conformance results;
- hardware notes.

It must **not** contain user files, credentials, license keys, personal paths, or other private context.

A shared profile registry should be signed/versioned and treated as untrusted supply-chain input until verified.

## v0.1 recommendation

Keep Demonstration B deliberately narrow:

> **x86_64 Windows application on x86_64 Linux through Wine, selected and launched by the Universal App Broker under a task-specific sandbox.**

Do not add cross-architecture translation to the first compatibility proof. Prove composition separately after the broker/profile model works.

## Near-term compatibility sequence

1. Linux native packages/providers.
2. Windows x86_64 on Linux x86_64 via Wine.
3. Android via Waydroid.
4. x86/x64 Linux-on-ARM64 via FEX/QEMU-user.
5. Compose FEX + Wine for selected Windows-on-ARM64 cases.
6. Full VM fallback.
7. Experimental macOS/Darling research.
8. iOS only after separate feasibility and legal/licensing study.
