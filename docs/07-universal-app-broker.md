# 07 — Universal App Broker

## Goal

Make legacy software compatibility as transparent as possible while avoiding the false claim that one runtime can natively execute every historical package format.

From the user's perspective:

> Select or request the software/task; the system decides the execution habitat.

Under the hood, the broker may use different compatibility technologies.

## Package classification

The broker inspects package and binary metadata rather than relying only on filename extensions.

Potential classifications include:

- Linux ELF / package formats;
- Windows PE/Win32/Win64;
- Android APK/AAB-derived installable packages;
- web/PWA;
- WASM/WASI;
- Java/JVM;
- container images;
- virtual-machine images;
- macOS-origin binaries where legal and technically supportable;
- architecture-mismatched binaries requiring translation/emulation.

## Execution habitats

A habitat is a compatibility environment with a defined security boundary.

Examples:

```text
linux-native
windows-compat
android-container
web-sandbox
wasm-sandbox
full-vm
cpu-translation
remote-hosted
```

The broker may combine habitats, e.g. a Windows application under CPU translation inside an isolated VM.

## Compatibility profile

Once a package is known to work, the system can record a community-shareable profile containing non-private information such as:

- required habitat;
- runtime version;
- required libraries;
- GPU requirements;
- known launch flags;
- integration adapters;
- known limitations;
- conformance test results.

This lets compatibility knowledge improve collectively without sharing user data.

## Capability extraction

Where possible, the broker exposes legacy application functionality to the capability layer.

Example:

```text
Legacy image editor
  ├── image.open
  ├── image.resize
  ├── image.mask
  └── image.export
```

The adapter may use an official API, CLI, plugin protocol, accessibility interface, or other method. The method must be declared in provenance.

## Compatibility promises

The project should distinguish:

- **supported** — covered by automated compatibility tests;
- **community-supported** — known working profile, not release-gated;
- **experimental** — partial or unstable;
- **unsupported** — no viable habitat;
- **prohibited** — blocked because of legal, security, DRM, or policy constraints.

The architecture aims for broad compatibility, not a dishonest “everything runs” guarantee.
