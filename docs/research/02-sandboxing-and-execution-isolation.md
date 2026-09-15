# Research 02 — Sandboxing and Execution Isolation

**Research date:** 2026-09-15  
**Status:** architecture recommendation; implementation details remain prototype work.

## Question

How should an AI-native OS translate task-scoped logical authority into real Linux execution boundaries for deterministic providers, third-party providers, AI runtimes, and legacy applications?

## Key conclusion

No single sandbox technology covers the whole problem.

The project should define a **logical authority model once** and map it onto a layered execution-isolation stack according to workload risk and compatibility needs.

```text
Task capability token
        ↓
Deterministic policy decision
        ↓
Execution profile
        ↓
┌───────────────────────────────────────────────┐
│ process restrictions / Landlock / seccomp    │
│ namespaces / bubblewrap / systemd cgroups    │
│ rootless OCI container                        │
│ VM / full compatibility habitat               │
└───────────────────────────────────────────────┘
```

A capability token is **not** a sandbox. The provider runner must enforce the token through kernel-visible boundaries wherever practical.

## Linux primitives reviewed

### Landlock

Landlock is a stackable Linux Security Module specifically designed to let processes, including unprivileged processes, restrict themselves and their descendants. Modern Landlock supports granular filesystem restrictions and network-related controls, and restrictions are additive rather than a way to grant new authority.

Why it fits our architecture:

- directly supports the principle of reducing ambient rights;
- can be applied by unprivileged execution paths;
- naturally complements, rather than replaces, normal DAC/LSM policy;
- recent kernel work includes audit visibility for denied Landlock access.

Limitations matter. Landlock is not a complete process/container isolation system; special filesystems, already-open file descriptors, namespaces, IPC, devices, and other attack surfaces require additional controls.

Primary sources:

- https://docs.kernel.org/userspace-api/landlock.html
- https://docs.kernel.org/admin-guide/LSM/landlock.html

### Bubblewrap

Bubblewrap is a low-level unprivileged sandbox used by Flatpak. It builds restricted mount/process/user/network namespaces and can combine these with seccomp.

Why it fits:

- mature desktop-oriented use;
- explicit filesystem construction;
- user, PID, IPC, and network namespaces;
- unprivileged user-namespace operation on current Fedora/Ubuntu-class systems;
- lightweight enough for short-lived capability providers.

Primary source:

- https://github.com/containers/bubblewrap

### Flatpak sandbox and portals

Flatpak demonstrates an important architectural pattern: applications begin with a strongly restricted sandbox and use **portals** for mediated access to files and host services.

We should borrow the *portal pattern* even if we do not make Flatpak itself the provider runtime:

> Providers should request access through a brokered capability interface rather than receive the user's whole home directory or desktop session by default.

That maps extremely well to artifact handles and capability tokens.

Primary sources:

- https://docs.flatpak.org/en/latest/basic-concepts.html
- https://docs.flatpak.org/en/latest/portal-api-reference.html

### Rootless Podman / OCI containers

Podman supports rootless operation using user namespaces. OCI containers are heavier than a minimal bubblewrap sandbox but provide a good packaging/execution boundary for providers that need their own dependency tree or repeatable runtime image.

Likely uses:

- third-party deterministic capability providers;
- model runtimes with substantial dependencies;
- legacy-support helper services;
- reproducible test environments.

Primary source:

- https://docs.podman.io/en/stable/markdown/podman.1.html

### systemd service isolation and resource control

systemd provides process supervision plus namespace, privilege, filesystem, syscall, and resource-control options. It can be useful as the lifecycle/resource supervisor even when bubblewrap or containers provide the filesystem sandbox.

Relevant concepts include:

- no-new-privileges;
- private networking/users/process environments;
- syscall filters;
- inaccessible/read-only paths;
- cgroup resource accounting/limits;
- transient service lifecycles.

Primary sources:

- https://www.freedesktop.org/software/systemd/man/systemd.nspawn.html
- https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

## Recommended isolation classes

The policy engine should output an **execution profile** separate from the capability token.

### Class P0 — trusted deterministic in-process library

Use only for small, reviewed, memory-safe or otherwise strongly trusted components that do not parse hostile complex formats and require no broad host authority.

Default: avoid expanding this class casually.

### Class P1 — restricted local process

For small deterministic providers.

Target controls:

- dedicated process identity/context;
- no-new-privileges;
- task-scoped filesystem view;
- Landlock restrictions where supported;
- seccomp profile where practical;
- no network unless granted;
- cgroup CPU/memory/pid limits;
- only required artifact handles/resources exposed.

### Class P2 — bubblewrap-style provider sandbox

For parsers/renderers and providers handling untrusted inputs or third-party code.

Target controls:

- private mount/PID/IPC/user namespace;
- task-specific read-only input bind mounts;
- separate writable output area;
- network namespace disabled by default;
- seccomp;
- no ambient host home directory;
- explicit portal/broker access for additional resources.

### Class P3 — rootless OCI provider container

For substantial provider stacks and runtimes with many dependencies.

Target controls:

- immutable provider image where practical;
- rootless execution;
- task-scoped mounts;
- explicit network policy;
- CPU/RAM/device limits;
- signed/versioned provider manifest associated with the image digest.

### Class P4 — legacy compatibility habitat

For Wine/Android/containerized legacy applications where ordinary provider assumptions do not fit.

Controls are application-profile dependent. Host integration such as clipboard, file picker, GPU, audio, input, camera, and network should be separately brokered instead of treating "desktop access" as one permission.

### Class P5 — virtual machine / high-risk habitat

Use when a workload requires a broad foreign OS environment, kernel-level assumptions, highly privileged drivers/services, or is too risky to trust to shared-kernel isolation.

VM execution is more expensive, but the resource broker can select it when security/compatibility justifies the cost.

## Authority-to-sandbox mapping

Example:

```text
Capability token:
  task = T123
  principal = provider:chart-renderer
  allow = read artifact:A1
  allow = write artifact-output:T123
  deny = network

Execution profile:
  class = P2
  ro-bind A1 -> /task/input/data.csv
  bind task output -> /task/output
  unshare-net = true
  memory.max = 512 MiB
  pids.max = 64
  seccomp = chart-renderer-v1
  landlock = /task/input:r, /task/output:rw
```

The provider sees paths inside its sandbox, while the control plane retains artifact identity and provenance.

## Why not rely only on containers?

Containers alone do not express our user/task authority model. A container can still be over-mounted, over-networked, or given excessive devices/secrets.

The order must remain:

1. determine allowed authority;
2. select execution class;
3. construct the narrowest practical sandbox;
4. execute;
5. record effective isolation and accesses in provenance.

## Why not rely only on model safety?

A perfectly aligned model can still be wrong, compromised through hostile input, or connected to a buggy provider. Kernel-enforced boundaries remain necessary even when reasoning behavior is benign.

## Prototype recommendation

For v0.1:

- use systemd/cgroups for lifecycle and resource supervision where convenient;
- use bubblewrap or equivalent namespace construction for most deterministic providers;
- use Landlock as defense-in-depth when available;
- use rootless Podman for dependency-heavy providers;
- use a dedicated compatibility habitat for Wine;
- reserve QEMU/KVM-class VM isolation for tests or high-risk fallback rather than the default Demonstration B path.

The provider API should not expose which mechanism was selected unless the provider explicitly requires one. Isolation is a resource/policy decision.

## Design requirements to add later

- execution profiles need stable IDs and versioning;
- effective sandbox configuration should be included in provenance;
- capability providers should declare minimum required host integration;
- policy should be able to force a stronger isolation class than a provider requests;
- providers must not be able to request a weaker class than policy permits;
- missing kernel isolation features should cause a safe fallback or refusal, not silent relaxation.
