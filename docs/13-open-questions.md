# 13 — Open Questions

These are architecture decisions that should be made deliberately rather than smuggled into the prototype through implementation convenience.

## Product / interaction

1. What is the canonical user-visible object: task, workspace, artifact, conversation, or a combination?
2. How much planning detail is shown by default?
3. How does a user override provider selection without falling back into app-centric thinking?
4. What happens when the user explicitly wants a traditional application interface?
5. How are long-running autonomous tasks represented?

## Capability system

6. What is the stable type system for capability inputs/outputs?
7. How are semantic capabilities versioned?
8. How do capabilities declare quality and determinism?
9. What conformance tests are required for a capability to be “supported”?
10. How should conflicting providers be ranked?

## Security

11. What capability-token technology should be used?
12. Is the policy language custom, eBPF-inspired, Rego-like, object-capability based, or something else?
13. Which operations can never be approved persistently?
14. How is provenance protected from tampering?
15. How are models, skills, and compatibility profiles signed and revoked?

## Memory / learning

16. What remains device-local by default?
17. How does a user inspect and delete learned procedures?
18. What proof is required before a probabilistic workflow can be compiled into deterministic code?
19. How are shared skills scrubbed of private context?

## Compatibility

20. Which legacy family should be supported first after Linux-native?
21. Is Android compatibility in-process/container-based or VM-based by default?
22. How should proprietary runtimes and DRM be handled?
23. How are CPU architecture translation and OS API translation composed?
24. What compatibility claims are legally safe to make?

## Base system

25. Which Linux base minimizes maintenance while preserving hardware reach?
26. Immutable base image or conventional mutable root filesystem?
27. systemd, alternative service manager, or custom control plane atop a standard init?
28. What is the update/rollback design?
29. How much functionality belongs in the trusted computing base?

## Open source / governance

30. License: Apache-2.0, MPL-2.0, GPL-family, or another model?
31. How should provider registries be governed?
32. What project name avoids dependence on any AI vendor or trademark?
33. How are security-sensitive capability providers reviewed?
