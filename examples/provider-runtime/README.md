# Provider Supervisor Fixtures

Synthetic fixtures for `docs/78-v0.1-execution-binding-and-provider-supervisor.md`.

They test immutable attempt bindings, bounded provider invocation, point-of-use grants, staged output publication, cancellation, and crash/recovery behavior.

They deliberately do not execute real providers. Runtime code belongs to later Codex implementation.

Core rule:

> A provider invocation may use only the exact resources/interfaces in its current Execution Binding and grants; a retry/substitution creates a new attempt rather than rewriting history.
