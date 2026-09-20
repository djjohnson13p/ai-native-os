# Recovery Fixtures

Synthetic crash/reconciliation cases for `docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md`.

They model deterministic evidence and safe next actions. No model judgment is required to classify the local v0.1 cases.

Core rule:

> Uncertainty is preserved as uncertainty until deterministic evidence resolves it; irreversible/opaque effects are never blindly retried merely because a response was lost.

`per-subject-cases.json` adds adversarial multi-subject cases. It requires each
subject to use evidence bound to its own identity and prevents a completed
sibling from supplying optimistic certainty for an unknown effect.
