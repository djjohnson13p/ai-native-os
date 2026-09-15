# Prototype Workspace

Implementation should begin only after the architecture documents and ADRs are reviewed.

The first prototype should remain deliberately small.

Suggested initial directories once implementation begins:

```text
prototypes/
  control-plane/
  intent-service/
  capability-registry/
  policy-engine/
  executor/
  resource-broker/
  provenance-store/
  universal-app-broker/
  shell/
  providers/
    table/
    chart/
    document/
    model-local/
    model-remote/
```

## Engineering rules for v0.1

- No custom kernel work.
- No generated privileged code in the boot path.
- Every side-effecting capability call goes through policy authorization.
- Every task emits provenance.
- AI-generated plans are validated before execution.
- Deterministic implementations are preferred when the operation is deterministic.
- Every remote provider declares what data leaves the machine.
- Legacy application support is brokered, never given unrestricted host access by default.
