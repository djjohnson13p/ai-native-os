# 08 — Security and Threat Model

## Security premise

An AI-native operating environment must assume that reasoning components can be mistaken, manipulated, compromised, or overly broad in their interpretation of user intent.

Therefore:

> AI output is a proposal. Authority comes from deterministic policy.

## Principal threats

### Prompt/instruction injection

Untrusted content may attempt to redirect agents.

Mitigation direction:

- label data by trust source;
- separate content from instructions;
- prohibit untrusted data from granting authority;
- require policy validation for every side-effecting action.

### Excessive authority

An agent with the user's full privileges can turn a reasoning error into a system compromise.

Mitigation:

- task-scoped capability tokens;
- no ambient authority;
- automatic expiration;
- resource and path scoping.

### Data exfiltration

Remote models or services may receive data beyond what the task requires.

Mitigation:

- local-first routing;
- data minimization;
- sensitivity labels;
- provider-specific egress policy;
- provenance for every external transfer.

### Supply-chain compromise

Capability providers, models, compatibility profiles, or skills may be malicious.

Mitigation:

- signed manifests;
- reproducible builds where feasible;
- provenance and publisher identity;
- sandboxing;
- community reputation separate from cryptographic trust;
- conformance testing.

### Model/provider compromise

A provider may return malicious plans or exploit parser behavior.

Mitigation:

- parse outputs into constrained schemas;
- validate every requested capability;
- never execute arbitrary generated shell/code with privileged authority by default.

### Destructive autonomous action

Mitigation:

- transactional writes where feasible;
- snapshots/rollback;
- human approval thresholds;
- delete/quarantine separation;
- explicit irreversible-action policies.

### Compatibility habitat escape

Legacy applications expand the attack surface.

Mitigation:

- sandbox habitats;
- separate filesystem namespaces;
- virtualized high-risk applications;
- network controls;
- per-app authority profiles.

## Approval model

Actions can be classified by impact:

```text
Level 0 — read-only, low sensitivity
Level 1 — reversible task-local writes
Level 2 — external communication or persistent modification
Level 3 — destructive/system/security-sensitive action
Level 4 — irreversible or high-consequence action
```

User policy determines which levels require confirmation.

## Provenance requirements

A user must be able to answer:

- What did the system read?
- What changed?
- Which provider/model produced this decision?
- Did data leave the device?
- Which permissions were granted?
- What can be rolled back?
