# ADR 0006 — No Ambient AI Authority

- **Status:** Accepted for architecture draft
- **Date:** 2026-09-15

## Context

An AI-native operating system must allow models and agents to propose actions across files, applications, network services, hardware, and system functions. If reasoning components simply inherit the logged-in user's authority, a prompt injection, model error, malicious provider, or compromised legacy application can turn a planning mistake into a full-account compromise.

Model safety behavior is not an operating-system authorization boundary.

## Decision

AI reasoning components, agents, capability providers, learned skills, and legacy application habitats receive **no ambient user authority**.

Side-effecting operations require deterministic task-scoped grants that bind at least:

- task;
- principal;
- semantic capability/action;
- resource scope;
- issuance/expiry;
- applicable constraints;
- approval/policy provenance where required.

Plans are proposals. The policy engine is the authority source. The execution layer verifies effective authority independently of planner/model output.

For trusted in-process adapters, the protected operation includes effects at
resource retirement, including a destructor that can write or close an external
destination. The core must admit and finish those effects before it records
success. If current authority cannot admit retirement, it suppresses the
destructor and records uncertainty instead of letting ordinary object lifetime
run the effect later. Arbitrary third-party adapters require isolation.

Persistent user preferences are represented as policy rules from which new task-scoped grants are derived; they are not immortal reusable agent tokens.

Delegation, if supported, may only narrow authority.

## Consequences

### Positive

- prompt injection cannot directly grant privileges;
- provider/model substitution does not change the authorization model;
- task actions are attributable;
- data egress can be mediated explicitly;
- legacy applications can be integrated without giving them full desktop access;
- user approvals can be precise and revocable.

### Costs

- resource identity and capability semantics must be designed carefully;
- providers need a broker/sandbox integration layer;
- some traditional applications will require compatibility adapters for narrow file/clipboard/device access;
- authorization checks add implementation complexity and some runtime overhead.

## Rejected alternatives

### Inherit the user's login/session permissions

Rejected because it makes AI reasoning equivalent to an unrestricted desktop automation tool and provides no meaningful blast-radius control.

### Let the model classify whether an action is safe

Rejected as the enforcement mechanism. Models may assist with explanation or risk context, but deterministic policy owns the decision.

### Grant broad persistent permissions to trusted agents

Rejected as the default. Trust in an agent implementation does not eliminate prompt injection, dependency compromise, context confusion, or future policy changes.

## Related

- `docs/08-security-threat-model.md`
- `docs/15-system-invariants.md`
- `docs/19-principal-and-authority-model.md`
- `specs/capability-token.schema.json`
