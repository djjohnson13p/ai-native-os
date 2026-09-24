## Summary

<!-- What does this PR change and why? -->

## Issue

Closes/addresses: #

## Current roadmap stage

<!-- See docs/53-system-of-everything-staged-roadmap.md -->

## Architecture sources followed

<!-- List the controlling docs/ADRs/schemas/fixtures. -->

- 

## System invariants

- [ ] Preserves all applicable invariants in `docs/15-system-invariants.md`
- [ ] Intentionally refines an invariant through an explicit ADR/documented decision (explain below)

Invariant notes:

## Contracts / compatibility

- [ ] No semantic/security contract changed
- [ ] Contract(s) changed; schemas + fixtures + tests/docs are updated together
- [ ] Migration/backward-compatibility impact is documented

Details:

## Security / authority / privacy

- [ ] No new ambient filesystem/network/secret authority
- [ ] No model/planner/Skill self-authority path introduced
- [ ] Provider/runtime-specific state remains outside semantic identity
- [ ] Data egress/credential use remains explicit and policy-controlled
- [ ] Negative/adversarial tests cover security-relevant changes

Details:

## Tests / checks run

```text
# exact commands + results
```

## Review evidence for trusted-boundary changes

<!-- For authority, persistence, revocation, retained handles, and recovery changes. Use N/A otherwise. Review the complete executable path before requesting external review. -->

- Public admission entry point and later point-of-use entry point:
- Durable state transitions and supported restart/migration states:
- Adversarial public-path tests and their observable denial/effect:
- Windows and Linux/WSL focused results before the full exact-head gate:
- Remaining unproven behavior (if any):

## Review-loop cost and decision

<!-- Update after each substantive review. Count distinct pushed heads, not comments or routine polling. After two successive heads expose different failures in one trust boundary, record the design challenge and scope decision before another patch. -->

- Head-changing review cycles so far:
- Findings: introduced / previously latent / uncertain:
- Full exact-head gates run so far:
- Boundary design or PR-scope decision, if the two-head escalation triggered:

## AIOS IR / validator-specific checks (if applicable)

- [ ] Positive fixtures pass
- [ ] Invalid/adversarial fixtures fail with expected reason-code family
- [ ] Duplicate-key/limit cases covered
- [ ] Canonical/hash equivalence + semantic-difference cases covered
- [ ] No network/model/provider execution occurs during semantic validation
- [ ] Hostile/malformed input does not panic

## Known limitations / non-goals

- 

## Follow-up architecture work

<!-- Link/create issue/ADR if implementation exposed a contract gap. -->

- 
