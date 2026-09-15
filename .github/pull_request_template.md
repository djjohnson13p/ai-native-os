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
