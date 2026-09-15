# 34 — Task / AIOS IR Lifecycle Integration

## Purpose

`docs/24-task-state-machine.md` defines durable task state. AIOS IR adds a second identity: the validated semantic program currently selected to satisfy the task.

These concepts must not be conflated.

A **Task** answers:

> What user/system outcome are we trying to achieve over time?

A **Semantic Program** answers:

> What validated capability graph currently represents how this task will achieve that outcome?

A task can survive multiple plan proposals, semantic programs, providers, execution attempts, and replans without changing task identity.

## Identity hierarchy

```text
Task
  task_id = T
  │
  ├─ intent revision(s)
  │
  ├─ planner proposal revision(s)
  │
  ├─ validated semantic program revision(s)
  │    program hash = P1, P2 ...
  │
  ├─ execution binding(s)
  │    binding = provider + authority + placement + attempt
  │
  └─ artifacts + provenance
```

A provider retry should normally create a new execution binding/attempt, not a new task or new semantic program.

A semantic replan that materially changes capabilities/dataflow creates a new semantic program hash but normally retains the same task ID.

## State relationship

### `CREATED`

Required:

- durable task ID;
- original intent;
- input artifact references known so far.

Semantic program:

- none required.

No execution binding may exist merely because the task was created.

### `PLANNING`

This state includes:

- intent normalization;
- capability discovery at semantic level;
- planner proposal generation/revision;
- lowering proposal to candidate AIOS IR;
- structural validation;
- semantic validation against a registry snapshot;
- bounded planner repair after validator diagnostics.

Important:

> `PLANNING` is not executable authority.

A task may have a prior validated program while replanning. The control plane must identify which program revision is currently active vs superseded.

### `WAITING_FOR_INPUT`

The system could not safely produce/choose a valid semantic program without additional information.

Examples:

- two incompatible interpretations require different capabilities;
- input artifact type cannot be selected deterministically;
- requested output has materially different privacy/effect consequences.

A partial planner proposal is diagnostic state only and must not be executed.

### `WAITING_FOR_AUTH`

Normally requires:

- a structurally/semantically valid current program;
- concrete authority request(s) derived from that program/provider/resource context;
- persisted policy/approval request IDs.

The semantic program is valid but not fully authorized.

A user denial does not make the program structurally invalid; it may cause failure, clarification, or bounded replan to a lower-authority program.

### `RUNNABLE`

For v0.1, a task may enter `RUNNABLE` only if all required preconditions exist:

1. validated active semantic program;
2. semantic program hash;
3. registry snapshot identity;
4. successful validation result;
5. current policy requirements satisfiable;
6. no mandatory user approval pending;
7. required capabilities have at least one eligible provider or a defined bounded resolution path;
8. resource constraints are currently satisfiable enough to schedule at least one ready node.

Not every node needs an execution binding before the task enters `RUNNABLE`; bindings may be created just in time so provider/resource state remains fresh.

### `RUNNING`

One or more semantic nodes have attempt-specific execution bindings and are executing/coordinating.

A runtime binding must refer back to:

```text
task_id
semantic program hash
node_id
```

This is how provenance proves that a concrete process/model/legacy app was executing a particular semantic request.

### `VERIFYING`

The active semantic program contains required verification gates whose outputs/final conditions are being resolved.

The system must not publish completion merely because every ordinary provider has exited successfully.

### `PAUSED`

Persist:

- active semantic program hash;
- registry snapshot;
- completed node outputs;
- incomplete/active execution binding state;
- outstanding approvals/resources;
- Skill identity if invoked;
- provenance cursor/event identity.

Resume revalidates time-sensitive runtime facts and current authority. It does not assume old grants are still valid.

### `RECOVERING`

On restart, recover separately:

1. task record;
2. active semantic program identity/validation result;
3. execution binding attempts;
4. provider supervisor state;
5. artifact integrity;
6. grant validity;
7. provenance chain.

The semantic program may remain valid even when every execution binding must be recreated.

### `ROLLING_BACK`

Rollback/compensation operations should themselves be represented as deterministic authorized operations with provenance.

A rollback graph may be generated from declared compensation contracts rather than pretending to reverse arbitrary AI reasoning.

### Terminal states

Terminal task state does not delete semantic history.

Retain under policy enough information to reconstruct:

- final active program hash;
- relevant prior program revisions;
- provider/runtime bindings;
- authority/provenance;
- produced artifacts;
- verification result.

## Planner proposal vs semantic program

During v0.1, `task-plan.schema.json` remains planner-facing.

Suggested relationship:

```text
Planner Proposal
   plan_id / plan_revision
        │
        ▼
 deterministic lower/normalization step
        │
        ▼
Candidate AIOS IR
        │
        ▼
 validator
     ┌──┴──┐
 invalid  valid
   │       │
diagnostic │
/repair    ▼
       Semantic Program
       hash + registry snapshot
```

Do not assign executable semantic identity to raw model text merely because it contains a plausible plan.

## Program revision history

A task should persist references to material semantic program revisions.

Candidate record:

```text
program_revision
program_id
semantic_hash
IR version
registry_snapshot_id
validation_result_id
created_from_plan_revision
created_at
superseded_at
superseded_reason
```

The Task Record may carry only the active program directly while a separate history table/store preserves revisions.

## What creates a new semantic program hash?

Examples:

- add/remove/reorder data dependency that changes meaning;
- change semantic capability;
- change semantic input/output type;
- add/remove verification gate;
- change authority request;
- change egress mode;
- change bounded failure behavior;
- change resource constraint that is defined as semantic rather than a runtime preference.

## What normally does NOT create a new semantic program hash?

Examples:

- choose Provider A instead of conforming Provider B;
- execute on CPU instead of GPU;
- move eligible execution from local machine to authorized peer/remote placement;
- issue a new current capability token;
- retry the same semantic node;
- change sandbox instance ID;
- restart a provider process;
- alter non-semantic debug metadata.

Those changes belong to execution binding/provenance.

## Policy-driven semantic replan

Example:

1. planner produces valid program with a remote reasoning capability;
2. user policy denies egress;
3. task cannot bind that node;
4. bounded replan produces an alternative local capability graph;
5. new graph receives a new semantic hash;
6. new graph is independently validated;
7. normal policy evaluation begins again.

The denial is never converted into permission by the planner.

## Provider failure without replan

Example:

1. semantic node `chart.render@1` is valid;
2. Provider A crashes;
3. bounded failure policy permits retry/fallback;
4. Broker selects conforming Provider B;
5. new execution binding/attempt is created;
6. semantic program hash remains unchanged;
7. provenance records both attempts.

This is a key test of provider independence.

## Skill invocation

A Skill invocation begins a new Task or is incorporated into an existing parent task according to future composition semantics.

In either case:

- Skill supplies a parameterized semantic program/template;
- current parameters become new input bindings;
- current registry compatibility is checked;
- current policy is evaluated;
- current execution bindings are created;
- old grants are not reused.

A compiled target is an optimization of eligible semantic nodes, not a different source of authority.

## Parent/child tasks — future direction

Complex autonomous work may need nested task identity.

Potential model:

```text
parent task
  ├─ child task: research
  ├─ child task: transform dataset
  └─ child task: send approved output
```

This is intentionally not required for v0.1. When added, authority delegation must be attenuated and provenance must link parent/child identities.

## Database implications

The v0.1 persistence design should likely separate tables/collections for:

```text
tasks
plan_revisions
semantic_program_revisions
validation_results
execution_bindings
execution_attempts
artifacts
policy_decisions
grants
provenance_events
skills
```

This is a conceptual model, not yet a mandated SQL schema.

## Completion invariant

A task may not transition to `COMPLETED` unless the control plane can identify the validated semantic program whose required outputs were satisfied and whose required verifiers passed.

## Architectural principle

> **Task identity persists across changing ideas of how to accomplish the work; semantic program identity persists across changing implementations of that work.**
