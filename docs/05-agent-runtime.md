# 05 — Agent Runtime

## Agent definition

An agent is a scoped reasoning process operating on behalf of a task under explicitly granted authority.

An agent is **not** synonymous with an AI model. An agent has:

- identity;
- task membership;
- purpose;
- authority token(s);
- accessible context;
- available capabilities;
- resource budget;
- model/provider policy;
- lifecycle state;
- audit/provenance stream.

A model is one resource an agent may use.

## Agent lifecycle

```text
instantiate
   ↓
receive task scope
   ↓
receive capability grants
   ↓
reason / propose actions
   ↓
policy validation
   ↓
execute capability calls
   ↓
verify outputs
   ↓
release grants
   ↓
terminate or persist bounded state
```

## Authority model

Agents do not receive ambient user authority.

Bad:

```text
User is administrator → Agent can do anything user can do
```

Preferred:

```text
User
  └── Task
       └── Agent
            ├── read: /Data/Payroll/Week37.xlsx
            ├── write: task-output/*
            └── invoke: table.calculate, chart.render
```

Tokens should be:

- narrow;
- revocable;
- time-bounded;
- task-bound;
- provider-aware;
- logged.

## Agent classes

The system may eventually distinguish:

### Planner agent

Decomposes intent and proposes task graphs.

### Execution agent

Coordinates capability calls for a bounded subtask.

### Verification agent

Checks claims, calculations, and task completion conditions.

### System agent

Handles privileged system-level maintenance under stricter policy and human approval requirements.

### Learning agent

Looks for stable repeated procedures suitable for compilation into skills.

## Multi-agent caution

Multiple agents should not be used by default. Agent count is not a measure of system intelligence.

The orchestrator should prefer the smallest architecture that satisfies the task. Extra agents increase:

- cost;
- nondeterminism;
- communication overhead;
- security surface;
- debugging difficulty.
