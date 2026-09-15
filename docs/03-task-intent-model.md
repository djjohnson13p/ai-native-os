# 03 — Task and Intent Model

## Why tasks replace apps

In an app-centric system, the user manually decides how to map a goal onto software. In a task-centric system, the system resolves that mapping.

Example request:

> “Understand these numbers, identify the important changes, produce a chart and a concise report, and save the result.”

The system might derive:

```text
Task
├── inspect source data
├── infer schema and semantics
├── validate numeric fields
├── calculate comparisons
├── identify material changes
├── render chart
├── compose report
├── verify numbers against source
└── save outputs
```

No step inherently requires the concept of “open spreadsheet app.”

## Intent object

An intent should capture at minimum:

```yaml
intent:
  goal: "Understand these numbers and produce a report"
  inputs:
    - data://local/inbox/source.xlsx
  desired_outputs:
    - artifact: chart
    - artifact: report
  constraints:
    privacy: local_preferred
    deadline: null
    max_remote_cost_usd: 0.25
  interaction:
    clarification_policy: when_material
```

## Task graph

The planner transforms intent into a directed acyclic graph where possible. Loops are represented explicitly for iterative reasoning or validation.

Each node declares:

- required capability;
- inputs;
- expected outputs;
- authority needed;
- execution constraints;
- verification strategy;
- rollback behavior;
- confidence expectations.

## Planning is provisional

Plans are not trusted simply because an AI produced them. Before execution, the system should verify:

- each requested capability exists;
- inputs and outputs are type-compatible;
- permission requirements are satisfiable;
- privacy constraints are honored;
- estimated resource/cost bounds are acceptable;
- destructive operations have rollback or approval rules.

## Task UX

The default interface should present work in task terms:

```text
Analyze payroll workbook                Running
  ✓ Read source workbook
  ✓ Validate formulas
  → Compare with previous week
  ○ Generate summary
  ○ Save corrected workbook

Remote data transfer: none
Authority: read source / write task output
Estimated remaining time: 18s
```

The system may still expose technical detail for developers and advanced users.

## Task portability

Tasks should be serializable. A user should eventually be able to export a task recipe without exporting private inputs.

That separation is central to community learning:

- **private task instance:** contains real user data and local context;
- **shareable task pattern:** contains generalized procedure, schemas, tests, and capability requirements.
