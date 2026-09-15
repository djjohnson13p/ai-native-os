# 20 — User and System Object Model

## Problem

Traditional operating systems organize the user's mental model around applications, windows, and files. An AI-native system needs a replacement model that remains understandable when one request spans many capabilities and execution environments.

The architecture should not force one object to do every job.

## Proposed object hierarchy

```text
Workspace (optional durable context)
│
├── Artifact(s) — durable user content
│
└── Task(s) — units of intent/execution
      │
      ├── Intent
      ├── Plan revision(s)
      ├── Agent/provider executions
      ├── Authority grants/approvals
      ├── Provenance events
      └── Output artifacts

Conversation / voice / GUI / API
      ↓
interaction channels that create or modify tasks
```

## Task — primary executable object

The **task** is the canonical unit for:

- user intent;
- planning;
- authorization;
- execution;
- status/progress;
- failure/retry;
- cost/resource accounting;
- provenance;
- verification;
- cancellation;
- learned-procedure extraction.

A task may be seconds long or may run for days.

Example:

> Analyze these sales numbers, identify the important changes, create a chart and report, then save it in this workspace.

That is one task even if it invokes six providers and two models.

## Artifact — primary durable content object

An **artifact** is the canonical unit of durable task input/output.

Examples:

- document;
- spreadsheet/table dataset;
- chart;
- image;
- video;
- 3D scene/model;
- source tree;
- compiled program;
- archive;
- compatibility profile;
- learned skill;
- report;
- machine-readable result.

An artifact is not defined by which application created it.

Artifacts should have:

- stable identity;
- media/semantic type;
- current representation/format(s);
- content hash/version where practical;
- sensitivity/retention metadata;
- lineage/provenance;
- permissions/policy labels;
- optional human-friendly name.

## Workspace — optional durable organizational context

A **workspace** groups related tasks, artifacts, policies, and context for a human purpose.

Examples:

```text
Easy Ride Payroll
House Renovation
Game Project
Fall 2026 Classes
Personal Photos
```

A workspace is not a process boundary and should not automatically grant every task access to every artifact inside it.

It can establish defaults such as:

- preferred output location;
- context sources;
- retention policy;
- preferred provider/model policy;
- collaboration membership;
- sensitivity defaults.

Actual task authority is still explicitly derived by policy.

## Conversation — interaction history, not the OS unit

Text/voice conversation is useful for expressing and refining intent, but it should not become the operating-system database model.

Why:

- not every task is conversational;
- automation/API/sensor events can create tasks;
- one conversation can create several independent tasks;
- a task can continue after the conversation UI closes;
- artifacts and authority need stable identity outside message history.

Conversation is therefore an **interaction channel and provenance source**, not the primary execution object.

## Application — legacy/provider object

Traditional applications remain real software entities for compatibility and explicit UI use, but they are not the primary organizational unit for native AI-OS work.

An installed application may appear as:

- a capability provider;
- a legacy habitat package;
- a traditional explicit-launch interface;
- a source of reusable capabilities discovered through adapters.

Example:

```text
User task: Remove backgrounds from 50 images and prepare web versions.

Possible providers:
  native image provider
  ImageMagick provider
  GIMP adapter
  Photoshop legacy/provider adapter
  remote image service
```

The task is stable even if provider selection changes.

## Session/window

A window should become a **view onto an object**, not the definition of the object's existence.

Possible views:

- task detail;
- artifact editor/viewer;
- workspace overview;
- compatibility app window;
- provenance inspector;
- approval prompt;
- system/resource dashboard.

Closing a view does not inherently terminate the underlying task.

## Artifact representations

One logical artifact may have several representations.

Example:

```text
artifact: quarterly-report
  semantic type: report
  representations:
    report.md
    report.pdf
    report.docx
```

The user can request another representation without creating an entirely unrelated information object.

This reduces unnecessary coupling between user data and application-specific file formats while preserving normal portable files.

## Direct manipulation still matters

Task-first computing must not mean every minor edit requires a chat prompt.

Users should be able to directly manipulate artifacts using context-appropriate views:

- select cells;
- drag an image crop;
- edit text;
- scrub a video timeline;
- move a 3D object;
- draw a mask;
- inspect a data chart.

The difference is that these editors are **views/capability interfaces over artifacts**, not necessarily monolithic applications owning the document lifecycle.

AI can participate in the same artifact/task context.

## Example end-to-end flow

```text
Workspace: Easy Ride Payroll

User attaches payroll.xlsx
        ↓
Artifact A17 created
        ↓
User: "Compare this with last week, flag anything strange,
       fix the summary, and give me the corrected workbook."
        ↓
Task T91
        ↓
reads Artifact A17 + authorized prior-week Artifact A12
        ↓
calculation / comparison / verification capabilities
        ↓
Output Artifact A18: corrected workbook
Output Artifact A19: audit summary
        ↓
Task T91 completed; provenance retained
```

No spreadsheet application had to own the workflow, but the resulting workbook remains a normal file and can still be opened in Excel/LibreOffice if the user wants.

## Proposed architecture decision

- **Task** = primary executable/auditable object.
- **Artifact** = primary durable content object.
- **Workspace** = optional organizational/context container.
- **Conversation** = interaction channel/history.
- **Application** = compatibility/provider/UI object, not the native unit of work.
- **Window/view** = presentation of one or more objects.

This division is intended to preserve familiar user concepts while removing the application as the mandatory center of computing.
