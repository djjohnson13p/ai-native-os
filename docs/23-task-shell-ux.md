# 23 — Task-First Shell UX Specification

## Purpose

Define the minimum human interaction model needed to prove that the system is task-first rather than an application launcher with an AI chat panel.

This is a behavioral specification, not a visual-style guide.

## UX principles

### 1. Outcome before application

The primary affordance asks:

> What do you want to accomplish?

not:

> Which application do you want to open?

### 2. Artifacts are directly attachable/manipulable

Users can select or drag files, datasets, images, documents, folders, media, or other artifacts into a task without deciding which application should own them.

### 3. Ask only consequential questions

Clarification is required when ambiguity materially changes:

- outcome;
- authority;
- privacy/data egress;
- cost;
- irreversible impact;
- output destination/format when it cannot be safely inferred.

Do not interrogate the user about implementation details the system can select safely.

### 4. Progress is task-oriented

A user sees what the machine is doing in terms of the task:

```text
Analyzing table
Comparing periods
Creating chart
Verifying calculations
Writing report
```

The default view does not need to say:

```text
python3 PID 8721
libreoffice --headless
container sha256:...
```

Those details remain available in diagnostics/provenance.

### 5. Authority prompts are concrete

Bad approval:

> Allow agent access?

Better:

> Send the detected changes and column summary to Remote Model X to write the report? The original spreadsheet will stay on this device.

Approvals should communicate:

- what action;
- which resources/data;
- destination;
- consequence;
- duration/scope;
- reversibility when relevant.

### 6. Traditional applications remain available

Users may explicitly request:

> Open this in Excel.

or choose an application from an artifact's **Open with…** / compatibility menu.

This is an escape hatch and transition feature, not the native default interaction.

## Primary shell regions

A v0.1 shell can be extremely simple.

```text
┌───────────────────────────────────────────────────────────────┐
│ AI-Native OS                                                 │
├───────────────────────────────────────────────────────────────┤
│ What do you want to accomplish?                              │
│ [___________________________________________________________] │
│                                                               │
│ Inputs: [numbers.xlsx] [+ Add artifact]                       │
│                                        [Start task]           │
├───────────────────────────────────────────────────────────────┤
│ Active tasks                                                 │
│                                                               │
│ ● Analyze payroll numbers                     Verifying  82%  │
│ ◐ Prepare photo set                           Waiting approval │
│ ✓ Summarize project notes                     Completed       │
├───────────────────────────────────────────────────────────────┤
│ Recent workspaces / artifacts                                │
└───────────────────────────────────────────────────────────────┘
```

This does not require a conventional desktop to disappear in v0.1. It can initially run as a dedicated shell/window over Linux.

## Task creation flow

### Step 1 — express intent

Supported v0.1 input:

- typed text;
- pasted text;
- drag/select artifacts.

Future:

- voice;
- gesture;
- camera/sensor context;
- automation/API triggers.

### Step 2 — intent preview only when useful

For simple tasks, start directly.

For consequential/ambiguous tasks, show a concise interpretation:

```text
I will:
  1. compare this workbook with the prior-period data you selected;
  2. flag unusual changes;
  3. create a chart and report;
  4. save new outputs without modifying the input.

Data policy: local-only
```

The user can edit constraints without editing an execution graph.

### Step 3 — create task

The UI receives a stable task ID immediately and moves to task detail/progress.

## Task detail view

Default information:

```text
Analyze payroll numbers
Running · started 12:42 PM

Current step
  Verifying report calculations

Progress
  ✓ Imported workbook
  ✓ Calculated changes
  ✓ Created chart
  ◐ Verifying report
  ○ Publish outputs

Inputs
  numbers.xlsx

Outputs
  chart.png (preview available)

Privacy
  Local-only

[Pause] [Cancel] [Details]
```

### Details expansion

Advanced detail should include:

- normalized intent;
- plan graph/revisions;
- provider selected for each capability;
- why that provider was selected;
- execution placement;
- model/runtime/version;
- authority grants;
- external data transfers;
- timing/resource/cost metrics;
- verification results;
- provenance event stream;
- sandbox/habitat identity for diagnostics.

This allows expert inspection without making every user operate at that level.

## Approval view

Approval prompts are task objects/events, not modal mystery dialogs from arbitrary applications.

Example:

```text
Approval needed

Task: Analyze payroll numbers

Requested action
  Send derived summary data to Model Provider X

Data leaving this device
  • Column names and types
  • Aggregate monthly totals
  • 6 detected change records

Not included
  • Original workbook
  • Names/identifiers not needed by this step

Purpose
  Compose the natural-language report

Scope
  This task only

[Use local model instead] [Deny] [Allow once]
```

If a local fallback exists, presenting it turns privacy/cost policy into a useful choice rather than a dead-end permission prompt.

## Artifact view

Artifacts should expose operations by capability, not only by application.

Example for a spreadsheet artifact:

```text
numbers.xlsx

Quick actions
  Analyze
  Compare
  Chart
  Convert
  Extract table
  Validate

Open/edit
  Native table view
  Open with LibreOffice
  Open with Excel compatibility profile

History
  Imported by Task T91
  Derived outputs: A21, A23
```

For an image:

```text
Quick actions
  Resize
  Remove background
  Enhance
  Convert
  Describe
  Extract text
  Create variants
```

The capability registry drives available actions.

## Artifact editor views

Applicationless does not mean prompt-only.

A user may directly edit an artifact using a specialized view:

### Document view

- text editing;
- formatting;
- comments;
- layout/page preview;
- AI operations over selections.

### Table view

- cells;
- formulas;
- sorting/filtering;
- charts;
- data types;
- AI operations over selected ranges.

### Image view

- crop/mask/brush/selection;
- layers/objects where supported;
- generative/edit capabilities over selected regions.

### 3D view

- scene hierarchy;
- viewport;
- transforms;
- material/animation controls;
- AI generation/edit capabilities.

These are **artifact views plus capability surfaces**. They may use existing open-source engines internally.

## Long-running tasks

Tasks can outlive their UI view.

The shell should surface long-running work through a task center:

```text
Active
  Rendering scene                     41% · local GPU
  Researching compatibility           waiting on network
  Organizing photo archive            8,213 / 31,440 files

Needs attention
  Install requested driver            approval needed
  Payroll analysis                    conflicting input dates
```

Closing the shell does not cancel a task unless policy says so.

## Notifications

Notify only on meaningful task state transitions:

- approval required;
- clarification required;
- completion;
- failure that needs action;
- significant policy/cost change;
- background task milestone explicitly requested by user.

Avoid model-generated chatter as a substitute for status.

## Failure presentation

Bad:

> Something went wrong.

Better:

```text
Could not create the report

Completed
  ✓ workbook import
  ✓ calculations
  ✓ chart

Failed
  report provider became unavailable

Your input was not changed.
No data left the device.

[Retry with local template] [Choose another provider] [Details]
```

The task should preserve partial artifacts without mislabeling the whole task as complete.

## Provider visibility

Provider choice should use progressive disclosure.

Default:

```text
Report writing: Local
```

Expanded:

```text
Capability: report.compose
Provider: local-model-report-writer 0.1
Runtime: llama.cpp
Model: <exact model id/hash>
Reason selected: local-only policy + available RAM
```

User preferences may pin/avoid providers, but the native workflow should not require routine provider selection.

## Cost/resource visibility

Where relevant, show simple summaries:

```text
Local compute: 18 seconds
Remote cost: $0.00
Data sent externally: none
Energy mode: balanced
```

Expert detail can expose CPU/GPU/memory and provider metrics.

## Workspace view

A workspace presents related activity without becoming an app.

Example:

```text
Easy Ride Payroll

Recent tasks
  Sep 15 payroll analysis
  Sep 8 payroll analysis
  Compare August grievances

Artifacts
  Current payroll workbook
  Prior-week workbook
  Driver rate policy
  Reports

Workspace defaults
  Privacy: local-first
  Output: Reports/
```

Workspace membership does not automatically grant a task access to every listed artifact.

## Compatibility launch flow

When a user selects a legacy executable/package:

```text
PayrollTool.exe

Detected
  Windows x86-64 application

Compatibility
  Verified profile available
  Wine habitat 11.x
  Network: disabled by current policy
  Files: only files explicitly opened through the task

[Run]
```

If setup is required, the broker owns the configuration process instead of sending the user through manual compatibility-layer tuning.

## v0.1 UX acceptance criteria

The shell passes its UX proof when a fresh user can:

1. attach a test dataset;
2. state the Demonstration A intent;
3. understand any approval request;
4. observe progress without knowing provider/process details;
5. receive chart/report artifacts;
6. inspect which models/providers/data transfers were used;
7. reopen the task after shell restart;
8. explicitly open an output in a traditional application if desired;
9. launch the Demonstration B legacy application through the broker;
10. understand a controlled failure without losing the input.

## Non-goals

v0.1 does not need:

- a polished desktop compositor;
- a replacement file manager;
- perfect voice input;
- every artifact editor;
- animated AI avatars;
- a global app store;
- fully autonomous background behavior;
- visual redesign of Linux.

The UX proof is simply that **task-first computing is understandable, controllable, and inspectable.**
