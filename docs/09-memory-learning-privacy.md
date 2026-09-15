# 09 — Memory, Learning, and Privacy

## Goal

Allow the system to become more efficient over time without turning private user behavior into uncontrolled training data.

## Three distinct concepts

### Personal context

Private, user-specific facts and preferences.

Default location: local encrypted storage.

Examples:

- preferred output format;
- local file relationships;
- device habits;
- private project context.

### Task history

Execution records and provenance for completed work.

Retention is policy-controlled.

### Generalizable skill

A procedure abstracted from one or more successful tasks that no longer contains private inputs.

Example:

```text
Private instance:
"Analyze Easy Ride payroll Week 37 workbook"

Generalized skill:
"Validate a weekly payroll workbook against prior-period totals and flag discrepancies"
```

## Learning pipeline

```text
successful task
    ↓
pattern detection
    ↓
proposed generalized procedure
    ↓
privacy scrub / schema abstraction
    ↓
test generation
    ↓
replay against synthetic or approved examples
    ↓
user/system approval
    ↓
compiled skill
```

## Compiled skills

A compiled skill can contain:

- deterministic code;
- capability graph;
- schemas;
- assertions;
- small model calls only where ambiguity remains;
- test cases;
- versioned provenance.

## Community sharing

A skill may be shared only after removing:

- user data;
- secrets;
- identifying paths;
- private model context;
- confidential task history.

The system should make the difference between **sharing a procedure** and **sharing data** visually explicit.

## Data-boundary indicator

Every task should expose a concise privacy summary such as:

```text
Data boundary
  Local files read: 3
  Local models used: 2
  Remote providers used: 0
  Data sent off-device: none
```
