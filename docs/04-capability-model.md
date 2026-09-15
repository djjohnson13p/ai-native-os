# 04 — Capability Model

## Definition

A capability is a typed operation the operating environment can request without caring which specific provider implements it.

Examples:

```text
table.read
table.join
table.calculate
chart.render
document.compose
document.export.pdf
image.remove_background
image.resize
3d.import_mesh
3d.render
mail.search
mail.draft
code.compile
web.fetch
```

## Provider types

A capability provider may be:

1. native deterministic service;
2. local AI model;
3. remote AI model/service;
4. conventional executable;
5. legacy GUI application adapter;
6. container;
7. virtual machine;
8. WASM module;
9. browser/web application;
10. another trusted device.

## Provider selection

The broker scores candidate providers against policy and task constraints.

Example dimensions:

- capability match;
- deterministic vs probabilistic behavior;
- local vs remote;
- data sensitivity;
- latency;
- expected quality;
- resource usage;
- energy cost;
- monetary cost;
- availability;
- reproducibility;
- user preference;
- provider trust level.

Conceptual scoring:

```text
score = compatibility
      + quality
      + locality
      + trust
      - latency
      - monetary_cost
      - energy_cost
      - privacy_penalty
```

Security policy is a hard constraint, not merely a score.

## Capability manifests

Providers declare machine-readable manifests. A draft schema exists at [`../specs/capability-manifest.schema.json`](../specs/capability-manifest.schema.json).

Illustrative manifest:

```yaml
id: org.example.table.engine
version: 0.1.0
provides:
  - capability: table.calculate
    input_types:
      - application/vnd.aios.table
    output_types:
      - application/vnd.aios.table
    execution:
      locality: local
      deterministic: true
    authority:
      requires:
        - data.read:input
        - artifact.write:task
```

## Capability composition

A major design objective is automatic composition.

For example:

```text
spreadsheet source
   │
   ▼
table.read
   │
   ▼
table.calculate
   ├──────────────► chart.render
   │                    │
   └────► document.compose ◄────┘
                    │
                    ▼
            document.export.pdf
```

## Legacy applications as providers

A legacy application can be wrapped by an adapter exposing a subset of capabilities. The user may never need to see the application's GUI for automatable operations.

Adapters must clearly distinguish:

- official API integration;
- command-line automation;
- accessibility/UI automation;
- reverse-engineered integration;
- unsupported heuristic control.

The provenance layer records which method was used.
