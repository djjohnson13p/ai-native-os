# 12 — Roadmap

## Phase 0 — Architecture and threat model

Deliverables:

- project charter;
- design principles;
- core object definitions;
- trust model;
- task/capability schemas;
- architecture decision records;
- narrow prototype acceptance tests.

Exit condition: implementation teams can build components without inventing incompatible definitions of task, capability, authority, or provenance.

## Phase 1 — Task-first userspace prototype

Deliver:

- intent service;
- capability registry;
- planner;
- policy engine;
- executor;
- provenance store;
- task-first shell;
- data-analysis demonstration.

Exit condition: a nontrivial outcome can be achieved without explicit application selection.

## Phase 2 — Legacy compatibility broker

Deliver:

- package classifier;
- Windows compatibility habitat;
- Android habitat proof;
- compatibility profile format;
- app sandbox policies;
- capability adapter proof.

Exit condition: multiple legacy software families can coexist behind one launch/orchestration model.

## Phase 3 — Hardware-adaptive compute fabric

Deliver:

- normalized hardware inventory;
- model/resource scheduling;
- trusted peer execution;
- hybrid remote execution;
- energy/cost/privacy routing policy.

Exit condition: the same task graph runs appropriately on low- and high-capability devices.

## Phase 4 — Skill compilation and learning

Deliver:

- repeated-pattern detector;
- generalization/privacy-scrub pipeline;
- skill compiler;
- skill conformance tests;
- signed skill packages.

Exit condition: repeated reasoning cost can demonstrably decrease without weakening privacy or correctness.

## Phase 5 — AI-native desktop/environment

Deliver:

- task-centric launcher/history;
- artifact workspace;
- persistent multimodal interaction;
- traditional app fallback surface;
- system settings expressed as policy and intent.

Exit condition: the environment can serve as a daily-driver shell for willing developers.

## Phase 6 — Distribution and governance

Deliver:

- install image;
- hardware support matrix;
- stable APIs;
- contribution/governance model;
- compatibility certification;
- capability registry governance;
- stable release/update/rollback system.

## What is intentionally not scheduled yet

- a custom kernel;
- custom general-purpose foundation model training;
- guaranteed macOS binary compatibility;
- mobile-phone replacement distribution;
- mass-market release date.

Those decisions depend on evidence from earlier phases.
