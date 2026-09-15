# 50 — Adaptive Presentation and Device UI

## Purpose

AIOS should not treat a 6-inch phone, 13-inch laptop, 49-inch ultrawide workstation, wall display, vehicle display, headset, television, terminal, voice-only device, and accessibility interface as the same desktop scaled to different pixel counts.

The **Task, semantic objects, authority, and AIOS IR remain stable**. Presentation is a device/context-specific projection.

## Principle

> **Views adapt to people, devices, input methods, context, and available display surfaces. Objects and tasks do not belong to one GUI.**

## Presentation stack

```text
Task / Semantic Objects
        ↓
View Model / Interaction Contract
        ↓
Presentation Broker
        ↓
Display + input + accessibility profile
        ↓
Concrete View Renderer
```

The View Model should describe what information/actions must be available, not hard-code pixels or one toolkit.

## Display profile

A normalized display/device profile should include relevant facts such as:

```text
logical width/height
physical size / DPI
orientation
refresh range
HDR/color capabilities
safe areas / cutouts
pointer available?
keyboard available?
touch available?
stylus available?
gamepad/controllers?
voice input/output?
cameras/sensors?
windowing/multi-surface capability
accessibility preferences
power/thermal constraints
privacy/display-trust class
```

This profile is separate from the general hardware compute profile because presentation decisions have different semantics.

## Presentation classes

Suggested broad classes:

```text
GLANCE
COMPACT_TOUCH
STANDARD_DESKTOP
LARGE_DESKTOP
MULTI_DISPLAY
IMMERSIVE
VOICE_FIRST
HEADLESS
REMOTE_SURFACE
ACCESSIBILITY_SPECIALIZED
```

These are selection hints, not product editions.

## Progressive disclosure

The same Task can project differently.

Phone:

```text
Task status
key result
one approval action
artifact preview
```

Laptop:

```text
Task timeline
result + artifacts
approval panel
expandable provenance
```

Engineering workstation:

```text
object tree
CAD/EDA viewport
constraint/error panels
Task/provenance dock
multiple synchronized Views
```

Voice-only:

```text
spoken summary
confirmation prompts
auditory progress
explicit high-consequence approval language
```

The semantic operation is the same; the interaction projection changes.

## View contracts

A Domain Pack may declare optional Views for direct manipulation, such as:

- spreadsheet grid;
- CAD viewport;
- schematic editor;
- PCB layout;
- timeline editor;
- source-code editor;
- CRM board;
- ledger;
- dashboard;
- document/page layout.

A View contract should declare:

```text
supported semantic object types
required interaction capabilities
minimum display class
input preferences
streaming requirements
latency sensitivity
accessibility alternatives
privileged actions exposed
```

A View does not own object identity or become the only API for mutation.

## Presentation Broker

The Presentation Broker chooses among compatible Views/renderers based on hard requirements and context.

Hard exclusions might include:

- renderer requires pointer but device is touch/voice only;
- confidential object cannot be mirrored to untrusted display;
- immersive renderer requires unavailable GPU/headset;
- task requires precise CAD manipulation unavailable in glance mode.

Among eligible renderers, preferences may consider:

- user choice/history;
- current input devices;
- display size;
- latency;
- battery;
- accessibility settings;
- focus/distraction mode;
- task consequence level.

AI can recommend a view; deterministic policy still controls sensitive display/approval behavior.

## Responsive semantics, not only responsive layout

Traditional responsive design often rearranges the same controls.

AIOS should permit **semantic adaptation**.

Example: a complex billing workspace on a phone may expose:

```text
"Three invoices require review"
```

instead of rendering a tiny 30-column grid.

The user can ask for details or move the Task to a larger display without losing state.

## Cross-device continuation

Presentation state should be separable into:

```text
semantic task/object state      durable/shared
view navigation state           optionally synchronized
transient UI state              local to surface
sensitive display state         policy controlled
```

A user might begin by voice on a phone, continue a CAD View on a workstation, then approve a summary on a tablet.

The same Task identity persists.

## Multi-display / multi-device workspace

AIOS should support one Task projected across multiple surfaces.

Example:

```text
workstation monitor 1 → CAD viewport
monitor 2             → BOM/cost table
phone                  → camera/scan input
wall display           → non-sensitive presentation preview
```

Each surface receives only the object fields/actions allowed by its trust and session context.

## Remote surfaces

A display can be remote without moving computation.

For example:

```text
headless workstation computes CAD
laptop renders/controls viewport stream
```

or:

```text
phone controls media task
TV displays output preview
```

Remote presentation is distinct from remote execution and needs its own latency, authentication, codec, privacy, and input-return policies.

## Accessibility

Accessibility is not an afterthought or separate application mode.

View contracts should support alternate projections including:

- screen-reader semantic trees;
- keyboard-only navigation;
- switch access;
- voice interaction;
- magnification/high-contrast;
- caption/transcript-first media;
- reduced motion;
- simplified cognitive presentation;
- haptic/audio alternatives where appropriate.

AI can simplify/explain, but essential controls and state must remain deterministically represented.

## GUI generation and AI

AI may dynamically compose low-risk Views from trusted components, but it should not invent arbitrary privileged UI behavior without validation.

For consequential actions:

- action identity is typed;
- target object/resource is explicit;
- effects are shown accurately;
- approval controls come from trusted system components;
- deceptive provider-supplied UI cannot impersonate system authorization.

## Direct manipulation remains important

Task-first computing does not mean every interaction becomes chat.

For spatial/visual/expert work, direct manipulation is often superior:

- dragging CAD constraints;
- sketching;
- editing a PCB route;
- trimming a video timeline;
- sculpting 3D geometry;
- manipulating a spreadsheet range;
- debugging source code.

AIOS should combine direct manipulation and natural-language intent rather than force either one universally.

## v0.1 scope

The first prototype needs only enough UI to prove the abstraction:

1. task submission;
2. artifact attachment/reference;
3. task progress/state;
4. approval surface;
5. result/artifact view;
6. provenance expansion;
7. simulated desktop + compact-device presentation profiles.

Specialized CAD/EDA/media Views can remain architectural contracts until their domains are implemented.

## Principle

> **The device determines the best projection of the work; it does not redefine the work itself.**
