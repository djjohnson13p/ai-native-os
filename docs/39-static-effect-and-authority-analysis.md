# 39 — Static Effect and Authority Analysis

## Purpose

An AI-native program should be inspectable before it runs.

For every validated AIOS IR program/subgraph, the trusted validator should be able to derive an upper-bound summary answering questions such as:

- Does this program only compute in memory?
- Does it read user artifacts?
- Can it create persistent output?
- Could any step send data externally?
- Could it send a message or trigger another external side effect?
- Does it request access to secrets/devices/system changes?
- Which verification barriers constrain the result?

This is a **static effect analysis**, not an authorization decision.

## Core distinction

```text
Effect = what kind of observable action the program may perform

Authority request = which protected action/resource it asks permission to use

Grant = deterministic policy's current permission for one task/principal/resource
```

A program can be statically effectful but currently unauthorized.

Example:

```text
mail.send@1
```

has an `EXTERNAL_MESSAGE` effect and requests message-send authority. That does not mean it may send a message until current policy grants the concrete action/resource.

## Why effects are useful

Effects provide a compact semantic signal for:

- pre-execution user explanations;
- optimizer safety;
- Skill review;
- provider registration;
- sandbox selection;
- approval thresholds;
- caching decisions;
- remote/peer placement;
- compiler lowering;
- test coverage;
- future AIOS source-language design.

They make security-relevant behavior visible without requiring a human or model to understand every provider implementation.

## v0.1 effect classes

The initial closed set should remain small.

### `PURE`

No externally observable side effect under the semantic contract.

Examples:

- arithmetic;
- deterministic transforms over already-bound values;
- schema checking.

### `ARTIFACT_READ`

Reads content from a protected Artifact/resource handle.

### `ARTIFACT_WRITE`

Creates/modifies task/user artifact content through an authorized allocation.

### `NETWORK`

Uses a network path. This alone does not necessarily mean user data egress; a health check may use network without task data.

### `DATA_EGRESS`

Transfers task/user data outside the current trust boundary.

Keep separate from generic `NETWORK` because external connectivity and sensitive data transfer have different policy significance.

### `EXTERNAL_MESSAGE`

Sends/edits/forwards/posts communication to another principal/system.

Examples:

- email send;
- Slack/Teams message;
- social post.

### `SECRET_ACCESS`

Requests use/access of a secret/credential capability.

### `PERSISTENT_STATE`

Changes persistent state outside ordinary task artifact creation.

Examples:

- update external database record;
- change account preference;
- modify durable provider state.

### `DEVICE_ACCESS`

Reads/controls device capabilities such as camera/microphone/location/sensors where those are not represented as ordinary pre-authorized input artifacts.

### `SYSTEM_CHANGE`

Changes the base system/security configuration.

Examples:

- install privileged package;
- update system policy;
- alter network/security configuration.

### `LEGACY_OPAQUE`

Invokes a legacy/opaque environment whose complete effects cannot be captured by a narrower semantic contract.

This effect should usually imply stronger isolation/approval/verification rather than pretending the behavior is pure.

## Effect hierarchy / ordering

The effects are not a single linear severity scale.

For example:

- `SECRET_ACCESS` may be sensitive but read-only;
- `EXTERNAL_MESSAGE` may be externally consequential without needing a secret;
- `SYSTEM_CHANGE` may be local but high consequence.

Therefore the static result is a **set** plus derived risk/policy facts rather than one numeric effect level.

Policy may map combinations to approval impact levels separately.

## Node effect derivation

For an IR node:

1. resolve Semantic Capability Contract;
2. obtain contract-allowed effect classes;
3. inspect node authority requests and egress declaration;
4. derive the semantic effect upper bound;
5. validate consistency;
6. later compare Provider Manifest/provider ABI reachability against that bound.

Example:

```text
artifact.hash@1
allowed effects: ARTIFACT_READ
node asks: artifact.read(input:source)
egress: deny

Derived node effect set:
  { ARTIFACT_READ }
```

Example:

```text
report.summarize@1
provider-independent contract may allow local or remote implementations
node egress: deny

Derived semantic node effects:
  no DATA_EGRESS for this program

Resource Broker must therefore select only a local/non-egress provider.
```

This is an important point: a capability contract describes possible valid implementations, while one AIOS IR program can impose a stricter effect/egress requirement.

## Program effect summary

The program summary is derived from node summaries plus explicit program/task constraints.

Basic v0.1 algorithm:

```text
program_effects = union(node_effects)
program_authority_classes = union(node authority request classes)
contains_probabilistic = any(probabilistic nodes)
contains_opaque = any(opaque external / LEGACY_OPAQUE)
may_egress = any(node egress == policy and execution route permits external transfer)
verification_barriers = collect verifier nodes
```

The static semantic program can report `egress_policy_capable` before a provider is selected; the concrete Execution Binding/provenance reports whether actual egress occurs.

## Lower/upper bounds

Where useful, validation can distinguish:

### Required semantic effects

Effects inherent to the program as written.

### Permitted implementation effects

The maximum effect classes a conforming provider may require under the selected contract/program restriction.

### Concrete binding effects

The actual provider/runtime interfaces/resource scopes selected for this attempt.

The concrete layer MUST be a subset of the permitted layer.

## Effect narrowing

An optimizer/provider may implement work with fewer effects than the semantic upper bound.

Example:

A capability supports local and remote implementations, but Resource Broker selects a local provider with no network.

Narrowing is desirable.

Effect broadening requires semantic/program/policy revalidation as appropriate.

## Effect-preserving optimization

Safe transformations must preserve or reduce the effect upper bound.

Examples:

- fuse two PURE nodes → PURE;
- fuse PURE + ARTIFACT_READ → ARTIFACT_READ;
- replace remote model node with conforming local model → remove DATA_EGRESS/NETWORK where semantics permit;
- cache a deterministic PURE intermediate → still PURE for compute, though cache storage mechanics are a runtime implementation detail under controlled system authority.

Unsafe examples:

- replace local computation with remote SaaS call without program/policy change;
- add telemetry that sends task content;
- convert artifact-local output into automatic email send;
- move a verifier after an externally visible side effect when it originally gated the effect.

## Verification ordering and effects

Verification is most valuable before high-impact effects.

The validator/planner should be able to identify patterns such as:

```text
probabilistic result
   ↓
EXTERNAL_MESSAGE
```

with no verifier/approval boundary.

Depending on policy and capability semantics, this may be valid, require approval, or require verification.

A stronger desirable pattern is:

```text
probabilistic draft
   ↓
verification/review
   ↓
explicit authority/approval
   ↓
external effect
```

Effect analysis helps surface this structure to policy/UX.

## External side-effect ordering

For effectful nodes, the semantic graph should keep preparation separate from commitment where practical.

Example:

```text
compose email (PURE/task-local)
   ↓
verify/review
   ↓
mail.send (EXTERNAL_MESSAGE + NETWORK/DATA_EGRESS)
```

This makes pre-effect work cacheable/reusable and allows user approval at the actual boundary.

## Skill effect contract

A Skill manifest should expose its derived effect/authority upper bound.

This enables the UI to say:

```text
This Skill reads selected input files and writes task outputs.
It never sends data externally.
```

or:

```text
This Skill can draft locally but may request approval to send email.
```

The manifest summary is recomputed/validated from source AIOS IR rather than trusted because the package author wrote it.

## Compiled targets

`specs/compiled-target.schema.json` already carries `effect_upper_bound`.

Compiler verification must prove:

```text
compiled_target_effects ⊆ source_subgraph_effects
compiled_target_authority_classes ⊆ source_subgraph_authority_classes
compiled_target_egress_modes ⊆ source_subgraph_egress_modes
```

A target that fails this proof is ineligible even if it produces correct output in happy-path tests.

## Provider ABI analysis

Provider registration should compare static ABI reachability/imports to effect claims.

Example Wasm component:

```text
imports artifact-read, progress, log
```

is consistent with an artifact-hash provider.

A component that additionally imports generic outbound network for `artifact.hash@1` should fail or require an explicitly different semantic/provider contract.

For native processes, equivalent reachability is enforced primarily through sandbox/execution profiles rather than statically introspecting every possible syscall.

## Authority request precision

Effect analysis should not replace resource-scoped authority requests.

These are very different:

```text
Effect: ARTIFACT_READ
```

and:

```text
Authority request:
  artifact.read
  resource = input:source
```

The effect is useful static classification; the authority request supplies concrete semantic scope for policy.

## Policy mapping

Policy can use static facts such as:

```text
contains SYSTEM_CHANGE
contains DATA_EGRESS
contains EXTERNAL_MESSAGE
contains LEGACY_OPAQUE
contains probabilistic node before high-impact effect
all effects task-local
```

but policy remains independently authored/evaluated.

The validator should not hard-code all social/user approval rules into the effect system.

## Diagnostics

Additional stable validator reason codes may include:

```text
IR_EFFECT_NOT_ALLOWED
IR_EFFECT_EGRESS_MISMATCH
IR_EFFECT_AUTHORITY_MISMATCH
IR_EFFECT_VERIFICATION_BARRIER_INVALID
IR_EFFECT_COMPILED_TARGET_BROADENING
```

Provider validation may use:

```text
PROVIDER_EFFECT_NOT_ALLOWED
PROVIDER_ABI_IMPORT_EXCEEDS_CONTRACT
```

## Machine-readable effect summary

`specs/effect-summary.schema.json` defines a draft derived record containing:

- semantic program hash;
- registry snapshot;
- whole-program effect set;
- requested authority classes;
- egress modes;
- probabilistic/opaque flags;
- per-node summaries;
- verification barriers.

The summary is generated by trusted tooling; it is not a planner-authored source of truth.

### Verification inventory is not output assurance (R17-05)

In v0.1, `verification_barriers` lists verifier nodes and `verification_gate=true`
identifies a verifier operation. Neither proves that all final outputs traverse
that verifier, that the verifier ran successfully, or that a Task's required
assurance claims are satisfied. An additional program output may legally reference
a pre-verification value even while another output uses the verifier's result.
Unused verifier nodes are also permitted under docs68.

Consumers must inspect actual data flow and separately enforce their required
claims; they must not use a nonempty inventory as a blanket verified-result flag.
The `review-repair-cases.json` fixture and regression test demonstrate the distinction.
This clarification changes no accepted graph or summary field shape.

## Future source-language implication

If AIOS later gains a human/AI authoring language, the effect system could become a major language feature.

Possible conceptual syntax:

```text
capability send_report(...)
  effects { artifact.read, external.message, data.egress }
  requires { artifact.read(input), mail.send(recipient) }
```

But the semantic effect model should be proven in structural AIOS IR first.

This follows the project's broader rule: own semantics before syntax.

## v0.1 tests

1. pure graph derives only `PURE`;
2. input file hash derives `ARTIFACT_READ`;
3. report output graph derives `ARTIFACT_READ` + `ARTIFACT_WRITE` but no data egress;
4. remote model candidate cannot bind when IR requires no egress;
5. provider with network import/effect exceeds local-only semantic contract and is rejected;
6. optimizer fusion preserves effect set;
7. compiled target with added network effect is rejected;
8. Skill effect summary matches recomputed source graph;
9. authority request class not allowed by effect/capability contract fails;
10. external message effect remains visible even when preparation is compiled/cached.

## Architectural principle

> **AIOS should know the shape of a program's effects before it gives the program the power to cause them.**
