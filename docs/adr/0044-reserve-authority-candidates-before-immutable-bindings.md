# ADR 0044 — Reserve Authority Candidates Before Immutable Bindings

Status: Accepted for the Stage-1 Issue #3 bounded implementation.

## Context

An Execution Binding is an immutable attempt receipt whose creation requires current policy decisions, approval conditions, and grant references. Creating a binding with empty references merely to obtain its ID would leave a permanent non-executable receipt: adding grants would require changing the binding. Conversely, runtime policy needs stable binding and attempt IDs before evaluating exact scope.

## Decision

The trusted coordinator first writes a **non-executable candidate reservation** under the Task Manager ownership fence. It reserves a fresh binding ID, attempt ID and attempt number and pins the validated Task/program/node, selected registry and conforming provider/build/evidence/trust source. Its sealed resource set maps every semantic authority request to one exact trusted Artifact identity or a fresh, coordinator-chosen Task output allocation identity. The resource set is complete before the PENDING status row is inserted and cannot be amended afterward. The reservation is not an Execution Binding, provider attempt, approval, grant, token, or permission to use an Artifact.

Reservation and non-executable policy evaluation may occur while the Task is `PLANNING`; otherwise an approval request could not exist before the guarded transition to `WAITING_FOR_AUTH` requires it. An approval-conditioned grant is finalized only after that ordinary transition. An entirely unconditional, current `ALLOW` set may finalize in `PLANNING` when the active plan and program match; this prepares authority but does not make the Task runnable or permit Artifact use. The ordinary Task transition and runtime checks still decide execution.

Stage-1 reservations also pin a derived local execution profile reference and isolation class from the admitted provider manifest, with local placement and denied egress. The reservation parser admits valid typed Task constraints (including nonempty local privacy constraints), rejects unknown or malformed fields and elapsed deadlines, and requires a node locality constraint to include local when present. Cost and input-preservation policy still need independent evaluation before finalization. Policy and finalization must not choose a different profile or placement under the same candidate ID.

`0016_authority_candidate_reservations` keeps immutable identity/resource rows and a separate CAS status row. A repeated reservation request with identical identities and resources returns the same PENDING candidate after a lost response; different content fails. Collision guards prevent subsequent binding, step, or allocation inserts from stealing reserved IDs or the reserved attempt tuple. Candidate-scoped update, delete, and duplicate-insert guards retain those identities even when SQLite `INSERT OR REPLACE` runs with recursive triggers disabled. Future coordinator finalization must revalidate all mutable facts and, in one commit, issue policy-backed grants and receipts, insert the exact immutable binding, create any exact bound output allocation and step attempt, then move the candidate status from PENDING to FINALIZED. A stale or cancelled candidate keeps its identities and cannot be reused. Recovery interprets a PENDING row as an unfinished proposal, never as launch authority.

The current `allocate_artifact_output` API owns its own transaction, so it cannot be called as-is from that future atomic finalizer. Finalization needs a transaction-level broker insertion core or an equivalent refactor. The 0016 relational guards permit only an exact bound allocation after the binding insert and before the status CAS; they do not themselves issue authority.

The current Artifact Store cannot attach a binding to an already unbound allocation. Therefore an output candidate reserves an **allocation ID** and exact node port/type but does not create an allocation row. Finalization will create the bound allocation using the reserved ID. Candidate admission rejects a conflicting existing allocation. Generic `task.output` on a node with several output ports remains unsupported in this slice because the one semantic request to multiple concrete allocations/grants rule is not yet defined; it fails closed without redefining IR semantics.

Similarly, `input:<name>` requires an unambiguous verified Task input Artifact of its semantic type. If several program input names or Task-linked Artifacts share that type, including pending or failed Artifacts, the current persistence schema has no name-to-Artifact binding; candidate admission fails closed until that mapping has its own trusted contract.

## Compatibility and trust

The migration does not backfill historical bindings, grants, or allocations with invented candidate facts. Legacy history remains readable under its existing quarantine rules. A privileged raw SQLite writer can forge a candidate row; the row is non-executable, and future finalization must use the private coordinator writer and revalidate every pin. The stamped table/index/trigger definitions are checked on reopen; missing or replaced guards require operator quarantine.
