# Workspace protocol contracts

`openapi/workspace-v1.yaml` is the canonical HTTP contract for the neutral
workspace runtime.  The schemas under `schemas/` are the closed JSON Schema
definitions referenced by the OpenAPI document.  They intentionally contain no
Astrid, REIGH, or product-specific types.

The protocol uses a clean, digest-pinned version (`workspace.v1`).  A client
must complete the handshake before using any non-health operation.  Every
state-changing request carries an idempotency key and mutating resources expose
an opaque `version` for optimistic concurrency.

Task admission may include an immutable `storage_estimate` derived from the
same canonical input snapshot as the task spec. `scratch_bytes` is the peak
additional temporary space needed while the task runs; `output_bytes` is the
maximum final output written before temporary data is released. The runtime
checks their sum against current free space at admission and again at claim.
When the field is absent, the registered capability estimates remain the
backward-compatible fallback.

## Astrid binding

Astrid binds a typed task family, project identity, ordered CAS/input
references, and idempotency key to a Runtime-owned workspace task and run.
Workers claim and settle that work through the Runtime contract. Settlement,
output provenance, receipts, and event history remain Runtime-owned and are
the canonical readback surface for Reigh's gallery and timeline consumers.
Product clients must not bypass this boundary with a direct database client or
legacy task-table fallback.
