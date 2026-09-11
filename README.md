# Banodoco Workspace Runtime

Independent neutral runtime and protocol repository for the Astrid Stage 1 beta and later REIGH integration.

The repository contains the first independently runnable neutral-runtime slice. It is dependency-free Python and can be exercised without any product checkout or hosted service. The daemon owns one realm's canonical SQLite database, append-only SHA-256 CAS, task/event ledger, credentials, and loopback HTTP boundary. Realm creation is explicit; startup and doctor never migrate or repair an existing root.

## Custody

- Initial branch: `main`
- No remote is configured by the seed operation.
- The Stage 1 oracle worktree is `../banodoco-workspace-runtime-oracle` on `megado/astrid-stage1-beta`.
- The exact Astrid source baseline and frozen roadmap inputs are recorded in the external Phase 0 custody receipt and in the oracle worktree.

## Development boundary

The runtime owns durable structured state, task/lease semantics, capability registration, append-only CAS accounting, verified backup/restore/replacement, and the language-neutral protocol. Product repositories consume generated clients and never open its database or storage directly.

## Run it

```bash
python3 -m runtime_protocol doctor --root .runtime --json
python3 -m runtime_protocol create --root .runtime
python3 -m runtime_protocol start --root .runtime
```

Backups are verified before publication into a new inactive sibling. An operator
can restore and activate one through the Runtime boundary:

```bash
python3 -m runtime_protocol backup --root .runtime --destination ./realm-backup
python3 -m runtime_protocol replace --root .runtime --backup ./realm-backup
```

Replacement retains the superseded root for recovery evidence, rotates the
owner credentials, advances the Runtime epoch, and publishes readiness only
after the new owner has passed admission. Old realms and backups are not
migrated or salvaged by Runtime.

`start` prints the loopback endpoint and owner credential path, then keeps the
daemon alive until SIGINT/SIGTERM. The test suite demonstrates the workspace.v1
HTTP boundary, project CRUD, managed object ingest and authenticated byte
reads (`ETag`/`Range`), deterministic worker claim/settlement, restart
reconnect, hash verification, path safety, and sole-owner refusal.

The HTTP binding in this slice is the canonical Stage 1 runtime transport
boundary used by the daemon and product integrations. OpenAPI and generated
product bindings consume this same protocol contract in the
protocol/conformance lane. No runtime module imports a product checkout.
