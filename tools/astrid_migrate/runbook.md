# Astrid B12 operator runbook

This runbook is explicit: choose one source and one selected neutral realm.
These commands never guess a source, stop a process by name, combine project
trees, or delete source data.

## Unified-execution relationship

The B12 migration/realm runbook is distinct from task admission. Runtime and
the selected neutral realm remain the authority for Astrid tasks, runs,
receipts, and settlement; Reigh/Supabase legacy task lifecycle paths are not
accepted as a migration shortcut or execution authority. Validate the
unified-execution CPU boundary and its receipts before considering any GPU or
historical-corpus operation.

## Preflight and dry run

For routine Stage 1 proof, use the tiny live acceptance fixture. It creates a
small SQLite-backed Astrid source, one managed media blob, a disposable neutral
realm, fresh B12 authorizations, the writer-stop receipt, and the complete
production compact journey under one fresh output root. It also cold-opens the
reactivated realm before returning. The fixture is only kilobytes, so it does
not require capacity for the historical corpus:

```bash
astrid-live-migrate tiny-acceptance \
  --output-root /absolute/stage1-tiny-b12 \
  --source-checkout /absolute/Astrid-stage1-convergence2 \
  --runtime-environment /absolute/venvs/banodoco-runtime
```

This command is the routine default and always uses compact redundancy. A
historical/full-corpus migration is a separate, explicit operator action; use
the `live-migrate` command below only with an explicitly selected real source.
`--redundancy extreme` is likewise opt-in and is not part of routine acceptance.

The tiny fixture provisions the current-Mac-shaped runtime support, selected
realm, activation trust, canonical Astrid source profile, and installed runtime
environment needed by its reboot plist. Its migration activation registry is
reported separately as `migration_support_root`; pass that path as the
terminal-support binding when arming the same evidence.

Use a fresh archive/destination parent on a volume with enough capacity for
source, archive, active backup, destination, signed destination backup,
rollback copy, activation temporary, CAS, evidence, and the safety margin.
Compact redundancy is the default; use `--redundancy extreme` only when the
historical full-copy allocation is explicitly required. Run the offline dry
run first:

```bash
PYTHONPATH=/path/to/runtime python -m tools.astrid_migrate \
  --source-root /absolute/source \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination --dry-run
```

The source must explicitly contain `.astrid/astrid.sqlite3` or a root-level
`astrid.sqlite3`; nested databases are not inferred.

## Bind authorizations

```bash
astrid-live-migrate issue-authorizations \
  --source-root /absolute/source \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination \
  --realm-id REALM_ID --output /absolute/operator/b12-authorizations.json
```

The output is owner-only and contains exactly the six B12 authorization IDs:

```text
AUTH-LIVE-INPUT-B12
AUTH-WRITER-STOP-B12
AUTH-LIVE-MIGRATION-B12
AUTH-ACTIVATION-B12
AUTH-ROLLBACK-B12
AUTH-REACTIVATION-B12
```

## Stop writers

Stop the actual Astrid/editor/bridge writers with the host supervisor. Do not
delete a stale-looking lock. After confirming no writer remains, write a
receipt containing the exact source root:

```json
{"format_version":1,"source_root":"/absolute/source","stopped":true,"writer_count":0,"method":"named-supervisor-or-manual-audit"}
```

The live command re-reads this receipt and probes all known source locks. A
missing/changed receipt, held lock, or nonzero writer count fails closed.

## Run B12

The neutral support catalog must already select `REALM_ID`, point to the
explicit active root, and contain owner-only `activation-trust.json`.

```bash
astrid-live-migrate live-migrate --confirm 'MIGRATE LIVE ASTRID' \
  --source-root /absolute/source \
  --active-root /absolute/Banodoco/runtime/realms/REALM_ID \
  --support-root /absolute/Banodoco/runtime \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination \
  --evidence-root /absolute/migration/migration-evidence-b12 \
  --realm-id REALM_ID \
  --authorization-file /absolute/operator/b12-authorizations.json \
  --writer-stop-receipt /absolute/operator/writer-stop.json \
  --redundancy compact
```

This invokes serialized B12: verified backups, import, reconciliation,
activation, rollback, reactivation, and JSON evidence. Derived siblings are
`<archive>-live-pre-migration-backup`, `-live-destination-backup`, and
`-live-rollback` in compact mode. Compact activates and reactivates directly
from the verified signed destination backup through an activation temporary;
it does not create `-live-candidate` or `-live-reactivated`. The explicit
`--redundancy extreme` mode additionally creates those two historical restore
trees. The terminal receipt is `activated-destination-b12.json` with journal
state `reactivated`.

## Actual reboot continuity (Stage 1 only)

Run this only after B12 is terminal and the runtime is not performing a
migration. The arm command is read-only with respect to the realm and writes
the owner-only R1 marker and evidence copy below the existing evidence root,
plus a checkpoint-specific owner-only plist at
`~/Library/LaunchAgents/com.banodoco.stage1.b12.reboot.CHECKPOINT_ID.plist`.
It never invokes `reboot` or `launchctl`:

```bash
astrid-live-migrate stage1-reboot-arm \
  --evidence-root /absolute/migration/migration-evidence-b12 \
  --active-root /absolute/Banodoco/runtime/realms/REALM_ID \
  --support-root /absolute/Banodoco/runtime \
  --terminal-support-root /absolute/stage1-tiny-b12/migration-support \
  --realm-id REALM_ID \
  --neutral-home "$HOME" \
  --source-manifest "/absolute/Banodoco/runtime/source-profiles/astrid.json"
```

Review the JSON output and R1 at
`/absolute/migration/migration-evidence-b12/stage1-b12-reboot.json`. It must
show the terminal B12.4 receipt, `journal_state=reactivated`, the pre-reboot OS
boot identity, and the bound LaunchAgent path/hash. Explicitly load the
generated LaunchAgent from that bound `~/Library/LaunchAgents` path; this
changes the user's launchd state and is the first machine-level action:

```bash
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/com.banodoco.stage1.b12.reboot.CHECKPOINT_ID.plist"
```

Confirm that the job is loaded, then perform the one actual machine reboot:

```bash
launchctl print "gui/$(id -u)/com.banodoco.stage1.b12.reboot.CHECKPOINT_ID"
sudo /sbin/reboot
```

The one-shot job first invokes the bound neutral `banodoco-local up` bootstrap,
then calls the R2 capture. It refuses to proceed unless the OS boot identity
and runtime epoch both changed, and writes `stage1-b12-reboot-r2.json`. If
launchd ran before the runtime came up, rerun the same bounded postboot command
manually:

Keep this checkout and its verified interpreter in place until R2 is captured;
the generated plist binds this checkout in `WorkingDirectory`.

```bash
astrid-live-migrate stage1-reboot-postboot \
  --evidence-root /absolute/migration/migration-evidence-b12 \
  --active-root /absolute/Banodoco/runtime/realms/REALM_ID \
  --support-root /absolute/Banodoco/runtime \
  --terminal-support-root /absolute/stage1-tiny-b12/migration-support \
  --realm-id REALM_ID \
  --neutral-home "$HOME" \
  --source-manifest "/absolute/Banodoco/runtime/source-profiles/astrid.json"
```

R2 is complete only when `stage1-b12-reboot-r2.json` exists with
`state=completed`, changed `boot_identity_after`, increased
`runtime_epoch_after`, and zero SQLite integrity errors. Repeating the postboot
command returns the same receipt and does not rerun migration or reboot. The R2
receipt records `launch_agent_cleanup.status=plist_removed_external_bootout_verification_required`.
The postboot job removes its installed plist before final R2 and deliberately
leaves bootout verification external because a job may terminate itself while
requesting bootout. After retaining the evidence, verify/boot out the exact
bound label and confirm the path is absent:

```bash
launchctl bootout "gui/$(id -u)/com.banodoco.stage1.b12.reboot.CHECKPOINT_ID" || {
  status=$?
  test "$status" -eq 3  # already unloaded is an idempotent replay
}
test ! -e "$HOME/Library/LaunchAgents/com.banodoco.stage1.b12.reboot.CHECKPOINT_ID.plist"
```

## Nested intro source

Only use this with the exact identified nested database. It clones and rewrites
known media locators in the clone; it never edits source data:

```bash
astrid-live-migrate normalize-nested-source \
  --source-root /absolute/Astrid/projects/astrid-intro \
  --database /absolute/Astrid/projects/astrid-intro/.astrid/source-projects-root-kernel/astrid.sqlite3 \
  --destination-root /absolute/migration/astrid-intro-normalized
```

Review `normalization-manifest.json`, then dry-run against the normalized root.
