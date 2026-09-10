from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import time
from pathlib import Path

from .daemon import RuntimeDaemon, WORKER_SCOPES
from .backup import create_backup, restore_backup, structured_export
from .errors import RuntimeErrorBase
from .store import RealmStore


def _parser():
    parser = argparse.ArgumentParser(prog="banodoco-runtime", description="Neutral loopback workspace runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start the loopback daemon")
    start.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    start.add_argument("--support-root")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=0)
    start.add_argument("--display-name", default="Workspace")
    start.add_argument("--realm-id")
    start.add_argument("--owner-lock")
    start.add_argument("--bootstrap-token-file")
    doctor = sub.add_parser("doctor", help="read-only runtime health check")
    doctor.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--support-root")
    backup = sub.add_parser("backup", help="create a verified self-contained realm backup")
    backup.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    backup.add_argument("--destination", required=True)
    restore = sub.add_parser("restore", help="restore a backup into a new inactive realm")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--destination", required=True)
    export = sub.add_parser("export", help="export structured realm state")
    export.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    export.add_argument("--destination")
    export.add_argument("--json", action="store_true")
    purge = sub.add_parser("purge", help="irreversibly remove a tombstoned realm (offline only)")
    purge.add_argument("--root", required=True)
    purge.add_argument("--confirm", required=True)
    identity = sub.add_parser("identity", help="capture or verify local release identities")
    identity.add_argument("operation", choices=("pre-live", "candidate-core", "verify"))
    identity.add_argument("--component", action="append", default=[])
    identity.add_argument("--pre-live")
    identity.add_argument("--receipt")
    identity.add_argument("--output")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "identity":
        from . import release_identity
        try:
            if args.operation == "verify":
                if not args.receipt:
                    raise release_identity.ReleaseIdentityError("identity verify requires --receipt")
                result = {"ok": True, "identity": release_identity.load_receipt(args.receipt)["identity"]}
            else:
                components = {}
                for value in args.component:
                    if "=" not in value:
                        raise release_identity.ReleaseIdentityError("--component must use COMPONENT_ID=CHECKOUT")
                    component, checkout = value.split("=", 1)
                    components[component] = checkout
                if args.operation == "pre-live":
                    result = release_identity.create_pre_live_identity(components, output=args.output)
                else:
                    if not args.pre_live:
                        raise release_identity.ReleaseIdentityError("candidate-core requires --pre-live")
                    result = release_identity.create_candidate_core_identity(args.pre_live, components, output=args.output)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0
        except release_identity.ReleaseIdentityError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
            return 1
    if args.command == "doctor":
        root = Path(args.root)
        result = RealmStore.inspect_realm(
            root,
            catalog_path=(Path(args.support_root) / "catalog.json") if args.support_root else None,
        )
        if result.get("state") == "uninitialized":
            result["next_action"] = "banodoco-runtime start"
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("ok") else 1
    if args.command == "backup":
        # Online backup goes through the owning HTTP service. The CLI is an
        # offline surface and must acquire that same realm-owner fence.
        store = RealmStore(args.root)
        try:
            result = create_backup(store, args.destination)
        finally:
            store.close()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "restore":
        result = restore_backup(args.backup, args.destination)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "export":
        # Export is an offline surface; share the same owner fence as startup
        # instead of opening a second migration-capable connection.
        store = RealmStore(args.root)
        try:
            value = structured_export(store)
        finally:
            store.close()
        if args.destination:
            from .util import atomic_json_write
            atomic_json_write(Path(args.destination).expanduser().resolve(), value)
        print(json.dumps(value, sort_keys=True))
        return 0
    if args.command == "purge":
        root = Path(args.root).expanduser().resolve()
        # Refuse even a correctly confirmed purge while a daemon owns the
        # realm.  The destructive operation remains explicit and offline.
        store = RealmStore(root)
        try:
            realm_id = store.realm["id"]
            if args.confirm != f"PURGE {realm_id}":
                raise SystemExit(f"confirmation must be exactly: PURGE {realm_id}")
            if store.realm_lifecycle()["state"] != "tombstoned":
                raise SystemExit("realm must be tombstoned before purge")
        finally:
            store.close()
        shutil.rmtree(root)
        print(json.dumps({"state": "purged", "realm_id": realm_id, "root": str(root)}, sort_keys=True))
        return 0
    try:
        daemon = RuntimeDaemon(args.root, support_root=args.support_root, display_name=args.display_name, host=args.host, port=args.port, realm_id=args.realm_id, owner_lock=args.owner_lock, bootstrap_token_file=args.bootstrap_token_file, production_worker_credentials=True).start()
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        # Installed operator entrypoints must fail as a stable JSON boundary;
        # never leak a traceback for a missing migration or bad root.
        error = exc.as_dict() if isinstance(exc, RuntimeErrorBase) else {"code": "startup_error", "message": str(exc)}
        print(json.dumps({"ok": False, "error": error}, sort_keys=True))
        return 1
    print(json.dumps({"endpoint": daemon.endpoint, "realm_id": daemon.service.realm["id"], "credential_file": str(daemon.credential_path), "worker_credential_file": str(daemon.worker_credential_path), "worker_actor": "astrid-pack-host", "worker_scopes": list(WORKER_SCOPES)}, sort_keys=True), flush=True)
    stop = False
    def handle(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    try:
        while not stop:
            time.sleep(0.2)
    finally:
        daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
