"""The intentionally thin ``banodoco-local`` command surface."""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    SourceProfile,
    _read_catalog,
    _read_support_json,
    _validate_loopback_endpoint,
    _validate_support_paths,
    bootstrap,
    connect,
    doctor,
    restart,
)
from .io import read_json
from .paths import RuntimePaths
from .runtime_boundary import LocalRuntimeBoundary


class UnconfiguredBoundary:
    """Prevent accidental authority creation when no generated client is wired."""

    def start(self, **kwargs):
        raise BootstrapError("No runtime client is configured. Set BANODOCO_LOCAL_SOURCE_MANIFEST and provide the runtime client.")

    def connect(self, **kwargs):
        raise BootstrapError("No runtime client is configured.")

    def health(self, **kwargs):
        return False

    def validate_owner(self, **kwargs):
        return False

    def is_pid_alive(self, pid):
        return False


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="banodoco-local", description="Neutral Banodoco local workspace bootstrap")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command")
    up = sub.add_parser("up", help="start or reconnect the selected runtime")
    _profile_args(up)
    connect_cmd = sub.add_parser("connect", help="connect to the selected live runtime without starting one")
    _profile_args(connect_cmd)
    status = sub.add_parser("status", help="read runtime discovery and health")
    _read_args(status)
    restart_cmd = sub.add_parser("restart", help="restart the selected runtime owner")
    _profile_args(restart_cmd)
    doc = sub.add_parser("doctor", help="read-only support-state diagnostics")
    _read_args(doc)

    backup = sub.add_parser("backup", help="create a verified backup through the runtime")
    _read_args(backup)
    backup.add_argument("--destination", required=True, type=Path)
    restore = sub.add_parser("restore", help="restore a verified backup into an inactive destination")
    _read_args(restore)
    restore.add_argument("backup", type=Path)
    restore.add_argument("--destination", required=True, type=Path)

    checkpoint = sub.add_parser("checkpoint", help="persist a nonce-bound recovery checkpoint")
    _read_args(checkpoint)
    _attempt_args(checkpoint)
    checkpoint.add_argument("--nonce", required=True)
    checkpoint.add_argument("--authorization", required=True)
    checkpoint.add_argument("--state", default="{}", help="checkpoint JSON object or @path")
    prepare = sub.add_parser("prepare-reboot", help="issue or reuse a nonce for checkpoint recovery")
    _read_args(prepare)
    _attempt_args(prepare)
    reboot = sub.add_parser("reboot", help="execute a prepared recovery reboot (disabled by default)")
    _read_args(reboot)
    reboot.add_argument("--checkpoint-id", required=True)
    reboot.add_argument("--nonce", required=True)
    reboot.add_argument("--authorization", required=True)
    reboot.add_argument("--runtime-epoch", required=True, type=int)
    reboot.add_argument("--command", dest="reboot_command", choices=["reboot", "resume"], default="reboot")
    resume = sub.add_parser("resume", help="resume a nonce-bound recovery checkpoint")
    _read_args(resume)
    resume.add_argument("--checkpoint-id", required=True)
    resume.add_argument("--nonce", required=True)
    resume.add_argument("--authorization", required=True)
    resume.add_argument("--runtime-epoch", required=True, type=int)
    recovery = sub.add_parser("recovery", help="recover the selected realm or inspect recovery state")
    _read_args(recovery)
    recovery.add_argument("--expected-realm-id", dest="expected_realm_id")
    recovery.add_argument("--expected-version", type=int)
    recovery.add_argument("--confirm", dest="confirmation")
    recovery.add_argument("--non-interactive", action="store_true")
    return root


def _profile_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--profile", default="astrid", choices=["astrid"])
    command.add_argument("--display-name", default="Astrid Workspace")
    command.add_argument("--source-manifest", type=Path)
    command.add_argument("--json", action="store_true")


def _read_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--json", action="store_true")
    command.add_argument("--home", type=Path, help="override the current-Mac support home (mainly for disposable roots)")


def _attempt_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--attempt-id", required=True)
    command.add_argument("--lease-id", required=True)
    command.add_argument("--fence", required=True, type=int)
    command.add_argument("--runtime-epoch", required=True, type=int)


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _emit(value: Any, *, json_mode: bool) -> None:
    rendered = _json_value(value)
    if json_mode:
        print(json.dumps(rendered, indent=2, sort_keys=True))
        return
    if isinstance(rendered, Mapping):
        for key in sorted(rendered):
            item = rendered[key]
            if isinstance(item, (dict, list)):
                item = json.dumps(item, sort_keys=True)
            print(f"{key}: {item}")
    else:
        print(rendered)


def _paths(args: argparse.Namespace) -> RuntimePaths:
    home = args.home if getattr(args, "home", None) else os.environ.get("BANODOCO_LOCAL_HOME")
    return RuntimePaths.current_mac(home)


def _config(args: argparse.Namespace, paths: RuntimePaths) -> BootstrapConfig:
    manifest = getattr(args, "source_manifest", None)
    if manifest is None:
        configured = os.environ.get("BANODOCO_LOCAL_SOURCE_MANIFEST")
        manifest = Path(configured) if configured else None
    return BootstrapConfig(profile=getattr(args, "profile", "astrid"), display_name=getattr(args, "display_name", "Astrid Workspace"), source_manifest=manifest)


def _credential(paths: RuntimePaths) -> str:
    # Product traffic uses the Astrid-scoped credential in app support.  An
    # operator command needs the daemon-issued owner credential, which is
    # scoped to admin/worker lifecycle operations and remains inside the
    # runtime support directory.  Never promote the product token's scope in
    # the launcher.
    owner = paths.runtime_support / "credentials" / "owner.token"
    try:
        token = owner.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if not token:
        raise BootstrapError("No runtime owner credential is available; run banodoco-local up --profile astrid.")
    return token


def _client(paths: RuntimePaths):
    _validate_support_paths(paths)
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("endpoint"):
        raise BootstrapError("No runtime discovery is available; run banodoco-local up --profile astrid.")
    try:
        from banodoco_workspace_client import WorkspaceClient
    except ImportError as exc:
        raise BootstrapError("The installed generated workspace client is unavailable; install banodoco-workspace-client.") from exc
    return WorkspaceClient(_validate_loopback_endpoint(str(discovery["endpoint"])), _credential(paths))


def _typed_health(paths: RuntimePaths) -> Mapping[str, Any]:
    value = _client(paths).health()
    return _json_value(value)


def _load_state(raw: str) -> Mapping[str, Any]:
    if raw.startswith("@"):
        raw = Path(raw[1:]).read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, Mapping):
        raise ValueError("--state must contain a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    paths = _paths(args)
    if args.command == "doctor":
        # Doctor is read-only but must still use the concrete process boundary
        # to distinguish a live, matching owner from a stale/reused PID.
        result = doctor(paths, LocalRuntimeBoundary())
        _emit(result, json_mode=args.json)
        return 0 if result["healthy"] else 1
    if args.command == "up":
        config = _config(args, paths)
        try:
            result = bootstrap(paths, LocalRuntimeBoundary(), config)
        except Exception as exc:
            # Operator-facing startup must be a stable boundary: client,
            # import, protocol, filesystem, and OS failures are represented as
            # one structured error with no traceback.  KeyboardInterrupt is a
            # BaseException and intentionally remains interruptible.
            _emit({"ok": False, "error": str(exc)}, json_mode=True)
            return 1
        _emit(result, json_mode=args.json)
        return 0
    try:
        if args.command == "connect":
            config = _config(args, paths)
            boundary = LocalRuntimeBoundary()
            boundary.configure_source(config.resolve_source_profile(paths))
            result = connect(paths, boundary, config)
            _emit(result, json_mode=args.json)
            return 0
        if args.command == "restart":
            config = _config(args, paths)
            boundary = LocalRuntimeBoundary()
            source = config.resolve_source_profile(paths)
            catalog = _read_catalog(paths)
            realm_id = str(catalog.get("selected_realm_id") or "")
            realm = next((item for item in catalog.get("realms", []) if str(item.get("realm_id")) == realm_id), None)
            discovery = _read_support_json(paths.discovery_path) or {}
            if not realm or not discovery.get("pid"):
                raise BootstrapError("No selected runtime owner to restart; run banodoco-local up --profile astrid.")
            boundary.prepare_restart(source_profile=source, realm_id=realm_id, realm_root=Path(str(realm["data_root"])), support_root=paths.runtime_support, pid=int(discovery["pid"]))
            result = restart(paths, boundary, config)
            _emit(result, json_mode=args.json)
            return 0
        if args.command == "status":
            _validate_support_paths(paths)
            discovery = _read_support_json(paths.discovery_path)
            result = {"discovery": discovery, "support": doctor(paths, LocalRuntimeBoundary())}
            if discovery is not None and not result["support"].get("pid_alive", False):
                result["stale_discovery"] = True
            if discovery and discovery.get("endpoint"):
                try:
                    result["health"] = _typed_health(paths)
                except Exception as exc:
                    result["health_error"] = str(exc)
            _emit(result, json_mode=args.json)
            return 0 if result["support"].get("healthy") and not result.get("stale_discovery") else 1
        if args.command == "backup":
            _emit(_client(paths).create_backup(str(args.destination.expanduser().resolve())), json_mode=args.json)
            return 0
        if args.command == "restore":
            _emit(_client(paths).restore_backup(str(args.backup.expanduser().resolve()), str(args.destination.expanduser().resolve())), json_mode=args.json)
            return 0
        if args.command == "checkpoint":
            client = _client(paths)
            value = client.checkpoint_attempt(args.attempt_id, lease_id=args.lease_id, fence=args.fence, nonce=args.nonce, authorization=args.authorization, state=_load_state(args.state), runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "prepare-reboot":
            value = _client(paths).prepare_reboot(args.attempt_id, lease_id=args.lease_id, fence=args.fence, runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "reboot":
            if args.reboot_command == "reboot" and os.environ.get("BANODOCO_LOCAL_ENABLE_REAL_REBOOT") != "1":
                raise BootstrapError("real reboot is safe-disabled; set BANODOCO_LOCAL_ENABLE_REAL_REBOOT=1 in an explicitly configured test/host environment")
            value = _client(paths).request_reboot(checkpoint_id=args.checkpoint_id, nonce=args.nonce, authorization=args.authorization, runtime_epoch=args.runtime_epoch, command=args.reboot_command)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "resume":
            value = _client(paths).resume_attempt(checkpoint_id=args.checkpoint_id, nonce=args.nonce, authorization=args.authorization, runtime_epoch=args.runtime_epoch)
            _emit(value, json_mode=args.json)
            return 0
        if args.command == "recovery":
            if not args.expected_realm_id or args.expected_version is None:
                raise ValueError("recovery requires --expected-realm-id and --expected-version")
            if bool(args.confirmation) == bool(args.non_interactive):
                raise ValueError("recovery requires exactly one of --confirm 'RECOVER <realm_id>' or --non-interactive")
            value = _client(paths).recover_realm(expected_realm_id=args.expected_realm_id, expected_version=args.expected_version, confirmation=args.confirmation, noninteractive=args.non_interactive)
            _emit(value, json_mode=args.json)
            return 0
    except (BootstrapError, ValueError, OSError) as exc:
        _emit({"ok": False, "error": str(exc)}, json_mode=True)
        return 1
    except Exception as exc:
        # Generated clients expose typed ApiError; keep that import lazy so
        # ``banodoco-local doctor`` remains usable without client installation.
        _emit({"ok": False, "error": str(exc)}, json_mode=True)
        return 1
    parser().print_help()
    return 0
