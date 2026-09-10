from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from banodoco_local.bootstrap import (
    BootstrapConfig,
    CompatibilityError,
    DuplicateOwnerError,
    LegacyRootCollisionError,
    SourceProfile,
    bootstrap,
    connect,
    doctor,
    restart,
)
from banodoco_local.paths import RuntimePaths


PROFILE = SourceProfile(
    profile="astrid",
    runtime_checkout="/checkouts/runtime",
    source_checkout="/checkouts/astrid",
    capability_digest="caps-v1",
)


class FakeConnection:
    def __init__(self, boundary):
        self.boundary = boundary

    def handshake(self, **kwargs):
        self.boundary.handshakes.append(kwargs)

    def provision_actor(self, **kwargs):
        self.boundary.provisions.append(kwargs)
        return {"scope": kwargs["scope"], "actor_id": kwargs["actor_id"]}

    def select_realm(self, **kwargs):
        self.boundary.selections.append(kwargs)


class FakeBoundary:
    def __init__(self):
        self.starts = []
        self.connects = []
        self.provisions = []
        self.selections = []
        self.handshakes = []
        self.alive = set()
        self.valid_owner = True
        self.next_pid = 41001
        self.restart_calls = 0

    def start(self, **kwargs):
        self.starts.append(kwargs)
        realm_root = kwargs["realm_root"]
        realm_root.mkdir(parents=True, exist_ok=True)
        (realm_root / "workspace.sqlite3").touch()
        pid = self.next_pid
        self.next_pid += 1
        self.alive.add(pid)
        return {
            "endpoint": "http://127.0.0.1:43100",
            "pid": pid,
            "runtime_instance_id": f"instance-{pid}",
            "coordinator_epoch": 1,
            "protocol_version": "workspace.v1",
            "schema_version": "workspace-schema-v1",
            "capability_digest": "caps-v1",
        }

    def connect(self, **kwargs):
        self.connects.append(kwargs)
        return FakeConnection(self)

    def health(self, **kwargs):
        return kwargs["pid"] in self.alive

    def validate_owner(self, **kwargs):
        return self.valid_owner

    def is_pid_alive(self, pid):
        return pid in self.alive

    def restart(self, **kwargs):
        self.restart_calls += 1
        self.alive.discard(kwargs["pid"])
        return self.start(realm_id="ignored", realm_root=Path(tempfile.mkdtemp()) / "realm", owner_lock=Path("/tmp/lock"), source_profile=PROFILE)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = RuntimePaths.sandbox(self.temp.name)
        self.boundary = FakeBoundary()
        self.config = BootstrapConfig(source_profile=PROFILE)

    def tearDown(self):
        self.temp.cleanup()

    def test_first_launch_writes_catalog_discovery_without_synthesizing_activation(self):
        result = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "started")
        self.assertEqual(result.credential_file, self.paths.credentials_dir / "astrid.json")
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(result.realm_id, json.loads(self.paths.discovery_path.read_text())["active_realm"])
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["selected_realm_id"], result.realm_id)
        self.assertEqual(len(catalog["realms"]), 1)
        discovery = json.loads(self.paths.discovery_path.read_text())
        self.assertNotIn("token", json.dumps(discovery))
        credential = json.loads((self.paths.credentials_dir / "astrid.json").read_text())
        self.assertEqual(credential["scope"], "astrid")
        self.assertEqual(len(credential["token"]), 64)
        mode = stat.S_IMODE((self.paths.credentials_dir / "astrid.json").stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertNotIn("activation_manifest", catalog["realms"][0])
        self.assertEqual(tuple(self.paths.activations_dir.glob("*.json")), ())
        source_manifest = self.paths.source_profiles_dir / "astrid.json"
        self.assertEqual(json.loads(source_manifest.read_text()), PROFILE.as_dict())
        self.assertEqual(stat.S_IMODE(source_manifest.stat().st_mode), 0o600)

    def test_second_launch_reconnects_same_owner_and_actor(self):
        first = bootstrap(self.paths, self.boundary, self.config)
        discovery_before = self.paths.discovery_path.read_bytes()
        updated = SourceProfile(
            profile="astrid",
            runtime_checkout="/checkouts/runtime-pinned",
            source_checkout="/checkouts/astrid-pinned",
            capability_digest="caps-v1",
        )
        second = bootstrap(self.paths, self.boundary, BootstrapConfig(source_profile=updated))
        self.assertEqual(second.status, "reconnected")
        self.assertEqual(first.realm_id, second.realm_id)
        self.assertEqual(first.actor_id, second.actor_id)
        self.assertEqual(len(self.boundary.starts), 1)
        self.assertEqual(len(self.boundary.connects), 2)
        self.assertEqual(self.paths.discovery_path.read_bytes(), discovery_before)
        self.assertEqual(json.loads((self.paths.source_profiles_dir / "astrid.json").read_text()), updated.as_dict())
        catalog = json.loads(self.paths.catalog_path.read_text())
        self.assertEqual(catalog["source_profiles"]["astrid"], updated.as_dict())

    def test_stale_discovery_restarts_without_second_realm(self):
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        second = bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(second.realm_id, first.realm_id)
        self.assertEqual(len(self.boundary.starts), 2)
        self.assertEqual(json.loads(self.paths.catalog_path.read_text())["selected_realm_id"], first.realm_id)

    def test_restart_reuses_selected_realm(self):
        first = bootstrap(self.paths, self.boundary, self.config)
        self.boundary.alive.clear()
        result = restart(self.paths, self.boundary, self.config)
        self.assertEqual(result.status, "restarted")
        self.assertEqual(result.realm_id, first.realm_id)
        self.assertEqual(self.boundary.restart_calls, 1)

    def test_legacy_collision_refuses_parallel_empty_realm_with_exact_action(self):
        legacy = self.paths.home / ".astrid"
        legacy.mkdir(parents=True)
        with self.assertRaises(LegacyRootCollisionError) as caught:
            bootstrap(self.paths, self.boundary, self.config)
        self.assertIn("banodoco-local migrate --profile astrid --source", str(caught.exception))
        self.assertEqual(len(self.boundary.starts), 0)
        self.assertFalse(self.paths.catalog_path.exists())

    def test_incompatible_live_owner_fails_closed_without_mutation(self):
        self.paths.runtime_support.mkdir(parents=True)
        self.paths.discovery_path.write_text(json.dumps({
            "protocol_version": "old", "schema_version": "old", "active_realm": "realm", "pid": 99,
        }))
        self.boundary.alive.add(99)
        before = self.paths.discovery_path.read_bytes()
        with self.assertRaises(CompatibilityError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(self.paths.discovery_path.read_bytes(), before)
        self.assertEqual(len(self.boundary.starts), 0)

    def test_duplicate_owner_refuses_when_lock_validation_fails(self):
        bootstrap(self.paths, self.boundary, self.config)
        self.boundary.valid_owner = False
        with self.assertRaises(DuplicateOwnerError):
            bootstrap(self.paths, self.boundary, self.config)
        self.assertEqual(len(self.boundary.starts), 1)

    def test_connect_is_side_effect_free_when_stopped(self):
        with self.assertRaisesRegex(Exception, "banodoco-local up --profile astrid"):
            connect(self.paths, self.boundary, self.config)
        self.assertFalse(self.paths.runtime_support.exists())

    def test_doctor_is_side_effect_free(self):
        report = doctor(self.paths, self.boundary)
        self.assertFalse(report["healthy"])
        self.assertFalse(self.paths.runtime_support.exists())

    def test_source_manifest_is_validated_and_recorded(self):
        self.paths.source_profiles_dir.mkdir(parents=True)
        manifest = self.paths.source_profiles_dir / "astrid.json"
        manifest.write_text(json.dumps(PROFILE.as_dict()))
        profile = SourceProfile.load(manifest)
        self.assertEqual(profile.profile, "astrid")
        self.assertEqual(profile.digest, SourceProfile.from_mapping(PROFILE.as_dict()).digest)


if __name__ == "__main__":
    unittest.main()
