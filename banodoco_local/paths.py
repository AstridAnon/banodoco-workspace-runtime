"""Support paths for the current-Mac beta composition.

The production default is intentionally boring and explicit.  Tests and local
development can inject ``home`` (or individual roots) without changing any
runtime behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class RuntimePaths:
    home: Path
    app_support: Path
    runtime_support: Path
    catalog_path: Path
    discovery_path: Path
    credentials_dir: Path
    realms_dir: Path
    source_profiles_dir: Path
    instance_lock_path: Path
    bootstrap_lock_path: Path

    @classmethod
    def current_mac(cls, home: Path | str | None = None) -> "RuntimePaths":
        home_path = Path(home or os.environ.get("HOME", "~")).expanduser()
        app_support = home_path / "Library" / "Application Support" / "Banodoco"
        runtime = app_support / "runtime"
        return cls(
            home=home_path,
            app_support=app_support,
            runtime_support=runtime,
            catalog_path=runtime / "catalog.json",
            discovery_path=runtime / "discovery.json",
            credentials_dir=app_support / "credentials",
            realms_dir=runtime / "realms",
            source_profiles_dir=runtime / "source-profiles",
            instance_lock_path=runtime / "instance.lock",
            bootstrap_lock_path=runtime / "bootstrap.lock",
        )

    @classmethod
    def sandbox(cls, root: Path | str) -> "RuntimePaths":
        """An injectable current-Mac-shaped filesystem rooted at ``root``."""

        return cls.current_mac(Path(root))

    def ensure_support_dirs(self) -> None:
        for directory in (
            self.app_support,
            self.runtime_support,
            self.credentials_dir,
            self.realms_dir,
            self.source_profiles_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
