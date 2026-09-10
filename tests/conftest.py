from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def stage1_runtime_environment(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One offline venv containing both installed runtime packages.

    The test runner may be a development Python without setuptools (notably
    the system 3.14 build on this host).  Build local wheels with whichever
    available interpreter has the build backend, then install those wheels
    into the clean target venv without consulting a package index.
    """
    root = Path(__file__).resolve().parents[1]
    environment = tmp_path_factory.mktemp("stage1-runtime") / "venv"
    wheelhouse = environment.parent / "wheelhouse"
    generated = (
        root / "build",
        root / "banodoco_workspace_runtime.egg-info",
        root / "banodoco_workspace_client.egg-info",
        root / "packages" / "python" / "build",
        root / "packages" / "python" / "banodoco_workspace_client.egg-info",
    )
    existed = {path: path.exists() for path in generated}
    try:
        builders = [sys.executable, "python3.11", "python3.12", "python3.13", "python3", "python"]
        builder = None
        for candidate in builders:
            try:
                probe = subprocess.run(
                    [candidate, "-c", "import setuptools.build_meta"],
                    capture_output=True,
                    check=False,
                )
            except OSError:
                continue
            if probe.returncode == 0:
                builder = candidate
                break
        if builder is None:
            raise RuntimeError("Stage 1 tests require an available Python with setuptools.build_meta")
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
        wheelhouse.mkdir()
        subprocess.run(
            [builder, "-m", "pip", "wheel", "--no-index", "--no-build-isolation", "--no-deps", "--wheel-dir", str(wheelhouse), str(root), str(root / "packages" / "python")],
            cwd=str(root),
            check=True,
        )
        pip = environment / "bin" / "pip"
        wheels = sorted(wheelhouse.glob("*.whl"))
        if len(wheels) != 2:
            raise RuntimeError(f"expected two local Stage 1 wheels, found {len(wheels)}")
        # The prepared interpreter may carry an editable checkout of this
        # project.  Force-install the exact wheels into the fresh child venv so
        # pip cannot mistake that outer editable metadata for an installed
        # package and silently omit one of the two runtime components.
        subprocess.run(
            [str(pip), "install", "--no-index", "--no-deps", "--force-reinstall", *(str(wheel) for wheel in wheels)],
            check=True,
        )
        yield environment
    finally:
        for path, was_present in existed.items():
            if not was_present and path.is_dir():
                shutil.rmtree(path)
