# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the Pyvider distribution owns the shared ``pyvider`` root files."""

from __future__ import annotations

import base64
import csv
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from typing import cast
import urllib.error
import urllib.request
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
ROOT_INITIALIZER = "pyvider/__init__.py"
ROOT_TYPING_MARKER = "pyvider/py.typed"
RPCPLUGIN_INITIALIZER = "pyvider/rpcplugin/__init__.py"
RPCPLUGIN_MODULE = "pyvider/rpcplugin/client/core.py"
RELEASE_VERSION = "0.5.5"
PUBLISHED_RPCPLUGIN_054_FILENAME = "pyvider_rpcplugin-0.5.4-py3-none-any.whl"
PUBLISHED_RPCPLUGIN_054_URL = (
    "https://files.pythonhosted.org/packages/07/f4/"
    "00954b3cda959afece3f470568454551043fa1204e6a15df187cd3f752f4/"
    f"{PUBLISHED_RPCPLUGIN_054_FILENAME}"
)
PUBLISHED_RPCPLUGIN_054_SHA256 = "764a248d26b35eecd2aa3d45f67af1dcfa07fdb14c512204eb8ce496f61c8feb"
PUBLISHED_RPCPLUGIN_054_SIZE = 107_670
PUBLISHED_RPCPLUGIN_054_CACHE_ENV = "PYVIDER_RPCPLUGIN_054_WHEEL"
TYPING_MARKERS = {
    "pyvider/rpcplugin/py.typed",
    "pyvider/rpcplugin/client/py.typed",
    "pyvider/rpcplugin/protocol/py.typed",
    "pyvider/rpcplugin/transport/py.typed",
}
PACKAGE_DATA = {
    "pyvider/rpcplugin/protocol/grpc_broker_pb2.pyi",
    "pyvider/rpcplugin/protocol/grpc_controller_pb2.pyi",
    "pyvider/rpcplugin/protocol/grpc_stdio_pb2.pyi",
}
CANONICAL_INITIALIZER = """#
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


from provide.foundation.utils.versioning import get_version

__path__ = __import__("pkgutil").extend_path(__path__, __name__)

__version__ = get_version("pyvider", caller_file=__file__)

__all__ = [
    "__version__",
]

# 🐍🏗️🔚
""".encode()


@dataclass(frozen=True)
class BuiltArtifacts:
    direct_wheel: Path
    sdist: Path
    sdist_wheel: Path


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def _published_rpcplugin_054(destination: Path) -> Path:
    wheel = destination / PUBLISHED_RPCPLUGIN_054_FILENAME
    cached = os.environ.get(PUBLISHED_RPCPLUGIN_054_CACHE_ENV)
    if cached:
        cache_path = Path(cached).expanduser().resolve()
        if not cache_path.is_file():
            raise AssertionError(f"{PUBLISHED_RPCPLUGIN_054_CACHE_ENV} is not a file: {cache_path}")
        payload = cache_path.read_bytes()
    else:
        try:
            # The URL is an immutable HTTPS files.pythonhosted.org constant.
            with urllib.request.urlopen(PUBLISHED_RPCPLUGIN_054_URL, timeout=60) as response:  # nosec B310
                payload = response.read(PUBLISHED_RPCPLUGIN_054_SIZE + 1)
        except urllib.error.URLError as exc:
            raise AssertionError(
                f"could not fetch pinned {PUBLISHED_RPCPLUGIN_054_FILENAME}; set "
                f"{PUBLISHED_RPCPLUGIN_054_CACHE_ENV} to a local copy: {exc}"
            ) from exc

    actual_size = len(payload)
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    assert actual_size == PUBLISHED_RPCPLUGIN_054_SIZE, (
        f"{wheel}: size {actual_size} != pinned size {PUBLISHED_RPCPLUGIN_054_SIZE}"
    )
    assert actual_sha256 == PUBLISHED_RPCPLUGIN_054_SHA256, (
        f"{wheel}: sha256 {actual_sha256} != pinned sha256 {PUBLISHED_RPCPLUGIN_054_SHA256}"
    )
    wheel.write_bytes(payload)
    return wheel


@pytest.fixture(scope="module")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> BuiltArtifacts:
    build_root = tmp_path_factory.mktemp("package-build")
    source = build_root / "source"
    shutil.copytree(REPOSITORY / "src", source / "src", ignore=shutil.ignore_patterns("*.egg-info"))
    for name in ("LICENSE", "README.md", "VERSION", "pyproject.toml"):
        shutil.copy2(REPOSITORY / name, source / name)

    direct_wheelhouse = build_root / "direct-wheel"
    _run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(direct_wheelhouse),
            "--no-create-gitignore",
        ],
        cwd=source,
    )
    direct_wheel = next(direct_wheelhouse.glob("pyvider_rpcplugin-*.whl"))

    sdist_house = build_root / "sdist"
    _run(
        ["uv", "build", "--sdist", "--out-dir", str(sdist_house), "--no-create-gitignore"],
        cwd=source,
    )
    sdist = next(sdist_house.glob("pyvider_rpcplugin-*.tar.gz"))

    sdist_wheelhouse = build_root / "sdist-wheel"
    _run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(sdist_wheelhouse),
            "--no-create-gitignore",
            str(sdist),
        ],
        cwd=build_root,
    )
    sdist_wheel = next(sdist_wheelhouse.glob("pyvider_rpcplugin-*.whl"))
    return BuiltArtifacts(direct_wheel=direct_wheel, sdist=sdist, sdist_wheel=sdist_wheel)


@pytest.fixture(scope="module")
def published_rpcplugin_054(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _published_rpcplugin_054(tmp_path_factory.mktemp("published-rpcplugin-054"))


def _candidate(built_artifacts: BuiltArtifacts, name: str) -> Path:
    if name == "direct_wheel":
        return built_artifacts.direct_wheel
    if name == "sdist_wheel":
        return built_artifacts.sdist_wheel
    raise AssertionError(f"unknown candidate artifact: {name}")


def _record_paths(record: Path) -> set[str]:
    with record.open(newline="") as rows:
        return {row[0] for row in csv.reader(rows)}


def _write_wheel(
    destination: Path,
    *,
    distribution: str,
    version: str,
    members: dict[str, bytes],
    requirements: tuple[str, ...] = (),
) -> Path:
    normalized = distribution.replace("-", "_")
    wheel = destination / f"{normalized}-{version}-py3-none-any.whl"
    dist_info = f"{normalized}-{version}.dist-info"
    requires_dist = "".join(f"Requires-Dist: {requirement}\n" for requirement in requirements)
    contents = {
        **members,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n{requires_dist}"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: pyvider-rpcplugin packaging test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
    }
    record_rows = []
    for name, content in contents.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        record_rows.append(f"{name},sha256={digest},{len(content)}\n")
    record_rows.append(f"{dist_info}/RECORD,,\n")
    contents[f"{dist_info}/RECORD"] = "".join(record_rows).encode()

    with ZipFile(wheel, "w", ZIP_DEFLATED) as archive:
        for name, content in contents.items():
            archive.writestr(name, content)
    return wheel


def _synthetic_owner(destination: Path) -> Path:
    return _write_wheel(
        destination,
        distribution="pyvider",
        version="0.8.0",
        members={
            ROOT_INITIALIZER: CANONICAL_INITIALIZER,
            ROOT_TYPING_MARKER: b"",
        },
        requirements=("provide-foundation>=0.4.0",),
    )


def _environment(destination: Path, *, seed: bool = False) -> tuple[Path, Path]:
    root = destination / "environment"
    command = ["uv", "venv", "--python", sys.executable, "--no-project"]
    if seed:
        command.append("--seed")
    command.append(str(root))
    _run(command)
    python = root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    purelib = Path(
        subprocess.check_output(
            [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True,
        ).strip()
    )
    return python, purelib


def _install(
    python: Path,
    package: Path,
    *,
    dependencies: bool = False,
    editable: bool = False,
    reinstall: bool = False,
) -> None:
    command = ["uv", "pip", "install", "--offline", "--python", str(python)]
    if not dependencies:
        command.append("--no-deps")
    if editable:
        command.append("--editable")
    if reinstall:
        command.append("--reinstall")
    command.append(str(package))
    _run(command)


def _uninstall(python: Path, *, installer: str) -> None:
    if installer == "uv":
        _run(["uv", "pip", "uninstall", "--python", str(python), "pyvider-rpcplugin"])
        return
    if installer == "pip":
        _run([str(python), "-m", "pip", "uninstall", "--yes", "pyvider-rpcplugin"])
        return
    raise AssertionError(f"unknown installer: {installer}")


def _assert_rpcplugin_uninstalled(python: Path, purelib: Path, cwd: Path) -> None:
    assert not list(purelib.glob("pyvider_rpcplugin-*.dist-info"))
    assert not (purelib / "pyvider" / "rpcplugin").exists()
    result = _run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import importlib.util; "
                "assert importlib.util.find_spec('pyvider.rpcplugin') is None"
            ),
        ],
        cwd=cwd,
    )
    assert result.stdout == ""


def _installed_versions(python: Path, cwd: Path) -> dict[str, str]:
    result = _run(
        [
            str(python),
            "-I",
            "-c",
            (
                "import json, pathlib, pyvider, pyvider.rpcplugin; "
                "print(json.dumps({'owner': pyvider.__version__, "
                "'root_file': str(pathlib.Path(pyvider.__file__).resolve()), "
                "'rpcplugin': pyvider.rpcplugin.__version__, "
                "'rpcplugin_file': str(pathlib.Path(pyvider.rpcplugin.__file__).resolve())}))"
            ),
        ],
        cwd=cwd,
    )
    return cast(dict[str, str], json.loads(result.stdout))


def test_source_tree_does_not_own_shared_root_files() -> None:
    assert not (REPOSITORY / "src" / ROOT_INITIALIZER).exists()
    assert not (REPOSITORY / "src" / ROOT_TYPING_MARKER).exists()
    attributes_path = REPOSITORY / ".gitattributes"
    attributes = attributes_path.read_text() if attributes_path.exists() else ""
    assert "src/pyvider/__init__.py" not in attributes


def test_release_notes_name_the_coordinated_compatibility_floor() -> None:
    release_notes = (REPOSITORY / "CHANGELOG.md").read_text().split("## [0.5.4]", maxsplit=1)[0]

    assert "## [0.5.5] - 2026-09-22" in release_notes
    assert "`pyvider-cty` 0.6.2" in release_notes
    assert "`Pyvider` 0.8.0" in release_notes
    assert "`pyvider-rpcplugin` 0.5.4" in release_notes
    assert "does not own" in release_notes
    assert "reinstall" in release_notes
    assert "byte-identical" not in release_notes


def test_built_artifacts_do_not_own_shared_root_files(built_artifacts: BuiltArtifacts) -> None:
    assert hashlib.sha256(CANONICAL_INITIALIZER).hexdigest() == (
        "364693ccf17415ffefb02e23608027e7d7a322e3ca51224e99f86f4cc5bc0306"
    )
    for wheel in (built_artifacts.direct_wheel, built_artifacts.sdist_wheel):
        with ZipFile(wheel) as archive:
            members = set(archive.namelist())
            record_name = next(name for name in members if name.endswith(".dist-info/RECORD"))
            record_paths = {row[0] for row in csv.reader(archive.read(record_name).decode().splitlines())}

        assert ROOT_INITIALIZER not in members
        assert ROOT_INITIALIZER not in record_paths
        assert ROOT_TYPING_MARKER not in members
        assert ROOT_TYPING_MARKER not in record_paths
        assert RPCPLUGIN_INITIALIZER in members
        assert RPCPLUGIN_MODULE in members
        assert members >= TYPING_MARKERS
        assert members >= PACKAGE_DATA

    with tarfile.open(built_artifacts.sdist) as archive:
        members = {member.name for member in archive.getmembers()}
        assert not any(name.endswith("/src/pyvider/__init__.py") for name in members)
        assert not any(name.endswith("/src/pyvider/py.typed") for name in members)
        assert any(name.endswith("/src/pyvider/rpcplugin/__init__.py") for name in members)


def test_wheels_report_the_release_version(built_artifacts: BuiltArtifacts) -> None:
    for wheel in (built_artifacts.direct_wheel, built_artifacts.sdist_wheel):
        with ZipFile(wheel) as archive:
            metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            metadata = archive.read(metadata_name).decode()

        assert wheel.name.startswith(f"pyvider_rpcplugin-{RELEASE_VERSION}-")
        assert f"Version: {RELEASE_VERSION}\n" in metadata


def test_source_tree_imports_rpcplugin_through_implicit_namespace(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, pathlib, pyvider, pyvider.rpcplugin; "
                "print(json.dumps({'root_file': pyvider.__file__, "
                "'file': str(pathlib.Path(pyvider.rpcplugin.__file__).resolve()), "
                "'version': pyvider.rpcplugin.__version__}))"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    imported = json.loads(result.stdout)
    assert imported["root_file"] is None
    assert Path(imported["file"]).is_relative_to(REPOSITORY / "src" / "pyvider" / "rpcplugin")
    assert imported["version"] == RELEASE_VERSION


@pytest.mark.parametrize("candidate_name", ["direct_wheel", "sdist_wheel"])
@pytest.mark.parametrize("order", ["rpcplugin-first", "owner-first"])
def test_fresh_coinstall_is_order_independent(
    built_artifacts: BuiltArtifacts,
    candidate_name: str,
    order: str,
    tmp_path: Path,
) -> None:
    candidate = _candidate(built_artifacts, candidate_name)
    owner = _synthetic_owner(tmp_path)
    python, purelib = _environment(tmp_path)

    if order == "rpcplugin-first":
        _install(python, candidate, dependencies=True)
        _install(python, owner)
    else:
        _install(python, owner)
        _install(python, candidate, dependencies=True)

    assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
    assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
    owner_record = next(purelib.glob("pyvider-*.dist-info/RECORD"))
    rpcplugin_record = next(purelib.glob("pyvider_rpcplugin-*.dist-info/RECORD"))
    assert ROOT_INITIALIZER in _record_paths(owner_record)
    assert ROOT_INITIALIZER not in _record_paths(rpcplugin_record)
    assert ROOT_TYPING_MARKER in _record_paths(owner_record)
    assert ROOT_TYPING_MARKER not in _record_paths(rpcplugin_record)

    imported = _installed_versions(python, tmp_path)
    assert imported["owner"] == "0.8.0"
    assert imported["rpcplugin"] == RELEASE_VERSION
    assert Path(imported["root_file"]).is_relative_to(purelib / "pyvider")
    assert Path(imported["rpcplugin_file"]).is_relative_to(purelib / "pyvider" / "rpcplugin")


def test_editable_coinstall_preserves_owner_and_imports_rpcplugin(tmp_path: Path) -> None:
    owner = _synthetic_owner(tmp_path)
    python, purelib = _environment(tmp_path)
    _install(python, owner)
    _install(python, REPOSITORY, dependencies=True, editable=True)

    assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
    assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
    imported = _installed_versions(python, tmp_path)
    assert imported["owner"] == "0.8.0"
    assert imported["rpcplugin"] == RELEASE_VERSION
    assert Path(imported["rpcplugin_file"]).is_relative_to(REPOSITORY / "src" / "pyvider" / "rpcplugin")


@pytest.mark.parametrize("installer", ["uv", "pip"])
def test_uninstall_preserves_the_canonical_owner_root_files(
    built_artifacts: BuiltArtifacts,
    installer: str,
    tmp_path: Path,
) -> None:
    owner = _synthetic_owner(tmp_path)
    python, purelib = _environment(tmp_path, seed=installer == "pip")
    _install(python, owner)
    _install(python, built_artifacts.direct_wheel, dependencies=True)

    assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
    assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
    assert _installed_versions(python, tmp_path)["owner"] == "0.8.0"

    _uninstall(python, installer=installer)

    _assert_rpcplugin_uninstalled(python, purelib, tmp_path)
    assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
    assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
    result = _run(
        [str(python), "-I", "-c", "import pyvider; print(pyvider.__version__)"],
        cwd=tmp_path,
    )
    assert result.stdout.strip() == "0.8.0"


def test_supported_upgrade_from_published_rpcplugin_054_repairs_owner_then_uninstalls_cleanly(
    built_artifacts: BuiltArtifacts,
    published_rpcplugin_054: Path,
    tmp_path: Path,
) -> None:
    payload = published_rpcplugin_054.read_bytes()
    assert published_rpcplugin_054.name == PUBLISHED_RPCPLUGIN_054_FILENAME
    assert len(payload) == PUBLISHED_RPCPLUGIN_054_SIZE
    assert hashlib.sha256(payload).hexdigest() == PUBLISHED_RPCPLUGIN_054_SHA256

    for candidate_name in ("direct_wheel", "sdist_wheel"):
        case = tmp_path / candidate_name
        case.mkdir()
        owner = _synthetic_owner(case)
        candidate = _candidate(built_artifacts, candidate_name)
        python, purelib = _environment(case)

        # This reproduces a healthy pre-upgrade state: 0.5.4 owns the shared
        # path in RECORD, then Pyvider 0.8.0 supplies the canonical bytes.
        _install(python, published_rpcplugin_054, dependencies=True)
        _install(python, owner)
        assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
        assert _installed_versions(python, case)["owner"] == "0.8.0"

        # uv removes every path owned by 0.5.4 before installing implicit
        # namespace contributor 0.5.5, so the legacy shared root is absent.
        _install(python, candidate, dependencies=True)

        assert not list(purelib.glob("pyvider_rpcplugin-0.5.4.dist-info"))
        assert not (purelib / ROOT_INITIALIZER).exists()
        assert not (purelib / ROOT_TYPING_MARKER).exists()

        # Reinstalling the sole root owner is the supported direct-upgrade
        # remediation and leaves rpcplugin as a removable namespace contributor.
        _install(python, owner, reinstall=True)
        assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
        assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
        owner_record = next(purelib.glob("pyvider-*.dist-info/RECORD"))
        rpcplugin_record = next(purelib.glob("pyvider_rpcplugin-*.dist-info/RECORD"))
        assert ROOT_INITIALIZER in _record_paths(owner_record)
        assert ROOT_INITIALIZER not in _record_paths(rpcplugin_record)
        assert ROOT_TYPING_MARKER in _record_paths(owner_record)
        assert ROOT_TYPING_MARKER not in _record_paths(rpcplugin_record)
        imported = _installed_versions(python, case)
        assert imported["owner"] == "0.8.0"
        assert imported["rpcplugin"] == RELEASE_VERSION

        _uninstall(python, installer="uv")
        _assert_rpcplugin_uninstalled(python, purelib, case)
        assert (purelib / ROOT_INITIALIZER).read_bytes() == CANONICAL_INITIALIZER
        assert (purelib / ROOT_TYPING_MARKER).read_bytes() == b""
        result = _run(
            [str(python), "-I", "-c", "import pyvider; print(pyvider.__version__)"],
            cwd=case,
        )
        assert result.stdout.strip() == "0.8.0"
