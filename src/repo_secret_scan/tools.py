"""Locate or install the external scanner binaries at pinned versions.

Resolution order for a tool ``name``:

1. ``REPO_SECRET_SCAN_<NAME>`` environment variable (explicit path);
2. the pinned release previously installed into the tool cache;
3. ``name`` on ``PATH``;
4. download the pinned release from GitHub and verify its SHA-256 checksum.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path


class ToolUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    github_repo: str
    # Maps (os, arch) -> the platform fragment used in release asset names.
    platforms: dict[tuple[str, str], str]

    def asset(self, os_arch: tuple[str, str]) -> str:
        fragment = self.platforms[os_arch]
        ext = "zip" if os_arch[0] == "windows" and self.name == "gitleaks" else "tar.gz"
        return f"{self.name}_{self.version}_{fragment}.{ext}"

    @property
    def checksums(self) -> str:
        return f"{self.name}_{self.version}_checksums.txt"

    def url(self, filename: str) -> str:
        return f"https://github.com/{self.github_repo}/releases/download/v{self.version}/{filename}"

    @property
    def exe(self) -> str:
        return self.name + (".exe" if platform.system() == "Windows" else "")


GITLEAKS = ToolSpec(
    name="gitleaks",
    version="8.30.1",
    github_repo="gitleaks/gitleaks",
    platforms={
        ("linux", "x86_64"): "linux_x64",
        ("linux", "arm64"): "linux_arm64",
        ("darwin", "x86_64"): "darwin_x64",
        ("darwin", "arm64"): "darwin_arm64",
        ("windows", "x86_64"): "windows_x64",
        ("windows", "arm64"): "windows_arm64",
    },
)

TRUFFLEHOG = ToolSpec(
    name="trufflehog",
    version="3.97.4",
    github_repo="trufflesecurity/trufflehog",
    platforms={
        ("linux", "x86_64"): "linux_amd64",
        ("linux", "arm64"): "linux_arm64",
        ("darwin", "x86_64"): "darwin_amd64",
        ("darwin", "arm64"): "darwin_arm64",
        ("windows", "x86_64"): "windows_amd64",
        ("windows", "arm64"): "windows_arm64",
    },
)

TOOLS = {spec.name: spec for spec in (GITLEAKS, TRUFFLEHOG)}


def current_platform() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return system, arch


def default_cache_dir() -> Path:
    if env := os.environ.get("REPO_SECRET_SCAN_CACHE"):
        return Path(env)
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "repo-secret-scan"


def _cached_path(spec: ToolSpec, cache_dir: Path) -> Path:
    return cache_dir / "tools" / spec.name / spec.version / spec.exe


def resolve(spec: ToolSpec, cache_dir: Path | None = None, install: bool = True) -> Path:
    cache_dir = cache_dir or default_cache_dir()
    if explicit := os.environ.get(f"REPO_SECRET_SCAN_{spec.name.upper()}"):
        path = Path(explicit)
        if not path.is_file():
            raise ToolUnavailableError(f"{spec.name}: {path} from environment does not exist")
        return path
    cached = _cached_path(spec, cache_dir)
    if cached.is_file():
        return cached
    if on_path := shutil.which(spec.name):
        return Path(on_path)
    if not install:
        raise ToolUnavailableError(f"{spec.name} not found; run `repo-secret-scan tools install`")
    return install_tool(spec, cache_dir)


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "repo-secret-scan"})
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def install_tool(spec: ToolSpec, cache_dir: Path | None = None) -> Path:
    cache_dir = cache_dir or default_cache_dir()
    os_arch = current_platform()
    if os_arch not in spec.platforms:
        raise ToolUnavailableError(f"{spec.name} has no release for {os_arch}")
    asset = spec.asset(os_arch)
    try:
        checksums = _download(spec.url(spec.checksums)).decode()
        archive = _download(spec.url(asset))
    except OSError as exc:
        raise ToolUnavailableError(f"failed to download {spec.name}: {exc}") from exc
    expected = next((line.split()[0] for line in checksums.splitlines() if line.endswith(asset)), None)
    actual = hashlib.sha256(archive).hexdigest()
    if expected != actual:
        raise ToolUnavailableError(f"checksum mismatch for {asset}: expected {expected}, got {actual}")

    target = _cached_path(spec, cache_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            payload = zf.read(spec.exe)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            member = tf.extractfile(spec.exe)
            if member is None:
                raise ToolUnavailableError(f"{spec.exe} missing from {asset}")
            payload = member.read()
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        tmp.write(payload)
    tmp_path = Path(tmp.name)
    tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp_path.replace(target)
    return target
