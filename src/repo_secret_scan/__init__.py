"""Pluggable secret-scanning pipeline for git repositories and GitHub organisations."""

from .config import Config, load_config
from .models import Finding, Location, RepoInfo, RepoScanResult, Severity, Verification
from .pipeline import scan_repo
from .sources import CommitRange, FullHistory, GitHubSource, LocalSource, WorkingTree, resolve_target

__all__ = [
    "CommitRange", "Config", "Finding", "FullHistory", "GitHubSource", "LocalSource", "Location", "RepoInfo",
    "RepoScanResult", "Severity", "Verification", "WorkingTree", "load_config", "resolve_target", "scan_repo",
]
