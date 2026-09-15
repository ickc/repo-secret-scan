"""Report writers.

``REPORTERS`` render a single repository's result (used by ``scan`` and in
CI); ``ORG_REPORTERS`` render a :class:`~repo_secret_scan.dataset.Dataset`
covering many repositories. Both are plain registries, so new formats are one
decorated class away.
"""

from .base import ORG_REPORTERS, REPORTERS, OrgReporter, RepoReporter
from . import annotations, dashboard, markdown, sarif  # noqa: F401,E402  (registers built-ins)

__all__ = ["ORG_REPORTERS", "REPORTERS", "OrgReporter", "RepoReporter"]
