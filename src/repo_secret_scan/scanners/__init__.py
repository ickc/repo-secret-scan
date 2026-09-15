"""Scanner adapters. Importing this package registers the built-in scanners."""

from . import gitleaks, trufflehog  # noqa: F401
from .base import SCANNERS, ScanOutput, Scanner, ScanTimeoutError, UnsupportedScopeError

__all__ = ["SCANNERS", "ScanOutput", "Scanner", "ScanTimeoutError", "UnsupportedScopeError"]
