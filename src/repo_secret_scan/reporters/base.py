from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..dataset import Dataset
from ..models import RepoScanResult
from ..registry import Registry


class RepoReporter(Protocol):
    def write(self, result: RepoScanResult, out_dir: Path) -> None: ...


class OrgReporter(Protocol):
    def write(self, dataset: Dataset, out_dir: Path, title: str) -> None: ...


REPORTERS: Registry[RepoReporter] = Registry("reporter")
ORG_REPORTERS: Registry[OrgReporter] = Registry("org reporter")


@ORG_REPORTERS.register("csv")
@dataclass
class CsvReporter:
    subdir: str = "data"

    def write(self, dataset: Dataset, out_dir: Path, title: str) -> None:
        dataset.write_csv(out_dir / self.subdir)
