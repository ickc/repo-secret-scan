"""Post-scan processing stages.

Each processor receives the full list of findings for one repository and
returns a (possibly modified) list. They run in the configured order, so later
stages can rely on facts established by earlier ones (``triage`` uses the
``in_head`` flag and tags). Future stages, such as live verification, slot in
here without touching scanners or reporters.

Processors marked ``offline`` need neither the plaintext secret nor the
repository, so they are re-applied to stored findings whenever reports are
built: changing triage policy never requires a rescan.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

from ._proc import git
from .models import Finding, Location, Severity, Verification
from .registry import Registry
from .sources import Checkout, Scope, WorkingTree


@dataclass
class ProcessContext:
    checkout: Checkout
    scope: Scope | None  # None when re-processing stored findings


class Processor(Protocol):
    offline: ClassVar[bool]

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]: ...


PROCESSORS: Registry[Processor] = Registry("processor")


def _grep_line(secret: str) -> str:
    """git grep is line oriented: search for the longest line of a multi-line secret."""
    return max(secret.strip().splitlines(), key=len)


@PROCESSORS.register("in-head")
@dataclass
class InHead:
    """Flag whether each secret is still present in the default branch tip.

    Also records where it is there, in ``extra["head_location"]``: scanners
    report the line in the commit that introduced a secret, which drifts as the
    file changes.
    """

    offline: ClassVar[bool] = False
    batch_size: int = 500

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        if isinstance(ctx.scope, WorkingTree):
            for f in findings:
                f.in_head = True
            return findings
        checkout = ctx.checkout
        if checkout.git_dir is None or checkout.head is None:
            return findings
        needles = {_grep_line(f.secret) for f in findings if f.secret}
        present: dict[str, list[tuple[str, int]]] = defaultdict(list)
        ordered = sorted(needles)
        for i in range(0, len(ordered), self.batch_size):
            batch = ordered[i : i + self.batch_size]
            # Patterns go through stdin so secrets never appear in the process list.
            result = git(
                "grep", "--no-color", "-o", "-n", "-z", "-I", "-F", "-f", "-", checkout.head, "--",
                git_dir=checkout.git_dir, input="\n".join(batch) + "\n", check=False,
            )
            if result.returncode not in (0, 1):  # 1 just means "no match"
                raise RuntimeError(f"git grep failed ({result.returncode}): {result.stderr.strip()[:200]}")
            # -z: "<head>:<path>\0<line>\0<match>" per match.
            for row in result.stdout.splitlines():
                if row.count("\0") < 2:  # a path containing a newline
                    continue
                name, line, match = row.split("\0", 2)
                present[match].append((name.removeprefix(f"{checkout.head}:"), int(line)))
        for f in findings:
            if f.secret:
                places = present.get(_grep_line(f.secret), [])
                f.in_head = bool(places)
                if places:
                    path, line = _nearest(places, f.location)
                    f.extra["head_location"] = {"path": path, "line": line}
        return findings


def _nearest(places: list[tuple[str, int]], location: Location) -> tuple[str, int]:
    """The occurrence most likely to be the reported one: same file, then closest line."""
    return min(places, key=lambda p: (p[0] != location.path, abs(p[1] - (location.line or 0)), p))


CONTENT_TAGS_KEY = "content_tags"


def add_content_tag(finding: Finding, tag: str) -> None:
    """Tag a fact read from the secret or the repository.

    Such facts cannot be recomputed from stored findings, so they are also kept
    in ``extra``, from which ``reprocess`` restores them.
    """
    finding.tags.add(tag)
    stored = finding.extra.setdefault(CONTENT_TAGS_KEY, [])
    if tag not in stored:
        stored.append(tag)


# Values that stand in for a credential in documentation and commented-out commands.
DEFAULT_PLACEHOLDER_WORDS = [
    "username", "user", "user_name", "login", "password", "passwd", "pass", "pwd", "secret", "token", "apikey",
    "api_key", "key", "changeme", "change_me", "example", "placeholder", "dummy", "someone", "foo", "bar",
]
# Reserved for documentation (RFC 2606 / RFC 6761); credentials for them cannot be real.
DEFAULT_PLACEHOLDER_HOSTS = ["example.com", "example.net", "example.org", "*.example", "*.test", "*.invalid"]
_URI_USERINFO = re.compile(r"^[a-z][a-z0-9+.-]*://([^:/@\s]*):([^@/\s]*)@([^/:?#\s]+)", re.IGNORECASE)
_TEMPLATE = re.compile(r"^(<[^<>]+>|\$\{[^{}]+\}|\{\{[^{}]+\}\}|%[^%]+%|x{6,}|\*{6,})$", re.IGNORECASE)


@PROCESSORS.register("placeholder")
@dataclass
class Placeholder:
    """Tag secrets that are documentation placeholders rather than credentials.

    Covers URIs whose user and password are both placeholder words
    (``ftp://username:password@host``) or whose host is reserved for
    documentation, and whole values such as ``<token>``, ``${API_KEY}`` or
    ``xxxxxxxx``. Needs the plaintext secret, so it runs at scan time.
    """

    offline: ClassVar[bool] = False
    words: list[str] = field(default_factory=lambda: list(DEFAULT_PLACEHOLDER_WORDS))
    hosts: list[str] = field(default_factory=lambda: list(DEFAULT_PLACEHOLDER_HOSTS))

    def is_placeholder(self, secret: str) -> bool:
        secret = secret.strip()
        if m := _URI_USERINFO.match(secret):
            user, password, host = m.groups()
            if self._is_placeholder_value(user) and self._is_placeholder_value(password):
                return True
            return any(fnmatch.fnmatchcase(host.lower(), h.lower()) for h in self.hosts)
        return self._is_placeholder_value(secret)

    def _is_placeholder_value(self, value: str) -> bool:
        # A template such as ``<password>`` or ``${DB_PASSWORD}`` stands in for a value whatever it names.
        return bool(_TEMPLATE.match(value)) or value.lower() in {w.lower() for w in self.words}

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        for f in findings:
            if f.secret and self.is_placeholder(f.secret):
                add_content_tag(f, "placeholder")
        return findings


_DATA_URI = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,[A-Za-z0-9+/=]+")


@PROCESSORS.register("embedded-data")
@dataclass
class EmbeddedData:
    """Tag secrets that occur only inside base64 ``data:`` URIs.

    Rendered HTML embeds images and fonts as data URIs. Keyword-proximity
    detectors match the keyword case-insensitively, so a long enough base64 run
    spells it somewhere and is followed by a token-shaped tail. Reads each file
    at the commit the finding came from, so it runs at scan time.
    """

    offline: ClassVar[bool] = False

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        by_file: dict[tuple[str | None, str], list[Finding]] = defaultdict(list)
        for f in findings:
            if f.secret and f.location.path:
                by_file[(f.location.commit, f.location.path)].append(f)
        for (commit, path), fs in by_file.items():
            text = _read_file(ctx.checkout, commit, path)
            if not text or "base64," not in text:
                continue
            spans = [m.span() for m in _DATA_URI.finditer(text)]
            for f in fs:
                if spans and _only_inside(text, _grep_line(f.secret), spans):
                    add_content_tag(f, "embedded-data")
        return findings


def _read_file(checkout: Checkout, commit: str | None, path: str) -> str | None:
    if commit and checkout.git_dir is not None:
        result = git("show", f"{commit}:{path}", git_dir=checkout.git_dir, check=False)
        return result.stdout if result.returncode == 0 else None
    if checkout.worktree is not None and (checkout.worktree / path).is_file():
        return (checkout.worktree / path).read_text(errors="replace")
    return None


def _only_inside(text: str, needle: str, spans: list[tuple[int, int]]) -> bool:
    """Whether ``needle`` occurs in ``text`` and every occurrence lies within one of ``spans``."""
    start = text.find(needle)
    if start < 0:
        return False
    while start >= 0:
        end = start + len(needle)
        if not any(s <= start and end <= e for s, e in spans):
            return False
        start = text.find(needle, start + 1)
    return True


DEFAULT_PATH_TAGS: dict[str, list[str]] = {
    "test": [r"(^|/)(tests?|testing|spec|__tests__|fixtures?|testdata|mocks?)(/|$)", r"(^|/)test_[^/]*$", r"_test\.[^/]+$"],
    "example": [r"(^|/)(examples?|samples?|demo|tutorials?)(/|$)", r"\.(example|sample|template|dist)$", r"(^|/)\.env\.(example|sample|template)$"],
    "docs": [r"(^|/)docs?/", r"\.(md|rst|txt|adoc)$"],
    "notebook": [r"\.ipynb$"],
    "lockfile": [
        r"(^|/)(package-lock\.json|pnpm-lock\.yaml|go\.sum)$", r"\.lock$",
        r"(^|/)(environment[^/]*\.ya?ml|requirements[^/]*\.txt|env_builds\.ya?ml)$",
    ],
    "vendored": [r"(^|/)(node_modules|vendor|third_party|site-packages|\.venv|venv)/", r"\.min\.(js|css)$", r"\.map$"],
    "generated": [r"(^|/)(__pycache__|\.ipynb_checkpoints|[^/]+\.dist-info|build|dist)/", r"(^|/)bundle\.js$"],
    "binary": [
        r"\.(pyc|pyo|class|jar|war|so|dylib|dll|exe|o|a|whl|egg|zip|gz|tgz|bz2|xz|7z|png|jpe?g|gif|bmp|tiff?|ico"
        r"|pdf|docx?|xlsx?|pptx?|pkl|pickle|npy|npz|h5|hdf5|pt|pth|onnx|bin|dat|mat|nc)$",
    ],
    "checksum": [r"\.(md5|md5sum|sha1|sha256|sha512|sum)$", r"(^|/)RECORD$"],
    # Rendered notebooks/R Markdown embed base64 assets that trip keyword detectors.
    "rendered": [r"\.html?$"],
    # Config formats (.json, .xml, .yaml) are deliberately absent: they are where real keys live.
    "data": [r"\.(csv|tsv|geojson|svg|log)$"],
}


@PROCESSORS.register("path-tags")
@dataclass
class PathTags:
    """Tag findings by the kind of file they live in (tests, docs, lockfiles, …)."""

    offline: ClassVar[bool] = True
    tags: dict[str, list[str]] = field(default_factory=lambda: dict(DEFAULT_PATH_TAGS))

    def __post_init__(self) -> None:
        self._compiled = {tag: [re.compile(p, re.IGNORECASE) for p in pats] for tag, pats in self.tags.items()}

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        for f in findings:
            for tag, patterns in self._compiled.items():
                if any(p.search(f.location.path) for p in patterns):
                    f.tags.add(tag)
        return findings


@PROCESSORS.register("cross-scanner")
@dataclass
class CrossScanner:
    """Record which scanners independently found the same secret."""

    offline: ClassVar[bool] = True

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        by_hash: dict[str, set[str]] = defaultdict(set)
        for f in findings:
            by_hash[f.secret_hash].add(f.scanner)
        for f in findings:
            scanners = by_hash[f.secret_hash]
            f.extra["found_by"] = sorted(scanners)
            if len(scanners) > 1:
                f.tags.add("multi-scanner")
        return findings


@dataclass
class IgnoreRule:
    reason: str = ""
    secret_hash: str | None = None
    rule: str | None = None
    path: str | None = None
    repo: str | None = None

    def matches(self, finding: Finding, repo_slug: str) -> bool:
        checks = [
            self.secret_hash is None or finding.secret_hash == self.secret_hash,
            self.rule is None or fnmatch.fnmatchcase(finding.rule, self.rule),
            self.path is None or fnmatch.fnmatchcase(finding.location.path, self.path),
            self.repo is None or fnmatch.fnmatchcase(repo_slug, self.repo),
        ]
        return all(checks) and any(v is not None for v in (self.secret_hash, self.rule, self.path))


def load_ignore_rules(text: str) -> list[IgnoreRule]:
    data = tomllib.loads(text)
    return [IgnoreRule(**entry) for entry in data.get("ignore", [])]


@PROCESSORS.register("ignore-file")
@dataclass
class IgnoreFile:
    """Mark reviewed findings as suppressed.

    Rules come from ``filename`` at the root of the scanned repository (so each
    repository can maintain its own list) and from an optional central
    ``path``. Suppressed findings are kept, but excluded from failure checks
    and pushed down in reports.
    """

    offline: ClassVar[bool] = False
    filename: str = ".secret-scan-ignore.toml"
    path: str | None = None

    def _repo_rules(self, checkout: Checkout) -> list[IgnoreRule]:
        text = None
        if checkout.worktree is not None and (checkout.worktree / self.filename).is_file():
            text = (checkout.worktree / self.filename).read_text()
        elif checkout.git_dir is not None and checkout.head is not None:
            result = git("show", f"{checkout.head}:{self.filename}", git_dir=checkout.git_dir, check=False)
            text = result.stdout if result.returncode == 0 else None
        return load_ignore_rules(text) if text else []

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        rules = self._repo_rules(ctx.checkout)
        if self.path:
            rules += load_ignore_rules(Path(self.path).read_text())
        for f in findings:
            for rule in rules:
                if rule.matches(f, ctx.checkout.repo.slug):
                    f.suppressed = True
                    f.suppression_reason = rule.reason
                    break
        return findings


# Rule names from either scanner, matched case-insensitively as globs.
# Detectors keyed on a distinctive token format rarely fire on random data.
DEFAULT_HIGH_CONFIDENCE_RULES = [
    "private-key", "privatekey", "aws*", "github*", "gitlab-pat*", "slack*", "openai*", "anthropic*", "stripe*",
    "gcp*", "azure*", "huggingface*", "npm*", "pypi*", "twilio*", "sendgrid*", "mailgun*", "mongodb", "postgres",
    "discord*", "telegram*", "shopify*", "dropbox*", "digitalocean*", "databricks*", "doppler*",
]
# Catch-all patterns: plausible but frequently match configuration noise.
DEFAULT_GENERIC_RULES = ["generic-*", "*entropy*", "jwt"]
# Keyword-proximity detectors that, unverified, mostly match random base64/hex
# (notebook outputs, checksums, compiled files). Observed on a real organisation scan.
DEFAULT_WEAK_RULES = ["box", "tly", "sirv", "unifyid", "juro", "alchemy", "eightxeight", "wit", "sumologic-access-id"]
DEFAULT_TAG_WEIGHTS = {
    "placeholder": -3, "embedded-data": -2,
    "test": -1, "example": -1, "docs": -1, "data": -1, "notebook": -1, "rendered": -1,
    "lockfile": -2, "vendored": -2, "generated": -2, "binary": -2, "checksum": -2,
    "multi-scanner": 1,
}


@PROCESSORS.register("triage")
@dataclass
class Triage:
    """Assign a severity from a transparent additive score.

    Base score by detector tier (high-confidence 4, other specific 2, generic 1,
    weak 0), plus modifiers for exposure (still in HEAD, public repository)
    and file-kind tags. Score >= 5 is critical, 4 high, 3 medium, 2 low, else
    info. The contributing reasons are stored in ``extra["severity_reasons"]``
    so the report can explain every rating.
    """

    offline: ClassVar[bool] = True
    high_confidence_rules: list[str] = field(default_factory=lambda: list(DEFAULT_HIGH_CONFIDENCE_RULES))
    generic_rules: list[str] = field(default_factory=lambda: list(DEFAULT_GENERIC_RULES))
    weak_rules: list[str] = field(default_factory=lambda: list(DEFAULT_WEAK_RULES))
    tag_weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_TAG_WEIGHTS))
    high_confidence_score: int = 4
    specific_score: int = 2
    generic_score: int = 1
    weak_score: int = 0
    in_head_score: int = 1
    public_score: int = 1

    def tier(self, rule: str) -> tuple[str, int]:
        name = rule.lower()
        for label, patterns, score in (
            ("high-confidence detector", self.high_confidence_rules, self.high_confidence_score),
            ("weak detector", self.weak_rules, self.weak_score),
            ("generic rule", self.generic_rules, self.generic_score),
        ):
            if any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns):
                return label, score
        return "specific detector", self.specific_score

    def score(self, f: Finding, visibility: str) -> tuple[int, list[str]]:
        label, score = self.tier(f.rule)
        reasons = [label]
        if f.in_head:
            score += self.in_head_score
            reasons.append("still in default branch")
        if visibility == "public":
            score += self.public_score
            reasons.append("public repository")
        for tag in sorted(f.tags):
            if weight := self.tag_weights.get(tag, 0):
                score += weight
                reasons.append(f"{tag} ({weight:+d})")
        return score, reasons

    def process(self, findings: list[Finding], ctx: ProcessContext) -> list[Finding]:
        visibility = ctx.checkout.repo.visibility
        for f in findings:
            score, reasons = self.score(f, visibility)
            if f.verification is Verification.LIVE:
                f.severity = Severity.CRITICAL
                reasons.append("verified live")
            elif f.verification is Verification.INVALID:
                f.severity = Severity.INFO
                reasons.append("verified invalid")
            else:
                f.severity = _severity_for(score)
            f.extra["severity_reasons"] = reasons
            f.extra["severity_score"] = score
        return findings


def _severity_for(score: int) -> Severity:
    if score >= 5:
        return Severity.CRITICAL
    if score == 4:
        return Severity.HIGH
    if score == 3:
        return Severity.MEDIUM
    if score == 2:
        return Severity.LOW
    return Severity.INFO
