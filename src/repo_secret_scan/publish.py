"""Harden a report for circulation: opaque secret ids and conservative previews.

A report travels further than the scan that produced it. It goes to the people who
have to rotate the credentials, which means it leaves the machine that holds the
results, and copies of it are hard to recall. Two of its columns are derived from
the secret values themselves:

``secret_hash``
    A keyed hash, used to correlate the same secret across scanners, commits,
    repositories and runs. It is only as unguessable as the key is secret, and the
    default key is a constant in this package. A reader who holds the report can
    therefore test candidate secrets against it offline, one hash per guess, which
    matters for human-chosen passwords inside connection strings.

``preview``
    The first four characters and the *exact* length of the secret. For a token with
    a fixed vendor prefix those four characters are public knowledge, but for a
    password they are four characters of the password — and the exact length turns a
    wordlist into a short candidate list.

Redaction separates the two jobs that ``secret_hash`` was doing. Correlation stays
on the operator's machine, in a :class:`LabelIndex` mapping each hash to a random
id; the report carries only the id. The id is unrelated to the secret, so guessing
is impossible however weak the secret and whatever the reader knows about the key.
Previews keep only prefixes that identify a credential *type* (and so are published
by the vendor anyway) and a bucketed length.

Redaction happens when a report is rendered, not when a scan runs, so it applies to
results that are already on disk and needs no rescan.
"""

from __future__ import annotations

import json
import re
import secrets as _secrets
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .dataset import Dataset

INDEX_FILENAME = "secret-labels.json"
INDEX_VERSION = 1
ID_PREFIX = "S-"

# Prefixes that identify a credential type rather than reveal one. Each is either a
# vendor-published token marker or a URI scheme, so keeping it tells a reader what
# kind of thing leaked without giving up any character they could not have guessed.
PUBLIC_PREFIXES = (
    # AWS
    "AKIA", "ASIA", "ABIA", "ACCA",
    # GitHub
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    # GitLab
    "glpat-", "glptt-", "gldt-",
    # OpenAI / Anthropic
    "sk-", "sk-proj-", "sk-ant-",
    # Slack
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-",
    # Google
    "AIza", "ya29.",
    # Stripe / Square
    "sk_live_", "pk_live_", "rk_live_", "sk_test_", "pk_test_", "sq0atp-", "sq0csp-",
    # Assorted vendors
    "SG.", "key-", "npm_", "hf_", "pypi-", "shpat_", "shpss_", "ATATT", "nvapi-",
    "lin_api_", "dop_v1_", "doo_v1_", "dor_v1_",
    # Structured credentials
    "eyJ", "-----BEGIN",
    # URI schemes: the scheme is already implied by the detector name
    "http", "ftp:", "ftps", "jdbc", "mong", "post", "mysq", "redi", "amqp", "smtp", "ldap", "sftp",
)

_PREVIEW_RE = re.compile(r"^(?P<prefix>.*)…\((?P<length>\d+) chars\)$")
_PEM_MARKER = "-----BEGIN"

# Upper bound (exclusive) of each bucket, so a length is reported as a range.
_LENGTH_BUCKETS = (16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024)


def bucket_length(length: int) -> str:
    """Report a length as a range, so the exact value can't narrow a guess."""
    low = 0
    for high in _LENGTH_BUCKETS:
        if length < high:
            return f"{low}-{high - 1}"
        low = high
    return f"{low}+"


def public_prefix(prefix: str) -> str:
    """The part of ``prefix`` that identifies a credential type, or ``""``.

    Only four characters of the secret reach a preview, so a longer marker can
    never be confirmed outright. A prefix that *extends* a known marker is reported
    as the marker alone; a prefix that is an initial segment of one is reported as
    itself, since those characters are the same for every credential of that kind.
    """
    if not prefix:
        return ""
    extends = [m for m in PUBLIC_PREFIXES if prefix.startswith(m)]
    if extends:
        return max(extends, key=len)
    if any(m.startswith(prefix) for m in PUBLIC_PREFIXES):
        return prefix
    return ""


def redact_preview(preview: str) -> str:
    """Rewrite a preview so it reveals a credential type but no secret characters."""
    if not preview:
        return ""
    if preview.startswith(_PEM_MARKER):
        # The BEGIN line of a PEM block is a fixed public header, not key material.
        return preview
    match = _PREVIEW_RE.match(preview)
    if not match:
        # An unrecognised shape may embed anything; say nothing about it.
        return "…(redacted)"
    kept = public_prefix(match["prefix"])
    return f"{kept}…({bucket_length(int(match['length']))} chars)"


@dataclass
class LabelIndex:
    """Mapping from keyed hash to published id, persisted beside the scan results.

    This is the correlation state that used to live in the hash itself: it keeps an
    id stable across runs, and keeps it out of the report. It holds no secret
    values and no plaintext, but it does link ids back to hashes, so it belongs
    with the results rather than with the report.
    """

    labels: dict[str, str] = field(default_factory=dict)
    path: Path | None = None
    dirty: bool = False

    @classmethod
    def load(cls, path: Path) -> LabelIndex:
        if not path.is_file():
            return cls(path=path)
        data = json.loads(path.read_text())
        version = data.get("version")
        if version != INDEX_VERSION:
            raise ValueError(f"{path}: unsupported label index version {version!r}")
        return cls(labels=dict(data.get("labels", {})), path=path)

    def label_for(self, secret_hash: str) -> str:
        if not secret_hash:
            return ""
        if secret_hash not in self.labels:
            used = set(self.labels.values())
            while (candidate := ID_PREFIX + _secrets.token_hex(4)) in used:
                pass
            self.labels[secret_hash] = candidate
            self.dirty = True
        return self.labels[secret_hash]

    def save(self, path: Path | None = None) -> Path:
        target = path or self.path
        if target is None:
            raise ValueError("no path to save the label index to")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": INDEX_VERSION, "labels": self.labels}
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        target.chmod(0o600)
        self.path, self.dirty = target, False
        return target


def _redact_row(row: dict[str, Any], index: LabelIndex) -> dict[str, Any]:
    out = dict(row)
    old_preview = out.get("preview") or ""
    new_preview = redact_preview(old_preview)
    if "secret_hash" in out:
        out["secret_hash"] = index.label_for(out["secret_hash"])
    if "preview" in out:
        out["preview"] = new_preview
    if out.get("context") and old_preview:
        # Context was built by masking the secret out of its surrounding line, so it
        # carries the same prefix and exact length as the preview did.
        out["context"] = out["context"].replace(old_preview, new_preview)
    if "entropy" in out:
        # Shannon entropy of the value is another numeric fingerprint of it.
        out["entropy"] = ""
    return out


def redact(dataset: Dataset, index: LabelIndex) -> Dataset:
    """A copy of ``dataset`` carrying no data derived from the secret values."""
    return replace(
        dataset,
        secrets=[_redact_row(s, index) for s in dataset.secrets],
        findings=[_redact_row(f, index) for f in dataset.findings],
        redacted=True,
    )
