# repo-secret-scan

Pluggable pipeline that finds leaked secrets in one git repository — a local
directory or a GitHub `OWNER/REPO` — or across every repository of a GitHub
organisation or user. It wraps [gitleaks](https://github.com/gitleaks/gitleaks) and
[trufflehog](https://github.com/trufflesecurity/trufflehog), normalises their
findings into one model, triages them, and writes reports to act on.

This tool never writes the raw secret value to disk. Findings carry a keyed hash
(`secret_hash`), used to correlate the same secret across scanners, commits,
repositories and runs, plus a masked preview such as `ghp_…(40 chars)`.

## Quick start

```bash
pip install 'repo-secret-scan[dashboard]'
repo-secret-scan tools install                  # pinned gitleaks + trufflehog, SHA-256 verified

# one repository: local path, OWNER/REPO or GitHub URL
repo-secret-scan scan my-org/some-repo --out results/some-repo
repo-secret-scan scan . --scope range --base origin/main --fail-on high   # CI-style

# every repository of an organisation or user (clones, results and reports live under --scratch)
repo-secret-scan org my-org --scratch /path/to/scratch --config secret-scan.toml

# rebuild reports (e.g. after changing triage settings) without rescanning
repo-secret-scan report /path/to/scratch --config secret-scan.toml
```

GitHub access uses `GH_TOKEN`/`GITHUB_TOKEN`, falling back to `gh auth token`.
The token is passed to git through environment config, never on the command line.

There are two ways to run it:

- **Single-repository scan** (`scan`): runs the whole pipeline on one repository.
  This is what a CI job runs.
- **Organisation scan** (`org`): lists an owner's repositories, runs the
  single-repository pipeline on each (in parallel, with caching), and merges the
  results into organisation-wide reports.

## How it compares to the scanners' own GitHub Actions

Both upstream projects ship a GitHub Action. This package uses the scanners'
**command-line tools** (gitleaks: MIT, trufflehog: AGPL-3.0). It does not use
either Action, so the Actions' terms don't apply to it.

| | [gitleaks-action](https://github.com/gitleaks/gitleaks-action) | [trufflehog Action](https://github.com/trufflesecurity/trufflehog#octocat-trufflehog-github-action) | repo-secret-scan |
|---|---|---|---|
| Licence | Proprietary EULA since v2 (source-available, no modifications, not usable in a similar product) | AGPL-3.0 | Your choice; calls both CLIs as subprocesses |
| Licence key | Required for repositories owned by an **organisation**; free sign-up form, unlimited repositories | None | None |
| Phones home | Online key validation (`api.keygen.sh`) exists in the code but has been disabled since late 2024; v2/v3 only check that the secret is non-empty | Pulls `ghcr.io/trufflesecurity/trufflehog:latest` by default | GitHub API/clone only; binaries downloaded once from GitHub releases |
| Scanners | gitleaks | trufflehog | gitleaks **and** trufflehog, merged into one finding model |
| Commit scope in CI | Push/PR commits, or full history | Push/PR commits (`base`/`head`) | `--scope range`, `history` or `tree` |
| Live-credential verification | No | Yes, usually enabled via `--results=verified,unknown` | Off by default; `[scanner.trufflehog] verify = true`, or a custom processor |
| False-positive handling | `.gitleaks.toml` allowlists, `.gitleaksignore` fingerprints | Verification; detector include/exclude | Everything the tools support, plus explained severity triage, path tags, cross-scanner agreement and a hash-based `.secret-scan-ignore.toml` |
| "Still in HEAD?" | No | No | Yes (`in-head` processor) |
| Output | Job summary, PR review comments, user notifications, SARIF artifact | Workflow annotations and a failing exit code; SARIF only when you run the CLI yourself | `report.md` (job summary), workflow annotations (`github-annotations`), failing exit code, SARIF, JSONL; CSV and dashboard for organisation scans |
| Many repositories at once | No (per repository) | CLI can scan a GitHub org (`trufflehog github --org`), without triage or reports | `org` command: filters, caching, retries, merged reports, reused-secret detection |
| Version pinning | Hard-coded default, or `GITLEAKS_VERSION` | Docker tag, default `latest` | Pinned versions with SHA-256 verification |
| Maintained by | Gitleaks LLC | Truffle Security | You |

Things the upstream Actions do that this package does not (yet): PR review
comments and user notifications (gitleaks-action), ready-made Docker images, and
trufflehog's non-git sources (S3, Docker images, Slack, …). Workflow annotations
cover most of what PR comments are used for.

Notes on the licences (not legal advice):

- **gitleaks-action's EULA.** The free key currently covers unlimited
  repositories. The EULA still describes repository-capped tiers, and the
  Action's code can register each repository online and fail past a cap
  (`TOO_MANY_MACHINES`), but that check is commented out in current releases.
  A future release could re-enable it, so pin the Action to a commit SHA.
  Section 2.2 forbids using the Action as part of a product or service with
  similar functionality. None of this applies when you run the
  MIT-licensed `gitleaks` binary directly, as this package does. Also note:
  `gitleaks-action@v2` runs on Node 20, which GitHub removes from hosted runners
  on 2026-09-16; use `@v3`.
- **trufflehog's AGPL-3.0.** Its obligations (offering source code) apply when
  you distribute trufflehog, or a modified version, or provide a modified
  version as a network service. Invoking the unmodified upstream binary as a
  separate process is generally not considered creating a derivative work, so
  it places no obligation on the calling program, whatever its licence, and
  whether it is private or public. If you redistribute the binary
  yourself, for example baked into a Docker image, include its licence and
  point to its source.

## What is SARIF?

[SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
(Static Analysis Results Interchange Format) is an OASIS-standard JSON format
for the output of code-analysis tools. GitHub code scanning imports it with
`github/codeql-action/upload-sarif`. Findings then appear as alerts in the
repository's *Security* tab and as annotations on pull-request diffs, and GitHub
tracks each alert as new or fixed across uploads. Uploading is free for public
repositories; private repositories need GitHub Code Security.

This package's `results.sarif` gives each finding a severity and
`security-severity` score and a stable `secretHash/v1` fingerprint. Suppressed
findings are marked as `suppressions`. gitleaks-action's authors warn that code
scanning can give a false sense of security: an alert closes once the secret
disappears from the scanned code, even though it is still in history. A
scheduled `--scope history` scan keeps reporting history-only secrets, and the
SARIF message says whether each one is still present.

## Architecture

```
            Source ─────► Scanners ─────► Processors ─────► Reporters
  "Org/Repo" → bare clone   gitleaks        in-head            findings.jsonl + result.json (always)
  ./path     → as is        trufflehog      ignore-file        markdown, sarif          (per repository)
                            (parallel)      path-tags *        csv, markdown, dashboard (organisation scan)
                                            cross-scanner *
                                            triage *
                                                         * offline: re-applied at report time
```

Every stage is a small protocol with a name → class registry
(`registry.Registry`). TOML tables map straight onto constructor keyword
arguments, so `[scanner.trufflehog] concurrency = 4` becomes
`TrufflehogScanner(concurrency=4)`.

| Module | Role |
|---|---|
| `models.py` | `Finding`, `Location`, `RepoScanResult`, severity/verification enums, hashing and masking |
| `sources.py` | `LocalSource`, `GitHubSource` → `Checkout`; scopes `FullHistory`, `CommitRange`, `WorkingTree` |
| `scanners/` | `ExternalToolScanner` base plus the gitleaks and trufflehog adapters |
| `processors.py` | Post-scan stages (see below) |
| `pipeline.py` | `scan_repo()`: the single-repository pipeline, retries, caching fingerprint, `reprocess()` |
| `dataset.py` | Flattens results into `repos.csv`, `secrets.csv` (one row per secret per repo) and `findings.csv` |
| `reporters/` | Per-repository (`markdown`, `sarif`) and multi-repository (`csv`, `markdown`, `dashboard`) writers |
| `org.py` | Organisation scan: lists repositories via the REST API, filters, runs `scan_repo` in parallel with caching |
| `tools.py` | Resolves or downloads the pinned scanner binaries |

### Processors

| Name | Offline | What it does |
|---|---|---|
| `in-head` | no | Is the secret still in the default-branch tip? Uses `git grep -F -f -`, so patterns go through stdin |
| `ignore-file` | no | Suppresses reviewed findings using `.secret-scan-ignore.toml` in the repo, and/or a central file |
| `path-tags` | yes | Tags the file kind: `test`, `example`, `docs`, `notebook`, `lockfile`, `vendored`, `generated`, `binary`, `checksum`, `rendered`, `data` |
| `cross-scanner` | yes | Records which scanners found the same secret (`multi-scanner` tag) |
| `triage` | yes | Additive, explained severity score (below) |

An *offline* processor needs neither the repository nor the plaintext secret.
Offline processors are re-run whenever reports are built, and their settings
are excluded from the cache fingerprint, so tuning triage never forces a rescan.

### Triage

The score starts from the detector tier: high-confidence token formats (private
keys, AWS, GitHub, OpenAI/Anthropic, Slack, Stripe, MongoDB, …) score 4, other
named detectors 2, generic rules 1, and weak keyword-proximity detectors 0.
Modifiers:

- +1 if the secret is still in HEAD
- +1 if the repository is public
- +1 if both scanners found it
- −1 or −2 for tags such as test, docs, notebook, vendored or binary

A score of ≥5 is critical, 4 high, 3 medium, 2 low, and anything lower info.
Every rating stores its reasons, and the report shows them. A live-verified
secret is always critical. All lists and weights can be changed under
`[processor.triage]`.

The defaults were tuned on a full scan of a research-software organisation
(about 150 repositories, many containing notebooks). Unverified trufflehog
detectors such as Box, TLy and Sirv fired hundreds of times on base64 notebook
outputs, checksum files and `.pyc` files, while the real exposures were API keys
in JSON configuration files.

### Caching and robustness (organisation scans)

- A repository is rescanned when any of these change: `pushed_at`, scanner
  versions, or the result-affecting settings (config fingerprint).
- Repositories that failed, timed out, or hit transient errors are also rescanned.
- Transient host failures (fork/thread exhaustion) are retried with backoff.
  Go scanners are capped with `GOMAXPROCS` (`max_procs`, default 4), because on
  many-core shared nodes they otherwise exhaust `ulimit -u`.
- **Permissions.** Clones of private repositories and the reports are both sensitive, so:
  - everything the CLI creates gets a `077` umask (owner-only);
  - `org` and `report` remove group/other permissions from the scratch
    directory itself, even if it already existed, which makes everything
    inside unreachable to other users;
  - `scan --out DIR` only warns if an existing `DIR` is shared, since it may be
    any directory.

  Files you create there yourself (e.g. `… > scratch/run.log`) follow your
  shell's umask, but stay unreachable while the directory is `drwx------`. Use a
  scratch directory on a filesystem that honours POSIX permissions, and don't
  loosen them to share results; share the Markdown report instead.

## Outputs

Per repository (`--out` for `scan`; `results/<owner>/<repo>/` under the scratch
directory for `org`):

- `findings.jsonl` — canonical, one normalised hit per line
- `result.json` — status, scanner runs, versions, errors, fingerprint
- `report.md` — human summary; also works as a GitHub job summary
- `results.sarif` — for GitHub code scanning (see *What is SARIF?*)
- `annotations.txt` — with `--format github-annotations` (or `reporters = [..., "github-annotations"]`)

### GitHub workflow annotations

The `github-annotations` reporter writes GitHub Actions
[workflow commands](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#setting-an-error-message)
such as `::error file=app/config.py,line=12,title=Possible secret: github-pat::…`.
When it runs inside GitHub Actions (`GITHUB_ACTIONS=true`), it also prints them,
and GitHub shows them on the workflow run and on the pull request's *Files
changed* view. They need no GitHub Code Security licence, so they work for
private repositories too.

- Severity mapping: critical/high → `error`, medium → `warning`, low/info → `notice`.
- One annotation per secret per file, most severe first. Suppressed findings are skipped.
- GitHub displays only a limited number of annotations per step, so the output
  is capped (`max_annotations`, default 50) and ends with a notice saying how
  many were left out.
- Messages contain only the masked preview and `secret_hash`, the same as the reports.
- Options under `[reporter.github-annotations]`: `min_severity` (default
  `"medium"`), `max_annotations`, `emit` (`"auto"`, `"always"`, `"never"`), `filename`.
- Findings only in history point to files that may no longer exist on the
  branch. They still appear on the workflow run, but not on the diff.

Organisation scan (`report/` under the scratch directory):

- `data/{repos,secrets,findings}.csv` — every other report is derived from these
- `report.md` — summary, action list (medium and above) with links to the exact
  commit and line, secrets reused across repositories, scan problems
- `dashboard.html` — self-contained Plotly dashboard with a filterable table
  (needs the `dashboard` extra)

## Configuration

All keys, with defaults:

```toml
[scan]
scanners = ["gitleaks", "trufflehog"]
processors = ["in-head", "path-tags", "cross-scanner", "ignore-file", "triage"]
reporters = ["markdown", "sarif"]
retries = 2
retry_delay = 30

[scanner.gitleaks]      # timeout, extra_args, max_procs, config, max_target_megabytes
[scanner.trufflehog]    # timeout, extra_args, max_procs, concurrency, verify (default false)
[processor.triage]      # high_confidence_rules, generic_rules, weak_rules, tag_weights, *_score
[processor.path-tags]   # tags = { name = [regex, …] }
[processor.ignore-file] # filename, path

[org]                   # organisation scans only
include_forks = true
include_archived = true
include_empty = true
visibility = "all"      # all | public | private | internal
include = ["*"]
exclude = []
jobs = 8

[report]
formats = ["csv", "markdown", "dashboard"]
```

## Suppressing findings

Put `.secret-scan-ignore.toml` in a repository root. You can also point
`[processor.ignore-file] path` at a central file, where `repo` globs are allowed:

```toml
[[ignore]]
secret_hash = "<secret_hash from a report>"
reason = "rotated; history rewrite not worth it"

[[ignore]]
repo = "my-org/*-training"
path = "notebooks/*"
rule = "generic-api-key"
reason = "teaching material"
```

Set `REPO_SECRET_SCAN_HASH_KEY` to a private value so that published hashes (for
example in a public repository's ignore file) can't be checked against guessed
secrets. Use the same key everywhere so hashes stay comparable.

## Using it as a GitHub Action in each repository

The single-repository pipeline has no heavy dependencies: it needs only `typer`,
`git` and the two binaries, which `tools install` downloads. See
[`examples/secret-scan.yml`](examples/secret-scan.yml). The example checks the
commits of each push or pull request with `--scope range` and the full history
weekly. It fails on high or critical findings, writes `report.md` to the job
summary, annotates findings on the run and the PR diff, and uploads SARIF for
public repositories.

## Extending

```python
from dataclasses import dataclass
from typing import ClassVar
from repo_secret_scan.processors import PROCESSORS
from repo_secret_scan.models import Verification

@PROCESSORS.register("verify-github")
@dataclass
class VerifyGitHubTokens:
    offline: ClassVar[bool] = False      # needs Finding.secret
    timeout: float = 5.0

    def process(self, findings, ctx):
        for f in findings:
            if f.secret and f.rule.lower().startswith("github"):
                live = token_works(f.secret, self.timeout)  # your check, e.g. GET https://api.github.com/user
                f.verification = Verification.LIVE if live else Verification.INVALID
        return findings
```

Then add `"verify-github"` to `[scan] processors`, placed before `triage`. New
scanners subclass `ExternalToolScanner` (or implement the `Scanner` protocol)
and register with `SCANNERS`; new outputs register with `REPORTERS` or
`ORG_REPORTERS`. The built-in trufflehog verification can also be enabled with
`[scanner.trufflehog] verify = true`. Note that verification sends candidate
secrets to the respective third-party APIs.

## Development

```bash
pip install -e . pytest
repo-secret-scan tools install
pytest
```

The end-to-end tests build a throwaway git repository with randomly generated
token-shaped strings and run both real scanners on it. They check that no
plaintext secret reaches any output file. If the binaries are missing, those
tests are skipped.
