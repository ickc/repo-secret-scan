# Rules for this repository

This repository is a generic, publishable secret-scanning tool. Treat everything
committed here — code, tests, docs, examples, commit messages, issue and PR text —
as public.

## Never commit sensitive or identifying information

Do not write any of the following anywhere in this repository or its history:

- **Real credentials**: API keys, tokens, passwords, private keys, connection
  strings, session keys — even expired, rotated, revoked or "obviously fake
  but copied from somewhere real".
- **Anything derived from real credentials**: `secret_hash` values, masked
  previews, fingerprints, partial prefixes/suffixes, entropy values or line
  numbers taken from an actual scan.
- **Real scan results**: report excerpts, CSV/JSONL/SARIF output, dashboards,
  screenshots, counts or statistics from scanning a specific organisation.
- **Identities**: names of real organisations, GitHub users, institutions,
  repositories, file paths inside them, commit SHAs, author emails, hostnames,
  usernames, home or scratch directory paths, cluster or machine names.
- **Environment details** that reveal where or by whom the tool is run
  (internal URLs, tokens in example commands, CI secrets).

Use neutral placeholders instead: `my-org`, `octo-org`, `some-repo`,
`/path/to/scratch`, `<secret_hash from a report>`.

## Test data

- Generate token-shaped test strings **at runtime** with random characters, and
  assemble recognisable prefixes by concatenation (e.g. `"ghp" + "_" + ...`), so
  no literal matches a real detector or GitHub push protection.
- Never paste scanner output from a real repository into fixtures; build
  synthetic records by hand.
- Tests must keep asserting that no plaintext secret reaches any output file.

## Tuning from real-world scans

Heuristics (detector tiers, path tags, weights) may be informed by private scans,
but describe the lesson generically ("keyword detectors fire on base64 notebook
outputs"), never the organisation, repository, file or finding that taught it.

## Before committing

Search the diff for organisation/user names, real paths, long hex strings and
token prefixes (`ghp_`, `sk-`, `AKIA`, `xox`, `-----BEGIN`), and check commit
messages too. If something sensitive was committed, stop and tell the
maintainer; don't just delete it in a follow-up commit, because it stays in history.
