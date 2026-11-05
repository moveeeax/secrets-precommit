# secrets-precommit

> Block committed secrets before they ever hit history.

[![ci](https://github.com/moveeeax/secrets-precommit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/secrets-precommit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen.svg)](https://pre-commit.com/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A pre-commit bundle that stops secrets at the one place it's cheap to stop them:
before the commit. It ships a fast, dependency-light scanner with a **curated
ruleset**, an **allowlist** to kill false positives, and a **baseline** so an
existing repo full of historical "secrets" can adopt the hook without a
day-one cleanup. It also wires the heavier hitters — `gitleaks` and
`trufflehog` — for teams that want defence in depth.

## Why

The expensive way to find a secret is a rotation ticket after it's already in
`git log`. Every other control is downstream of the commit. A pre-commit hook
is the earliest, cheapest gate — but only if people actually keep it on, and
they only keep it on if it doesn't cry wolf. So the whole design here is about
the *false-positive story*: an allowlist for placeholders and fixtures, and a
baseline so turning the hook on doesn't drown you in ten years of legacy noise.

## What it does

- Scans files for secret-shaped strings using a small, high-signal ruleset
  (AWS keys, GitHub/Slack/Google/Stripe tokens, PEM private keys, JWTs, and
  generic `password = "..."` literals).
- **Allowlist** (`.secrets-allowlist.yaml`) suppresses by file glob, by secret
  value regex (documented placeholders like `AKIAIOSFODNN7EXAMPLE`), or by rule.
- **Baseline** (`.secrets-baseline.json`) records known findings as *accepted*
  so an existing repo adopts cleanly — new secrets still fail.
- **CI job** runs the exact same command as the local hook, so "green locally"
  and "green in CI" mean the same thing.
- Redacts matched values in output (`ghp_…7UaG`) — no leaking the secret while
  reporting it.

## Install

Add to a downstream repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/moveeeax/secrets-precommit
    rev: v0.1.0
    hooks:
      - id: secrets-precommit
```

```console
$ pre-commit install
$ pre-commit run secrets-precommit --all-files
```

The fuller wiring (this bundle **plus** `gitleaks` and `trufflehog`) is in
[`examples/consumer-pre-commit-config.yaml`](examples/consumer-pre-commit-config.yaml).

## Usage

Scan explicitly (this is what the hook and CI run):

```console
$ secrets-precommit scan src/ config/
secrets-precommit: 1 potential secret(s) found:
src/settings.py:42: aws-access-key-id: AWS access key ID [AKIA…DE01] (fingerprint f93b14148f0015e0)

If these are false positives, allowlist them in .secrets-allowlist.yaml; to
adopt on an existing repo run `secrets-precommit baseline`.
$ echo $?
1
```

Adopt on an existing repo (accept everything that's there today, fail on
anything new):

```console
$ secrets-precommit baseline .
secrets-precommit: wrote baseline with 12 accepted finding(s) to .secrets-baseline.json
$ git add .secrets-baseline.json && git commit -m "Add secrets baseline"
```

Allowlist a placeholder or a fixtures directory — `.secrets-allowlist.yaml`:

```yaml
paths:
  - "tests/fixtures/*"
regexes:
  - "AKIAIOSFODNN7EXAMPLE"
rules: []          # e.g. ["jwt"] to disable a whole rule
```

## How it works

The scanner reads each file, skips binaries and anything over 2 MB, and runs the
compiled ruleset line by line. Each match is reduced to a stable **fingerprint**
— `sha256(rule_id, path, secret)`, truncated — that is *independent of line
number*, so editing code above a known finding doesn't resurrect it. The
allowlist filters matches by path, value, or rule; the baseline filters by
fingerprint. What survives is a real finding, and a non-empty finding list is a
non-zero exit code. The pre-commit hook, the CI job, and your terminal all call
the same `secrets-precommit scan`.

## Development

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest -q
```

CI runs the tests, self-scans the repo, and asserts the planted fixtures in
`examples/` fail when the allowlist is removed.

## License

MIT — see [LICENSE](LICENSE).

---

**Archived on 2026-11-05.** gitleaks, trufflehog and detect-secrets are mature, ship far larger rulesets, and between them already have allowlists and baselines; this repo's own example config wires gitleaks and trufflehog, so the custom scanner adds little.
