# Onboarding a repo

A four-step path from "no secret scanning" to "the hook is on and green,"
including the awkward middle case of a repo that already has secrets in it.

## 1. Wire the hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/moveeeax/secrets-precommit
    rev: v0.1.0
    hooks:
      - id: secrets-precommit
```

Then:

```console
$ pre-commit install
$ pre-commit run secrets-precommit --all-files
```

For defence in depth, also add `gitleaks` and `trufflehog` — see
[`examples/consumer-pre-commit-config.yaml`](../examples/consumer-pre-commit-config.yaml).

## 2. Deal with false positives

If the first run flags documented placeholders or test fixtures, allowlist them
in `.secrets-allowlist.yaml` rather than disabling the hook:

```yaml
paths:
  - "tests/fixtures/*"
  - "docs/**"
regexes:
  - "AKIAIOSFODNN7EXAMPLE"     # canonical AWS placeholder
rules: []
```

- `paths`   — globs matched on both full path and basename.
- `regexes` — matched against the detected *value*; use for known placeholders.
- `rules`   — rule IDs to disable entirely (rare; prefer the narrower knobs).

## 3. Baseline an existing repo (accept-known)

A repo with real history usually has findings you can't clean up today (rotated
keys, sample data). Record them as accepted so the hook can go on now, while any
**new** secret still fails:

```console
$ secrets-precommit baseline .
secrets-precommit: wrote baseline with 12 accepted finding(s) to .secrets-baseline.json
$ git add .secrets-baseline.json
$ git commit -m "Add secrets baseline"
```

The baseline stores line-independent fingerprints, so ordinary edits don't
reintroduce accepted findings. Re-run `baseline` whenever you deliberately
accept new known findings.

## 4. Mirror it in CI

Run the identical command in CI so a bypassed local hook (`--no-verify`) is
still caught on the server:

```yaml
- name: Secret scan
  run: |
    pip install "secrets-precommit @ git+https://github.com/moveeeax/secrets-precommit@v0.1.0"
    secrets-precommit scan .
```

Because CI and the hook call the same `secrets-precommit scan`, they can never
disagree about what counts as a secret.
