"""Command-line entrypoint. This is what the pre-commit hook and CI both call,
so that "green in CI" and "green locally" mean exactly the same thing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .allowlist import Allowlist
from .baseline import Baseline
from .scanner import Finding, scan_paths

DEFAULT_ALLOWLIST = ".secrets-allowlist.yaml"
DEFAULT_BASELINE = ".secrets-baseline.json"


# Directories that are never worth walking: VCS internals (the .git/config of a
# cloned repo literally contains an auth token in its remote URL), caches, and
# virtualenvs. pre-commit passes explicit files so this only bites `scan .`.
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}


def _collect(files: list[str]) -> list[str]:
    """Expand any directory arguments into their files; keep file args as-is.
    pre-commit passes explicit files, but a human running `... scan .` expects
    a recursive walk."""
    out: list[str] = []
    for f in files:
        p = Path(f)
        if p.is_dir():
            for c in p.rglob("*"):
                if not c.is_file():
                    continue
                if any(part in _SKIP_DIRS for part in c.parts):
                    continue
                out.append(str(c))
        else:
            out.append(f)
    return out


def _print_findings(findings: list[Finding], stream=sys.stderr) -> None:
    for f in findings:
        print(
            f"{f.path}:{f.line}: {f.rule_id}: {f.description} "
            f"[{f.redacted()}] (fingerprint {f.fingerprint})",
            file=stream,
        )


def cmd_scan(args: argparse.Namespace) -> int:
    allowlist = Allowlist.load(args.allowlist)
    baseline = Baseline.load(args.baseline)
    findings = scan_paths(_collect(args.files), allowlist, baseline)
    if findings:
        print(
            f"secrets-precommit: {len(findings)} potential secret(s) found:",
            file=sys.stderr,
        )
        _print_findings(findings)
        print(
            "\nIf these are false positives, allowlist them in "
            f"{args.allowlist}; to adopt on an existing repo run "
            "`secrets-precommit baseline`.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    allowlist = Allowlist.load(args.allowlist)
    # A baseline is generated against *all* current findings, ignoring any
    # existing baseline, so it captures the true current state.
    findings = scan_paths(_collect(args.files), allowlist, Baseline.empty())
    baseline = Baseline({f.fingerprint for f in findings})
    baseline.save(args.baseline)
    print(
        f"secrets-precommit: wrote baseline with {len(baseline.fingerprints)} "
        f"accepted finding(s) to {args.baseline}",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets-precommit",
        description="Block committed secrets before they hit history.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    common.add_argument("--baseline", default=DEFAULT_BASELINE)

    p_scan = sub.add_parser("scan", parents=[common], help="scan files for secrets")
    p_scan.add_argument("files", nargs="*", default=["."])
    p_scan.set_defaults(func=cmd_scan)

    p_base = sub.add_parser(
        "baseline",
        parents=[common],
        help="record current findings as accepted (accept-known)",
    )
    p_base.add_argument("files", nargs="*", default=["."])
    p_base.set_defaults(func=cmd_baseline)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.files:
        args.files = ["."]
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
