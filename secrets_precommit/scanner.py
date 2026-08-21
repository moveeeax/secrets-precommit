"""The scanner: turn files into findings, filtered by allowlist and baseline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .allowlist import Allowlist
from .baseline import Baseline, fingerprint
from .rules import RULES, rule_value

# Files above this size are almost always build artefacts or media; scanning
# them line-by-line with a dozen regexes is slow and pointless.
MAX_FILE_BYTES = 2_000_000


@dataclass
class Finding:
    rule_id: str
    description: str
    path: str
    line: int
    secret: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, self.path, self.secret)

    def redacted(self) -> str:
        s = self.secret
        if len(s) <= 8:
            return s[0] + "*" * (len(s) - 1) if s else s
        return f"{s[:4]}…{s[-4:]}"


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def scan_text(text: str, path: str, allowlist: Allowlist) -> list[Finding]:
    """Scan already-loaded text. Split out so tests need no filesystem."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if allowlist.allows_rule(rule.id):
                continue
            for m in rule.pattern.finditer(line):
                value = rule_value(m)
                if allowlist.allows_value(value):
                    continue
                findings.append(
                    Finding(rule.id, rule.description, path, lineno, value)
                )
    return findings


def scan_file(path: str | Path, allowlist: Allowlist) -> list[Finding]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return []
        raw = p.read_bytes()
    except (OSError, ValueError):
        return []
    if _looks_binary(raw[:1024]):
        return []
    text = raw.decode("utf-8", errors="replace")
    return scan_text(text, str(path), allowlist)


def scan_paths(
    paths: list[str],
    allowlist: Allowlist,
    baseline: Baseline | None = None,
) -> list[Finding]:
    """Scan a list of files, dropping allowlisted paths and baselined findings."""
    baseline = baseline or Baseline.empty()
    results: list[Finding] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_file():
            continue
        if allowlist.allows_path(str(p)):
            continue
        for f in scan_file(p, allowlist):
            if baseline.contains(f.fingerprint):
                continue
            results.append(f)
    return results
