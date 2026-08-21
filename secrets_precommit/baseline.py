"""Baseline handling: accept-known findings so existing repos adopt cleanly.

A brand-new repo can start clean. A ten-year-old monorepo cannot — it already
has a dozen historical "secrets" (rotated keys, test tokens, false positives)
that no one is going to clean up as the price of turning on a hook. The baseline
records a stable fingerprint for each *currently known* finding; on later runs a
finding whose fingerprint is in the baseline is suppressed. New secrets still
fail. That is the difference between a hook a team adopts and one they rip out.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    """Stable ID for a finding. Independent of line number so that unrelated
    edits above a known finding do not resurrect it."""
    norm = path.replace("\\", "/")
    h = hashlib.sha256(f"{rule_id}\0{norm}\0{secret}".encode()).hexdigest()
    return h[:16]


@dataclass
class Baseline:
    fingerprints: set[str]

    @classmethod
    def empty(cls) -> "Baseline":
        return cls(set())

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        if not p.exists():
            return cls.empty()
        data = json.loads(p.read_text() or "{}")
        return cls(set(data.get("fingerprints", [])))

    def contains(self, fp: str) -> bool:
        return fp in self.fingerprints

    def save(self, path: str | Path, meta: dict | None = None) -> None:
        payload = {
            "_comment": "secrets-precommit baseline: known findings accepted so "
            "the hook can be adopted on an existing repo. New secrets still fail.",
            "version": 1,
            "fingerprints": sorted(self.fingerprints),
        }
        if meta:
            payload.update(meta)
        Path(path).write_text(json.dumps(payload, indent=2) + "\n")
