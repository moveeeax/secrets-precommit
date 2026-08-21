"""Allowlist loading and matching.

The allowlist is the pressure valve that keeps a secret scanner usable. Without
it the first ``example.pem`` or documented ``AKIAEXAMPLE`` turns the hook into
noise people learn to ``--no-verify`` past. Three axes cover the real cases:

- ``paths``   — glob patterns for files that are allowed to contain "secrets"
                (test fixtures, docs, vendored samples).
- ``regexes`` — patterns matched against the detected secret *value*; use for
                well-known placeholders like ``AKIAIOSFODNN7EXAMPLE``.
- ``rules``   — rule IDs to disable wholesale (rarely needed, but honest).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - yaml is a hard dependency
    yaml = None


@dataclass
class Allowlist:
    paths: list[str] = field(default_factory=list)
    regexes: list[re.Pattern[str]] = field(default_factory=list)
    rules: set[str] = field(default_factory=set)

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls()

    @classmethod
    def from_dict(cls, data: dict | None) -> "Allowlist":
        data = data or {}
        return cls(
            paths=list(data.get("paths", []) or []),
            regexes=[re.compile(p) for p in (data.get("regexes", []) or [])],
            rules=set(data.get("rules", []) or []),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Allowlist":
        p = Path(path)
        if not p.exists():
            return cls.empty()
        if yaml is None:  # pragma: no cover
            raise RuntimeError("PyYAML is required to read an allowlist file")
        return cls.from_dict(yaml.safe_load(p.read_text()) or {})

    def allows_path(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        return any(
            fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(Path(norm).name, pat)
            for pat in self.paths
        )

    def allows_value(self, value: str) -> bool:
        return any(rx.search(value) for rx in self.regexes)

    def allows_rule(self, rule_id: str) -> bool:
        return rule_id in self.rules
