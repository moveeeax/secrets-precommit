"""Curated secret-detection rules.

Each rule is a named, compiled regex plus a short human description. The set is
deliberately small and high-signal: I would rather miss an exotic token than
drown a team in false positives on their first day with the hook. Extra rules
are easy to bolt on; noisy rules are hard to walk back once people learn to
ignore the hook.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    description: str
    pattern: re.Pattern[str]


# The value-bearing group is always group 1 when present, otherwise the whole
# match. `_val` normalises that so the scanner never has to care.
def _val(match: re.Match[str]) -> str:
    if match.re.groups >= 1 and match.group(1) is not None:
        return match.group(1)
    return match.group(0)


RULES: list[Rule] = [
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16})\b"),
    ),
    Rule(
        "aws-secret-access-key",
        "AWS secret access key",
        re.compile(
            r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]?([0-9a-zA-Z/+]{40})['\"]?"
        ),
    ),
    Rule(
        "github-token",
        "GitHub personal-access / OAuth token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b"),
    ),
    Rule(
        "github-fine-grained-token",
        "GitHub fine-grained PAT",
        re.compile(r"\b(github_pat_[0-9A-Za-z_]{82})\b"),
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ),
    Rule(
        "stripe-secret-key",
        "Stripe secret key",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,99})\b"),
    ),
    Rule(
        "slack-webhook",
        "Slack incoming webhook URL",
        re.compile(
            r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)"
        ),
    ),
    Rule(
        "private-key",
        "PEM private key block",
        re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"),
    ),
    Rule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    ),
    Rule(
        "generic-assigned-secret",
        "Generic assigned secret/password/token literal",
        re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
    ),
]


def rule_value(match: re.Match[str]) -> str:
    """Return the secret substring a rule match should fingerprint on."""
    return _val(match)
