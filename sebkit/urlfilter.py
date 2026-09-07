"""
URL allowlist construction and breadth analysis.

With URLFilterEnable on, SEB denies by default: a request that matches no rule
is blocked. That makes the allowlist the entire perimeter, and it is where
real exam configurations leak. A rule like `*.medtech.tn/*` looks tight and is
not - it grants the library, the wiki, webmail, and anything else ever hosted
under the institution's domain.

This module builds the minimum rule set a Moodle quiz needs, and scores any
existing rule set for how much it actually lets through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

ACTION_BLOCK = 0
ACTION_ALLOW = 1

ACTION_NAMES = {ACTION_BLOCK: "block", ACTION_ALLOW: "allow"}


@dataclass(frozen=True)
class FilterRule:
    expression: str
    action: int = ACTION_ALLOW
    regex: bool = False
    active: bool = True

    def to_seb(self) -> dict:
        return {
            "active": self.active,
            "expression": self.expression,
            "regex": self.regex,
            "action": self.action,
        }


@dataclass(frozen=True)
class BreadthFinding:
    expression: str
    severity: str  # "critical" | "high" | "medium"
    reason: str


# Expressions that place no meaningful restriction at all.
_WILDCARD_ONLY = re.compile(r"^[*./\\\s]*$")
# A bare public suffix with a wildcard in front, e.g. "*.tn/*" or "*.com/*".
_BARE_SUFFIX = re.compile(r"^\*\.[a-z]{2,4}(/\*?)?$", re.IGNORECASE)
# Regex expressions that match everything.
_REGEX_MATCH_ALL = {".*", "^.*$", ".+", "^.+$", "(.*)", "^(.*)$"}

# Hosts that, once allowed, defeat the point of an allowlist.
_HIGH_RISK_HOSTS = {
    "google.com", "www.google.com", "bing.com", "duckduckgo.com",
    "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com",
    "perplexity.ai", "copilot.microsoft.com", "poe.com",
    "translate.google.com", "wikipedia.org", "en.wikipedia.org",
    "chegg.com", "coursehero.com", "studocu.com", "quizlet.com",
    "stackoverflow.com", "github.com", "gist.github.com",
    "drive.google.com", "docs.google.com", "mail.google.com",
    "web.whatsapp.com", "web.telegram.org", "discord.com", "messenger.com",
    "pastebin.com", "reddit.com", "youtube.com",
}


def normalise_host(url_or_host: str) -> str:
    """Extract a bare lowercase hostname from a URL or host string."""
    value = url_or_host.strip()
    if "//" not in value:
        value = "https://" + value
    host = urlsplit(value).hostname or ""
    return host.lower()


def build_moodle_rules(
    quiz_url: str,
    *,
    extra_allowed: list[str] | None = None,
    allow_static_cdn: bool = False,
) -> list[FilterRule]:
    """Build a least-privilege allowlist for a Moodle quiz.

    Scoped to the Moodle host only. Moodle serves its own JavaScript, CSS and
    question media from that host, so a correctly configured quiz needs nothing
    else - which is exactly what makes a tight rule set practical here.
    """
    host = normalise_host(quiz_url)
    if not host:
        raise ValueError(f"could not determine a hostname from {quiz_url!r}")

    rules = [
        FilterRule(expression=f"{host}/*", action=ACTION_ALLOW),
        FilterRule(expression=f"https://{host}/*", action=ACTION_ALLOW),
    ]

    for entry in extra_allowed or []:
        entry = entry.strip()
        if not entry:
            continue
        expression = entry if ("/" in entry or "*" in entry) else f"{entry}/*"
        rules.append(FilterRule(expression=expression, action=ACTION_ALLOW))

    if allow_static_cdn:
        # Some Moodle themes pull fonts/icons from these. Left off by default:
        # switch on only if the quiz visibly fails to render without them.
        for host_pattern in ("fonts.googleapis.com/*", "fonts.gstatic.com/*", "cdn.jsdelivr.net/*"):
            rules.append(FilterRule(expression=host_pattern, action=ACTION_ALLOW))

    return rules


def analyse_rules(rules: list[dict]) -> list[BreadthFinding]:
    """Score an existing URLFilterRules array for over-broad entries."""
    findings: list[BreadthFinding] = []

    for raw in rules:
        if not isinstance(raw, dict):
            continue
        if not raw.get("active", True):
            continue
        if raw.get("action", ACTION_ALLOW) != ACTION_ALLOW:
            continue

        expression = str(raw.get("expression", "")).strip()
        is_regex = bool(raw.get("regex", False))

        if not expression:
            continue

        if is_regex and expression in _REGEX_MATCH_ALL:
            findings.append(BreadthFinding(
                expression, "critical",
                "This regular expression matches every URL, so the allowlist permits the whole internet.",
            ))
            continue

        if not is_regex and _WILDCARD_ONLY.match(expression):
            findings.append(BreadthFinding(
                expression, "critical",
                "This expression is only wildcards, so the allowlist permits the whole internet.",
            ))
            continue

        if _BARE_SUFFIX.match(expression):
            findings.append(BreadthFinding(
                expression, "critical",
                "This allows an entire top-level domain, not a single site.",
            ))
            continue

        host = normalise_host(expression.replace("*.", "").split("/")[0])
        if host in _HIGH_RISK_HOSTS:
            findings.append(BreadthFinding(
                expression, "critical",
                f"{host} is a search engine, AI assistant, answer site or messaging service - "
                "allowing it defeats the exam.",
            ))
            continue

        if expression.startswith("*.") and expression.count(".") <= 2:
            findings.append(BreadthFinding(
                expression, "high",
                "A wildcard across a whole domain also allows every other service hosted under it "
                "(webmail, wikis, shared drives, student sites).",
            ))
            continue

        if not is_regex and "/" not in expression:
            findings.append(BreadthFinding(
                expression, "medium",
                "No path restriction, so the entire site is reachable, not just the exam.",
            ))

    return findings


def describe_rules(rules: list[dict]) -> list[str]:
    """Human-readable one-line summaries of a rule array, for the report."""
    lines = []
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        state = "" if raw.get("active", True) else " (inactive)"
        action = ACTION_NAMES.get(raw.get("action", ACTION_ALLOW), "?")
        kind = "regex" if raw.get("regex") else "pattern"
        lines.append(f"{action:>5}  {raw.get('expression', '')}  [{kind}]{state}")
    return lines
