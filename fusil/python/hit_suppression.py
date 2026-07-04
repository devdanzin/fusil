"""Regex-based hit suppression for the Python fuzzer (issue #53).

Pure-Python engine (no runtime stack), mirroring ``oom_dedup.py``'s split so it unit-tests
in isolation. A "hit" is a crashing session that scored as a success; this engine decides,
from that session's captured stdout, whether the hit matches a user- or plugin-supplied
suppression regex -- a known or uninteresting crash the maintainer would otherwise drop by
hand when deduplicating -- and should be pruned rather than persisted. The matched rule's
reason is returned so the caller can record it in the logs.

Rules come from three composable sources, unioned in this order:
  * repeatable ``--suppress-hit-regex`` command-line options,
  * one or more ``--suppress-hit-file`` files, and
  * plugins (via ``PluginManager.add_suppression_entry`` -- issue #52).

Suppression-file format (one rule per line):
  * blank lines and lines whose first non-space character is ``#`` are ignored (comments),
  * an optional human-readable reason may follow the regex after a `` ## `` separator, e.g.
    ``Objects/dictobject\\.c:205 ## known FT set_keys OOM assert (benign on release)``.
Matching is ``re.search`` over the decoded stdout, case-sensitive unless ``ignore_case``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Separator between a regex and its optional human reason in a suppression file. Chosen to be
# readable in a hand-authored file and very unlikely to occur inside a real stdout regex.
REASON_SEPARATOR = " ## "


class InvalidSuppressionRule(ValueError):
    """A suppression pattern failed to compile (bad regex)."""


@dataclass
class SuppressionRule:
    """A compiled hit-suppression rule: a regex plus an optional human reason."""

    pattern: str
    reason: str | None
    regex: re.Pattern[str]

    def matches(self, text: str) -> bool:
        return self.regex.search(text) is not None


def compile_rule(
    pattern: str, reason: str | None = None, ignore_case: bool = False
) -> SuppressionRule:
    """Compile a single pattern into a SuppressionRule, raising on a bad regex."""
    flags = re.IGNORECASE if ignore_case else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as err:
        raise InvalidSuppressionRule(f"invalid suppression regex {pattern!r}: {err}") from err
    return SuppressionRule(pattern=pattern, reason=reason, regex=regex)


def parse_suppression_file(text: str, ignore_case: bool = False) -> list[SuppressionRule]:
    """Parse a suppression file's contents into rules (see module docstring for format)."""
    rules: list[SuppressionRule] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if REASON_SEPARATOR in line:
            pattern, reason = line.split(REASON_SEPARATOR, 1)
            reason = reason.strip() or None
        elif line.endswith(REASON_SEPARATOR.rstrip()):
            # a dangling ' ##' with an empty reason (the trailing space was stripped away)
            pattern, reason = line[: -len(REASON_SEPARATOR.rstrip())], None
        else:
            pattern, reason = line, None
        rules.append(compile_rule(pattern.strip(), reason, ignore_case=ignore_case))
    return rules


class HitSuppressor:
    """Holds suppression rules and decides whether a crashing hit's stdout should be dropped."""

    def __init__(self, rules):
        self.rules = list(rules)
        self.suppressed_count = 0
        self._hits_by_pattern: dict[str, int] = {}

    def __bool__(self):
        return bool(self.rules)

    def match(self, text: str) -> SuppressionRule | None:
        """Return the first rule whose regex matches ``text``, or None."""
        for rule in self.rules:
            if rule.matches(text):
                return rule
        return None

    def decide(self, text: str):
        """Return ``(keep, rule)``: ``keep`` is False (drop the hit) when a rule matches.

        On a match the hit is tallied for :meth:`report`; ``rule`` is the matched
        :class:`SuppressionRule` (carrying ``.reason`` and ``.pattern``), or None when
        nothing matched (``keep`` True).
        """
        rule = self.match(text)
        if rule is None:
            return True, None
        self.suppressed_count += 1
        self._hits_by_pattern[rule.pattern] = self._hits_by_pattern.get(rule.pattern, 0) + 1
        return False, rule

    def report(self) -> str:
        """A one-shot summary of how many hits each rule dropped (for the exit log)."""
        if not self.suppressed_count:
            return "Hit suppression: no hits dropped (%d rule(s) active)" % len(self.rules)
        lines = [
            "Hit suppression: dropped %d hit(s) via %d of %d rule(s):"
            % (self.suppressed_count, len(self._hits_by_pattern), len(self.rules))
        ]
        by_pattern = {r.pattern: r for r in self.rules}
        for pattern, count in sorted(self._hits_by_pattern.items(), key=lambda kv: (-kv[1], kv[0])):
            reason = by_pattern[pattern].reason if pattern in by_pattern else None
            suffix = "  (%s)" % reason if reason else ""
            lines.append("    %5d  %s%s" % (count, pattern, suffix))
        return "\n".join(lines)


def build_suppressor(
    regexes=None, files=None, plugin_entries=None, ignore_case=False
) -> HitSuppressor:
    """Build a HitSuppressor from CLI regexes, suppression files, and plugin entries.

    ``regexes``: iterable of pattern strings (from ``--suppress-hit-regex``).
    ``files``: iterable of file paths (from ``--suppress-hit-file``), read as UTF-8.
    ``plugin_entries``: iterable of ``(pattern, reason)`` pairs (PluginManager entries).
    Rules are unioned in that order. Raises :class:`InvalidSuppressionRule` on a bad
    pattern and lets file-read errors (OSError) propagate to the caller.
    """
    rules: list[SuppressionRule] = []
    for pattern in regexes or ():
        rules.append(compile_rule(pattern, None, ignore_case=ignore_case))
    for path in files or ():
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        rules.extend(parse_suppression_file(text, ignore_case=ignore_case))
    for pattern, reason in plugin_entries or ():
        rules.append(compile_rule(pattern, reason, ignore_case=ignore_case))
    return HitSuppressor(rules)
