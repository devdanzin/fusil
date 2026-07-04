"""Unit tests for the regex hit-suppression engine (fusil.python.hit_suppression, issue #53).

Pure-Python: exercises rule compilation, file parsing, the keep/drop decision, and the
report, without the python-ptrace runtime stack, so it runs in the dev venv.
"""

import os
import tempfile
import unittest

from fusil.python import hit_suppression as hs

# A crash stdout that names a specific abort site (the kind the maintainer dedups by hand).
CRASH = "\n".join(
    [
        "Fatal Python error: Segmentation fault",
        "python: Objects/dictobject.c:205: set_keys: Assertion failed.",
        "Current thread 0x00 (most recent call first):",
    ]
)


class TestCompileRule(unittest.TestCase):
    def test_valid_pattern_matches_via_search(self):
        rule = hs.compile_rule(r"dictobject\.c:205", reason="known FT assert")
        self.assertEqual(rule.reason, "known FT assert")
        self.assertTrue(rule.matches(CRASH))
        self.assertFalse(rule.matches("nothing to see here"))

    def test_invalid_pattern_raises(self):
        with self.assertRaises(hs.InvalidSuppressionRule):
            hs.compile_rule(r"unbalanced(")

    def test_ignore_case(self):
        self.assertFalse(hs.compile_rule("ASSERTION").matches(CRASH))
        self.assertTrue(hs.compile_rule("ASSERTION", ignore_case=True).matches(CRASH))


class TestParseFile(unittest.TestCase):
    def test_comments_blanks_and_reason_separator(self):
        text = "\n".join(
            [
                "# a comment",
                "",
                "   ",
                r"dictobject\.c:205 ## FT set_keys OOM assert",
                r"segfault",
                "  # indented comment is NOT stripped as comment (starts with space)",
            ]
        )
        rules = hs.parse_suppression_file(text)
        # 3 non-comment, non-blank lines. The "indented comment" starts with '#' after strip,
        # so it IS treated as a comment.
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].pattern, r"dictobject\.c:205")
        self.assertEqual(rules[0].reason, "FT set_keys OOM assert")
        self.assertEqual(rules[1].pattern, "segfault")
        self.assertIsNone(rules[1].reason)

    def test_empty_reason_after_separator_is_none(self):
        (rule,) = hs.parse_suppression_file("pattern ## ")
        self.assertEqual(rule.pattern, "pattern")
        self.assertIsNone(rule.reason)


class TestHitSuppressor(unittest.TestCase):
    def test_no_rules_keeps_everything(self):
        sup = hs.HitSuppressor([])
        self.assertFalse(sup)  # __bool__
        keep, rule = sup.decide(CRASH)
        self.assertTrue(keep)
        self.assertIsNone(rule)

    def test_match_drops_and_returns_rule(self):
        sup = hs.HitSuppressor([hs.compile_rule(r"Objects/dictobject\.c:205", "known")])
        self.assertTrue(sup)
        keep, rule = sup.decide(CRASH)
        self.assertFalse(keep)
        self.assertEqual(rule.reason, "known")
        self.assertEqual(sup.suppressed_count, 1)

    def test_no_match_keeps(self):
        sup = hs.HitSuppressor([hs.compile_rule("this-never-appears")])
        keep, rule = sup.decide(CRASH)
        self.assertTrue(keep)
        self.assertIsNone(rule)
        self.assertEqual(sup.suppressed_count, 0)

    def test_first_matching_rule_wins(self):
        first = hs.compile_rule("Fatal Python error", "generic fatal")
        second = hs.compile_rule(r"dictobject\.c:205", "specific")
        sup = hs.HitSuppressor([first, second])
        _, rule = sup.decide(CRASH)
        self.assertEqual(rule.reason, "generic fatal")

    def test_report_counts_per_rule(self):
        sup = hs.HitSuppressor(
            [hs.compile_rule(r"dictobject\.c:205", "known site"), hs.compile_rule("never-here")]
        )
        for _ in range(3):
            sup.decide(CRASH)
        report = sup.report()
        self.assertIn("dropped 3 hit(s)", report)
        self.assertIn("dictobject", report)
        self.assertIn("(known site)", report)

    def test_report_when_nothing_dropped(self):
        sup = hs.HitSuppressor([hs.compile_rule("x")])
        self.assertIn("no hits dropped", sup.report())


class TestBuildSuppressor(unittest.TestCase):
    def test_unions_cli_file_and_plugin_rules(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("from-file ## file reason\n")
        self.addCleanup(os.unlink, path)

        sup = hs.build_suppressor(
            regexes=["from-cli"],
            files=[path],
            plugin_entries=[("from-plugin", "plugin reason")],
        )
        self.assertEqual(len(sup.rules), 3)
        patterns = [r.pattern for r in sup.rules]
        self.assertEqual(patterns, ["from-cli", "from-file", "from-plugin"])
        # reasons: CLI rule has none; file/plugin carry theirs
        self.assertIsNone(sup.rules[0].reason)
        self.assertEqual(sup.rules[1].reason, "file reason")
        self.assertEqual(sup.rules[2].reason, "plugin reason")

    def test_ignore_case_propagates(self):
        sup = hs.build_suppressor(regexes=["ASSERTION"], ignore_case=True)
        self.assertFalse(sup.decide(CRASH)[0])

    def test_bad_regex_raises(self):
        with self.assertRaises(hs.InvalidSuppressionRule):
            hs.build_suppressor(regexes=["oops("])

    def test_empty_sources_build_empty(self):
        self.assertFalse(hs.build_suppressor())


if __name__ == "__main__":
    unittest.main()
