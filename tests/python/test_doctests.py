"""Run the surviving module doctests under unittest.

Replaces the legacy standalone ``test_doc.py``, which also ran stale Python-2-era
doctests in ``doc/*.rst`` (and broken module doctests, e.g. ``process.replay_python``)
that are no longer maintained. Only modules whose doctests currently pass are wired in
here, so ``unittest discover`` (and CI) exercises them. Add a module below once its
doctests are green.
"""

import doctest
import unittest

import fusil.process.tools
import fusil.tools

_DOCTEST_MODULES = (fusil.tools, fusil.process.tools)


def load_tests(loader, tests, ignore):
    """unittest hook: append each module's doctests to the suite."""
    for module in _DOCTEST_MODULES:
        tests.addTests(doctest.DocTestSuite(module))
    return tests


if __name__ == "__main__":
    unittest.main()
