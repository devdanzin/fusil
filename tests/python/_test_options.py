"""Shared test helper: a fully-populated fuzzer *options* object.

Tests that instantiate ``WritePythonCode`` (and friends) need an options object that
carries every ``--*`` attribute the generator reads. Hand-maintaining that list in each
test's ``setUp`` is what rotted the suite before (a new option added to the code ->
``AttributeError`` in every test). Instead we harvest the **real** defaults straight from
the fuzzer's own option parser, so new options appear automatically.

Not collected by ``unittest discover`` (the default pattern is ``test*.py``; this module's
name starts with an underscore).
"""

from functools import lru_cache
from optparse import OptionParser
from types import SimpleNamespace

from fusil.python import Fuzzer


@lru_cache(maxsize=1)
def _harvested_defaults():
    """All fuzzing-option defaults, harvested from Fuzzer.createFuzzerOptions().

    createFuzzerOptions only touches the parser plus ``self.plugin_manager.get_cli_options``,
    so a tiny stub is enough to drive it without constructing a full Application.
    """
    parser = OptionParser()
    stub = SimpleNamespace(plugin_manager=SimpleNamespace(get_cli_options=lambda: []))
    Fuzzer.createFuzzerOptions(stub, parser)
    return vars(parser.get_default_values())


def make_test_options(**overrides):
    """Return an options object carrying every real fuzzer-option default, then any
    ``overrides``. Use this in test ``setUp`` instead of hand-listing options.

    Mirrors what ``application.parseOptions`` produces at runtime -- the parsed optparse
    ``Values`` -- as a plain ``SimpleNamespace`` that tests can freely read and mutate."""
    return SimpleNamespace(**{**_harvested_defaults(), **overrides})
