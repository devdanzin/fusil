"""Discover a target module's members by introspecting it in a subprocess running the TARGET
interpreter (`--python`), instead of importing the extension in the runner venv.

Motivation: fusil normally imports the target module in the *runner* process to enumerate its
functions/classes/objects and their arities/methods, which forces the runner venv to have the
target extension installed -- painful for FT/debug CPython builds with no wheels, or when the
runner and target are different interpreters. But the generated ``source.py`` already re-imports
the module *by name in the target*, so the extension is present where the fuzzing runs; only the
runner-side introspection needs it. This module moves that introspection into the target.

Design: the subprocess (``_DISCOVERY_SRC``) is a **stdlib-only** introspector -- it imports the
module and emits *raw* per-member metadata as JSON on stdout. It applies **no fusil policy**
(blacklists, ``--test-private``, ``--fuzz-exceptions``, name-table arity overrides); the parent
(:class:`WritePythonCode`) keeps all of that. So the script needs none of fusil's tables and stays
stable. Arity mirrors :func:`fusil.python.arg_numbers.get_arg_number`'s argspec branch
(``args - defaults, args`` with ``self``/``cls`` discounted); when ``getfullargspec`` fails (C /
PyO3 builtins) it emits ``arity: null`` plus the raw ``__doc__`` so the parent can run its own
``parseDocumentation`` and otherwise fall back to the default range -- faithful to the live path.

The emitted schema (see ``_DISCOVERY_SRC``), one entry per fuzzable member::

    {"module": "<name>", "ok": true, "members": [
        {"name": "f", "kind": "function", "arity": [1, 3], "doc": null},
        {"name": "C", "kind": "class", "is_exception": false,
         "ctor_arity": [1, 2], "ctor_doc": null,
         "methods": [{"name": "m", "arity": [1, 1], "doc": null}, ...]},
        {"name": "OBJ", "kind": "object", "is_module": false, "is_exception": false,
         "class_name": "Foo", "methods": [...]}]}

Module-level members that classify as a bare module or a trivial-typed value (int/str/list/...) are
dropped by the subprocess (never fuzzable), matching ``_get_module_members``'s object branch.
"""

from __future__ import annotations

import json
import subprocess

# The introspection script, run as `python -c _DISCOVERY_SRC <module_name>` under the TARGET
# interpreter. Stdlib-only; prints exactly one JSON object to stdout. Kept deliberately close to
# WritePythonCode._get_module_members / _get_object_methods / arg_numbers.get_arg_number so the
# two discovery paths (runner-live vs target-subprocess) stay in parity.
_DISCOVERY_SRC = r'''
import sys, json, inspect, importlib
from types import FunctionType, BuiltinFunctionType, ModuleType, MethodType

# Mirror WritePythonCode.TRIVIAL_TYPES (top-level object branch skips these).
_TRIVIAL = {int, str, float, bool, bytes, tuple, list, dict, set, type(None)}
_MAX_METHODS = 300


def _arity(obj):
    """(-> [lo, hi] | None, doc). Mirrors arg_numbers.get_arg_number's argspec branch; on failure
    returns (None, first-line-of-__doc__) so the parent can parseDocumentation / default."""
    try:
        spec = inspect.getfullargspec(obj)
    except TypeError:
        doc = getattr(obj, "__doc__", None)
        return None, (doc if isinstance(doc, str) else None)
    has_self = 1 if ("self" in spec.args or "cls" in spec.args) else 0
    args = (len(spec.args) - has_self) if spec.args else 0
    defaults = (len(spec.defaults) - has_self) if spec.defaults else 0
    return [args - defaults, args], None


def _ctor_arity(cls):
    try:
        spec = inspect.getfullargspec(cls.__init__)
    except TypeError:
        doc = getattr(cls, "__doc__", None)
        return None, (doc if isinstance(doc, str) else None)
    args = (len(spec.args) - 1) if spec.args else 0  # drop self
    defaults = len(spec.defaults) if spec.defaults else 0
    return [args - defaults, args], None


def _methods(owner):
    """All callable members of a class/instance (raw; parent applies blacklist/private/plugin
    filtering). Mirrors _get_object_methods' dir()+callable() walk."""
    out = []
    if type(owner) in _TRIVIAL:
        return out
    try:
        names = dir(owner)
    except Exception:
        return out
    for name in names:
        try:
            attr = getattr(owner, name, None)
        except Exception:
            continue
        if attr is None or not callable(attr):
            continue
        ar, doc = _arity(attr)
        out.append({"name": name, "arity": ar, "doc": doc})
        if len(out) >= _MAX_METHODS:
            break
    return out


def main():
    module_name = sys.argv[1]
    try:
        mod = importlib.import_module(module_name)
    except BaseException as exc:  # SystemExit on import, etc.
        print(json.dumps({"module": module_name, "ok": False,
                          "error": "%s: %s" % (type(exc).__name__, exc)}))
        return
    members = []
    try:
        names = dir(mod)
    except Exception as exc:
        print(json.dumps({"module": module_name, "ok": False, "error": str(exc)}))
        return
    for name in names:
        try:
            attr = getattr(mod, name)
        except Exception:
            continue
        try:
            if isinstance(attr, (FunctionType, BuiltinFunctionType, MethodType)) or (
                callable(attr) and not isinstance(attr, type) and not inspect.isclass(attr)
                and type(attr).__name__ in ("builtin_function_or_method", "method_descriptor")
            ):
                ar, doc = _arity(attr)
                members.append({"name": name, "kind": "function", "arity": ar, "doc": doc})
            elif isinstance(attr, type) or inspect.isclass(attr):
                is_exc = isinstance(attr, type) and issubclass(attr, BaseException)
                car, cdoc = _ctor_arity(attr)
                members.append({"name": name, "kind": "class", "is_exception": is_exc,
                                "ctor_arity": car, "ctor_doc": cdoc, "methods": _methods(attr)})
            else:
                if isinstance(attr, ModuleType) or type(attr) in _TRIVIAL:
                    continue  # not fuzzable (matches _get_module_members object branch)
                is_exc = isinstance(attr, BaseException)
                members.append({"name": name, "kind": "object", "is_module": False,
                                "is_exception": is_exc,
                                "class_name": type(attr).__name__, "methods": _methods(type(attr))})
        except Exception:
            continue
    print(json.dumps({"module": module_name, "ok": True, "members": members}))


main()
'''


def introspect_module(python_path, module_name, env=None, timeout=60):
    """Run the discovery script under ``python_path`` and return the parsed metadata dict.

    Returns the ``{"module","ok","members"}`` dict on success, or ``None`` on timeout / non-zero
    exit / unparseable output / ``ok: False`` (the caller then skips the module, exactly like the
    runner-import failure path in ``PythonSource.on_session_start``). ``env`` is the child
    environment (the caller supplies the minimal target env -- ``PYTHON_GIL`` etc.); ``None`` uses
    the current environment.
    """
    try:
        proc = subprocess.run(
            [python_path, "-c", _DISCOVERY_SRC, module_name],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout.splitlines()[-1])
    except (ValueError, IndexError):
        return None
    if not isinstance(data, dict) or not data.get("ok") or "members" not in data:
        return None
    return data
