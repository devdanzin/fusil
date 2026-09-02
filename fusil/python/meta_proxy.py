"""The metadata stand-in used when module discovery ran in the target subprocess.

Lives in its own module so both the generator (``write_python_code``) and the arity code
(``arg_numbers``) can identify a proxy by TYPE. They cannot share it through
``write_python_code`` -- that module imports ``arg_numbers``, so the dependency would be
circular -- and identifying it by a duck-typed attribute instead is not safe here: see
``is_meta_proxy``.
"""


class _MetaProxy:
    """Stand-in for a live target member when module discovery ran in the target subprocess
    (see ``target_introspect``). Carries the serializable metadata the generation path needs.
    Never a ``FunctionType`` / ``type`` / ``ModuleType`` -- the classification already happened
    in the subprocess."""

    _fusil_is_meta = True

    def __init__(self, name: str, meta: dict):
        self._name = name
        self._meta = meta
        self._fusil_arity = meta.get("arity")  # function/method: [lo, hi] or None (C builtin)
        self._fusil_doc = meta.get("doc")
        self._fusil_ctor_arity = meta.get("ctor_arity")  # class: [lo, hi] or None
        self._fusil_is_exception = bool(meta.get("is_exception"))
        self._fusil_class_name = meta.get("class_name", name)

    def _fusil_raw_methods(self):
        """(name, method-proxy) candidates for ``_get_object_methods`` to filter (blacklist /
        private / plugin / exception-``__init__`` filtering stays in the parent)."""
        return [(m["name"], _MetaProxy(m["name"], m)) for m in self._meta.get("methods", [])]


def is_meta_proxy(obj) -> bool:
    """True only for a real ``_MetaProxy``.

    This is an isinstance check on purpose. The previous
    ``getattr(obj, "_fusil_is_meta", False)`` was spoofable by any target object with a
    catch-all ``__getattr__``, and a real one shipped in CPython 3.16:

        class _ShutdownTheme:                       # Lib/traceback.py
            def __getattr__(self, _): return self

    ``getattr(theme, "_fusil_is_meta", False)`` returns the theme itself -- truthy -- so
    generation took the metadata branch and then called ``theme._fusil_raw_methods()``, which
    returns the theme again and is not callable. The resulting TypeError escapes into the MAS
    and terminates the whole fusil process, not just the session: it ended 15 of 29 runs in one
    fleet, roughly half the wall-clock, and it does so even with ``--discover-in-target`` off,
    where no proxy can exist at all.

    Duck-typing on ``type(obj)`` instead would fix that one class but not a hostile metaclass
    with ``__getattr__``, which fusil injects deliberately (the metaclass bombs). isinstance is
    the only check a target cannot forge.
    """
    return isinstance(obj, _MetaProxy)
