+++++++++++++++++++
Fusil configuration
+++++++++++++++++++

Fusil is configured entirely through **command-line options**. Run a fuzzer with
``--help`` to see every option and its default::

    fusil-python-threaded --help

Options are grouped (Input, Running, Fuzzing, OOM Fuzzing, Logging, ...). See
``doc/python-fuzzer.md`` for a narrative reference of the Python fuzzer's options.

.. note::

    Older versions of Fusil also read a ``fusil.conf`` file (``--use-config`` /
    ``--write-config``). That round-trip was removed: it duplicated the option defaults
    and the file it read never actually reached the running configuration. Command-line
    options are now the single source of truth.

Non-command-line defaults
=========================

A small number of settings have no command-line flag -- session scoring thresholds, the
memory limit, and the dedicated-``fusil``-user subprocess sandbox (user/group). These live
as constants in ``fusil/config.py`` (:class:`fusil.config.FusilConfig`) and are rarely
changed. Edit that class if you need to adjust them.
