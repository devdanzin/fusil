"""
Python Fuzzer Blacklists

This module defines the blacklists used by the Fusil Python fuzzer to filter out
dangerous, problematic, or irrelevant functions, methods, classes, and modules.
"""

MODULE_BLACKLIST = {
    "logging",
    "pydoc",
    "getpass",
    "commands",
    "subprocess",
    "antigravity",
    "compileall",
    "user",
    "this",
    "_testcapi",
    "_testlimitedcapi",
    "_testinternalcapi",
    "test",  # This should be handled by --skip-test
    "ctypes",
    "_ctypes",
    "fusil",
    "ptrace",
    "pip",
    "idlelib",
    "idle",
    "turtledemo",
    "turtle",
    "setuptools",
    "distutils",
    "_signal",
    "signal",
    "__builtin__",
    "__future__",
    "xxlimited",
    "xxlimited_35",
    "xxsubtype",
    "tkinter",
    # The REPL's module-name completer imports arbitrary modules (via importlib) to offer
    # completions; fuzzing it reaches _get_import_completion_action's unguarded
    # importlib.import_module(), which bypasses the completer's own AUTO_IMPORT_DENYLIST and
    # imports side-effect modules -- e.g. antigravity (opens a browser to xkcd/353). Like
    # pydoc, it's an arbitrary-module importer, not a useful fuzz target.
    "_pyrepl._module_completer",
}
CTYPES = {
    "PyObj_FromPtr",
    "string_at",
    "wstring_at",
    "call_function",
    "call_cdeclfunction",
    "Py_INCREF",
    "Py_DECREF",
    "dlsym",
    "dlclose",
    "_string_at_addr",
    "_wstring_at_addr",
    "dlopen",
}
SOCKET = {
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "getaddrinfo",
    "socket",
    "SocketType",
    # The int-as-FD family: the same self-harm shape as the int-as-pointer functions in
    # CTYPES above, one layer up. These four take a RAW INTEGER file descriptor
    # (`close(integer) -> None`, `dup(integer) -> integer`, `fromfd(fd, family, type)`,
    # `send_fds(sock, buffers, fds)`), so handing them any fuzz integer closes or
    # reinterprets a descriptor the interpreter is still using. It is not a target defect --
    # the contract is the argument: `close(integer)` does what it is told, on any interpreter.
    # (A standalone harness closing fd 11 while sibling threads call getaddrinfo did NOT
    # reproduce the abort on either interpreter, so the window needs the full stress region;
    # the case here rests on the evidence below, not on a differential.)
    #
    # Measured, and it is not a small effect: 163 of 229 kept dirs in one PyPy
    # --concurrency-stress fleet (71%) were this, in two faces that split exactly on the
    # value passed. 120 closed some other descriptor and were captured with glibc's own
    # `Unexpected error 9 on netlink descriptor 11` -- 11 being `socket.AF_ROSE`, which the
    # stress region had picked as a shared object. The other 43 were SIGABRTs with an EMPTY
    # stdout, and all 43 shared a constant whose value is 0, 1 or 2: they had closed the
    # child's own stdout or stderr, so the diagnostic had nowhere to go.
    "close",
    "dup",
    "fromfd",
    "send_fds",
}
POSIX = {
    "_exit",
    "abort",
    "read",
    "ftruncate",
    "rmdir",
    "unlink",
    "kill",
    "killpg",
    "fork",
    "forkpty",
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "wait",
    "wait3",
    "waitpid",
    "tcsetpgrp",
    "closerange",
}
BUILTINS = {"pow", "round"}

# Functions and methods blacklist. Format:
#   module name => function and class names
# and
#    module name:class name => method names
BLACKLIST = {
    # sys tracing that will cause an error in fuzzing
    "sys": {"settrace", "setprofile"},
    # Dangerous module: ctypes
    "ctypes": CTYPES,
    "_ctypes": CTYPES,
    # Eat a lot of CPU with large arguments
    "itertools": {"tee"},
    "math": {"factorial", "perm", "comb"},
    "operator": {
        "pow",
        "__pow__",
        "ipow",
        "__ipow__",
        "mul",
        "rmul",
        "imul",
        "__mul__",
        "__rmul__",
        "__imul__",
        "repeat",
        "__repeat__",
    },
    "__builtin__": BUILTINS,
    "builtins": BUILTINS,
    # Don't raise SystemError
    "__builtin__:set": {"test_c_api"},  # py2 module name (was a typo: "_builtin__:set")
    "builtins:set": {"test_c_api"},
    # Sleep
    "time": {"sleep", "pthread_getcpuclockid"},
    "select": {"epoll", "poll", "select"},
    "signal": {"default_int_handler", "pause", "alarm", "setitimer", "pthread_kill"},
    "_signal": {
        # Raises KeyboardInterrupt -- a BaseException, so it blows straight through the
        # generated script's `except Exception` handlers and kills the session (the fusil
        # #192 class). Called directly as a fuzz target it tagged 16 dirs `-sigint` in one
        # PyPy fleet, and it also hit the rustpython fleets; it exists on every interpreter.
        "default_int_handler",
        "pause",
        "alarm",
        "setitimer",
        "pthread_kill",
        "sigwait",
        "sigwaitinfo",
        "sigtimedwait",
    },
    # PyPy interpreter internals (__pypy__) that attack the fuzzer or the host rather than
    # the target -- the "generated code kills its own session" class (see fusil #192).
    # Everything else in __pypy__ is deliberately left fuzzable: it is PyPy-only surface with
    # no CPython counterpart, which is the whole point of fuzzing PyPy.
    "__pypy__": {
        # Spawns an interp-level gdb *inside the session*. Observed live: gdb's own banner
        # ("For bug reporting instructions...") lands in the captured stdout and scores on
        # the "bug" word, so the session is kept as a crash that never happened.
        "attach_gdb",
        # "Executes a script of Python code in a given remote Python process." A fuzzer-chosen
        # pid means arbitrary code injection into any process on the box -- including sibling
        # fleet instances and the fuzzer itself.
        "remote_exec",
        # Installs a process-global hook invoked on every code-object creation; handing it one
        # of fusil's bomb objects makes the rest of the session detonate on unrelated code.
        "set_code_callback",
        # Blocks: calls PyOS_InputHook() / stops under the reverse debugger.
        "pyos_inputhook",
        "revdb_stop",
        # Documented as "for testing purposes, raise an interpreter-level ValueError.
        # Should turn into a SystemError automatically" -- a deliberate self-test helper.
        # "SystemError" is a 1.0 crash word, so with --test-private this alone tagged
        # EVERY __pypy__ session as a crash. Manufactured signal, never a target bug.
        "_internal_crash",
    },
    # _testmultiphase.call_state_registration_func() exists to PROVE the error path: it calls
    # PyState_AddModule/PyState_RemoveModule on a multi-phase-init module, which is defined to
    # raise SystemError -- a 1.0 crash word. Identical on CPython and on PyPy's cpyext
    # (verified both), so it is a guaranteed false positive on any interpreter; it kept 11
    # dirs in one PyPy fleet. Only this function is blacklisted, not the module: the rest of
    # _testmultiphase (foo/Example/Str) is real multi-phase-init surface worth fuzzing, and on
    # PyPy it exercises the cpyext C-API emulation layer.
    "_testmultiphase": {"call_state_registration_func"},
    # asyncio.runners.Runner._on_sigint is the SIGINT handler the Runner installs; called
    # directly as a fuzz target it unconditionally `raise KeyboardInterrupt()`. Like
    # signal.default_int_handler, that is a BaseException, so it escapes the generated
    # script's `except Exception` handlers and kills the session (the #192 class). It was
    # 29 of 53 kept dirs -- 55% -- in one PyPy fleet, reached because --test-private exposes
    # the underscore-prefixed method.
    # Keyed on the module the class is DEFINED in. That is not enough on its own -- the same
    # class is re-exported as `asyncio.Runner`, and a session whose target module is `asyncio`
    # reaches `_on_sigint` through that path with this key never matching. `_on_sigint` is
    # therefore also in METHOD_BLACKLIST, which is name-based and module-agnostic; this entry
    # stays because it also filters the static generation path for the defining module.
    "asyncio.runners:Runner": {"_on_sigint"},
    "_socket": SOCKET,
    "socket": SOCKET,
    "posix": POSIX,
    "os": POSIX,
    "_fileio:_FileIO": {"read", "readall"},
    # timeout
    "multiprocessing": {"Pool"},
    "_multiprocessing:SemLock": {"acquire"},
    "_multiprocessing:Connection": {"recv", "recv_bytes", "poll"},
    "_tkinter": {"dooneevent", "create", "mainloop"},
    "termios": {"tcflow"},
    "dl": {"open"},
    "pydoc": {"serve", "doc", "apropos"},
    # listen to a socket and wait for requests
    "BaseHTTPServer": {"test"},
    "CGIHTTPServer": {"test"},
    "SimpleHTTPServer": {"test"},
    "pprint": {"_perfcheck"},  # timeout (unlimited loop?)
    "tabnanny": {"check"},  # python 2.5.2 implementation is just slow
    # create child process
    "popen2": {"popen2", "popen3", "popen4", "Popen3", "Popen4"},
    "pty": {"fork", "spawn"},
    "platform": {"_syscmd_uname"},
    # avoid false positive with pattern on stdout
    "logging": {"warning", "error", "fatal", "critical"},
    "formatter": {"test"},
    # Create huge integer, very long string or list
    "fpformat": {"fix"},
    # remove directory
    "shutil": {"copytree", "rmtree"},
    # open a network connection (timeout)
    # FIXME: only blacklist the blocking methods, not the whole class?
    "imaplib": {"IMAP4", "IMAP4_stream"},
    "telnetlib": {"Telnet"},
    "nntplib": {"NNTP"},
    "smtplib": {"SMTP", "SMTP_SSL"},
    # open a network connection (timeout),
    # the constructor opens directly a connection
    "poplib": {"POP3", "POP3_SSL"},
    "ftplib": {"FTP", "FTP_TLS"},
    # set resource limit, may stop the process:
    # setrlimit(RLIMIT_CPU, (0, 0)) kills the process with a SIGKILL signal
    "resource": {"setrlimit"},
    "xmllib": {"test"},  # timeout
    "urllib2": {"randombytes"},  # unlimited loop
    "py_compile": {"compile"},
    "runpy": {"run_path"},
    "faulthandler": {
        "_fatal_error",
        "_read_null",
        "_sigabrt",
        "_sigbus",
        "_sigfpe",
        "_sigill",
        "_sigsegv",
        "_stack_overflow",
        "_fatal_error_c_thread",
    },
    "_thread": {
        "LockType",
        "RLock",
        "interrupt_main",
        "exit",
        "lock",
        "allocate_lock",
        "allocate",
        "_exit_thread",
    },
    "_queue:SimpleQueue": {"get"},
    "queue:LifoQueue": {"get"},
    "queue:PriorityQueue": {"get"},
    "queue:Queue": {"get"},
    "queue:SimpleQueue": {"get"},
    "queue:_PySimpleQueue": {"get"},
    "gc": {"get_objects"},
    # TODO: blacklist distutils/spawn.py (35): spawn
    # TODO: blacklist distutils/spawn.py (121): _spawn_posix
}
OBJECT_BLACKLIST = {
    "_PyRLock",
    "BoundedSemaphore",
    "LockType",
    "Lock",
    "RLock",
    "Semaphore",
    "AtomicInt64",
}
METHOD_BLACKLIST = {
    "__class__",
    "__enter__",  # Damn locks
    "__imul__",
    "__ipow__",
    "__mul__",
    "__pow__",
    "__rmul__",
    "_acquire_lock",
    "_acquire_restore",
    "_handle_request_noblock",
    # Two SIGINT handlers that unconditionally `raise KeyboardInterrupt()`. Called directly as
    # fuzz targets they raise a BaseException, which escapes the generated script's
    # `except Exception` handlers and kills the session; an uncaught KeyboardInterrupt then
    # makes the interpreter re-raise SIGINT, so the process looks "killed by signal 2" and
    # WatchProcess scores it 1.0. Name-based so every path to them is covered, including the
    # runtime generic-method loop and re-export modules (`asyncio.Runner`, not just
    # `asyncio.runners.Runner`) -- three kept dirs in one PyPy fleet came in that way.
    "_on_sigint",
    "sigint_handler",
    "_randbelow",
    "_randbelow_with_getrandbits",
    "_read",
    "_rehash",
    "_run_once",
    "_serve",
    "_shutdown",
    "accept",
    "acquire",
    "acquire_lock",
    "cmdloop",
    "copyfileobj",
    "get",  # Damn queues
    "get_request",
    "handle_request",
    "handle_request_noblock",
    "prefix",
    "raise_signal",
    "repeat",
    "run_forever",
    "select",
    "serve_forever",
    "shutdown",
    "sleep",
    "test",
    "tri",
    "tril_indices",
    "wait",
    "zfill",
}
