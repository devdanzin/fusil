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
    "_builtin__:set": {"test_c_api"},
    "builtins:set": {"test_c_api"},
    # Sleep
    "time": {"sleep", "pthread_getcpuclockid"},
    "select": {"epoll", "poll", "select"},
    "signal": {"pause", "alarm", "setitimer", "pthread_kill"},
    "_signal": {
        "pause",
        "alarm",
        "setitimer",
        "pthread_kill",
        "sigwait",
        "sigwaitinfo",
        "sigtimedwait",
    },
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
    "_randbelow",
    "_randbelow_with_getrandbits",
    "_read",
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
