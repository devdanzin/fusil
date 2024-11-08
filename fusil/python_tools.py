from sys import version

RUNNING_PYPY = ("pypy" in version.lower())

# Kept for backward compatibility
from ptrace.os_tools import RUNNING_PYTHON3

