from ptrace.os_tools import RUNNING_WINDOWS
SUPPORT_UID = not RUNNING_WINDOWS
if SUPPORT_UID:
    from os import getuid

def permissionHelp(options):
    """
    On "Operation not permitted error", propose some help to fix this problem.
    Example: "retry as root".
    """
    if not SUPPORT_UID:
        return None
    help = []
    if getuid() != 0:
        help.append('retry as root')
    if not options.unsafe:
        help.append('use --unsafe option')
    if not help:
        return None
    return ' or '.join(help)

