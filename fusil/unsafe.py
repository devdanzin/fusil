from os import getuid


def permissionHelp(options):
    """
    On "Operation not permitted error", propose some help to fix this problem.
    Example: "retry as root".
    """
    help = []
    if getuid() != 0:
        help.append("retry as root")
    if not options.unsafe:
        help.append("use --unsafe option")
    if not help:
        return None
    return " or ".join(help)
