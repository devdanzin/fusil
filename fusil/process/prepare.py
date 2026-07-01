from errno import EACCES
from os import X_OK, access, chdir, getgid, getuid, setgid, setgroups, setuid
from pwd import getpwuid
from shutil import chown

from fusil.process.tools import allowCoreDump, beNice, limitMemory, limitUserProcess
from fusil.unsafe import permissionHelp


class ChildError(Exception):
    # Exception raised after the fork(), in prepareProcess()
    pass


def prepareProcess(process):
    from sys import stderr

    project = process.project()
    config = project.config
    options = process.application().options

    # Set current working directory
    directory = process.getWorkingDirectory()
    # Hand the working directory to the unprivileged process user -- while still
    # privileged and before the drop below. Skipped when no drop is configured (--unsafe).
    if config.process_uid is not None and config.process_gid is not None:
        try:
            chown(directory, config.process_uid, config.process_gid)
        except OSError as err:
            print(
                "Unable to chown %s to %s:%s: %s"
                % (directory, config.process_uid, config.process_gid, err),
                file=stderr,
            )
    # Drop privileges. A failed or ineffective drop MUST abort the child (ChildError is
    # turned into a ProcessError by the parent); never continue running as root -- that is
    # how a fuzzed file-write clobbered /bin/sh and /etc/machine-id.
    changeUserGroup(config, options)

    try:
        chdir(directory)
    except OSError as err:
        print(f"CHDIR ERROR: {err}", file=stderr)
        print(
            "Make sure the whole path is accessible to user 'fusil' (chmod +xr path_part).",
            file=stderr,
        )
        if err.errno != EACCES:
            raise
        user = getuid()
        user = getpwuid(user).pw_name
        message = "The user %s is not allowed enter directory to %s" % (user, directory)
        help = permissionHelp(options)
        if help:
            message += " (%s)" % help
        print(message, file=stderr)
        raise ChildError(message)

    # Make sure that the program is executable by the current user
    program = process.current_arguments[0]
    if not access(program, X_OK):
        user = getuid()
        user = getpwuid(user).pw_name
        message = "The user %s is not allowed to execute the file %s" % (user, program)
        help = permissionHelp(options)
        if help:
            message += " (%s)" % help
        print(message, file=stderr)
        raise ChildError(message)

    # Limit process resources (memory cap is skipped for ASan targets / --no-memory-limit;
    # see CreateProcess.__init__ where max_memory is zeroed in that case).
    limitResources(process, config, options)


def limitResources(process, config, options):
    # Change process priority to be nice
    if not options.fast:
        beNice()

    # Set process priority to nice and limit memory
    if 0 < process.max_memory:
        limitMemory(process.max_memory, hard=True)
    elif 0 < config.fusil_max_memory:
        # Reset Fusil process memory limit
        limitMemory(-1)
    if process.core_dump:
        allowCoreDump(hard=True)
    if config.process_user and (0 < process.max_user_process):
        limitUserProcess(process.max_user_process, hard=True)


def changeUserGroup(config, options):
    """Drop privileges to the configured process user/group.

    No-op when neither is configured (e.g. under --unsafe). On any failure -- the drop
    raising OSError, or silently not taking effect -- raises ChildError so the caller
    aborts the child instead of continuing with elevated privileges.
    """
    uid = config.process_uid
    gid = config.process_gid
    if uid is None and gid is None:
        return  # nothing to drop (e.g. --unsafe)

    errors = []
    # Group (and supplementary groups) first, while still privileged: after setuid() we
    # can no longer change groups.
    if gid is not None:
        try:
            setgroups([gid])  # drop root's supplementary groups
        except OSError:
            pass  # best-effort; the effectiveness check below is authoritative
        try:
            setgid(gid)
        except OSError:
            errors.append("group to %s" % gid)
    if uid is not None:
        try:
            setuid(uid)
        except OSError:
            errors.append("user to %s" % uid)

    # A drop that silently failed to take effect is as dangerous as one that raised, so
    # verify it actually happened rather than trusting the calls above.
    if gid is not None and getgid() != gid:
        errors.append("effective gid (still %s, wanted %s)" % (getgid(), gid))
    if uid is not None and getuid() != uid:
        errors.append("effective uid (still %s, wanted %s)" % (getuid(), uid))

    if not errors:
        return

    # On error: propose some help and abort the child.
    message = "Unable to drop privileges: " + " and ".join(errors)
    help = permissionHelp(options)
    if help:
        message += " (%s)" % help
    raise ChildError(message)
