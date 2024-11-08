from fusil.unsafe import SUPPORT_UID
from errno import EACCES
from os import chdir, access, X_OK
from fusil.process.tools import (
    limitMemory, beNice, allowCoreDump, limitUserProcess)
from fusil.unsafe import permissionHelp
if SUPPORT_UID:
    from os import getuid, setuid, setgid
    from pwd import getpwuid

class ChildError(Exception):
    # Exception raised after the fork(), in prepareProcess()
    pass

def prepareProcess(process):
    project = process.project()
    config = project.config
    options = process.application().options

    # Trace the new process
    process.debugger.traceme()

    # Change the user and group
    if SUPPORT_UID:
        changeUserGroup(config, options)

    # Set current working directory
    directory = process.getWorkingDirectory()
    try:
        chdir(directory)
    except OSError as err:
        if err.errno != EACCES:
            raise
        user = getuid()
        user = getpwuid(user).pw_name
        message = 'The user %s is not allowed enter directory to %s' \
            % (user, directory)
        help = permissionHelp(options)
        if help:
            message += ' (%s)' % help
        raise ChildError(message)

    # Make sure that the program is executable by the current user
    program = process.current_arguments[0]
    if not access(program, X_OK):
        user = getuid()
        user = getpwuid(user).pw_name
        message = 'The user %s is not allowed to execute the file %s' \
            % (user, program)
        help = permissionHelp(options)
        if help:
            message += ' (%s)' % help
        raise ChildError(message)

    # Limit process resources
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
    # Change group?
    gid = config.process_gid
    errors = []
    if gid is not None:
        try:
            setgid(gid)
        except OSError:
            errors.append("group to %s" % gid)

    # Change user?
    uid = config.process_uid
    if uid is not None:
        try:
            setuid(uid)
        except OSError:
            errors.append("user to %s" % uid)
    if not errors:
        return

    # On error: propose some help
    help = permissionHelp(options)

    # Raise an error message
    errors = ' and '.join(reversed(errors))
    message = 'Unable to set ' + errors
    if help:
        message += ' (%s)' % help
    raise ChildError(message)

