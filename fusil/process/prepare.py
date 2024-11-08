import grp
import pwd
from errno import EACCES
from os import X_OK, access, chdir
from shutil import chown

from fusil.process.tools import (allowCoreDump, beNice, limitMemory,
                                 limitUserProcess)
from fusil.unsafe import SUPPORT_UID, permissionHelp

if SUPPORT_UID:
    from os import getuid, setgid, setuid
    from pwd import getpwuid

class ChildError(Exception):
    # Exception raised after the fork(), in prepareProcess()
    pass

def prepareProcess(process):
    from sys import stderr
    print(f"USER {getuid()}", file=stderr)
    project = process.project()
    config = project.config
    options = process.application().options

    # Trace the new process
    process.debugger.traceme()
    # Set current working directory
    directory = process.getWorkingDirectory()
    try:
        uid = pwd.getpwnam("fusil").pw_uid
        gid = grp.getgrnam("fusil").gr_gid
        chown(directory, uid, gid)
    except Exception as e:
        print(e)
    # Change the user and group
    if SUPPORT_UID:
        changeUserGroup(config, options)

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
        except Exception as e:
            print(e)
            raise

    # Change user?
    uid = config.process_uid
    if uid is not None:
        try:
            setuid(uid)
        except OSError:
            errors.append("user to %s" % uid)
        except Exception as e:
            print(e)
            raise
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

