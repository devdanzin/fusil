from datetime import datetime
from errno import EEXIST
from os import fstat, getcwd, getpid, mkdir
from os.path import basename

from ptrace.os_tools import RUNNING_LINUX

if RUNNING_LINUX:
    from ptrace.linux_proc import readProcessLink


def safeMkdir(path):
    try:
        mkdir(path)
    except OSError as err:
        if err.errno == EEXIST:
            return
        else:
            raise


def filenameExtension(filename):
    ext = basename(filename)
    if "." in ext:
        return "." + ext.rsplit(".", 1)[-1]
    else:
        return None


def dumpFileInfo(logger, file_obj):
    try:
        fileno = file_obj.fileno()
    except AttributeError:
        logger.info("File object class: %s" % file_obj.__class__.__name__)
        return
    if RUNNING_LINUX:
        filename = readProcessLink(getpid(), "fd/%s" % fileno)
        logger.info("File name: %r" % filename)
    logger.info("File descriptor: %s" % fileno)

    stat = fstat(fileno)
    logger.info("File user/group: %s/%s" % (stat.st_uid, stat.st_gid))
    logger.info("File size: %s bytes" % stat.st_size)
    logger.info("File mode: %04o" % stat.st_mode)
    mtime = datetime.fromtimestamp(stat.st_mtime)
    logger.info("File modification: %s" % mtime)


def relativePath(path, cwd=None):
    if not cwd:
        cwd = getcwd()
    if path.startswith(cwd):
        path = path[len(cwd) + 1 :]
    return path
