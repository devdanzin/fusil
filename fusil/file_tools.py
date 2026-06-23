from os import getcwd
from os.path import basename


def filenameExtension(filename):
    ext = basename(filename)
    if "." in ext:
        return "." + ext.rsplit(".", 1)[-1]
    else:
        return None


def relativePath(path, cwd=None):
    if not cwd:
        cwd = getcwd()
    if path.startswith(cwd):
        path = path[len(cwd) + 1 :]
    return path
