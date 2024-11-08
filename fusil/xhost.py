from fusil.process.tools import locateProgram

def xhostCommand(xhost_program, user, allow=True):
    if not xhostCommand.program:
        xhostCommand.program = locateProgram(
            xhost_program,
            raise_error=True)
    if allow:
        prefix = '+'
    else:
        prefix = '-'
    return [
        xhostCommand.program,
        "%slocal:%s" % (prefix, user)]
xhostCommand.program = None

