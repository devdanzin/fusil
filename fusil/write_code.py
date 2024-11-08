from os import chmod

from fusil.six import text_type


class WriteCode:
    def __init__(self):
        self.indent = u' ' * 4
        self.base_level = 0

    def useStream(self, stream):
        self.output = stream

    def createFile(self, filename, mode=None):
        self.output = open(filename, 'w')
        if mode:
            chmod(filename, mode)

    def close(self):
        if not self.output:
            return
        self.output.close()
        self.output = None

    def emptyLine(self):
        self.output.write("\n")

    def addLevel(self, delta):
        level = self.base_level
        self.base_level += delta
        return level

    def restoreLevel(self, level):
        self.base_level = level

    def indentLine(self, level, text):
        if not isinstance(text, text_type):
            text = unicode(text, 'ASCII')
        return self.indent * (self.base_level + level) + text

    def write(self, level, text):
        line = self.indentLine(level, text)
        self.output.write(line + "\n")

