from os import chmod
from textwrap import dedent


class WriteCode:
    def __init__(self):
        self.indent = " " * 4
        self.base_level = 0

    def useStream(self, stream):
        self.output = stream

    def createFile(self, filename, mode=None):
        self.output = open(filename, "w")
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
        if self.base_level < 0:
            raise ValueError("Negative indentation level in addLevel()")
        return level

    def restoreLevel(self, level):
        if level < 0:
            raise ValueError("Negative indentation level in restoreLevel()")
        self.base_level = level

    def indentLine(self, level, text):
        if not isinstance(text, str):
            text = str(text, "ASCII")
        return self.indent * (self.base_level + level) + text

    def write(self, level, text):
        line = self.indentLine(level, text)
        self.output.write(line + "\n")

    def write_block(self, level: int, code_block: str):
        """
        Writes a multi-line block of code at a specific indentation level.
        Correctly handles indentation for the entire block.
        """
        for line in dedent(code_block).strip().splitlines():
            self.write(level, line)
