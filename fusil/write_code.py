import re
import textwrap
from os import chmod
from textwrap import dedent, indent


class CodeTemplate:
    def __init__(self, template_text: str):
        # Dedent the template to handle templates defined in indented code
        self.template = textwrap.dedent(template_text)

    def render(self_, **kwargs) -> str:
        """
        Renders the template by substituting placeholders, handling both
        multi-line indented blocks and single-line inline values.
        """
        output = self_.template

        # For each key-value pair, perform both block and inline substitutions.
        for key, value in kwargs.items():
            placeholder = f"{{{key}}}"

            # 1. BLOCK SUBSTITUTION:
            # First, find and replace all occurrences of the placeholder that are
            # at the beginning of a line (i.e., need indentation).
            block_pattern = re.compile(f"^(?P<indent>\\s*){re.escape(placeholder)}", re.MULTILINE)

            def replacer(match):
                """A replacer function for re.sub that indents the value."""
                indent_str = match.group('indent')
                # Dedent the value to normalize it, then re-indent it to match the placeholder.
                return textwrap.indent(textwrap.dedent(str(value)).strip(), indent_str)

            # Perform the substitution for all block-style placeholders.
            output = block_pattern.sub(replacer, output)

            # 2. INLINE SUBSTITUTION:
            # After handling the blocks, any remaining placeholders must be inline.
            # Perform a simple, global string replacement for them.
            output = output.replace(placeholder, str(value))

        return output


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
