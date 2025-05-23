import re


class Option:
    def __init__(self, format, nb_argument):
        self.format = format
        self.nb_argument = nb_argument

    def formatArguments(self, arguments):
        result = []
        index = 0
        for part in self.format.split():
            count = part.count("%s")
            arg = part % tuple(arguments[index : index + count])
            result.append(arg)
            index += count
        if index != len(arguments):
            raise TypeError("not all arguments converted during formatting")
        return result

    def __str__(self):
        text = self.format
        arguments = tuple(("ARG%s" % index) for index in range(1, self.nb_argument + 1))
        return text % arguments


class CommandHelpParser:
    def __init__(self, program):
        self.program = program
        self.options = []
        self.options_set = set()
        self.parse_line = self.parseLine

        # "-a", "-9" or "-C"
        SHORT_OPT_REGEX = r"-[a-zA-Z0-9]"

        # "-long", "-long-option" or "-Wunsued"
        LONG_OPT_REGEX = r"-[a-zA-Z][a-z-]+"

        # "--print" or "--very-long-option
        LONGLONG_OPT_REGEX = r"--[a-z][a-z-]+"

        # "value", "VALUE", "define:option" or "LONG_VALUE"
        VALUE_REGEX = "[a-zA-Z_:]+"

        # @ value@, @=value@, @,<value>@, @ "value"@, @[=value]@, ...
        VALUE_REGEX = r'[ =]%s|[ ,=]<%s>|[ =]"%s"|\[=%s\]' % (
            VALUE_REGEX,
            VALUE_REGEX,
            VALUE_REGEX,
            VALUE_REGEX,
        )

        # -o
        # -o, --option
        # -o, --long-option=VALUE
        self.gnu_regex = re.compile(
            r"^\s+(%s), (%s)?(%s)?" % (SHORT_OPT_REGEX, LONGLONG_OPT_REGEX, VALUE_REGEX)
        )

        # -option
        # -Long-option VALUE
        self.long_opt_regex = re.compile(
            r"^\s+(%s)(%s)?(%s)?" % (LONG_OPT_REGEX, VALUE_REGEX, VALUE_REGEX)
        )

        # -C
        # -o VALUE
        # --option
        # --long-option=VALUE
        self.opt_regex = re.compile(
            r"^\s+(%s|%s)(%s)?" % (SHORT_OPT_REGEX, LONGLONG_OPT_REGEX, VALUE_REGEX)
        )
        self.opt2_regex = re.compile(
            r"^(%s|%s)(%s)?\s+: " % (SHORT_OPT_REGEX, LONGLONG_OPT_REGEX, VALUE_REGEX)
        )

        # Match "Usage: ping [-LRUbdfnqrvVaA]"
        self.usage_prefix_regex = re.compile(r"^[Uu]sage: %s (.*)$" % self.program)

        # Match "[..]"
        self.usage_group_regex = re.compile(r"\[([^]]+)\]")

    def addOption(self, name, values, default_separator=None):
        nb_arg = 0
        format = []
        if not values:
            value = tuple()
        for value in values:
            if not value:
                continue
            if default_separator:
                separator = default_separator
            else:
                separator = value[0]
            if '"' in value:
                format.append(separator + '"%s"')
            else:
                if separator == "[":
                    separator = value[1]
                format.append(separator + "%s")
        nb_arg = len(format)
        format = name + "".join(format)

        option = Option(format, nb_arg)
        self._addOption(option)

    def _addOption(self, option):
        key = str(option)
        if key in self.options_set:
            return
        self.options.append(option)
        self.options_set.add(key)

    def parseFile(self, stdout):
        for line in stdout:
            line = line.rstrip()
            self.parse_line(line)

    def parseLine(self, line):
        match = self.gnu_regex.match(line)
        if match:
            name = match.group(1)
            value = match.group(3)
            # Short option: -f FILE
            self.addOption(name, [value], " ")

            name = match.group(2)
            if name:
                # Long option: --file=FILE
                self.addOption(name, [value])
            return

        match = self.long_opt_regex.match(line)
        if match:
            name = match.group(1)
            value = match.group(2)
            value2 = match.group(3)
            if value2:
                self.addOption(name, (value, value2))
            else:
                self.addOption(name, [value])
            return

        match = self.opt_regex.match(line)
        if not match:
            match = self.opt2_regex.match(line)
        if match:
            name = match.group(1)
            value = match.group(2)
            self.addOption(name, [value])
            return

        match = self.usage_prefix_regex.match(line)
        if match:
            self.parseUsage(match.group(1))
            return

    def parseUsageGroup(self, line):
        """
        Parse "group" like [-cdaf] (line="-cdaf")
        """
        line = line.strip()
        if not line.startswith("-"):
            return False
        if " " in line:
            # '-c count'
            parts = line.split()
            values = parts[1:]
            self.addOption(parts[0], values, " ")
        else:
            # '-ntpu'
            for opt in line[1:]:
                self.addOption("-" + opt, tuple())
        return True

    def parseUsage(self, line):
        line = line.strip()
        match_line = False
        for match in self.usage_group_regex.finditer(line):
            line = match.group(1)
            for group in line.split("|"):
                match_line |= self.parseUsageGroup(group)
        if match_line:
            self.parse_line = self.parseUsage
        else:
            self.parse_line = self.parseLine
            self.parse_line(line)
