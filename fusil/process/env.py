from os import getenv
from random import choice, randint

from fusil.bytes_generator import ASCII0, BytesGenerator, LengthGenerator
from fusil.project_agent import ProjectAgent
from fusil.unicode_generator import IntegerGenerator


class EnvironmentVariable:
    def __init__(self, name, max_count=1):
        self.name = name
        self.min_count = 1
        self.max_count = max_count

    def hasName(self, name):
        if isinstance(self.name, (list, tuple)):
            return name in self.name
        else:
            return self.name == name

    def createName(self):
        """
        Generate variable name
        """
        if isinstance(self.name, (list, tuple)):
            return choice(self.name)
        else:
            return self.name

    def createValue(self):
        """
        Generate variable content (bytes string)
        """
        raise NotImplementedError()

    def create(self):
        """
        Generate variable content
        """
        if isinstance(self.name, (list, tuple)):
            max_count = len(self.name)
        else:
            max_count = 1
        if self.max_count:
            max_count = min(max_count, self.max_count)
        count = randint(self.min_count, max_count)
        for index in range(count):
            name = self.createName()
            value = self.createValue()
            yield (name, value)


class EnvVarValue(EnvironmentVariable):
    def __init__(self, name, value="", max_count=1):
        EnvironmentVariable.__init__(self, name, max_count)
        self.value = value

    def createValue(self):
        return self.value


class EnvVarLength(LengthGenerator, EnvironmentVariable):
    def __init__(self, name, max_length, min_length=0, max_count=1):
        LengthGenerator.__init__(self, min_length=min_length, max_length=max_length)
        EnvironmentVariable.__init__(self, name, max_count)


class EnvVarInteger(IntegerGenerator, EnvironmentVariable):
    def __init__(self, name, max_count=1):
        IntegerGenerator.__init__(self)
        EnvironmentVariable.__init__(self, name, max_count)

    def createValue(self):
        return str(IntegerGenerator.createValue(self))


class EnvVarIntegerRange(EnvironmentVariable):
    def __init__(self, name, min, max, max_count=1):
        EnvironmentVariable.__init__(self, name, max_count)
        self.min = min
        self.max = max

    def createValue(self):
        value = randint(self.min, self.max)
        return str(value)


class EnvVarRandom(BytesGenerator, EnvironmentVariable):
    def __init__(
        self, name, min_length=0, max_length=10000, max_count=1, bytes_set=ASCII0
    ):
        BytesGenerator.__init__(self, min_length, max_length, bytes_set)
        EnvironmentVariable.__init__(self, name, max_count)


class Environment(ProjectAgent):
    def __init__(self, process):
        ProjectAgent.__init__(self, process.project(), "%s:env" % process.name)
        self.clear()
        self.copies.append("PYTHON_GIL")
        self.copies.append("PYTHON_JIT")
        self.copies.append("LSAN_OPTIONS")
        self.copies.append("ASAN_OPTIONS")

    def clear(self):
        self.copies = []
        self.variables = []

    def set(self, name, value, max_count=1):
        """
        Set a fixed environment variable value: create an EnvVarValue.
        Return the EnvVarValue objet.
        """
        try:
            variable = self[name]
            if not isinstance(variable, EnvVarValue):
                raise TypeError(
                    "Variable %s is already set but the type is not EnvVarValue but %s"
                    % (name, variable.__class__.__name__)
                )
        except KeyError:
            variable = EnvVarValue(name, value, max_count)
            self.add(variable)
        return variable

    def add(self, variable):
        """
        Add a new EnvironmentVariable object.
        """
        self.variables.append(variable)

    def copy(self, name):
        """
        Add the name of the environment variable to copy.
        """
        if name in self.copies:
            return
        self.copies.append(name)

    def __getitem__(self, name):
        if isinstance(name, (list, tuple)):
            raise TypeError("Environment[name] doesn't support name list")
        for var in self.variables:
            if var.hasName(name):
                return var
        raise KeyError("No environment variable: %r" % name)

    def create(self):
        """
        Create process environment variable dictionnary:
        name (str) => value (str).
        """
        env = {}

        # Copy some environment variables
        for name in self.copies:
            value = getenv(name)
            if value is not None:
                env[name] = value

        # Generate new variables
        for var in self.variables:
            for name, value in var.create():
                message = "Create environment variable %s: (len=%s)" % (
                    name,
                    len(value),
                )
                if len(value) <= 50:
                    message += " " + repr(value)
                self.info(message)
                if "\0" in value:
                    raise ValueError(
                        "Nul byte in environment variable value is forbidden!"
                    )
                env[name] = value

        # Write result to logs
        self.info("Environment: %r" % env)
        return env

    def copyX11(self):
        self.copy("HOME")
        self.copy("DISPLAY")
