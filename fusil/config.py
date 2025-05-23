import configparser
import optparse
import pathlib
from configparser import NoOptionError, NoSectionError, RawConfigParser
from io import StringIO
from optparse import OptionGroup, OptionParser
from os import getenv
from os.path import exists as path_exists
from os.path import join as path_join

DEFAULTS = {
    "fusil_max_memory": 500 * 1024 * 1024,
    "fusil_success_score": 0.50,
    "fusil_error_score": -0.50,
    "fusil_success": 1,
    "fusil_session": 0,
    "fusil_normal_calm_load": 0.50,
    "fusil_normal_calm_sleep": 0.5,
    "fusil_slow_calm_load": 0.30,
    "fusil_slow_calm_sleep": 3.0,
    "fusil_xhost_program": "xhost",
    "process_use_cpu_probe": True,
    "process_max_memory": 2000 * 1024 * 1024,
    "process_core_dump": True,
    "process_max_user_process": 1000,
    "process_user": "fusil",
    "process_uid": None,
    "process_group": "fusil",
    "process_gid": None,
    "debugger_use_debugger": True,
    "debugger_trace_forks": False,
}


class ConfigError(Exception):
    pass


def createFilename(name=None, configdir=None):
    """Create a filename from the given name and configdir."""
    if name is None:
        name = "fusil.conf"
    if configdir is None:
        configdir = getenv("XDG_CONFIG_HOME")
        if not configdir:
            homedir = getenv("HOME")
            if not homedir:
                raise ConfigError(
                    "Unable to retrieve user home directory: empty HOME environment variable"
                )
            configdir = path_join(homedir, ".config")
    return path_join(configdir, name)


class FusilConfig:
    def __init__(
        self, options=None, filename=None, configdir=None, read=False, write=False
    ):
        self._parser = ConfigParserWithHelp(allow_unnamed_section=True)
        self.filename = createFilename(filename, configdir)
        if read and path_exists(self.filename):
            self._parser.read([self.filename])

        # Fusil application options
        self.fusil_max_memory = self.getint(
            "fusil", "max_memory", DEFAULTS["fusil_max_memory"]
        )
        self.fusil_success_score = self.getfloat(
            "fusil", "success_score", DEFAULTS["fusil_success_score"]
        )
        self.fusil_error_score = self.getfloat(
            "fusil", "error_score", DEFAULTS["fusil_error_score"]
        )
        self.fusil_success = self.getint("fusil", "success", DEFAULTS["fusil_success"])
        self.fusil_session = self.getint("fusil", "session", DEFAULTS["fusil_session"])
        self.fusil_normal_calm_load = self.getfloat(
            "fusil", "normal_calm_load", DEFAULTS["fusil_normal_calm_load"]
        )
        self.fusil_normal_calm_sleep = self.getfloat(
            "fusil", "normal_calm_sleep", DEFAULTS["fusil_normal_calm_sleep"]
        )
        self.fusil_slow_calm_load = self.getfloat(
            "fusil", "slow_calm_load", DEFAULTS["fusil_slow_calm_load"]
        )
        self.fusil_slow_calm_sleep = self.getfloat(
            "fusil", "slow_calm_sleep", DEFAULTS["fusil_slow_calm_sleep"]
        )
        self.fusil_xhost_program = self.getstr(
            "fusil", "xhost_program", DEFAULTS["fusil_xhost_program"]
        )

        # Process options
        self.process_use_cpu_probe = self.getbool(
            "process", "process_use_cpu_probe", DEFAULTS["process_use_cpu_probe"]
        )
        self.process_max_memory = self.getint(
            "process", "max_memory", DEFAULTS["process_max_memory"]
        )
        self.process_core_dump = self.getbool(
            "process", "core_dump", DEFAULTS["process_core_dump"]
        )
        self.process_max_user_process = self.getint(
            "process", "max_user_process", DEFAULTS["process_max_user_process"]
        )

        # User used for subprocess
        self.process_user = self.getstr("process", "user", DEFAULTS["process_user"])
        self.process_uid = DEFAULTS["process_uid"]

        # Group used for subprocess
        self.process_group = self.getstr("process", "group", DEFAULTS["process_group"])
        self.process_gid = DEFAULTS["process_gid"]

        # Debugger options
        self.debugger_use_debugger = self.getbool(
            "debugger", "debugger_use_debugger", DEFAULTS["debugger_trace_forks"]
        )
        self.debugger_trace_forks = self.getbool(
            "debugger", "trace_forks", DEFAULTS["debugger_trace_forks"]
        )

        # Options from command line
        options: optparse.Values

        if options:
            for section, option_dict in options.option_groups.items():
                for name, (value, help) in option_dict.items():
                    if not self._parser.has_section(section):
                        self._parser.add_section(section)
                    elif self._parser.has_option(section, name):
                        value = get_and_convert(self._parser, section, name)
                        print(
                            f"{section}: {name} = {value} {type(value)} (from config file)"
                        )

                    self._parser.set(section, name, str(value), help)
                    setattr(self, name, value)

        self.version = getattr(options, "version", False)

        if write:
            print("Writing configuration file %s" % self.filename)
            with pathlib.Path(self.filename).open("w") as config_file:
                config_file.write("""# Fusil configuration file\n\n""")
                self._parser.write(config_file)
                config_file.close()
                self._parser = None

    def write_sample_config(self, write_file=True):
        """Create a sample configuration file and optionally write it."""
        output = StringIO()
        self._parser = RawConfigParser(allow_unnamed_section=True)
        filename = createFilename()
        config_file = pathlib.Path(filename)
        if write_file and config_file.exists():
            raise ConfigError("Configuration file already exists: %s" % filename)

        output.write("""# Fusil default configuration file\n\n""")
        for session_and_key, value in DEFAULTS.items():
            section, key = session_and_key.split("_", maxsplit=1)
            if section not in self._parser:
                self._parser.add_section(section)
            self._parser.set(section, key, str(value))
        self._parser.write(output)
        self._parser = None

        if write_file:
            with config_file.open("w") as file:
                file.write(output.getvalue())
        return output

    def _gettype(self, func, type_name, section, key, default_value):
        try:
            value = func(section, key)
            if func == self._parser.get:
                value = value.strip()
            return value
        except (NoSectionError, NoOptionError):
            return default_value
        except ValueError as err:
            raise ConfigError(
                "Value %s of section %s is not %s! %s" % (key, section, type_name, err)
            )

    def getstr(self, section, key, default_value=None):
        return self._gettype(self._parser.get, "a string", section, key, default_value)

    def getbool(self, section, key, default_value):
        return self._gettype(
            self._parser.getboolean, "a boolean", section, key, default_value
        )

    def getint(self, section, key, default_value):
        return self._gettype(
            self._parser.getint, "an integer", section, key, default_value
        )

    def getfloat(self, section, key, default_value):
        return self._gettype(
            self._parser.getfloat, "a float", section, key, default_value
        )


def optparse_to_configparser(parser, output=None, defaults=False, options=None):
    """Convert optparse options to a configparser."""
    if defaults and options:
        raise ConfigError("Cannot use both defaults and options")
    elif not (defaults or options is not None):
        raise ConfigError("Must use either defaults or options")

    if output is None:
        output = StringIO("# Fusil configuration file\n\n")
    config_writer = ConfigParserWithHelp(allow_unnamed_section=True)

    option: optparse.Option
    for option in parser.option_list:
        if option.dest is not None and option.dest != "version":
            if not config_writer.has_section(configparser.UNNAMED_SECTION):
                config_writer.add_section(configparser.UNNAMED_SECTION)
            if defaults:
                config_writer.set(
                    configparser.UNNAMED_SECTION,
                    option.dest,
                    f"{option.default}",
                    option.help,
                )
            else:
                config_writer.set(
                    configparser.UNNAMED_SECTION,
                    option.dest,
                    f"{getattr(options, option.dest)}",
                    option.help,
                )

    for section in parser.option_groups:
        for option in section.option_list:
            if not config_writer.has_section(section.title.lower()):
                config_writer.add_section(section.title.lower())
            if defaults:
                config_writer.set(
                    section.title.lower(), option.dest, f"{option.default}", option.help
                )
            else:
                config_writer.set(
                    section.title.lower(),
                    option.dest,
                    f"{getattr(options, option.dest)}",
                    option.help,
                )

    config_writer.write(output)
    if isinstance(output, StringIO):
        return output.getvalue()
    output.close()
    output = open(output.name)
    return output.read()


def configparser_to_options(parser):
    """Convert a configparser to optparse options."""
    options = optparse.Values()

    for section in parser.sections():
        for key in parser[section]:
            setattr(options, key, parser[section][key])
    return options


class OptionGroupWithSections(OptionGroup):
    """
    OptionGroup class with sections:
    - add_option(*args, section=None, **kwargs)
    """

    def __init__(self, parser, title, description=None):
        super().__init__(parser, title, description)
        self.option_sections = {}

    def add_option(self, *args, **kwargs):
        super().add_option(*args, **kwargs)
        section = self.title.lower()
        if "dest" in kwargs:
            self.option_sections[kwargs["dest"]] = section
        elif args[0].startswith("--"):
            self.option_sections[args[0][2:].replace("-", "_")] = section
        else:
            self.option_sections[args[1][2:].replace("-", "_")] = section


class OptionParserWithSections(OptionParser):
    """OptionParser class which records sections."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.option_sections = {}

    def add_option_group(self, group, *args, **kwargs):
        super().add_option_group(group, *args, **kwargs)
        self.option_sections.update(group.option_sections)

    def parse_args(self, args=None, values=None):
        options, args = super().parse_args(args, values)
        options.option_sections = self.option_sections
        options.option_groups = {}
        for section in self.option_groups:
            options.option_groups[section.title.lower()] = {}
            for option in section.option_list:
                options.option_groups[section.title.lower()][option.dest] = (
                    getattr(options, option.dest),
                    option.help,
                )

        return options, args


class ConfigParserWithHelp(configparser.ConfigParser):
    """ConfigParser class which records and writes help messages."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.help = {}

    def set(self, section, option, value=None, help=None):
        super().set(section, option, value)
        if help is not None:
            if not self.has_section(section):
                self.add_section(section)
            elif section not in self.help:
                self.help[section] = {}
            if option in self.help[section]:
                raise ConfigError(
                    "Option %s of section %s already has a help message: %s"
                    % (option, section, self.help[section][option])
                )
            self.help[section][option] = help

    def add_section(self, section):
        super().add_section(section)
        self.help[section] = {}

    def _write_section(self, fp, section_name, section_items, delimiter):
        fp.write("\n[%s]\n" % section_name)
        for key, value in section_items:
            if key in self.help[section_name]:
                fp.write("\n# %s\n" % self.help[section_name][key])

            value = self._interpolation.before_write(self, section_name, key, value)
            if value is not None or not self._allow_no_value:
                value = delimiter + str(value).replace("\n", "\n\t")
            else:
                value = ""
            fp.write("%s%s\n" % (key, value))
        fp.write("#" + "-" * 40 + "\n")
        fp.write("\n")


BOOLEANS = {
    "True": True,
    "False": False,
    "true": True,
    "false": False,
    "yes": True,
    "no": False,
    "y": True,
    "n": False,
}


def get_and_convert(parser, section, key):
    """Get a value from a parser and convert it to the appropriate type."""
    value: str = parser.get(section, key)

    if value in BOOLEANS:
        return BOOLEANS[value]
    elif value == "None":
        return None

    try:
        return int(value, 0)
    except ValueError:
        pass

    for num_type in (int, float, complex):
        try:
            return num_type(value)
        except ValueError:
            pass

    return value
