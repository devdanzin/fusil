try:
    from configparser import NoOptionError, NoSectionError, RawConfigParser
except ImportError:
    # Python 2
    from ConfigParser import RawConfigParser, NoSectionError, NoOptionError

from os import getenv
from os.path import exists as path_exists
from os.path import join as path_join


class ConfigError(Exception):
    pass

class FusilConfig:
    def __init__(self):
        self._parser = RawConfigParser()
        self.filename = self.createFilename()
        if path_exists(self.filename):
            self._parser.read([self.filename])

        # Fusil application options
        self.fusil_max_memory = self.getint('fusil', 'max_memory', 500 * 1024 * 1024)
        self.fusil_success_score = self.getfloat('fusil', 'success_score', 0.50)
        self.fusil_error_score = self.getfloat('fusil', 'error_score', -0.50)
        self.fusil_success = self.getint('fusil', 'success', 1)
        self.fusil_session = self.getint('fusil', 'session', 0)
        self.fusil_normal_calm_load = self.getfloat('fusil', 'normal_calm_load', 0.50)
        self.fusil_normal_calm_sleep = self.getfloat('fusil', 'normal_calm_sleep', 0.5)
        self.fusil_slow_calm_load = self.getfloat('fusil', 'slow_calm_load', 0.30)
        self.fusil_slow_calm_sleep = self.getfloat('fusil', 'slow_calm_sleep', 3.0)
        self.fusil_xhost_program = self.getstr('fusil', 'xhost_program', 'xhost')

        # Process options
        self.use_cpu_probe = self.getbool('process', 'use_cpu_probe', True)
        self.process_max_memory = self.getint('process', 'max_memory',  2000 * 1024 * 1024)
        self.process_core_dump = self.getbool('process', 'core_dump', True)
        self.process_max_user_process = self.getint('process', 'max_user_process', 1000)

        # User used for subprocess
        self.process_user = self.getstr('process', 'user', 'fusil')
        self.process_uid = None

        # Group used for subprocess
        self.process_group = self.getstr('process', 'group', 'fusil')
        self.process_gid = None

        # Debugger options
        self.use_debugger = self.getbool('debugger', 'use_debugger', True)
        self.debugger_trace_forks = self.getbool('debugger', 'trace_forks', False)

        self._parser = None

    def createFilename(self):
        configdir = getenv("XDG_CONFIG_HOME")
        if not configdir:
            homedir = getenv("HOME")
            if not homedir:
                raise ConfigError("Unable to retreive user home directory: empty HOME environment variable")
            configdir = path_join(homedir, ".config")
        return path_join(configdir, "fusil.conf")

    def _gettype(self, func, type_name, section, key, default_value):
        try:
            value = func(section, key)
            if func == self._parser.get:
                value = value.strip()
            return value
        except (NoSectionError, NoOptionError):
            return default_value
        except ValueError as err:
            raise ConfigError("Value %s of section %s is not %s! %s" % (
                key, section, type_name, err))

    def getstr(self, section, key, default_value=None):
        return self._gettype(self._parser.get, "a string", section, key, default_value)

    def getbool(self, section, key, default_value):
        return self._gettype(self._parser.getboolean, "a boolean", section, key, default_value)

    def getint(self, section, key, default_value):
        return self._gettype(self._parser.getint, "an integer", section, key, default_value)

    def getfloat(self, section, key, default_value):
        return self._gettype(self._parser.getfloat, "a float", section, key, default_value)

