from configparser import NoOptionError, NoSectionError, RawConfigParser
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
    "fusil_xhost_program": 'xhost',
    "process_use_cpu_probe": True,
    "process_max_memory":  2000 * 1024 * 1024,
    "process_core_dump": True,
    "process_max_user_process": 1000,
    "process_user": 'fusil',
    "process_uid": None,
    "process_group": 'fusil',
    "process_gid": None,
    "debugger_use_debugger": True,
    "debugger_trace_forks": False,
}

class ConfigError(Exception):
    pass

class FusilConfig:
    def __init__(self):
        self._parser = RawConfigParser()
        self.filename = self.createFilename()
        if path_exists(self.filename):
            self._parser.read([self.filename])

        # Fusil application options
        self.fusil_max_memory = self.getint('fusil', 'max_memory', DEFAULTS['fusil_max_memory'])
        self.fusil_success_score = self.getfloat('fusil', 'success_score', DEFAULTS['fusil_success_score'])
        self.fusil_error_score = self.getfloat('fusil', 'error_score', DEFAULTS['fusil_error_score'])
        self.fusil_success = self.getint('fusil', 'success', DEFAULTS['fusil_success'])
        self.fusil_session = self.getint('fusil', 'session', DEFAULTS['fusil_session'])
        self.fusil_normal_calm_load = self.getfloat('fusil', 'normal_calm_load', DEFAULTS['fusil_normal_calm_load'])
        self.fusil_normal_calm_sleep = self.getfloat('fusil', 'normal_calm_sleep', DEFAULTS['fusil_normal_calm_sleep'])
        self.fusil_slow_calm_load = self.getfloat('fusil', 'slow_calm_load', DEFAULTS['fusil_slow_calm_load'])
        self.fusil_slow_calm_sleep = self.getfloat('fusil', 'slow_calm_sleep', DEFAULTS['fusil_slow_calm_sleep'])
        self.fusil_xhost_program = self.getstr('fusil', 'xhost_program', DEFAULTS['fusil_xhost_program'])

        # Process options
        self.process_use_cpu_probe = self.getbool('process', 'process_use_cpu_probe', DEFAULTS['process_use_cpu_probe'])
        self.process_max_memory = self.getint('process', 'max_memory',  DEFAULTS['process_max_memory'])
        self.process_core_dump = self.getbool('process', 'core_dump', DEFAULTS['process_core_dump'])
        self.process_max_user_process = self.getint('process', 'max_user_process', DEFAULTS['process_max_user_process'])

        # User used for subprocess
        self.process_user = self.getstr('process', 'user', DEFAULTS['process_user'])
        self.process_uid = DEFAULTS['process_uid']

        # Group used for subprocess
        self.process_group = self.getstr('process', 'group', DEFAULTS['process_group'])
        self.process_gid = DEFAULTS['process_gid']

        # Debugger options
        self.debugger_use_debugger = self.getbool('debugger', 'debugger_use_debugger', DEFAULTS['debugger_trace_forks'])
        self.debugger_trace_forks = self.getbool('debugger', 'trace_forks', DEFAULTS['debugger_trace_forks'])

        self._parser = None

    def createFilename(self):
        configdir = getenv("XDG_CONFIG_HOME")
        if not configdir:
            homedir = getenv("HOME")
            if not homedir:
                raise ConfigError("Unable to retrieve user home directory: empty HOME environment variable")
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

