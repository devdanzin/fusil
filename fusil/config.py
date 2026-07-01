from os import getenv
from os.path import join as path_join


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
    """Fusil's non-CLI defaults: scoring thresholds, memory limits, and the subprocess
    user/group used by the dedicated-``fusil``-user sandbox.

    Every ``--*`` command-line option lives on the parsed optparse ``Values`` object
    (``application.options``); this class is the single home for the handful of settings
    that have no CLI flag. It used to also read/write a ``fusil.conf`` file, but that
    round-trip was never used in practice (and the file it read never reached the running
    config), so it was removed in favour of these constants as the single source of truth.
    """

    def __init__(self):
        self.filename = createFilename()

        # Fusil application defaults
        self.fusil_max_memory = 500 * 1024 * 1024
        self.fusil_success_score = 0.50
        self.fusil_error_score = -0.50
        self.fusil_success = 1
        self.fusil_session = 0
        self.fusil_normal_calm_load = 0.50
        self.fusil_normal_calm_sleep = 0.5

        # Subprocess defaults
        self.process_max_memory = 2000 * 1024 * 1024
        self.process_core_dump = True
        self.process_max_user_process = 5000
        self.process_user = "fusil"
        self.process_uid = None
        self.process_group = "fusil"
        self.process_gid = None
