import pathlib
import sys
import warnings
from io import StringIO
from sys import exit, stdout

from os import getgid, getuid

from ptrace.error import PTRACE_ERRORS, writeError

from fusil.application_logger import ApplicationLogger
from fusil.config import (
    ConfigError,
    FusilConfig,
    OptionGroupWithSections,
    OptionParserWithSections,
    optparse_to_configparser,
)
from fusil.blacklist_config import load_blacklist_config
from fusil.file_tools import relativePath
from fusil.filter_manager import create_filter_manager, detect_pattern_type
from fusil.mas.agent_list import AgentList
from fusil.mas.application_agent import ApplicationAgent
from fusil.mas.mta import MTA
from fusil.mas.univers import Univers
from fusil.process.tools import beNice, runCommand
from fusil.project import Project
from fusil.version import LICENSE, VERSION, WEBSITE
from fusil.xhost import xhostCommand

from grp import getgrgid, getgrnam
from pwd import getpwnam, getpwuid


def formatLimit(limit):
    if 0 < limit:
        return str(limit)
    else:
        return "unlimited"


class Application(ApplicationAgent):
    """
    Application class is responsible to execute a fuzzer using Fusil:
     - parse the command line
     - setup logging
     - create the project
     - execute the project
     - cleanup on exit
    """

    # Fuzzer name: short alphanumeric string
    NAME = "fusil"

    # Command line usage
    USAGE = "%prog [options]"

    # Number of command line arguments: fixed value or a range (min, max).
    # Use (min, None) to only check the minimum number of arguments.
    NB_ARGUMENTS = 0

    def __init__(self):
        self.agents = AgentList()
        ApplicationAgent.__init__(self, "application", self, None)

        # Initialize PluginManager
        from fusil.plugin_manager import get_plugin_manager
        self.plugin_manager = get_plugin_manager()

        self.setup()

        # Create FilterManager with mode from options
        self.filter_manager = create_filter_manager(
            mode=getattr(self.options, 'mode', 'blacklist'),
            verbose=self.options.verbose
        )

        # Load config file if requested
        if getattr(self.options, 'use_blacklist_config', False):
            try:
                load_blacklist_config(
                    self.options.blacklist_config,
                    self.filter_manager
                )
            except Exception as e:
                print(
                    f"[FilterManager] Warning: Failed to load config file: {e}",
                    file=sys.stderr
                )

        # Parse CLI filter options
        self._load_cli_filters()

        # Handle deprecated --blacklist option for backward compatibility
        if getattr(self.options, 'blacklist', ''):
            warnings.warn(
                "--blacklist is deprecated, use --blacklist-modules instead",
                DeprecationWarning,
                stacklevel=2
            )
            for module in self.options.blacklist.split(','):
                module = module.strip()
                if module:
                    self.filter_manager.add_blacklist_entry(
                        'module', module, 'exact', source='cli'
                    )

        # Give PluginManager access to FilterManager
        self.plugin_manager.set_filter_manager(self.filter_manager)

        # Discover and load plugins (they can add filters)
        self.plugin_manager.discover_and_load_plugins()

        # Check plugin dependencies
        dep_errors = self.plugin_manager.check_dependencies()
        if dep_errors:
            for error in dep_errors:
                print(f"[Plugin Error] {error}", file=sys.stderr)

        # Finalize FilterManager (validates whitelist mode, etc.)
        try:
            self.filter_manager.finalize()
        except ValueError as e:
            print(f"[FilterManager] Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Run startup hooks
        if self.plugin_manager:
            self.plugin_manager.run_hooks('startup', self.options)

    def _load_cli_filters(self):
        """Parse CLI filter options and add to FilterManager."""
        # Process blacklist entries
        for item_type in self.filter_manager.ITEM_TYPES:
            option_name = f'blacklist_{item_type}s'  # e.g., 'blacklist_modules'
            if hasattr(self.options, option_name):
                entries = getattr(self.options, option_name, '')
                if entries:
                    for entry in entries.split(','):
                        entry = entry.strip()
                        if entry:
                            pattern_type = detect_pattern_type(entry)
                            self.filter_manager.add_blacklist_entry(
                                item_type, entry, pattern_type,
                                source='cli'
                            )

        # Process whitelist entries
        for item_type in self.filter_manager.ITEM_TYPES:
            option_name = f'whitelist_{item_type}s'  # e.g., 'whitelist_modules'
            if hasattr(self.options, option_name):
                entries = getattr(self.options, option_name, '')
                if entries:
                    for entry in entries.split(','):
                        entry = entry.strip()
                        if entry:
                            pattern_type = detect_pattern_type(entry)
                            self.filter_manager.add_whitelist_entry(
                                item_type, entry, pattern_type,
                                source='cli'
                            )

    def registerAgent(self, agent):
        self.agents.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        if agent not in self.agents:
            return
        self.agents.remove(agent, destroy)

    def createFuzzerOptions(self, parser):
        """
        Create command line options specific to a fuzzer
        """

    def createOptionParser(self, output=None):
        """
        Create all command line options, including Fusil options.
        """
        parser = OptionParserWithSections(usage=self.USAGE)
        parser.add_option(
            "--version",
            help="Display Fusil version (%s) and exit" % VERSION,
            action="store_true",
        )

        self.createFuzzerOptions(parser)
        config_options = StringIO()
        fuzzer = OptionGroupWithSections(parser, "Fuzzer")
        fuzzer.add_option(
            "--success",
            help="Maximum number of success sessions (default: %s)"
            % formatLimit(self.config.fusil_success),
            type="int",
            default=self.config.fusil_success,
        )
        fuzzer.add_option(
            "--sessions",
            help="Maximum number of session (default: %s)"
            % formatLimit(self.config.fusil_session),
            type="int",
            default=self.config.fusil_session,
        )
        fuzzer.add_option(
            "--fast",
            help="Run as fast as possible (opposite of --slow)",
            action="store_true",
            default=False,
        )
        fuzzer.add_option(
            "--slow",
            help="Try to keep system load low: be nice with CPU (opposite of --fast)",
            action="store_true",
            default=True,
        )
        fuzzer.add_option(
            "--keep-generated-files",
            help="Keep a session directory if it contains generated files",
            action="store_true",
            default=False,
        )
        fuzzer.add_option(
            "--keep-sessions",
            help="Do not remove session directories",
            action="store_true",
            default=False,
        )
        fuzzer.add_option(
            "--aggressivity",
            help="Initial aggressivity factor in percent, value in -100.0..100.0 (default: 0.0%%)",
            type="float",
            default=0.0,
        )
        fuzzer.add_option(
            "--unsafe",
            help="Don't change user or group for child processes",
            action="store_true",
            default=False,
        )
        fuzzer.add_option(
            "--force-unsafe",
            help="Similar to --unsafe option but don't ask confirmation",
            action="store_true",
            default=False,
        )
        parser.add_option_group(fuzzer)

        log = OptionGroupWithSections(parser, "Logging")
        log.add_option(
            "-v",
            "--verbose",
            help="Enable verbose mode (set log level to WARNING)",
            action="store_true",
            default=False,
        )
        log.add_option(
            "--quiet",
            help="Be quiet (lowest log level), don't create log file",
            action="store_true",
            default=False,
        )
        parser.add_option_group(log)

        debug = OptionGroupWithSections(parser, "Development")
        debug.add_option(
            "--debug",
            help="Enable debug mode (set log level to DEBUG)",
            action="store_true",
            default=False,
        )
        debug.add_option(
            "--profiler",
            help="Enable Python profiler",
            action="store_true",
            default=False,
        )
        parser.add_option_group(debug)

        if output:
            optparse_to_configparser(parser, config_options, defaults=True)
            output.write(config_options.getvalue())

        return parser

    def parseOptions(self, with_options=False):
        """Create command line options and parse them."""
        default_config = FusilConfig(read=False)
        config_output = default_config.write_sample_config(write_file=False)
        parser = self.createOptionParser(config_output)

        self.options, self.arguments = parser.parse_args()
        filename = configdir = None
        if self.options.use_config:
            file_path = pathlib.Path(self.options.config_file)
            filename = file_path.name
            configdir = file_path.parent

        if with_options:
            self.options = FusilConfig(
                self.options,
                filename=filename,
                configdir=configdir,
                read=self.options.use_config,
                write=self.options.write_config,
            )

        # Just want to know the version?
        if self.options.version:
            print("Fusil version %s" % VERSION)
            print("License: %s" % LICENSE)
            print("Website: %s" % WEBSITE)
            print("")
            exit(0)

        if self.options.quiet:
            self.options.debug = False
            self.options.verbose = False
        if self.options.debug:
            self.options.verbose = True
        if self.options.verbose:
            print("\nReceived options:")
            default_configs = self.options.write_sample_config(False)
            received_options = optparse_to_configparser(
                parser, default_configs, defaults=False, options=self.options
            )
            print("\n")
            print(received_options, "\n\n")

        # --force-unsafe enables --unsafe
        if self.options.force_unsafe:
            self.options.unsafe = True

        self.processOptions(parser, self.options, self.arguments)

        # Just want to write a config file?
        if self.options.write_config:
            exit(0)

    def processOptions(self, parser, options, arguments):
        """Check the number of arguments."""
        nb_arg = len(arguments)
        if isinstance(self.NB_ARGUMENTS, tuple):
            # Range (min, max)
            min_arg, max_arg = self.NB_ARGUMENTS
            need_arg = False
            if nb_arg < min_arg:
                need_arg = True
            elif (max_arg is not None) and (max_arg < nb_arg):
                need_arg = True
        else:
            # Fixed number of arguments
            need_arg = nb_arg != self.NB_ARGUMENTS
        if need_arg:
            parser.print_help()
            exit(1)

    def setup(self):
        """Prepare the application."""
        # Application objects
        self.exitcode = 0
        self.interrupted = False
        self.project: Project | None = None
        self._setup_x11 = False
        self.options = None

        # Create the logger
        self.logger = ApplicationLogger(self)

        # Read configuration
        try:
            self.config = FusilConfig()
        except ConfigError as err:
            self.fatalError("Configuration error: %s" % err)

        # Read command line options
        self.parseOptions(with_options=True)

        # Setup the logger and display Fusil version, license and website
        self.logger.applyOptions(self.options)
        self.error("Fusil version %s -- %s" % (VERSION, LICENSE))
        self.error(WEBSITE)

        # Check the configuration
        try:
            self.processConfig()
        except ConfigError as err:
            self.fatalError("Configuration error: %s" % err)

        # Limit Fusil environment
        if not self.options.fast:
            beNice(True)
        if 0 < self.config.fusil_max_memory:
            self.error(
                "Skip limiting memory to %s bytes" % self.config.fusil_max_memory
            )
            # limitMemory(self.config.fusil_max_memory)

        # Create multi agent system
        self.createMAS()

    def processConfig(self):
        config = self.config

        # Use --unsafe?
        if self.options.unsafe:
            config.process_user = None
            config.process_group = None

        # Get user name and identifier
        errors = []
        user = config.process_user
        if user:
            try:
                try:
                    # user is the user identifier (as string)
                    config.process_uid = int(user)
                    config.process_user = getpwuid(config.process_uid).pw_name
                except ValueError:
                    # user is the user name
                    config.process_uid = getpwnam(user).pw_uid
            except KeyError:
                errors.append("the user %r" % user)

        # Get group name and identifier
        group = config.process_group
        if group:
            try:
                try:
                    # group is the group identifier (as string)
                    config.process_gid = int(group)
                    config.process_user = getgrgid(config.process_gid).gr_name
                except ValueError:
                    # group is the group name
                    config.process_gid = getgrnam(group).gr_gid
            except KeyError:
                errors.append("the group %r" % group)

        # Display error if any
        if errors:
            message = "Unable to get the identifier of "
            message += " and ".join(errors)
            message += " (create missing user/group or use --unsafe option)"
            raise ConfigError(message)

        # Display the safety warning (if needed)
        self.safetyWarning()

        # Display second warning about force unsafee
        if self.options.force_unsafe:
            self.error("")
            self.error(
                "!!!WARNING!!! You choosed --force-unsafe, so don't cry if you lost any file or process!"
            )
            self.error("")

    def safetyWarning(self):
        # uid or gid is None?
        uid = self.config.process_uid
        gid = self.config.process_gid
        if (uid is not None) and (gid is not None):
            return

        # Don't show the warning
        running_root = (uid is None) and (getuid() == 0)
        if self.options.force_unsafe and not running_root:
            return

        # Display huge error message
        if uid is None:
            uid = getuid()
        if gid is None:
            gid = getgid()
        self.error("")
        self.error(
            "!!!WARNING!!! The fuzzer will run as user %s and group %s," % (uid, gid)
        )
        self.error(
            "!!!WARNING!!! and may remove arbitrary files and kill arbitrary processes."
        )
        if not self.options.unsafe:
            self.error(
                "!!!WARNING!!! Change your Fusil configuration (%s)"
                % self.config.filename
            )
            self.error(
                "!!!WARNING!!! to use different user and group, or use --unsafe command"
            )
            self.error(
                "!!!WARNING!!! line option to use current user and group (%s:%s)."
                % (getuid(), getgid())
            )
        if not running_root:
            # always show the warning when running as root!
            self.error("!!!WARNING!!! Use --force-unsafe to avoid this warning.")
        self.error("")

        # Ask confirmation
        try:
            answer = None
            while answer not in ("yes", "no", ""):
                if answer:
                    prompt = 'Please answer "yes" or "no": '
                else:
                    prompt = "Do you want to continue? (yes/NO) "

                answer = input(prompt)
                answer = answer.strip().lower()
            confirm = answer == "yes"
        except (KeyboardInterrupt, EOFError):
            stdout.write("\n")
            confirm = False
        if not confirm:
            self.fatalError()

    def createMAS(self):
        # Create mail transfer agent (MTA)
        self.mta = None
        mta = MTA(self)

        # Create univers
        if self.options.fast:
            # note: without sleep, the fuzzer is slower than sleep(0.001)
            step_sleep = 0.001
        elif not self.options.slow:
            step_sleep = 0.010
        else:
            step_sleep = 0.050
        self.univers = Univers(self, mta, step_sleep)

        # Finish to setup application
        self.setupMTA(mta, self.logger)
        self.registerAgent(self)

        # Activate agents
        mta.activate()
        self.activate()
        self.univers.activate()

    def interrupt(self, message):
        self.interrupted = True
        self.error(message)

    def exit(self, keep_log=True):
        """
        Cleanup on exiting: destroy agents
        """
        self.warning("Exit Fusil")

        if hasattr(self, 'plugin_manager') and self.plugin_manager:
            self.plugin_manager.run_hooks('shutdown')

        if not keep_log:
            self.logger.unlinkFile()
        elif self.logger.filename:
            self.error("Fusil log written into %s" % relativePath(self.logger.filename))

        self.mta = None
        self.univers = None
        try:
            self.agents.clear()
        except KeyboardInterrupt:
            self.interrupt("Application cleanup interrupted!")
        except PTRACE_ERRORS as error:
            writeError(None, error, "AGENT DEINIT ERROR")
            self.exitcode = 1
        self.deinitX11()
        self.config = None

    def fatalError(self, message=None):
        """
        Fatal error: display a message (if message is set) and exit
        the fuzzer.
        """
        self.exit_code = 1
        if message:
            self.error(message)
        self.exit(keep_log=False)
        exit(self.exitcode)

    def executeProject(self):
        """
        Execute the fuzzer: create a session, execute the session, destroy the
        session, create a second session, etc.
        """
        self.project.activate()
        try:
            if self.options.profiler:
                from ptrace.profiler import runProfiler

                runProfiler(self, self.univers.execute, (self.project,))
            else:
                self.univers.execute(self.project)
        except KeyboardInterrupt:
            self.interrupt("Fuzzer execution interrupted!")
        except PTRACE_ERRORS as error:
            writeError(self, error, "Fuzzer execution error")
            self.exitcode = 1
        self.project.deactivate()

    def setupProject(self):
        """
        (Abstract method) Setup the project: create project agents, prepare the
        environment, create some files or directories, etc.
        """
        raise NotImplementedError()

    def runProject(self):
        """
        Load, execute and destroy the project.
        """
        # Load project
        self.project = Project(self)
        try:
            # Create the project
            self.setupProject()
            self.registerAgent(self.project)

            # Execute project
            self.executeProject()
            self.unregisterAgent(self.project)
        finally:
            # Destroy project
            self.project.destroy()
            self.project = None

    def on_application_interrupt(self):
        self.error("User interrupt!")
        self.send("univers_stop")

    def on_application_error(self, message):
        self.error(message)
        self.exitcode = 1
        self.send("univers_stop")

    def main(self, exit_at_end=True):
        """
        Main function of a fuzzer using Fusil: call runProject(), catch errors,
        and exit (if exit_at_end is True) with 0 on success or 1 on error.
        """
        try:
            self.runProject()
        except KeyboardInterrupt:
            self.interrupt("Project interrupted!")
        except PTRACE_ERRORS as error:
            writeError(self, error)
            self.exitcode = 1
        if exit_at_end:
            self.exit()
            exit(self.exitcode)

    def initX11(self):
        """
        X11 initialization: allow the fusil user to use X11 using
        xhost program.
        """
        if self._setup_x11:
            return
        self._xhost(self.config, True)
        self._setup_x11 = True

    def deinitX11(self):
        """
        X11 deinitialization: disallow the fusil user to use X11 using
        xhost program.
        """
        if not self._setup_x11:
            return
        self._setup_x11 = False
        self._xhost(self.config, False)

    def _xhost(self, config, allow):
        if config.process_uid is None:
            return
        command = xhostCommand(config.fusil_xhost_program, config.process_uid, allow)
        runCommand(self, command, stdout=None)
