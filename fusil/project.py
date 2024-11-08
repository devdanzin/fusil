from fusil.project_agent import ProjectAgent
from fusil.session import Session
from fusil.mas.agent_list import AgentList
from fusil.project_directory import ProjectDirectory
from time import time
from fusil.aggressivity import AggressivityAgent
from ptrace.os_tools import RUNNING_LINUX, RUNNING_PYPY
from fusil.process.debugger import Debugger
from shutil import copyfile
if RUNNING_PYPY:
    from gc import collect as gc_collect
if RUNNING_LINUX:
    from fusil.system_calm import SystemCalm

class Project(ProjectAgent):
    """
    A fuzzer project runs fuzzing sessions until we get enough successes or the
    user interrupts the project. Initialize all agents before a session starts,
    and cleanup agents at the session end.

    Before a session start, the project sleeps until the system load is under
    50% (may change with command line options).
    """
    def __init__(self, application):
        ProjectAgent.__init__(self, self, "project", mta=application.mta(), application=application)
        self.config = application.config
        options = application.options
        self.agents = AgentList()
        if RUNNING_LINUX:
            if options.fast:
                self.system_calm = None
            elif not options.slow:
                self.system_calm = SystemCalm(
                    self.config.fusil_normal_calm_load,
                    self.config.fusil_normal_calm_sleep)
            else:
                self.system_calm = SystemCalm(
                    self.config.fusil_slow_calm_load,
                    self.config.fusil_slow_calm_sleep)
        else:
            self.warning("SystemCalm class is not available")
            self.system_calm = None

        # Configuration
        self.max_session = options.sessions
        self.success_score = self.config.fusil_success_score
        self.error_score = self.config.fusil_error_score
        self.max_success = options.success

        # Session
        self.step = None
        self.nb_success = 0
        self.session = None
        self.session_index = 0
        self.session_timeout = None # in second

        # Statistics
        self.session_executed = 0
        self.session_total_duration = 0
        self.total_duration = None
        self._destroyed = False

        # Add Application agents, order is important:
        # MTA have to be the first agent
        for agent in application.agents:
            self.registerAgent(agent)
        self.registerAgent(self)

        # Create aggressivity agent
        self.aggressivity = AggressivityAgent(self)

        # Initial aggresssivity value
        if options.aggressivity is not None:
            self.aggressivity.setValue(options.aggressivity / 100)
            self.error("Initial aggressivity: %s" % self.aggressivity)

        # Create the debugger
        self.debugger = Debugger(self)

        # Create the working directory
        self.directory = ProjectDirectory(self)
        self.directory.activate()
        self.error("Use directory: %s" % self.directory.directory)

        # Initilize project logging
        self.initLog()

    def registerAgent(self, agent):
        self.agents.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        if agent not in self.agents:
            return
        self.agents.remove(agent, destroy)

    def init(self):
        """
        Function called once on project creation: create the project working
        directory, prepare the logging and create the first session.
        """
        self.project_start = time()
        self.createSession()

    def initLog(self):
        # Move fusil.log into run-xxx/project.log: copy fusil.log content
        # and then remove fusil.log file and log handler)
        logger = self.application().logger
        filename = self.createFilename("project.log")
        if logger.filename:
            copyfile(logger.filename, filename)
            logger.unlinkFile()
            mode = 'a'
        else:
            mode = 'w'
        logger.file_handler = logger.addFileHandler(filename, mode=mode)
        logger.filename = filename

    def deinit(self):
        if self.session_executed:
            self.summarize()

    def destroy(self):
        if self._destroyed:
            return
        self._destroyed = True

        # Destroy all project agents
        self.aggressivity = None
        self.debugger = None
        for agent in self.application().agents:
            self.agents.remove(agent, False)
        self.agents.clear()

        # Keep project directory?
        keep = self.directory.keepDirectory()
        if not keep:
            # Don't keep the directory: destroy log file
            logger = self.application().logger
            logger.unlinkFile()
            # And then remove the whole directory
            self.directory.rmtree()
        self.directory = None

        if RUNNING_PYPY:
            gc_collect()

    def createSession(self):
        """
        Create a new session:
         - make sure that system load is under 50%
         - activate all project agents
         - send project_start (only for the first session)
           and session_start messages
        """
        # Wait until system is calm
        if self.system_calm:
            self.system_calm.wait(self)

        self.info("Create session")
        self.step = 0
        self.session_index += 1
        self.use_timeout = bool(self.session_timeout)
        self.session_start = time()

        # Enable project agents
        for agent in self.agents:
            if not agent.is_active:
                agent.activate()

        # Create session
        self.session = Session(self)

        # Send 'project_start' and 'session_start' message
        if self.session_index == 1:
            self.send('project_start')
        self.send('session_start')
        text = "Start session"
        if self.max_session:
            percent = self.session_index * 100.0 / self.max_session
            text += " (%.1f%%)" % percent
        self.error(text)


    def destroySession(self):
        """
        Destroy the current session:
         - deactive all project agents
         - clear agents mailbox
        """
        # Update statistics
        if not self.application().exitcode:
            self.session_executed += 1
            self.session_total_duration += (time() - self.session_start)

        # First deactivate session agents
        self.session.deactivate()

        # Deactivate project agents
        application_agents = self.application().agents
        for agent in self.agents:
            if agent not in application_agents:
                agent.deactivate()

        # Clear session variables
        self.step = None
        self.session = None

        # Remove waiting messages
        for agent in application_agents:
            agent.mailbox.clear()
        self.mta().clear()

    def on_session_done(self, session_score):
        self.send('project_session_destroy', session_score)

    def on_project_stop(self):
        self.send('univers_stop')

    def on_univers_stop(self):
        if self.session:
            self.destroySession()

    def on_project_session_destroy(self, session_score):
        # Use session score
        self.session.score = session_score
        duration = time() - self.session_start
        if self.success_score <= session_score:
            log = self.error
        else:
            log = self.warning
        log("End of session: score=%.1f%%, duration=%.3f second" % (
            session_score*100, duration))

        # Destroy session
        self.destroySession()

        # Session success? project is done
        if self.success_score <= session_score:
            self.nb_success += 1
            text = "#%s" % self.nb_success
            if 0 < self.max_success:
                percent = self.nb_success * 100.0 / self.max_success
                text += "/%s (%.1f%%)" % (self.max_success, percent)
            self.error("Success %s!" % text)
            if 0 < self.max_success \
            and self.max_success <= self.nb_success:
                self.error("Stop! Limited to %s successes, use --success option for more" % self.max_success)
                self.send('univers_stop')
                return

        # Hit maximum number of session?
        if 0 < self.max_session \
        and self.max_session <= self.session_index:
            self.error("Stop! Limited to %s sessions, use --sessions option for more" % self.max_session)
            self.send('univers_stop')
            return

        # Otherwise: start new session
        self.createSession()

    def live(self):
        if self.step is not None:
            self.step += 1
        if not self.session:
            return
        if not self.use_timeout:
            return
        duration = time() - self.session_start
        if self.session_timeout <= duration:
            self.error("Project session timeout!")
            self.send('session_stop')
            self.use_timeout = False

    def summarize(self):
        """
        Display a summary of all executed sessions
        """
        count = self.session_executed
        info = []
        if count:
            duration = self.session_total_duration
            info.append("%s sessions in %.1f seconds (%.1f ms per session)"
                % (count, duration, duration * 1000 / count))
        duration = time() - self.project_start
        info.append("total %.1f seconds" % duration)
        info.append("aggresssivity: %s" % self.aggressivity)
        self.error("Project done: %s" % ", ".join(info))
        self.error("Total: %s success" % self.nb_success)

    def createFilename(self, filename, count=None):
        """
        Create a filename in the project working directory: add directory
        prefix and make sure that the generated filename is unique.
        """
        return self.directory.uniqueFilename(filename, count=count)

