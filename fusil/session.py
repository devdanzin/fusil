from fusil.project_agent import ProjectAgent
from fusil.session_agent import SessionAgent
from fusil.mas.agent_list import AgentList
from fusil.session_directory import SessionDirectory
from fusil.score import normalizeScore
from logging import INFO
from ptrace.os_tools import RUNNING_PYPY
from logging import Formatter
import re
if RUNNING_PYPY:
    from gc import collect as gc_collect

# Match "[0][session 0010] "
PREFIX_REGEX = re.compile(r"\[[0-9]\]\[+session [0-9]+\] ")

class SessionFormatter(Formatter):
    """
    Log formatter for session.log: only write the message and
    remove fusil prefix:

    "[0][session 0010] text" => "text"
    """
    def format(self, record):
        text = Formatter.format(self, record)
        return PREFIX_REGEX.sub('', text)

class Session(SessionAgent):
    """
    A session of the fuzzer:
     - create a directory as working directory
     - compute the score of the session
    """
    def __init__(self, project):
        self.agents = AgentList()
        self.score = None
        self.log_handler = None
        name = "session %s" % project.session_index
        SessionAgent.__init__(self, self, name, project=project)

    def isSuccess(self):
        if self.score is None:
            return False
        return self.project().success_score <= self.score

    def computeScore(self, verbose=False):
        """
        Compute the score of the session:
         - call getScore() method of all agents
         - normalize the score in [-1.0; 1.0]
         - apply score factor (weight)
         - compute the sum of all scores
        """
        session_score = 0
        for agent in self.project().agents:
            if not issubclass(agent.__class__, ProjectAgent):
                # Skip application agent which has no score
                continue
            if not agent.is_active:
                continue
            score = agent.getScore()
            if score is None:
                continue
            score = normalizeScore(score)
            score *= agent.score_weight
            score = normalizeScore(score)
            if verbose and score:
                self.info("- %s score: %.1f%%" % (agent, score*100))
            session_score += score
        return session_score

    def registerAgent(self, agent):
        self.agents.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        if agent not in self.agents:
            return
        self.agents.remove(agent, destroy)

    def init(self):
        self.directory = SessionDirectory(self)

        log_filename = self.createFilename("session.log")
        self.log_handler = self.logger.addFileHandler(
            log_filename, level=INFO, formatter_class=SessionFormatter)

        self.stopped = False

    def deinit(self):
        if self.log_handler:
            self.logger.removeFileHandler(self.log_handler)
        self.agents.clear()
        if RUNNING_PYPY:
            gc_collect()

    def live(self):
        """
        Compute the score of the session and stop the session if the score is
        smaller than -50% or bigger than 50%.
        """
        if self.stopped:
            return
        score = self.computeScore()
        if score is None:
            return
        project = self.project()
        if not(project.success_score <= score or score <= project.error_score):
            return
        self.send('session_stop')

    def on_session_stop(self):
        if self.stopped:
            return
        self.stopped = True
        score = self.computeScore(True)
        if self.project().success_score <= score:
            self.send('session_success')
        self.send('session_done', score)

    def createFilename(self, filename, count=None):
        """
        Create a filename in the session working directory: add directory
        prefix and make sure that the generated filename is unique.
        """
        return self.directory.uniqueFilename(filename, count=count)

