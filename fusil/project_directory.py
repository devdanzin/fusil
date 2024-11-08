from os.path import basename
from fusil.project_agent import ProjectAgent
from fusil.directory import Directory
from os import getcwd

class ProjectDirectory(ProjectAgent, Directory):
    def __init__(self, project):
        # Create $PWD/run-0001 directory name
        Directory.__init__(self, getcwd())
        name = project.application().NAME
        self.directory = self.uniqueFilename(name, save=False)

        # Initialize the agent and create the directory
        ProjectAgent.__init__(self, project, "directory:%s" % basename(self.directory))
        self.warning("Create the directory: %s" % self.directory)
        self.mkdir()

    def keepDirectory(self, verbose=True):
        if not self.directory:
            return False

        # No session executed? Remove the directory
        project = self.project()
        application = self.application()

        # Fusil error? Keep the directory
        if application \
        and application.exitcode:
            if verbose:
                self.warning("Fusil error: keep the directory %s" % self.directory)
            return True

        # Not session executed: remove the directory
        if project \
        and not project.session_executed \
        and (not application or not application.options.keep_sessions):
            return False

        # Keep generated files?
        if not self.isEmpty(True):
            # Project generated some extra files: keep the directory
            if verbose:
                self.error("Keep the non-empty directory %s" % self.directory)
            return True

        # Default: remove the directory
        return False

    def rmtree(self):
        if not self.directory:
            return
        self.info("Remove the directory: %s" % self.directory)
        Directory.rmtree(self)
        self.directory = None

    def destroy(self):
        keep = self.keepDirectory(verbose=False)
        if not keep:
            self.rmtree()

