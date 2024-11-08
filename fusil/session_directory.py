from fusil.session_agent import SessionAgent
from fusil.directory import Directory
from fusil.tools import makeUnicode
from fusil.error import FusilError
from os.path import basename
from fusil.unsafe import SUPPORT_UID
from os import rename
if SUPPORT_UID:
    from os import getgid, chown
from fusil.unsafe import permissionHelp
import re
import grp
from errno import EPERM

# allow letters, digits, understand and dash
NORMALIZE_REGEX = re.compile(u'[^a-zA-Z0-9_-]')

# len('invalid_mem-access-0x8000000000000000') = 37
PART_MAXLEN = 40

class SessionDirectory(SessionAgent, Directory):
    def __init__(self, session):
        project = session.project()
        directory = project.createFilename(u'session',
            count=project.session_index)
        Directory.__init__(self, directory)
        SessionAgent.__init__(self, session, "directory:%s" % basename(self.directory))
        self.rename_parts = []
        self.rename_set = set()

    def init(self):
        self.info("Create the directory: %s" % self.directory)
        self.mkdir()

        # Allow fuzzer to write in the session directory
        uid = self.application().config.process_uid
        if uid is not None:
            self.changeOwner(uid)

    def changeOwner(self, uid):
        if not SUPPORT_UID:
            return
        gid = grp.getgrnam("fusil").gr_gid
        try:
            chown(self.directory, uid, gid)
        except OSError as err:
            raise
            if err.errno != EPERM:
                raise
            help = permissionHelp(self.application().options)
            message = "You are not allowed to change the owner of the directory %s to %s:%s" \
                % (self.directory, uid, gid)
            if help:
                message += " (%s)" % help
            raise FusilError(message)

    def checkKeepDirectory(self):
        session = self.session()
        application = self.application()
        if not self.isEmpty(False):
            if session.isSuccess():
                # Session sucess and non-empty directory: keep directory
                self.warning("Success: keep the directory %s" % self.directory)
                return True

            if application.exitcode:
                # Session sucess and non-empty directory: keep directory
                self.warning("Fusil error: keep the directory %s" % self.directory)
                return True

            if application.options.keep_sessions:
                # User asked to keep all datas
                self.warning("Keep the directory %s" % self.directory)
                return True

        if application.options.keep_generated_files \
        and not self.isEmpty(True):
            # Project generated some extra files: keep the directory
            self.warning("Keep the non-empty directory %s" % self.directory)
            return True

        # Remove empty directory
        return False

    def keepDirectory(self):
        # Ask project directory to keep the session directory at exit
        filename = basename(self.directory)
        project_dir = self.project().directory
        project_dir.ignore(filename)

        # Rename the session directory?
        if not self.rename_parts:
            return

        # Create the new filenme
        old_directory = self.directory
        filename = '-'.join(self.rename_parts)
        self.directory = project_dir.uniqueFilename(filename, save=False)
        self.error("Rename the session directory: %s" % basename(self.directory))
        rename(old_directory, self.directory)

    def deinit(self):
        if self.checkKeepDirectory():
            self.keepDirectory()
            return
        self.info("Remove the directory %s" % self.directory)
        self.rmtree()

    def on_session_rename(self, part):
        # Convert to unicode if needed
        part = makeUnicode(part)
        if not part:
            return

        # Truncate length
        if PART_MAXLEN < len(part):
            orig_part = part
            part = part[:PART_MAXLEN]
            self.info("Truncate the session name part %r to %r" % (orig_part, part))

        # Normalize
        orig_part = part
        part = NORMALIZE_REGEX.sub('_', part)
        if part != orig_part:
            self.info("Normalize the session name part %r: %r" % (orig_part, part))

        # Store the name part
        if part in self.rename_set:
            # skip duplicates
            return
        self.rename_set.add(part)
        self.rename_parts.append(part)

