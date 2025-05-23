import re
from errno import EBADF
from os.path import basename
from time import time

from fusil.project_agent import ProjectAgent
from fusil.score import scoreLogFunc
from fusil.six import b, iteritems, text_type
from fusil.tools import makeFilename

VALID_POS = ("zero", "end", "current")


class FileWatch(ProjectAgent):
    def __init__(self, project, file_obj, name, start=None):
        if not start:
            start = "zero"
        if start not in VALID_POS:
            raise ValueError(
                "start position (%r) have to be in %s" % (start, VALID_POS)
            )

        ProjectAgent.__init__(self, project, name)
        self.file_obj = file_obj
        self.ignore = []
        self.start = start
        self.regexs = []
        self.compiled_patterns = None
        self._need_compile = True
        # Minimum number of lines:
        # eg. (10, -0.2) to add -20% to score if there is fewer than 10 lines
        self.min_nb_line = None
        self.max_nb_line = (100, 1.0)
        self.last_seed = None
        self.log_not_matching = False
        self.show_matching = False
        self.show_not_matching = self.application().options.debug
        self.read_size = 4096
        self.cleanup_func = None
        self.max_process_time = 0.250  # second
        # FIXME: write methods instead of direct access to self.words
        # to be able to update self._need_compile
        self.words = {
            # Notice and warning
            "too large": 0.10,
            "unknown": 0.10,
            "can't": 0.10,
            "could not": 0.10,
            "not allowed": 0.10,
            "invalid": 0.10,
            "not valid": 0.10,
            "failed": 0.10,
            "failure": 0.10,
            "warning": 0.10,
            # Non fatal errors
            "oops": 0.30,  # Linux kernel Oops: "Oops: 0000"
            "bug": 0.30,
            "pointer": 0.30,
            "error": 0.30,
            "allocate": 0.40,
            "memory": 0.40,
            "permission": 0.40,
            "overflow": 0.40,
            # Fatal errors
            "fatal": 0.1,
            "assert": 0.2,
            "assertion": 1.0,
            "critical": 1.0,
            "exception": 1.0,
            "panic": 1.0,
            "glibc detected": 1.0,
            "segfault": 1.0,
            "segmentation fault": 1.0,
        }
        # Matches that should make the whole session ignored
        self.kill_words = set()

    @staticmethod
    def fromFilename(project, filename, start=None):
        input_file = open(filename, "rb")
        return FileWatch(project, input_file, basename(filename), start)

    def ignoreRegex(self, regex, flags=0):
        if isinstance(regex, text_type):
            regex = regex.encode("ASCII")
        regex = re.compile(regex, flags)
        self.ignore.append(regex.search)

    def addRegex(self, regex, score, flags=0):
        if isinstance(regex, text_type):
            regex = regex.encode("ASCII")
        match = re.compile(regex, flags).search
        self.regexs.append((regex, score, match))
        self._need_compile = True

    def compilePatterns(self):
        for text, score, match in self.regexs:
            yield (text, score, match)

        for text, score in iteritems(self.words):
            text = text.lower()
            if isinstance(text, text_type):
                text = text.encode("ASCII")
            regex = re.escape(text)
            regex = b(r"(?:^|\W)") + regex + b(r"(?:$|\W)")
            match = re.compile(regex, re.IGNORECASE).search
            yield (text, score, match)

        for text in self.kill_words:
            text = text.lower()
            if isinstance(text, text_type):
                text = text.encode("ASCII")
            regex = re.escape(text)
            regex = b(r"(?:^|\W)") + regex + b(r"(?:$|\W)")
            match = re.compile(regex, re.IGNORECASE).search
            yield (text, 100, match)

    def setFileObject(self, file_obj):
        self.file_obj = file_obj
        self.prepareFile()

    def init(self):
        if self.start == "zero":
            self.last_seed = None
        self.total_line = 0
        self.nb_line = 0
        self.score = 0
        if (self.compiled_patterns is None) or self._need_compile:
            self._need_compile = False
            self.compiled_patterns = list(self.compilePatterns())
        self.buffer = []
        if self.file_obj:
            self.prepareFile()

    def prepareFile(self):
        oldpos = self.file_obj.tell()
        if self.start == "zero":
            self.file_obj.seek(0)
        elif self.start == "end":
            self.file_obj.seek(0, 2)
        self.file_seed = self.file_obj.tell()
        self.file_obj.seek(oldpos)

    def splitlines(self, data):
        lines = data.splitlines(1)
        for index, line in enumerate(lines):
            if index == len(lines) - 1 and line[-1] not in b("\n\r"):
                self.buffer.append(line)
                return
            if index == 0 and self.buffer:
                self.buffer.append(line)
                line = b("").join(self.buffer)
                self.buffer = []
            yield line.rstrip()

    def processLine(self, line):
        # Total number of line
        self.total_line += 1
        if self.max_nb_line and self.max_nb_line[0] <= self.total_line:
            score = self.max_nb_line[1]
            log = scoreLogFunc(self, score)
            log(
                "More than %s lines written: increment score by %.1f%%"
                % (self.total_line, score * 100)
            )
            self.score += score
            self.max_nb_line = None
            self.send("session_rename", "long_output")

        # Ignore this line?
        if self.cleanup_func:
            if not line:
                return
            line = self.cleanup_func(line)
        if not line:
            return
        for ignore_func in self.ignore:
            if ignore_func(line):
                return

        # Number of line
        self.nb_line += 1

        # Search the matching pattern with the highest score
        found = None
        self.kill_patterns = {word.lower().encode() for word in self.kill_words}
        for pattern, score, match in self.compiled_patterns:
            if found and abs(score) < abs(found[1]):
                continue
            if not match(line):
                continue
            found = (pattern, score)
            if pattern in self.kill_patterns:
                break
        if not found:
            message = "Not matching line: %r" % line
            if self.show_not_matching:
                self.error(message)
            elif self.log_not_matching:
                self.info(message)
            return

        pattern, score = found
        if pattern in self.kill_patterns:
            self.error(f"Ignoring session due to kill word: {pattern}.")
            return "KILL"

        if self.show_matching:
            log = self.error
        else:
            log = self.warning
        log("Match pattern %r (score %.1f%%) in %r" % (pattern, score * 100, line))
        self.score += score
        name = makeFilename(pattern)
        self.send("session_rename", name)

    def readlines(self):
        try:
            first_line = self.total_line
            time0 = time()
            while True:
                duration = time() - time0
                if self.max_process_time < duration:
                    count = self.total_line - first_line
                    self.warning(
                        "Too slow: proceed %s lines in %.1f sec" % (count, duration)
                    )
                    return
                oldpos = self.file_obj.tell()
                self.file_obj.seek(self.file_seed)
                data = self.file_obj.read(self.read_size)
                self.file_seed = self.file_obj.tell()
                self.file_obj.seek(oldpos)
                if not data:
                    return
                for line in self.splitlines(data):
                    yield line
        except IOError as err:
            if err.errno == EBADF:
                self.error(
                    "Unable to read data: closed file (Bad file descriptor error)"
                )
                self.file_obj = None
                return
            else:
                raise

    def on_session_stop(self):
        if self.min_nb_line and (self.total_line < self.min_nb_line[0]):
            self.warning(
                "Fewer than %s lines (total=%s): add %+.1f to the score"
                % (self.min_nb_line[0], self.total_line, self.min_nb_line[1] * 100)
            )
            self.score += self.min_nb_line[1]

    def live(self):
        # File closed: just exit
        if not self.file_obj:
            return
        for line in self.readlines():
            if 1.0 <= abs(self.score):
                break
            res = self.processLine(line)
            if res == "KILL":
                break

    def getScore(self):
        return self.score

    def close(self):
        if not self.file_obj:
            return
        self.file_obj.close()
        self.file_obj = None
