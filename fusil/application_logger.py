from sys import stdout
from weakref import ref as weakref_ref
from logging import (getLogger, StreamHandler, Formatter,
    DEBUG, INFO, WARNING, ERROR)
from os import unlink

LOG_FILENAME = 'fusil.log'

class ApplicationLogger:
    def __init__(self, application):
        self.application = weakref_ref(application)
        self.timestamp_format = '%(asctime)s: %(message)s'

        # Get the logger
        self.logger = getLogger()
        self.logger.setLevel(ERROR)

        # Create stdout logger
        handler = StreamHandler(stdout)
        self.stdout = self.addHandler(handler, ERROR)

        # File logger is not set yet
        self.filename = None
        self.file_handler = None

    def applyOptions(self, options):
        # Choose log levels
        if options.debug:
            stdout_level = INFO
            file_level = DEBUG
        elif options.verbose:
            stdout_level = WARNING
            file_level = INFO
        elif not options.quiet:
            stdout_level = ERROR
            file_level = WARNING
        else:
            stdout_level = ERROR
            file_level = INFO
        logger_level = min(INFO, stdout_level, file_level)

        # Update log levels
        self.logger.setLevel(logger_level)
        self.stdout.setLevel(stdout_level)

        # fusil.log file
        self.filename = LOG_FILENAME
        self.file_handler = self.addFileHandler(self.filename, file_level)

    def addFileHandler(self, filename, level=None, mode='w', formatter_class=Formatter):
        if level is None:
            if self.application().options.verbose:
                level = DEBUG
            else:
                level = INFO
        handler = StreamHandler(open(filename, mode))
        formatter = formatter_class(self.timestamp_format)
        handler.setFormatter(formatter)
        self.addHandler(handler, level)
        return handler

    def addHandler(self, handler, level=None):
        handler.setLevel(level)
        self.logger.addHandler(handler)
        return handler

    def removeFileHandler(self, handler):
        handler.stream.close()
        self.removeHandler(handler)

    def removeHandler(self, handler):
        handler.close()
        self.logger.removeHandler(handler)

    def unlinkFile(self):
        if self.file_handler:
            self.removeFileHandler(self.file_handler)
            self.file_handler = None
        if self.filename:
            unlink(self.filename)
            self.filename = None

    def formatMessage(self, message, sender):
        message = str(message)
        application = self.application()
        prefix = []
        if application:
            if application.options:
                debug = application.options.debug
            else:
                debug = False
            project = application.project
            if project and project.session_index:
                prefix.append('[%s]' % project.nb_success)
                session = project.session
                if session:
                    prefix.append('[%s]' % session.name)
                if debug and project.step:
                    prefix.append('[step %s]' % project.step)
        else:
            debug = False
        if debug and sender is not None:
            prefix.append('[%s]' % sender.name)
        if prefix:
            message = ''.join(prefix)+' '+message
        return message

    def debug(self, message, sender):
        self.log(self.logger.debug, message, sender)

    def info(self, message, sender):
        self.log(self.logger.info, message, sender)

    def warning(self, message, sender):
        self.log(self.logger.warning, message, sender)

    def error(self, message, sender):
        self.log(self.logger.error, message, sender)

    def log(self, func, message, sender):
        message = self.formatMessage(message, sender)
        func(message)

