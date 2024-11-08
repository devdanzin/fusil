   >>> from fusil.mockup import Project, Logger
   >>> from fusil.file_watch import FileWatch
   >>> from os import unlink
   >>> from StringIO import StringIO
   >>> logger = Logger(show=True)
   >>> project = Project(logger)

   >>> buffer = StringIO()
   >>> def writeText(text):
   ...    buffer.write(text)
   ...
   >>> watch = FileWatch(project, buffer, 'test')
   >>> watch.show_matching = True
   >>> watch.show_not_matching = True
   >>> watch.ignoreRegex("[Hh]ello")
   >>> watch.ignoreRegex("hello")
   >>> watch.addRegex('XDSDFOS', 1.0)
   >>> watch.activate()
   >>> watch.init()
   >>> writeText("HELLO\nhello\nHello\n")
   >>> watch.live()
   Not matching line: 'HELLO'
   >>> writeText("this is an error\n")
   >>> watch.live()
   Match pattern 'error' (score 30.0%) in 'this is an error'
   >>> writeText("test pattern XDSDFOS\n")
   >>> watch.live()
   Match pattern 'XDSDFOS' (score 100.0%) in 'test pattern XDSDFOS'

