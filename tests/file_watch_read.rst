   >>> filename = 'test.txt'
   >>> from fusil.mockup import Project
   >>> from fusil.file_watch import FileWatch
   >>> from os import unlink
   >>> output = open(filename, 'wb')
   >>> def writeText(text):
   ...    output.write(text)
   ...    output.flush()
   ...
   >>> input = open(filename, 'rb')
   >>> project = Project()
   >>> watch = FileWatch(project, input, 'test')
   >>> watch.read_size = 1
   >>> watch.init()
   >>> list(watch.readlines())
   []
   >>> writeText('da')
   >>> list(watch.readlines())
   []
   >>> writeText('t')
   >>> list(watch.readlines())
   []
   >>> writeText('a\n')
   >>> list(watch.readlines())
   ['data']
   >>> writeText('linea\nlineb\n')
   >>> list(watch.readlines())
   ['linea', 'lineb']
   >>> writeText('line1\nline2\nline')
   >>> list(watch.readlines())
   ['line1', 'line2']
   >>> writeText('3\n')
   >>> list(watch.readlines())
   ['line3']
   >>> unlink(filename)

