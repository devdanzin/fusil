+++++++++
FileWatch
+++++++++

.. section-numbering::
.. contents::

FileWatch is a probe used by WatchProcessStdout agent to watch a plain text file. It
looks for patterns in new inserted lines.

Constructor
-----------

Fake objects used for the documentation:

   >>> from fusil.mockup import Project, Logger
   >>> logger = Logger()
   >>> project = Project(logger)

Constructor syntax:

   >>> from fusil.file_watch import FileWatch
   >>> log = FileWatch(project, open('README', 'rb'), 'README')

Or just fromFilename() static method to only write the filename once:

   >>> log = FileWatch.fromFilename(project, 'README')

If you watch server log, use start="end" to skip existing logs:

   >>> log = FileWatch.fromFilename(project, 'README', start='end')


Ignore lines
------------

Use ignoreRegex() method to ignore lines:

   >>> from re import IGNORECASE
   >>> log.ignoreRegex('^error: meaningless error')
   >>> log.ignoreRegex('^ErrOR: another error', IGNORECASE)

You can add your own ignore handler:

   >>> def ignoreNumber42(text):
   ...    try:
   ...       return int(text) == 42
   ...    except ValueError:
   ...       return False
   ...
   >>> log.ignore.append(ignoreNumber42)
   >>> ignoreEmptyLine = lambda line: len(line.strip()) == 0
   >>> log.ignore.append(ignoreEmptyLine)


Words patterns
--------------

'words' patterns are case insensitive and only match 'word'.
Example: "abc" pattern which match line "text: abc" but not "abcd".

FileWatch includes many text patterns in 'words' attribute:

   >>> words = log.words.keys()
   >>> from pprint import pprint
   >>> words.sort(); pprint(words)
   [u'allocate',
    u'assert',
    u'assertion',
    u'bug',
    u"can't",
    u'could not',
    u'critical',
    u'error',
    u'exception',
    u'failed',
    u'failure',
    u'fatal',
    u'glibc detected',
    u'invalid',
    u'memory',
    u'not allowed',
    u'not valid',
    u'oops',
    u'overflow',
    u'panic',
    u'permission',
    u'pointer',
    u'segfault',
    u'segmentation fault',
    u'too large',
    u'unknown',
    u'warning']

Get/set pattern score:

   >>> print log.words['overflow']
   0.4
   >>> log.words['overflow'] = 0.5


Regex patterns
--------------

'regexs' attribute is a list of regex, use addRegex() to add a regex:

   >>> log.addRegex('^Crash: ', 1.0)
   >>> log.addRegex('null pointer$', 1.0, flags=IGNORECASE)


Patterns compilation
--------------------

All patterns are compiled by createRegex() method on agent initialisation.
It uses 'patterns' and 'words' attributes. Example:

   >>> log = FileWatch.fromFilename(project, 'README')
   >>> log.words = {'error': 0.5}
   >>> log.addRegex('mplayer', 1.0)
   >>> for pattern, score, match in log.compilePatterns():
   ...     print "%r, score %.1f%%, regex=%s" % (pattern, score, match)
   ...
   'mplayer', score 1.0%, regex=...
   'error', score 0.5%, regex=...


Cleanup line
------------

You can register a function to cleanup lines:

   >>> log.cleanup_func = lambda text: text[7:]

Test of the function:

   >>> # Prepare test
   >>> log.activate()
   >>> log.init()
   >>> log.show_not_matching = True; logger.show = True
   >>> # Example of line
   >>> log.processLine('PREFIX:Real line content')
   Not matching line: 'Real line content'
   >>> # Empty line
   >>> log.processLine('PREFIX:')
   >>> # Cleanup test
   >>> log.show_not_matching = False; logger.show = False


Line number
-----------

'nb_line' contains the number of lines (without ignored lines) and
'total_line' the total number of lines. 'max_nb_line' attribute is the maximum
number of total lines: (max, score). If 'nb_line' becomes bigger than max,
score is incremented by score. Ignored lines are not included in 'nb_line'.
Default value:

    >>> log.max_nb_line
    (100, 1.0)

To disable the maximum of line number, set 'max_nb_line' to None.

There is a similar option for the minimum number of line, but it's disabled
by default (no minimum). Example to add -50% to the score if there is fewer
than 10 lines of output:

    >>> log.min_nb_line = (10, -0.5)


Pattern matching
----------------

For each text line, FileWatch calls processLine(). First it checks if the
line matchs one ignore pattern. If not, it tries all patterns and uses
the one with the biggest absolute score.

   >>> log.init()
   >>> log.processLine('This is an error')
   >>> print log.score
   0.5

Attributes:
 - show_matching (default: False): use True to show matching lines
   (use ERROR log level instead of WARNING)
 - show_not_matching (default: False): use True to show not matching lines
   (--debug option enable this option)
 - log_not_matching (default: False): use True to log not matching lines.
   By default, lines are not logged because the output is already
   written to session "stdout" file.

