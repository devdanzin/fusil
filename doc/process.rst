++++++++++++++++++++
Fusil process agents
++++++++++++++++++++

.. section-numbering::
.. contents::

Create your process
===================

Today, Fusil only supports UNIX process.

runCommand()
------------

runCommand() function from fusil.process.tools is a wrapper to os.system(). It
raises a RuntimeError() if the command failed (exit code is different than
zero). ::

    >>> from fusil.process.tools import runCommand
    >>> from fusil.mockup import Logger
    >>> logger = Logger()
    >>> runCommand(logger, ['echo', 'Hello World!'])

CreateProcess and ProjectProcess
--------------------------------

This action class does prepare the environment for a process and then use
subprocess.Popen() to create the process object.

ProjectProcess creates the process with 'session_start()' event whereas
CreateProcess have to be inherited to add your own session handler calling
self.createProcess() method.

Attributes:

 * env: Environment() object used to create environment variables
 * stdin: if value is False, use a null device as stdin.
 * stdout: Stdout type:

   - 'file' (default): stdout and stderr are written in a file
   - 'null': use a a null device as stdout and stderr

 * cmdline: CommandLine() object used to create the command line
 * timeout: maximum execution duration of the process in second (default: 10
   second). If the timeout is reached, the process is directly killed with
   SIGKILL signal. Use None value to disable timeout.
 * max_memory: Limit of memory grow in bytes (default: 100 MB). Use None value
   to disable memory limitation.
 * popen_args: Dictionary of supplementary options to Popen() constructor
   (default: see source code).

Example: ::

   >>> from fusil.mockup import Project
   >>> project = Project()
   >>> from fusil.process.create import CreateProcess
   >>> null_stdout = CreateProcess(project, ['/bin/ls', '-lR'],
   ...     stdout='null', timeout=None)
   ...


Environment
-----------

This class is responsible to create new process environment variables. It
does copy some variables from Fusil environment and allow to set/generate some
others. On Linux, no variable is copied. On Windows, only SYSTSEMROOT is
copied. You may copy variables like LANGUAGE, LANG, PATH, HOME or DISPLAY
using: ::

    env.copy('DISPLAY')

Methods:

 * set(name, value): set a fixed value variable value
 * add(var): add a new fuzzy variable
 * copy(name): copy an environment variable value (only if it's set)
 * copyX11(): copy X11 environment variables (don't use directly! use
   process.setupX11())

To set/generate a variable, use on of these classes:

 * EnvVarValue: fixed value
 * EnvVarLength: generate long value to find buffer overflow.
 * EnvVarInteger: generate signed integer value
 * EnvVarIntegerRange(min, max): generate an integer value in the range [min; max]
 * EnvVarRandom: generate random bytes, use all byte values except nul byte
   (forbidden in environment variable value)

Attributes (EnvVarValue has only name attribute):

 * name: Variable name, it can be a list
 * min_length: Minimum number of bytes (default: 0)
 * max_length: Maximum number of bytes (default: 2000)
 * bytes: bytes set (default: set('A'))

Variable name is a string but it can be a tuple or list of strings. Examples: ::

   env.set('LANGUAGE', 'fr')
   env.set(('LANGUAGE', 'LANG', 'LC_ALL'), 'C', max_count=2)
   env.add(EnvVarLength('PATH'))
   env.add(EnvVarRandom('HOME'))
   env.add(EnvVarInteger(['COLUMNS', 'SIZE']))


Command line
------------

CreateProcess object has cmdline attribute of type CommandLine. This object
has only one attribute: arguments which is a list of string.


Linux graphical application (X11)
---------------------------------

To be able to use a graphical application on Linux, use: ::

    >>> process = CreateProcess(project, ['ls', '-l'])
    >>> process.setupX11()

It allows fuzzer process to access to X11 server and copy needed environment
variables (HOME, DISPLAY and XAUTHORITY). See Environment.copyX11().


Watch process activity
======================

WatchProcess
------------

Watch the process created by CreateProcess: wait until the process exit or the
process death (killed by a signal). It uses the exit status to compute the
probe score:

 - if process time has been reached the timeout, probe score is:
   'timeout_score' (default: 100%)
 - if exit code is nul, score is 'default_score' (default: 0%)
 - if exit code is not nul, score is 'exitcode_score' (default: 50%)
 - if process has been killed by a signal, score is 'signal_score'
   (default: 100%)


WatchProcessStdout
------------------

WatchProcessStdout inherits on FileWatch_: it looks for error message patterns
in process stdout (and stderr if process is configured to write stderr to
stdout).

.. _FileWatch: file_watch.html

AttachProcessPID
----------------

Watch an existing process: find it using its identifier. Example: ::

  >>> from fusil.mockup import Project
  >>> from fusil.process.attach import AttachProcessPID
  >>> project = Project()
  >>> pid =  42
  >>> process = AttachProcessPID(project, pid)


AttachProcess
-------------

Similar to AttachProcessPID but find the process using its name instead of its
identifier. Example: ::

    >>> from fusil.mockup import Project
    >>> from fusil.process.attach import AttachProcess
    >>> project = Project()
    >>> AttachProcess(project, "clamav")
    <AttachProcess id=13, name='attach_process:clamav' is_active=False>


CPU load probe: CpuProbe
========================

AttachProcess, AttachProcessPID and WatchProcess have 'cpu' attribute of type
CpuLoad.  If CPU load is bigger than maximum load during maximum duration, set
score to 'max_score' (default: 100%). Default values: ::

   >>> from fusil.mockup import Project
   >>> project = Project()
   >>> from fusil.process.cpu_probe import CpuProbe
   >>> probe = CpuProbe(project, 'cpu')
   >>> probe.max_load
   0.75
   >>> probe.max_duration
   10.0
   >>> probe.max_score
   1.0

