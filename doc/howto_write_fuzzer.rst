+++++++++++++++++++++++++++++++++
HOWTO: Write a fuzzer using Fusil
+++++++++++++++++++++++++++++++++

.. section-numbering::
.. contents::

Identify your target
====================

Before writing a fuzzer, you have to analyze your target: identify input
vectors and list methods to watch target activity.

Identify input vectors
----------------------

Example of input vectors:

 - the command line
 - environment variables
 - files
 - sockets (TCP, UDP, UNIX, etc.)
 - etc.

Some tools help in this job:
 - strace to watch syscalls (eg. "strace -e open program ...")
 - ltrace to watch library function calls (eg. "ltrace -e getenv program ...")
 - netstat to watch network connections (sockets)

Watch target activity
---------------------

Example target probes:

 - standard output: stdout and stderr
 - process exit status (exit code or signal used to kill the process)
 - logging file (eg. /var/log/clamav/clamav.log)
 - network ping
 - run the process in a debugger to trace faults (signals)
 - ...


Hello world fuzzer
==================

First draft
-----------

Let's start with the most simple fuzzer. Create a file "hello.py" with this code: ::

    #!/usr/bin/env python
    from fusil.application import Application
    from fusil.process.create import ProjectProcess

    class Fuzzer(Application):
        def setupProject(self):
            ProjectProcess(self.project, ['echo', 'Hello World!'])

    if __name__ == "__main__":
        Fuzzer().main()

Source code details:

 - it's a Python (executable) program
 - you have to inherit Application class and define the setupProject() method
 - setupProject() creates the project "agents"
 - the process agent is not stored in a variable: it's transparently register in Fusil agent list
 - main() method starts the fuzzer, activate agents, execute the different sessions, etc.

Let's try this amazing fuzzer! Stop it using CTRL+c: ::

    $ chmod +x hello.py
    $ ./hello.py
    Fusil version 0.9.1 -- GNU GPL v2
    http://fusil.hachoir.org/
    Use directory: /home/haypo/prog/SVN/fusil/trunk/run-1
    [0][session 1] Start session
    ^C
    [0][session 1] Project execution interrupted!
    [0][session 1] Project done: total 5.6 seconds, aggresssivity: 1.0%
    [0][session 1] Total: 0 success
    [0][session 1] Process 8210 exited normally

Working example
---------------

This fuzzer is useless because it doesn't know if the process is still active
or not. We have to add some probes: WatchProcess to watch the exit status and
WatchStdout to watch the standard output: ::

    from fusil.process.watch import WatchProcess
    from fusil.process.stdout import WatchStdout

    class Fuzzer(Application):
        def setupProject(self):
            process = ProjectProcess(self.project, ['echo', '"Hello World!"'])
            WatchProcess(process)
            WatchStdout(process)

Let's retry with a maximum of 1 session: ::

    $ ./hello.py  --sessions=1
    Fusil version 0.9.1 -- GNU GPL v2
    http://fusil.hachoir.org/
    Use directory: /home/haypo/prog/SVN/fusil/trunk/run-1
    [0][session 1] Start session
    [0][session 1] Process 8222 exited normally
    Stop! Limited to 1 sessions, use --session option for more
    Project done: 1 sessions in 0.1 seconds (63.8 ms per session), total 1.1 seconds, aggresssivity: 2.0%
    Total: 0

See "Process 8222 exited normally" line: the session stopped because the
process is done.

Real fuzzer
-----------

Execute the echo program with a constant argument is not so funny, we have to
add some random arguments. ProjectProcess can't be used because it creates
automatically the process on session start. So we will use CreateProcess which
allows to do some operations before the process start. The patch: ::

    from fusil.process.create import CreateProcess
    from fusil.bytes_generator import BytesGenerator, ASCII0
    from random import randint, choice

    class EchoProcess(CreateProcess):
        OPTIONS = ("-e", "-E", "-n")

        def __init__(self, project):
            CreateProcess.__init__(self, project, ["echo"])
            self.datagen = BytesGenerator(1, 10, ASCII0)

        def createCmdline(self):
            arguments = ['echo']
            for index in xrange(randint(3, 6)):
                if randint(1, 5) == 1:
                    option = choice(self.OPTIONS)
                    arguments.append(option)
                else:
                    data = self.datagen.createValue()
                    arguments.append(data)
            return arguments

        def on_session_start(self):
            self.cmdline.arguments = self.createCmdline()
            self.createProcess()

Details:

 - The most important method is on_session_start(): it's called when the event
   "session_start" is emitted. This method recreates the command line
   arguments and create the process.
 - createCmdline() creates random arguments for the echo program: 25% of
   options (-e, -E or -n) and 75% of random strings (ASCII characters in
   range 1..255)
 - __init__() is overwrite to create the datagen attribute
 - fusil.bytes_generator module contains tools (classes) to generate
   random byte strings

Test examples
-------------

See examples/ directory. It contains hello-world (first version of Hello World)
and good-bye-world (working echo fuzzer).


Inject data to your target
==========================

Command line and environment variable
-------------------------------------

See process.rst documentation.

Files
-----

See mangle.rst documentation.

To write a C program, see c_tools.rst documentation

Network
-------

See network.rst documentation.


Watch target activity
=====================

Standard output and logging files
---------------------------------

Use WatchStdout and FileWatch. See also file_watch.rst documentation.

Process exit status
-------------------

Use WatchProcess and read process.rst documentation.

