++++++++++++++++
Fusil user guide
++++++++++++++++

.. section-numbering::
.. contents::

Introduction
============

Fusil projects contains a set of fuzzers called "fusil-..." (eg.
fusil-firefox). Each fuzzer has its own command line options, use different
input data (text, picture, video, etc.), and test a different program or
library. For each crash, Fusil stores all files used to run the session in a
dedicated directory and generate a script to replay the session (eg. reproduce a
crash in gdb).

The document presents how to run a fuzzer and analyze the crashs.


Fuzzer list
===========

Applications
------------

 * fusil-clamav: ClamAV antivirus
 * fusil-firefox: Any content embedded in an HTML page in Firefox
   (JPEG/PNG pictures, video, Flash, etc.)
 * fusil-imagemagick: Image Magick (image manipulation), use identify
   or convert program
 * fusil-mplayer: Mplayer (audio/video player)
 * fusil-ogg123: Ogg/Vorbis music player, use the programs ogg123 (default)
   or ogginfo
 * fusil-vlc: VLC (audio/video player)

Libraries
---------

 * fusil-gettext: Gettext library (text internationalization aka i18n),
   part of the GNU C library
 * fusil-gstreamer: Gstreamer (audio/video codec and player), use the
   program gst-launch-0.10 with playbin or build a pipeline
 * fusil-libc-printf: printf() function of the system C library
 * fusil-poppler: popper (PDF) library used by Evince and Kpdf programs

Programming language
--------------------

 * fusil-php: PHP language
 * fusil-python: Python language

Other
-----

 * fusil-wizzard: Generic Linux command line fuzzer
 * fusil-zzuf: wrapper to the zzuf fuzzer (mutation of input files and network
   sockets)


Run a fuzzer
============

Example with the execution of gettext fuzzer: ::

    $ fusil-gettext
    Fusil version 0.9.1 -- GNU GPL v2
    http://fusil.hachoir.org/
    (...)
    [0][session 13] Start session
    [0][session 13] ------------------------------------------------------------
    [0][session 13] PID: 16989
    [0][session 13] Signal: SIGSEGV
    [0][session 13] Invalid read from 0x0c1086e0
    [0][session 13] - instruction: CMP EDX, [EAX]
    [0][session 13] - mapping: 0x0c1086e0 is not mapped in memory
    [0][session 13] - register eax=0x0c1086e0
    [0][session 13] - register edx=0x00000019
    [0][session 13] ------------------------------------------------------------
    [0][session 13] End of session: score=100.0%, duration=3.806 second
    (...)
    Success 1/1!
    Project done: 13 sessions in 5.4 seconds (414.5 ms per session), total 5.9 seconds, aggresssivity: 19.0%
    Total: 1 success
    Keep non-empty directory: /home/haypo/prog/SVN/fusil/trunk/run-3

A fuzzer does not require any human interaction: it generates data, start the
target software, store files if the software crashed, and restart with new
data. By default, the fuzzer stops after the first "success" (crash). You
can interrupt the fuzzer with the key combinaison CTRL+c.


Fuzzer options
==============

Each fuzzer has its own options plus common Fusil options. Use --help option
(eg. "fusil-firefox --help") to get the list of all available options.

Common options:

 * --success=50: Stop after 50 success (default: 1)
 * --sessions=1000: Stop after 1000 sessions (default: unlimited)
 * --fast/--slow: Run faster/slower (more/less CPU intensive).
   WARNING: --fast may introduce false positive with some fuzzers.
 * -v or --verbose: Verbose mode, display more details about the fuzzer
   execution. Use --debug to get all messages, and --quiet for less messages.


Analyze a crash
===============

After a crash, Fusil stores all files used to execute the program in a
dedicated directory. Go into this directory to analyze the crash.

Directory names
---------------

The directory tree looks like: ::

   gettext-4/
   gettext-4/exitcode-1/
   gettext-4/invalid_read-null/
   gettext-4/invalid_read-null-2/
   gettext-4/session-609/

The main directory name (gettext-4) is based on the fuzzer name (fusil-gettext
in our example), and duplicate names ends with a number (gettext-2, gettext-3,
...). The name of a crash directory contains informations about the crash:

 * exitcode-1: gettext exited with the code 1
 * invalid_read-null: gettext was killed because of an invalid memory read from
   the NULL addresss
 * session-609: Fusil doesn't know any useful information about the crash,
   the name is just the number of the session

Duplicate directories have also a number as suffix (invalid_read-null-2,
invalid_read-null-3, ...).

List crash directories gives a global view of the crashs. You can also see
duplicate crashs: invalid_read-null and invalid_read-null-2 should be the same
bug.

If the fuzzer is still running, you may see a temporary directory which will be
destroyed at the end of the session (eg. session-130, session-131, session-132,
...).

Read the session.log
--------------------

A session directory always contains a file called "session.log" which contains
events from the fuzzer. The file always contains useful informations about
input data and usually also informations about the crash.

Read the stdout
---------------

Most fuzzers create a process. The process output, standard output and error
streams (stdout/stderr), is written into a file called "stdout". It's the
second most useful file to analyze a crash.

The output may be truncated before the program crash because the output buffer
was not flushed before the crash. fusil-python fuzzer uses the Python command
line option "-u" to get unbuffered output.

Replay the crash
----------------

To replay a crash, Fusil creates a script called replay.py to replay
(reproduce) the crash. It starts the process with the same command line
options, environment variables, but also the same process limitations (limit
memory, start under a different user, ...) to avoid a denial of service of your
computer.

Just type "./replay.py" to replay the session. To get more information, you can
run the process in the gdb debugger (--gdb option) or Valgrind (--valgrind).

There are other options: use "./replay.py --help" to get the list of all
options.

