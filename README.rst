Fusil is back, sorta
====================

This is a republishing of Victor Stinner's fusil project. It's probable
that much of the code doesn't work, as only the Python fuzzing code is
being tested and worked on. While some development is planned for
fuzzing Python, many other aspects of the library and other fuzzers
are currently out of scope for this repository.


However, code contributions to any parts of fusil will be accepted. Just
don't expect that new features will be worked on absent corresponding
code.

Many links in the docs don't work, but some can be retrieved using the
WayBack Machine. We'll probably update them sometime.

------------------------------------------------------------

Fusil is a Python library used to write fuzzing programs. It helps to start
process with a prepared environment (limit memory, environment variables,
redirect stdout, etc.), start network client or server, and create mangled
files. Fusil has many probes to detect program crash: watch process exit code,
watch process stdout and syslog for text patterns (eg. "segmentation fault"),
watch session duration, watch cpu usage (process and system load), etc.

Fusil is based on a multi-agent system architecture. It computes a session
score used to guess fuzzing parameters like number of injected errors to input
files.

Available fuzzing projects: ClamAV, Firefox (contains an HTTP server),
gettext, gstreamer, identify, libc_env, libc_printf, libexif, linux_syscall,
mplayer, php, poppler, vim, xterm.

Website: http://bitbucket.org/haypo/fusil/wiki/Home


Usage
=====

Fusil is a library and a set of fuzzers called "fusil-...". To run a fuzzer,
call it by its name. Example: ::

    $ fusil-gettext
    Fusil version 0.9.1 -- GNU GPL v2
    http://bitbucket.org/haypo/fusil/wiki/Home
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


Features
========

Why using Fusil instead your own hand made C script?

 * Fusil limits child process environment: limit memory, use timeout, make
   sure that process is killed on session end
 * Fusil waits until system load is load before starting a fuzzing session
 * Fusil creates a session directory used as the process current working
   directory and Fusil only creates files in this directory (and not in /tmp)
 * Fusil stores all actions in fusil.log but also session.log for all
   actions related of a session
 * Fusil has multiple available probes to compute session score: guess if
   a sessions is a succes or not
 * Fusil redirects process output to a file and searchs bug text patterns
   in the stdout/stderr (Fusil contains many text patterns to detect crashes
   and problems)


Installation
============

Read INSTALL documentation file.


Documentation
=============

Read doc/index.rst: documentation index.

