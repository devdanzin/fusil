Status of Windows support
=========================

Windows support of Fusil is minimal. No fuzzer works because all depends on
programs missing on Windows (eg. strace for fusil-gettext).

TODO
====

 * SUPPORT_UID: Run child process as a different user/group
 * Create replay.bat (instead of replay.sh)
 * CreateProcess: write workaround for preexec_fn
 * Implement functions in fusil.process.tools (eg. limitMemory())
 * Implement AttachProcessPID.checkAlive()
 * Implement searching a process for AttachProcessPID

