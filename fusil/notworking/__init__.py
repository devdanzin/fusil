"""Legacy / out-of-scope fusil modules, parked here to keep the live tree focused.

Only the Python fuzzing path (``fusil.python`` + ``fuzzers/fusil-python-threaded``) is
actively developed. The modules under this package support the legacy fuzzers
(``fuzzers/notworking/*``): file/process mangling, the network subsystem, X11 helpers,
libc/png helpers, etc. They are not imported by the Python fuzzer and may not work as-is;
they are kept (rather than deleted) so the old fuzzers remain recoverable.
"""
