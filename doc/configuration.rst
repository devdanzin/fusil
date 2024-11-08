+++++++++++++++++++
Fusil configuration
+++++++++++++++++++

You can configure Fusil using a fusil.conf file in your configuration directory
($XDG_CONFIG_HOME environment variable or ~/.config/). Template file: ::

    ###############################################################
    # General Fusil options
    ###############################################################
    [fusil]

    # Maximum number of session (0=unlimited)
    session = 0

    # Maximum number of success before exit (0=unlimited)
    success = 1

    # Minimum score for a successful session
    success_score = 0.50

    # Maximum score for a session error
    error_score = -0.50

    # Maximum memory in bytes (0=unlimited)
    max_memory = 0

    # (Normal) Maximum system load
    normal_calm_load = 0.50

    # (Normal) Seconds to sleep until system load is low
    normal_calm_sleep = 0.5

    # (Slow) Maximum system load
    slow_calm_load = 0.30

    # (Slow) Seconds to sleep until system load is low
    slow_calm_sleep = 3.0

    # xhost program path (change X11 permissions)
    xhost_program = xhost

    ###############################################################
    # Debugger used to trace child processes
    ###############################################################
    [debugger]

    # Use the debugger?
    use_debugger = True

    # Enable trace forks option
    trace_forks = True


    ###############################################################
    # Child processes options
    ###############################################################
    [process]

    # Dump core on crash
    core_dump = True

    # Maximum user process (RLIMIT_NPROC)
    max_user_process = 10

    # Default maximum memory in bytes (O=unlimited)
    max_memory = 104857600

    # Change the user (setuid)
    user = fusil

    # Change the group (setgid)
    group = fusil

    # Use a probe to watch CPU activity
    use_cpu_probe = True

