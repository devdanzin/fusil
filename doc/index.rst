+++++++++++++++++++
Documentation index
+++++++++++++++++++

User documentation
==================

Start with `Fusil usage guide`_: quick guide to learn how to execute a fuzzer.

 * configuration_: Fusil configuration file
 * safety_: Protection used in Fusil to avoid denial of service of your computer

.. _`Fusil usage guide`: usage.html
.. _configuration: configuration.html
.. _safety: safety.html

Fuzzer developer documentation
==============================

Start with the `HOWTO: Write a fuzzer using Fusil`_ document: quick introduction to write
your own fuzzer.

Technical documents:

 * architecture_: List of the most common action and probe agents
 * c_tools_: Tools for C source code manipulation
 * file_watch_: Probe reading a text to search text patterns (eg. stdout)
 * mangle_: Inject errors in a valid file
 * process_: Create your process (create the command line, set environment
   variables, setup X11) and watch its activity
 * score_: Probe agent score and probe weight
 * time_: Session timeout and process execution time
 * network_: Network client and server agents

.. _`HOWTO: Write a fuzzer using Fusil`: howto_write_fuzzer.html
.. _architecture: architecture.html
.. _c_tools: c_tools.html
.. _file_watch: file_watch.html
.. _mangle: mangle.html
.. _process: process.html
.. _score: score.html
.. _time: time.html
.. _network: network.html

Multi agent system
==================

 * agent_: Agent API, Fusil is a multi-agent system
 * events_: List of the Fusil agent events
 * mas_: Description of the multi agent system

.. _agent: agent.html
.. _events: events.html
.. _mas: mas.html

Misc documents
==============

 * linux_process_limits_: Process limits supported by Linux kernel

.. _linux_process_limits: linux_process_limits.html

