# **Architect's Guide to the Fusil JIT Fuzzing Framework**

This document provides a high-level overview of the architecture and design philosophy behind the CPython Tier 2 JIT fuzzing subsystem in fusil. It is intended for developers who wish to understand how the system works at a strategic level, contribute new features, or debug its behavior.

## **Core Philosophy: Generative and Multi-faceted Attacks**

The primary goal of this framework is to move beyond simple, random inputs and generate sophisticated, structurally complex, and semantically plausible Python code designed to stress specific and known-fragile mechanisms within the JIT optimizer.

Our development has been guided by a few core principles:

1. **The Principle of Simplicity**: The JIT has different optimization paths for different code profiles. To target a specific, fragile path, the "signal" of our attack must be as simple and direct as possible, minimizing unrelated "noise" that could inadvertently cause the JIT to take a more robust (but less buggy) path.  
2. **The Environment is Part of the Fuzzing Input**: We recognize that the JIT's analysis is function-centric. Code that is benign at the module level can trigger a bug when placed inside a nested function, a class method, a generator, or an async function. Our framework treats the execution environment not as a constant, but as a variable to be fuzzed.  
3. **The High-Frequency, Low-Level Principle**: Some of the deepest bugs lie in the JIT's interaction with low-level, high-frequency systems like the garbage collector and reference counting. Our scenarios are designed to create this kind of intense pressure through tight loops and repeated object creation/destruction.

## **The Three Engines: A Mode-Based Architecture**

The fuzzer's behavior is controlled by the primary \--jit-mode flag, which selects one of three distinct generation engines.

### **1\. The Synthesizer (**\--jit-mode=synthesize**)**

This is our most advanced and the default generation engine. It does not rely on any pre-written templates. Instead, it uses the ASTPatternGenerator to create entirely new fuzzing scenarios from scratch by programmatically building a Python Abstract Syntax Tree (AST).

* **How it Works**: It uses a stateful, grammar-based approach to construct a list of valid statements, including assignments, function calls, and control flow (if/for). It is "JIT-aware" and can autonomously decide to synthesize known attack patterns, such as \_\_del\_\_ side-effect attacks or "Twin Execution" correctness tests.  
* **Use Case**: This is the best mode for broad, exploratory fuzzing to discover entirely new bug classes.

### **2\. The Variational Engine (**\--jit-mode=variational**)**

This engine is designed for targeted fuzzing of known bug classes. It reads a pattern from the bug\_patterns.py library and applies a series of mutations to generate thousands of unique variations around that central theme.

* **How it Works**: It uses the ASTMutator, a library of ast.NodeTransformer subclasses, to structurally rewrite the code from the pattern. This includes swapping operators, perturbing constants, duplicating statements, and more. It can also be modified with flags like \--jit-fuzz-systematic-values to methodically test all known boundary values against a pattern.  
* **Use Case**: This mode is ideal when a new bug has been found and we want to deeply explore the surrounding code space to find related vulnerabilities.

### **3\. The Legacy Engine (**\--jit-mode=legacy**)**

This engine runs the original, hard-coded "friendly" and "hostile" scenarios that were created at the beginning of the project.

* **How it Works**: It contains a list of specific generator methods (e.g., \_generate\_invalidation\_scenario, \_generate\_deep\_calls\_scenario) and randomly chooses one to execute.  
* **Use Case**: This mode is primarily preserved for regression testing and for comparing the effectiveness of our newer engines against the original baseline.

## **High-Level Component Diagram**

The JIT subsystem is composed of several key classes that work together:

* fusil.python.write\_python\_code.WritePythonCode: The main fuzzer class. It owns the WriteJITCode instance.  
  * fusil.python.jit.write\_jit\_code.WriteJITCode: The central **Orchestrator**. It reads the command-line options and dispatches tasks to the appropriate engine.  
    * fusil.python.jit.ast\_pattern\_generator.ASTPatternGenerator: The **Creator**. Synthesizes new patterns from scratch. Used by synthesize mode.  
    * fusil.python.jit.ast\_mutator.ASTMutator: The **Mutator**. Applies structural changes to existing code. Used by variational mode.  
    * fusil.python.jit.bug\_patterns.BUG\_PATTERNS: The **Knowledge Base**. A dictionary containing the templates and metadata for known bug classes. Used by variational mode.

## **The "Kitchen-Sink" Mode (**\--jit-mode=all**)**

For maximum coverage during long-running, unsupervised fuzzing campaigns, the all mode provides a "fire-and-forget" strategy. For each test case it generates, it will randomly select one of the three primary modes (synthesize, variational, legacy) and a random, compatible combination of their modifiers. This ensures that the full breadth of our fuzzing capabilities is exercised over the course of a single session.