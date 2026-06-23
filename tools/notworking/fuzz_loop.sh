#!/bin/bash

# ==============================================================================
#           Fusil JIT Fuzzer - Master Feedback Loop Script
# ==============================================================================
# This script automates the coverage-guided fuzzing process. It continuously:
#   1. Generates a new test case (prioritizing mutation of the corpus).
#   2. Runs the test case with JIT logging enabled.
#   3. Parses the log for new coverage with jit_coverage_parser.py.
#   4. The parser automatically saves interesting test cases to the corpus.
#   5. The loop repeats, creating an evolutionary fuzzing cycle.
# ==============================================================================

# --- Configuration ---
# Path to the fusil executable
FUSIL_PATH="/mnt/c/Users/ddini/PycharmProjects/fusil/fuzzers/fusil-python-threaded"

# Path to the coverage parser tool
PARSER_PATH="/mnt/c/Users/ddini/PycharmProjects/fusil/tools/jit_coverage_parser.py"

# Temporary files for the current run
TMP_SOURCE_FILE="/home/fusil/runs/source_01.py"
TMP_LOG_FILE="/home/fusil/runs/stdout_01.txt"

# Environment variables to enable JIT's verbose logging
export PYTHON_LLTRACE=4
export PYTHON_OPT_DEBUG=4

# --- Main Fuzzing Loop ---
echo "[+] Starting JIT fuzzer feedback loop. Press Ctrl+C to stop."

# Ensure corpus directory exists
mkdir -p corpus/jit_interesting_tests

session_count=0
while true; do
    session_count=$((session_count + 1))
    echo "----------------------------------------------------------------------"
    echo "[+] Fuzzing Session #$session_count: Generating new test case..."

    # Step 1: Generate a new test case using feedback-driven mode
    # The --jit-target-uop=ALL is a fallback for the first few runs before the corpus is populated.
    python3 "$FUSIL_PATH" \
        --jit-fuzz \
        --jit-feedback-driven-mode \
        --jit-target-uop=ALL \
        --classes-number=0 \
        --functions-number=1 \
        --methods-number=0 \
        --objects-number=0 \
        --sessions=1 \
        --python=/home/danzin/venvs/jit_cpython_venv/bin/python \
        -v \
        --no-threads \
        --no-async \
        --jit-loop-iterations 300 \
        --no-numpy \
        --modules=encodings.ascii \
        --source-output-path /home/fusil/runs/source_01.py \
        --stdout-path /home/fusil/runs/stdout_01.txt

    if [ $? -ne 0 ]; then
        echo "[!] ERROR: Fusil failed to generate a test case. Exiting."
        exit 1
    fi

    echo "[+] Running test case and capturing JIT log..."
    # Step 2: Execute the test case, redirecting all output to the log file
    python3 "$TMP_SOURCE_FILE" > "$TMP_LOG_FILE" 2>&1

    echo "[+] Analyzing log for new coverage..."
    # Step 3 & 4: Parse the log. The parser handles corpus saving.
    python3 "$PARSER_PATH" "$TMP_LOG_FILE" "$TMP_SOURCE_FILE"

    echo "[+] Session #$session_count complete."
    sleep 1 # Small delay to prevent overwhelming the system
done
