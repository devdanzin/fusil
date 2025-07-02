#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import sys
from pathlib import Path

# The regular expression to find uops in the JIT log files.
# It captures the uop name from lines starting with "ADD_TO_TRACE: " or "OPTIMIZED: ".
UOP_REGEX = re.compile(r"(?:ADD_TO_TRACE|OPTIMIZED): (_[A-Z0-9_]+)")

# --- Phase 2: Define paths for the corpus directory ---
PROJECT_ROOT = Path(__file__).parent.parent
COVERAGE_DIR = PROJECT_ROOT / "coverage"
CORPUS_DIR = PROJECT_ROOT / "corpus" / "jit_interesting_tests"
MASTER_COVERAGE_FILE = COVERAGE_DIR / "all_uops_seen.txt"


def parse_log_for_uops(log_path: Path) -> set[str]:
    """
    Reads a JIT log file and extracts all unique uop names.

    Args:
        log_path: The path to the JIT log file.

    Returns:
        A set of unique uop names found in the log.
    """
    if not log_path.is_file():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return set()

    uops_found = set()
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = UOP_REGEX.search(line)
            if match:
                uops_found.add(match.group(1))
    return uops_found


def get_master_coverage_set() -> set[str]:
    """
    Reads the master coverage file and returns the set of all uops seen so far.
    """
    if not MASTER_COVERAGE_FILE.is_file():
        return set()

    with open(MASTER_COVERAGE_FILE, "r", encoding="utf-8") as f:
        # Read lines and strip any whitespace/newlines
        return {line.strip() for line in f if line.strip()}


def update_master_coverage(new_uops: set[str]):
    """
    Appends newly discovered uops to the master coverage file.
    """
    # Ensure the coverage directory exists.
    COVERAGE_DIR.mkdir(exist_ok=True)

    with open(MASTER_COVERAGE_FILE, "a", encoding="utf-8") as f:
        for uop in sorted(list(new_uops)):
            f.write(f"{uop}\n")


def save_to_corpus(source_path: Path):
    """
    Copies an interesting source file to the corpus directory.
    """
    if not source_path or not source_path.is_file():
        print(f"Warning: Source file not provided or not found. Cannot save to corpus.", file=sys.stderr)
        return

    # Ensure the corpus directory exists.
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    destination_path = CORPUS_DIR / source_path.name
    while destination_path.exists():
        filename = Path(destination_path.parts[-1])
        stem = filename.stem
        base, number_str = stem.split("_")
        number = int(number_str.lstrip("0"))
        number += 1
        new_filename = f"{base}_{number:02}.py"
        destination_path = destination_path.parent / new_filename
    print(f"Saving interesting source file to corpus: {destination_path}", file=sys.stderr)
    source = source_path.read_text()
    imp_stderr = ["from sys import stderr"]
    interesting_source = "\n".join(imp_stderr + source[source.index("fuzz_target_module = "):].splitlines()[1:])
    if "[f1]" in interesting_source.lower():
        destination_path.write_text(interesting_source)


def main():
    """
    Main entry point for the JIT coverage parser tool.
    """
    parser = argparse.ArgumentParser(
        description="Parses CPython JIT logs to extract micro-op (uop) coverage."
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the JIT log file to be parsed."
    )
    # --- Phase 2: Add argument for the source file ---
    parser.add_argument(
        "source_file",
        type=Path,
        help="Path to the source Python file that generated the log. Used for saving to corpus on new coverage."
    )
    args = parser.parse_args()

    # Step 1.1: Extract all unique uops from the current log file.
    uops_from_current_log = parse_log_for_uops(args.log_file)
    if not uops_from_current_log:
        print("No uops found in the log file.", file=sys.stderr)
        return

    print(f"Found {len(uops_from_current_log)} unique uops in '{args.log_file.name}'.")

    # Step 1.2: Compare against the master coverage set.
    master_set = get_master_coverage_set()
    newly_discovered_uops = uops_from_current_log - master_set

    if newly_discovered_uops:
        print("-" * 20, file=sys.stderr)
        print(f"!!! NEW COVERAGE DISCOVERED !!!", file=sys.stderr)
        print(f"Found {len(newly_discovered_uops)} new uops:", file=sys.stderr)
        for uop in sorted(list(newly_discovered_uops)):
            print(f"  - {uop}", file=sys.stderr)
        print("-" * 20, file=sys.stderr)

        # Update the master file with the new discoveries.
        update_master_coverage(newly_discovered_uops)
        print(f"Master coverage file updated: {MASTER_COVERAGE_FILE}", file=sys.stderr)

        # --- Phase 2: Save the interesting source file to the corpus ---
        save_to_corpus(args.source_file)
    else:
        print("No new coverage found in this run.", file=sys.stderr)


if __name__ == "__main__":
    main()
