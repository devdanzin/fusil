#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import defaultdict, Counter
from pathlib import Path

# Regex to find our harness markers, e.g., "[f1]", "[f12]", etc.
HARNESS_MARKER_REGEX = re.compile(r"\[(f\d+)\]")

# Regex to find standard uops in the JIT log files.
UOP_REGEX = re.compile(r"(?:ADD_TO_TRACE|OPTIMIZED): (_[A-Z0-9_]+)(?=\s|\n|$)")

# Regex to find "rare" but highly interesting JIT events.
RARE_EVENT_REGEX = re.compile(r"(_DEOPT|_GUARD_FAIL)")

# Define paths for the coverage directory and the new state file.
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
COVERAGE_DIR = PROJECT_ROOT / "coverage"
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.json"


def parse_log_for_edge_coverage(log_path: Path) -> dict[str, dict[str, Counter]]:
    """
    Reads a JIT log file and extracts hit counts for uops, edges, and rare events,
    grouping them by the harness function that produced them.
    """
    if not log_path.is_file():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return {}

    # The new data structure uses Counters for hit tracking.
    coverage_by_harness = defaultdict(lambda: {
        "uops": Counter(),
        "edges": Counter(),
        "rare_events": Counter()
    })
    current_harness_id = None
    previous_uop = None

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            harness_match = HARNESS_MARKER_REGEX.search(line)
            if harness_match:
                current_harness_id = harness_match.group(1)
                previous_uop = "_START_OF_HARNESS_"

            if not current_harness_id:
                continue

            uop_match = UOP_REGEX.search(line)
            if uop_match:
                current_uop = uop_match.group(1)
                # Increment hit count for the individual uop.
                coverage_by_harness[current_harness_id]["uops"][current_uop] += 1

                if previous_uop:
                    edge = f"{previous_uop}->{current_uop}"
                    # Increment hit count for the edge.
                    coverage_by_harness[current_harness_id]["edges"][edge] += 1
                previous_uop = current_uop

            rare_event_match = RARE_EVENT_REGEX.search(line)
            if rare_event_match:
                rare_event = rare_event_match.group(1)
                # Increment hit count for the rare event.
                coverage_by_harness[current_harness_id]["rare_events"][rare_event] += 1

    # No need to sort, as Counters handle their own structure.
    return coverage_by_harness


def load_coverage_state() -> dict[str, dict[str, int]]:
    """
    Loads the global coverage state from the JSON file.
    Returns a default structure if the file doesn't exist.
    """
    if not COVERAGE_STATE_FILE.is_file():
        return {"uops": {}, "edges": {}, "rare_events": {}}
    try:
        with open(COVERAGE_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load coverage state file. Starting fresh. Error: {e}", file=sys.stderr)
        return {"uops": {}, "edges": {}, "rare_events": {}}


def save_coverage_state(state: dict[str, dict[str, int]]):
    """
    Saves the updated global coverage state to the JSON file.
    """
    COVERAGE_DIR.mkdir(exist_ok=True)
    with open(COVERAGE_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def main():
    """
    Main entry point for the JIT coverage parser tool.
    """
    parser = argparse.ArgumentParser(
        description="Parses JIT logs, updates global coverage state, and reports new discoveries."
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the JIT log file to be parsed."
    )
    args = parser.parse_args()

    # 1. Parse the current log for per-harness coverage.
    per_harness_coverage = parse_log_for_edge_coverage(args.log_file)
    if not per_harness_coverage:
        print("No per-harness coverage found in the log file.", file=sys.stderr)
        return

    # 2. Load the persistent global coverage state.
    global_coverage_state = load_coverage_state()
    newly_discovered = False

    # 3. Iterate through the new coverage and update the global state.
    for harness_id, data in per_harness_coverage.items():
        # Update uops
        for uop, count in data["uops"].items():
            if uop not in global_coverage_state["uops"]:
                print(f"[NEW UOP] Discovered new uop in harness '{harness_id}': {uop}", file=sys.stderr)
                newly_discovered = True
                global_coverage_state["uops"][uop] = 0
            global_coverage_state["uops"][uop] += count

        # Update edges
        for edge, count in data["edges"].items():
            if edge not in global_coverage_state["edges"]:
                print(f"[NEW EDGE] Discovered new edge in harness '{harness_id}': {edge}", file=sys.stderr)
                newly_discovered = True
                global_coverage_state["edges"][edge] = 0
            global_coverage_state["edges"][edge] += count

        # Update rare events
        for event, count in data["rare_events"].items():
            if event not in global_coverage_state["rare_events"]:
                print(f"[NEW RARE EVENT] Discovered new rare event in harness '{harness_id}': {event}", file=sys.stderr)
                newly_discovered = True
                global_coverage_state["rare_events"][event] = 0
            global_coverage_state["rare_events"][event] += count

    if not newly_discovered:
        print("No new coverage found in this run.", file=sys.stderr)

    # 4. Save the updated state back to the file.
    save_coverage_state(global_coverage_state)
    print(f"Global coverage state updated: {COVERAGE_STATE_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
