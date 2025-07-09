# state_tool.py
import argparse
import copy
import json
import pickle
import sys
from collections import Counter
from pathlib import Path


def def_jsonify(data):
    """
    Recursively converts a data structure to be JSON serializable.
    Specifically, it converts `set` objects to `list` and `Counter` objects
    to `dict`.
    """
    if isinstance(data, dict):
        return {k: def_jsonify(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [def_jsonify(i) for i in data]
    elif isinstance(data, (set, Counter)):
        # Convert sets and Counter keys to a sorted list for consistent output
        return sorted(list(data))
    else:
        return data


def main():
    """Main entry point for the state management tool."""
    parser = argparse.ArgumentParser(
        description="A tool to inspect and convert the fuzzer's pickle state file.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  - Show state file contents as JSON:
    python state_tool.py coverage_state.pkl

  - Convert a JSON state file to Pickle format:
    python state_tool.py coverage_state.json coverage_state.pkl

  - Convert a Pickle state file to JSON format:
    python state_tool.py coverage_state.pkl coverage_state.json
"""
    )
    parser.add_argument("input_file", type=Path, help="The input state file (.pkl or .json)")
    parser.add_argument("output_file", type=Path, nargs='?', default=None,
                        help="The output file (optional). If omitted, prints to console.")
    args = parser.parse_args()

    # --- Validate Input ---
    if not args.input_file.exists():
        print(f"Error: Input file not found at '{args.input_file}'", file=sys.stderr)
        sys.exit(1)

    input_ext = args.input_file.suffix
    if input_ext not in ['.pkl', '.json']:
        print(f"Error: Input file must be a .pkl or .json file.", file=sys.stderr)
        sys.exit(1)

    # --- Load Data ---
    print(f"[*] Loading {args.input_file}...")
    state_data = None
    try:
        if input_ext == '.pkl':
            with open(args.input_file, 'rb') as f:
                state_data = pickle.load(f)
        else:  # .json
            with open(args.input_file, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
    except Exception as e:
        print(f"Error: Failed to load data from '{args.input_file}': {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] Data loaded successfully.")

    # --- Process and Output Data ---
    if args.output_file is None:
        # "Show" mode: Print to console as JSON
        print("[*] No output file specified. Pretty-printing state as JSON to console.")
        print("-" * 80)
        # We must convert non-serializable types like sets and Counters first
        json_compatible_data = def_jsonify(copy.deepcopy(state_data))
        print(json.dumps(json_compatible_data, indent=2))
    else:
        # "Convert" mode: Save to output file
        output_ext = args.output_file.suffix
        print(f"[*] Converting to {args.output_file}...")
        try:
            if output_ext == '.pkl':
                with open(args.output_file, 'wb') as f:
                    pickle.dump(state_data, f)
            elif output_ext == '.json':
                json_compatible_data = def_jsonify(copy.deepcopy(state_data))
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_compatible_data, f, indent=2)
            else:
                print(f"Error: Output file must be .pkl or .json", file=sys.stderr)
                sys.exit(1)
            print(f"[+] Successfully saved to {args.output_file}")
        except Exception as e:
            print(f"Error: Failed to save data to '{args.output_file}': {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
