#!/usr/bin/env python3
import re
import argparse
from pathlib import Path

# Dictionary mapping file paths (relative to CPYTHON_SRC_PATH) to the changes.
JIT_TWEAKS = {
    "Include/internal/pycore_backoff.h": [
        # (Parameter Name, New Value)
        ("JUMP_BACKWARD_INITIAL_VALUE", 63),
        ("JUMP_BACKWARD_INITIAL_BACKOFF", 6),
        ("SIDE_EXIT_INITIAL_VALUE", 63),
        ("SIDE_EXIT_INITIAL_BACKOFF", 6),
        # Add other parameters from this file...
    ],
    "Include/internal/pycore_optimizer.h": [
        ("MAX_CHAIN_DEPTH", 8),
        ("UOP_MAX_TRACE_LENGTH", 1600),
        ("TRACE_STACK_SIZE", 10),
        ("MAX_ABSTRACT_INTERP_SIZE", 8192),
        ("JIT_CLEANUP_THRESHOLD", 150000),
        # Add other parameters...
    ]
    # Add other files and parameters as needed
}


def apply_jit_tweaks(cpython_path: Path, dry_run: bool = False):
    """
    Finds and replaces CPython JIT parameters using regular expressions.
    """
    print(f"[*] Starting JIT parameter tweaks for CPython at: {cpython_path.resolve()}")

    if not cpython_path.is_dir():
        print(f"[!] Error: CPython source directory not found at '{cpython_path}'")
        return

    for rel_path, tweaks in JIT_TWEAKS.items():
        file_path = cpython_path / rel_path
        if not file_path.exists():
            print(f"[-] Warning: File not found, skipping: {file_path}")
            continue

        print(f"[*] Processing file: {file_path}")
        try:
            content = file_path.read_text()
            original_content = content

            for param_name, new_value in tweaks:
                # This regex looks for a line starting with #define, followed by the
                # parameter name, and then one or more digits. It's not tied to line numbers.
                # It captures the part before the number to preserve whitespace.
                pattern = re.compile(rf"^(#define\s+{param_name}\s+)\d+", re.MULTILINE)

                # The replacement string uses the captured group `\g<1>`
                replacement = rf"\g<1>{new_value}"

                content, num_subs = pattern.subn(replacement, content)

                if num_subs > 0:
                    print(f"  - Changed '{param_name}' to '{new_value}'")
                else:
                    print(f"  - Warning: Could not find and replace '{param_name}'")

            if content != original_content and not dry_run:
                print(f"[*] Writing changes to: {file_path}")
                file_path.write_text(content)
            elif dry_run:
                print(f"[*] Dry run: Changes for {file_path} were not written.")


        except Exception as e:
            print(f"[!] Error processing {file_path}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apply aggressive JIT settings to the CPython source code."
    )
    parser.add_argument(
        "cpython_dir",
        type=str,
        help="Path to the root of the CPython source repository.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print changes without modifying files.",
    )
    args = parser.parse_args()

    CPYTHON_SRC_PATH = Path(args.cpython_dir)
    apply_jit_tweaks(CPYTHON_SRC_PATH, args.dry_run)
    print("[*] Done.")
