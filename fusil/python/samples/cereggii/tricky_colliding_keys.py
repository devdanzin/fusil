"""
This module generates sets of integer keys that are guaranteed to cause hash
collisions in a `cereggii.AtomicDict` for a given size.

This is inspired by the `cereggii` test suite's own strategy of using targeted
collisions to test the dictionary's probing and collision-handling logic.
By hammering the same internal hash bucket repeatedly, we can stress-test the
most complex parts of the dictionary's C implementation.

The primary export is `colliding_key_sets`, a dictionary mapping dictionary
log_sizes to collections of colliding keys.
"""

import cereggii
import collections
import sys

# --- Step 1.1: Imports and Setup ---
# A single, module-level dummy dict to access the internal _rehash method.
# This saves us from having to instantiate it repeatedly.
try:
    _DUMMY_DICT = cereggii.AtomicDict()
except (ImportError, AttributeError):
    print(
        "FATAL: Could not import cereggii.AtomicDict. Is cereggii installed?",
        file=sys.stderr,
    )
    _DUMMY_DICT = None


# --- Step 1.2: Key Generation Function ---
def generate_colliding_keys(
    log_size: int, num_buckets_to_fill: int = 16, keys_per_bucket: int = 32
) -> dict[int, list[int]]:
    """
    Finds and groups integers that collide in the same hash bucket for an
    AtomicDict of a given `log_size`.

    Args:
        log_size: The internal log_size of the AtomicDict to target. The total
                  number of buckets will be 2**log_size.
        num_buckets_to_fill: The number of distinct buckets to find keys for.
        keys_per_bucket: The number of colliding keys to find for each bucket.

    Returns:
        A dictionary where keys are bucket indices and values are lists of
        integers that all hash to that bucket.
    """
    if _DUMMY_DICT is None:
        return {}

    print(f"Generating colliding keys for log_size={log_size}...")
    results = collections.defaultdict(list)
    filled_buckets = set()

    # Iterate through integers until we've found enough colliding keys.
    # We set a high limit to prevent an accidental infinite loop if something goes wrong.
    for i in range(2**24):  # Search up to ~16 million
        # This mimics the internal hash-to-bucket calculation of AtomicDict.
        # We right-shift the full 64-bit rehash value to get the top `log_size` bits.
        bucket = _DUMMY_DICT._rehash(i) >> (64 - log_size)

        # We only care about filling the first N buckets for our test cases.
        if bucket < num_buckets_to_fill and len(results[bucket]) < keys_per_bucket:
            results[bucket].append(i)
            filled_buckets.add(bucket)

        # Stop once we've filled the desired number of buckets.
        if len(filled_buckets) >= num_buckets_to_fill:
            # Check if all targeted buckets are full
            all_full = all(
                len(v) >= keys_per_bucket
                for k, v in results.items()
                if k < num_buckets_to_fill
            )
            if all_full:
                break
    else:
        print(
            f"Warning: Exhausted search range for log_size={log_size} without filling all buckets.",
            file=sys.stderr,
        )

    return dict(results)


# --- Step 1.3: Pre-Generate and Export Collision Sets ---
colliding_key_sets = {}
LOG_SIZES_TO_GENERATE = [
    6,  # Default minimum size
    7,  # First growth size
    8,
    10,  # A larger, more sparse size
]

for log_size in LOG_SIZES_TO_GENERATE:
    key = f"log_size_{log_size}"
    colliding_key_sets[key] = generate_colliding_keys(log_size)

# --- Final Sanity Check ---
print("-" * 50)
print(f"Generated colliding key sets for {len(colliding_key_sets)} dictionary sizes.")
for name, sets in colliding_key_sets.items():
    buckets_found = len(sets)
    total_keys = sum(len(keys) for keys in sets.values())
    print(f"  - {name}: Found {total_keys} keys across {buckets_found} buckets.")
print("-" * 50)
