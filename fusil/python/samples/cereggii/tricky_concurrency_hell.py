import cereggii
import threading
import time
import random
import itertools
import os
import sys

# --- 1. Imports ---
# ThreadSet is the ideal tool for orchestrating these scenarios.
try:
    from cereggii import ThreadSet
except ImportError:
    print(
        "Warning: cereggii.ThreadSet not found. Using standard threading.",
        file=sys.stderr,
    )

    # Provide a dummy ThreadSet if cereggii is not fully available
    class ThreadSet:
        def __init__(self, *threads):
            self._threads = threads

        def start(self):
            for t in self._threads:
                t.start()

        def join(self):
            for t in self._threads:
                t.join()

        def start_and_join(self):
            self.start()
            self.join()

        @classmethod
        def range(cls, n):
            def decorator(target):
                threads = [threading.Thread(target=target, args=(i,)) for i in range(n)]
                return cls(*threads)

            return decorator


# --- 2. Configurable Concurrency Levels ---
# These constants define our interpretation of "extreme" concurrency, keeping
# system stability in mind. They can be tuned by the fuzzer.
CPU_COUNT = os.cpu_count() or 4
HIGH_THREAD_COUNT = CPU_COUNT * 16  # High, but should be stable. (e.g., 128 on 8 cores)
EXTREME_THREAD_COUNT = (
    CPU_COUNT * 64
)  # Very high, for more aggressive tests. (e.g., 512 on 8 cores)


# --- 3. Define Callable Torture Test Scenarios ---


# --- Scenario A: The "Dogpile" ---
def dogpile_on_atomicint(num_threads=HIGH_THREAD_COUNT, ops_per_thread=10000):
    """Creates maximum contention on a single AtomicInt64."""
    counter = cereggii.AtomicInt64(0)

    @ThreadSet.range(num_threads)
    def worker(thread_id):
        for _ in range(ops_per_thread):
            counter.increment_and_get()

    worker.start_and_join()

    expected = num_threads * ops_per_thread
    actual = counter.get()
    if actual != expected:
        print(
            f"WARNING (dogpile_on_atomicint): Final count is wrong! Expected {expected}, got {actual}",
            file=sys.stderr,
        )
    return True  # Survived without crashing


def dogpile_on_atomicref(num_threads=HIGH_THREAD_COUNT, ops_per_thread=1000):
    """Creates maximum contention on a single AtomicRef."""
    ref = cereggii.AtomicRef(0)

    @ThreadSet.range(num_threads)
    def worker(thread_id):
        # Threads will try to swap the value between their ID and its negative
        my_val = thread_id + 1
        for _ in range(ops_per_thread):
            current = ref.get()
            ref.compare_and_set(current, my_val)
            ref.compare_and_set(my_val, -my_val)

    worker.start_and_join()
    return True  # Survived without crashing


def dogpile_on_atomicdict_key(num_threads=HIGH_THREAD_COUNT, ops_per_thread=5000):
    """Creates maximum contention on a single key within an AtomicDict."""
    d = cereggii.AtomicDict()
    THE_KEY = "the_one_key"

    @ThreadSet.range(num_threads)
    def worker(thread_id):
        # reduce_sum is the most direct way to hammer a single key
        for _ in range(ops_per_thread):
            d.reduce_sum([(THE_KEY, 1)])

    worker.start_and_join()

    expected = num_threads * ops_per_thread
    actual = d.get(THE_KEY)
    if actual != expected:
        print(
            f"WARNING (dogpile_on_atomicdict_key): Final count is wrong! Expected {expected}, got {actual}",
            file=sys.stderr,
        )
    return True  # Survived without crashing


# --- Scenario B: The "Migration Storm" ---
def migration_storm(num_threads=HIGH_THREAD_COUNT, keys_per_thread=500):
    """Forces rapid, concurrent growth and resizing of an AtomicDict."""
    # Start with a small size to guarantee migrations will happen
    d = cereggii.AtomicDict(min_size=16)

    @ThreadSet.range(num_threads)
    def worker(thread_id):
        # Each thread gets a unique, non-overlapping block of keys to insert
        start_key = thread_id * keys_per_thread
        end_key = start_key + keys_per_thread
        for i in range(start_key, end_key):
            d[i] = thread_id

    worker.start_and_join()

    expected_len = num_threads * keys_per_thread
    actual_len = len(d)
    if actual_len != expected_len:
        print(
            f"WARNING (migration_storm): Final dict length is wrong! Expected {expected_len}, got {actual_len}",
            file=sys.stderr,
        )
    return True  # Survived without crashing


# --- Scenario C: The "Churn" ---
def thread_churn_test(num_cycles=50, num_threads_per_cycle=HIGH_THREAD_COUNT // 4):
    """
    Tests for resource leaks by rapidly creating and destroying threads and
    cereggii objects that might hold thread-local data.
    """
    print(
        f"Starting churn test: {num_cycles} cycles of {num_threads_per_cycle} threads each..."
    )
    for i in range(num_cycles):
        # Create a fresh dict for each cycle
        d = cereggii.AtomicDict()

        @ThreadSet.range(num_threads_per_cycle)
        def worker(thread_id):
            # Do a small amount of work
            d[thread_id] = thread_id
            d.reduce_sum([(thread_id, 1)])

        worker.start_and_join()

        # Explicitly delete to signal intent to GC. The real test is whether
        # running this loop for a long time causes memory to grow indefinitely.
        del d
        del worker

    return True  # Survived the churn


# --- New Scenario: `fast_iter` Abuse ---
def fast_iter_vs_mutation_race(
    num_iter_threads=4, num_chaos_threads=2, duration_sec=0.2
):
    """
    Creates a race condition between multiple threads iterating with `fast_iter`
    and "chaos" threads that are concurrently inserting and deleting keys.
    This directly tests the iterator's robustness against mutation.
    """
    d = cereggii.AtomicDict()
    # Pre-populate with enough items to make iteration meaningful
    for i in range(num_iter_threads * 1000):
        d[i] = i

    stop_event = threading.Event()

    # Worker for threads that will be iterating
    def iterator_worker(thread_id: int):
        while not stop_event.is_set():
            try:
                # Iterate over the assigned partition. We don't care about the
                # result, only that the process doesn't crash.
                for _, _ in d.fast_iter(
                    partitions=num_iter_threads, this_partition=thread_id
                ):
                    pass
            except Exception as e:
                # We don't expect exceptions here, but if they happen,
                # we should report them without stopping the fuzzer.
                print(
                    f"ERROR (fast_iter_race): Iterator thread {thread_id} caught exception: {e}",
                    file=sys.stderr,
                )

    # Worker for threads that will be causing chaos
    def chaos_worker():
        key_counter = num_iter_threads * 1000
        while not stop_event.is_set():
            # Choose a random action
            action = random.randint(0, 10)
            key = random.randint(0, key_counter)

            if action < 6:  # 60% chance to set/update
                d[key] = key_counter
                key_counter += 1
            else:  # 40% chance to delete
                try:
                    del d[key]
                except KeyError:
                    pass  # Key might have already been deleted by another chaos thread

    iter_threads = [
        threading.Thread(target=iterator_worker, args=(i,))
        for i in range(num_iter_threads)
    ]
    chaos_threads = [
        threading.Thread(target=chaos_worker) for _ in range(num_chaos_threads)
    ]

    all_threads = iter_threads + chaos_threads
    for t in all_threads:
        t.start()

    time.sleep(duration_sec)
    stop_event.set()

    for t in all_threads:
        t.join()

    return True  # Survived without crashing


# --- 4. Aggregate All Scenarios ---
concurrency_hell_scenarios = {
    "dogpile_on_atomicint": dogpile_on_atomicint,
    "dogpile_on_atomicref": dogpile_on_atomicref,
    "dogpile_on_atomicdict_key": dogpile_on_atomicdict_key,
    "migration_storm": migration_storm,
    "thread_churn_test": thread_churn_test,
    # "fast_iter_vs_mutation_race": fast_iter_vs_mutation_race,
}

# Add configurable versions for the fuzzer to pick from
concurrency_hell_scenarios["dogpile_on_atomicint_EXTREME"] = (
    lambda: dogpile_on_atomicint(num_threads=EXTREME_THREAD_COUNT, ops_per_thread=5000)
)
concurrency_hell_scenarios["migration_storm_EXTREME"] = lambda: migration_storm(
    num_threads=EXTREME_THREAD_COUNT, keys_per_thread=500
)


# --- Final Sanity Check ---
print(f"Generated {len(concurrency_hell_scenarios)} extreme concurrency scenarios.")
