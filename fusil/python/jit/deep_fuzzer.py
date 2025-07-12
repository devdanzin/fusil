import argparse
import ast
import copy
import hashlib
import json
import math
import os
import pickle
import platform
import random
import secrets
import shutil
import subprocess
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent
from typing import Any, Literal

from fusil.python.jit.jit_coverage_parser import parse_log_for_edge_coverage
from fusil.python.jit.ast_mutator import ASTMutator, VariableRenamer

RANDOM = random.Random()

# --- Paths for Fuzzer Outputs (relative to current working directory) ---
# This allows running multiple fuzzer instances from different directories.
CORPUS_DIR = Path("corpus") / "jit_interesting_tests"
TMP_DIR = Path("tmp_fuzz_run")
CRASHES_DIR = Path("crashes")
TIMEOUTS_DIR = Path("timeouts")
LOGS_DIR = Path("logs")
RUN_STATS_FILE = Path("fuzz_run_stats.json")
COVERAGE_DIR = Path("coverage")
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.pkl"

# --- Paths for Fuzzer Tooling (relative to this script's location) ---
# This ensures the fuzzer can find its own executable regardless of the CWD.
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
FUSIL_PATH = str(PROJECT_ROOT / "fuzzers" / "fusil-python-threaded")

CRASH_KEYWORDS = [
    "Segmentation fault",
    "Traceback (most recent call last):",
    "JITCorrectnessError",
    "Assertion",
    "Abort",
    "Fatal Python error",
    "panic",
    "AddressSanitizer",
]

BOILERPLATE_START_MARKER = "# FUSIL_BOILERPLATE_START"
BOILERPLATE_END_MARKER = "# FUSIL_BOILERPLATE_END"

ENV = os.environ.copy()
ENV.update({
    "PYTHON_LLTRACE": "4",
    "PYTHON_OPT_DEBUG": "4",
})

AnalysisResult = Literal["CRASH", "NEW_COVERAGE", "NO_CHANGE"]


def load_coverage_state() -> dict[str, Any]:
    """
    Loads the global and per-file coverage state from the pickle file.
    Returns a default structure if the file doesn't exist.
    """
    if not COVERAGE_STATE_FILE.is_file():
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {}
        }
    try:
        with open(COVERAGE_STATE_FILE, "rb") as f: # Open in binary read mode
            state = pickle.load(f)
            # Ensure both keys are present for backward compatibility
            state.setdefault("global_coverage", {"uops": {}, "edges": {}, "rare_events": {}})
            state.setdefault("per_file_coverage", {})
            return state
    except (pickle.UnpicklingError, IOError, EOFError) as e:
        print(f"Warning: Could not load coverage state file. Starting fresh. Error: {e}", file=sys.stderr)
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {}
        }


def save_coverage_state(state: dict[str, Any]):
    """
    Saves the updated coverage state to its pickle file atomically.
    """
    COVERAGE_DIR.mkdir(exist_ok=True)
    # Create a unique temporary file path in the same directory.
    tmp_path = COVERAGE_STATE_FILE.with_suffix(f".pkl.tmp.{secrets.token_hex(4)}")

    try:
        with open(tmp_path, "wb") as f: # Open in binary write mode
            pickle.dump(state, f)
        # The write was successful, now atomically rename the file.
        os.rename(tmp_path, COVERAGE_STATE_FILE)
    except (IOError, OSError, pickle.PicklingError) as e:
        print(f"[!] Error during atomic save of coverage state: {e}", file=sys.stderr)
        # If an error occurred, try to clean up the temporary file.
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError as e_unlink:
                print(f"[!] Warning: Could not remove temporary state file {tmp_path}: {e_unlink}", file=sys.stderr)


class CorpusScheduler:
    """
    Calculates a "fuzzing score" for each item in the corpus to guide
    the parent selection process.
    """

    def __init__(self, coverage_state: dict[str, Any]):
        self.coverage_state = coverage_state
        self.global_coverage = coverage_state.get("global_coverage", {})

    def _calculate_rarity_score(self, file_metadata: dict[str, Any]) -> float:
        """
        Calculates a score based on how rare the coverage in this file is.
        Rarer edges (lower global hit count) contribute more to the score.
        """
        rarity_score = 0.0
        baseline_coverage = file_metadata.get("baseline_coverage", {})

        for harness_data in baseline_coverage.values():
            for edge in harness_data.get("edges", []):
                # The score for an edge is the inverse of its global hit count.
                # We add 1 to the denominator to avoid division by zero.
                global_hits = self.global_coverage.get("edges", {}).get(edge, 0)
                rarity_score += 1.0 / (global_hits + 1)
        return rarity_score

    def calculate_scores(self) -> dict[str, float]:
        """
        Iterates through the corpus and calculates a score for each file.
        """
        scores = {}
        for filename, metadata in self.coverage_state.get("per_file_coverage", {}).items():
            # Start with a base score
            score = 100.0

            # --- Heuristic 1: Performance (lower is better) ---
            # Penalize slow and large files.
            score -= metadata.get("execution_time_ms", 100) * 0.1
            score -= metadata.get("file_size_bytes", 1000) * 0.01

            # --- Heuristic 2: Rarity (higher is better) ---
            # Reward files that contain globally rare coverage.
            rarity = self._calculate_rarity_score(metadata)
            score += rarity * 50.0

            # --- Heuristic 3: Fertility (higher is better) ---
            # Reward parents that have produced successful children.
            score += metadata.get("total_finds", 0) * 20.0
            # Heavily penalize sterile parents that haven't found anything new in a long time.
            if metadata.get("is_sterile", False):
                score *= 0.1

            # --- Heuristic 4: Depth (higher is better) ---
            # Slightly reward deeper mutation chains to encourage depth exploration.
            score += metadata.get("lineage_depth", 1) * 5.0

            # Ensure score is non-negative
            scores[filename] = max(1.0, score)

        return scores


def load_run_stats() -> dict[str, Any]:
    """
    Loads the persistent run statistics from the JSON file.
    Returns a default structure if the file doesn't exist.
    """
    if not RUN_STATS_FILE.is_file():
        return {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "last_update_time": None,
            "total_sessions": 0,
            "total_mutations": 0,
            "corpus_size": 0,
            "crashes_found": 0,
            "timeouts_found": 0,
            "new_coverage_finds": 0,
            "sum_of_mutations_per_find": 0,
            "average_mutations_per_find": 0.0,
            "global_seed_counter": 0,
            "corpus_file_counter": 0,
        }
    try:
        with open(RUN_STATS_FILE, "r", encoding="utf-8") as f:
            stats = json.load(f)
            # Add new fields if loading an older stats file
            stats.setdefault("sum_of_mutations_per_find", 0)
            stats.setdefault("average_mutations_per_find", 0.0)
            stats.setdefault("global_seed_counter", 0)
            stats.setdefault("corpus_file_counter", 0)
            return stats
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load run stats file. Starting fresh. Error: {e}", file=sys.stderr)
        # Return a default structure on error
        return load_run_stats()

def save_run_stats(stats: dict[str, Any]):
    """
    Saves the updated run statistics to the JSON file.
    """
    with open(RUN_STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True)


class TeeLogger:
    """
    A file-like object that writes to both a file and another stream
    (like the original stdout), and flushes immediately.
    """
    def __init__(self, file_path, original_stream):
        self.original_stream = original_stream
        self.log_file = open(file_path, 'w', encoding='utf-8')

    def write(self, message):
        self.original_stream.write(message)
        self.log_file.write(message)
        self.flush()

    def flush(self):
        self.original_stream.flush()
        self.log_file.flush()

    def close(self):
        self.log_file.close()


class DeepFuzzerOrchestrator:
    """
    The "brain" of the feedback-driven fuzzer.

    This class manages the main evolutionary loop: selecting interesting
    test cases from the corpus, applying mutation strategies, executing the
    mutated children, and analyzing the results for new coverage.
    """

    def __init__(self, min_corpus_files: int = 1):
        self.ast_mutator = ASTMutator()
        self.coverage_state = load_coverage_state()
        self.run_stats = load_run_stats()
        self.boilerplate_code = None
        self.scheduler = CorpusScheduler(self.coverage_state)
        self.min_corpus_files = min_corpus_files
        self.mutations_since_last_find = 0
        self.global_seed_counter = self.run_stats.get("global_seed_counter", 0)
        self.corpus_file_counter = self.run_stats.get("corpus_file_counter", 0)
        self.known_hashes = set()
        print(f"[+] Initialized with {len(self.known_hashes)} known file hashes.")

        # Ensure temporary and corpus directories exist
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
        TIMEOUTS_DIR.mkdir(exist_ok=True)
        LOGS_DIR.mkdir(exist_ok=True)

        run_timestamp = self.run_stats.get("start_time", datetime.now(timezone.utc).isoformat())
        # Sanitize timestamp for use in filename
        safe_timestamp = run_timestamp.replace(":", "-").replace("+", "Z")
        self.timeseries_log_path = LOGS_DIR / f"timeseries_{safe_timestamp}.jsonl"
        print(f"[+] Time-series analytics for this run will be saved to: {self.timeseries_log_path}")

        # Synchronize the corpus and state at startup.
        self._synchronize_corpus_and_state()

        # Re-populate known_hashes after synchronization is complete.
        self.known_hashes = {
            metadata.get("content_hash")
            for metadata in self.coverage_state.get("per_file_coverage", {}).values()
            if "content_hash" in metadata
        }
        print(f"[+] Fuzzer is ready with {len(self.known_hashes)} known file hashes.")

    def _synchronize_corpus_and_state(self):
        """
        Reconciles the state file with the corpus directory on disk.

        This method ensures the fuzzer's state is consistent with the
        actual files in the corpus. It handles three cases:
        1. Files in the state file but not on disk (deleted).
        2. Files on disk but not in the state file (new).
        3. Files in both whose content hash has changed (modified).
        """
        print("[*] Synchronizing corpus directory with state file...")
        if not CORPUS_DIR.exists():
            CORPUS_DIR.mkdir(parents=True, exist_ok=True)

        disk_files = {p.name for p in CORPUS_DIR.glob("*.py")}
        state_files = set(self.coverage_state["per_file_coverage"].keys())

        # 1. Prune state for files that were deleted from disk.
        missing_from_disk = state_files - disk_files
        if missing_from_disk:
            print(f"[-] Found {len(missing_from_disk)} files in state but not on disk. Pruning state.")
            for filename in missing_from_disk:
                del self.coverage_state["per_file_coverage"][filename]

        # 2. Identify new or modified files to be analyzed.
        files_to_analyze = set()
        for filename in disk_files:
            file_path = CORPUS_DIR / filename
            if filename not in state_files:
                print(f"[+] Discovered new file in corpus: {filename}")
                files_to_analyze.add(filename)
            else:
                # File exists in both, verify its hash.
                try:
                    content = file_path.read_text()
                    current_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                    if self.coverage_state["per_file_coverage"][filename].get("content_hash") != current_hash:
                        print(f"[~] File content has changed for {filename}. Re-analyzing.")
                        del self.coverage_state["per_file_coverage"][filename]
                        files_to_analyze.add(filename)
                except (IOError, KeyError) as e:
                    print(f"[!] Error processing existing file {filename}: {e}. Re-analyzing.")
                    if filename in self.coverage_state["per_file_coverage"]:
                        del self.coverage_state["per_file_coverage"][filename]
                    files_to_analyze.add(filename)

        # 3. Run analysis on all new/modified files to generate their metadata.
        if files_to_analyze:
            print(f"[*] Analyzing {len(files_to_analyze)} new or modified corpus files...")
            for filename in sorted(list(files_to_analyze)):
                source_path = CORPUS_DIR / filename
                log_path = TMP_DIR / f"sync_{source_path.stem}.log"
                print(f"  -> Analyzing {filename}...")
                try:
                    with open(log_path, "w") as log_file:
                        start_time = time.monotonic()
                        result = subprocess.run(
                            ["python3", str(source_path)],
                            stdout=log_file, stderr=subprocess.STDOUT, timeout=10, env=ENV
                        )
                        end_time = time.monotonic()
                    execution_time_ms = int((end_time - start_time) * 1000)
                    self.analyze_run(
                        log_path, source_path, result.returncode,
                        parent_baseline_coverage={}, parent_id=None,
                        execution_time_ms=execution_time_ms,
                        mutation_info={"strategy": "seed"}, mutation_seed=0
                    )
                except Exception as e:
                    print(f"  [!] Failed to analyze seed file {filename}: {e}", file=sys.stderr)

        # 4. Synchronize the global file counter to prevent overwrites.
        current_max_id = 0
        for filename in disk_files:
            try:
                file_id = int(Path(filename).stem)
                if file_id > current_max_id:
                    current_max_id = file_id
            except (ValueError, IndexError):
                continue  # Ignore non-integer filenames

        if current_max_id > self.corpus_file_counter:
            print(f"[*] Advancing file counter from {self.corpus_file_counter} to {current_max_id} to match corpus.")
            self.corpus_file_counter = current_max_id

        # 5. Save the synchronized state.
        save_coverage_state(self.coverage_state)
        print("[*] Corpus synchronization complete.")

    def _extract_and_cache_boilerplate(self, source_code: str):
        """
        Parses a full source file to find, extract, and cache the
        static boilerplate code.
        """
        try:
            start_index = source_code.index(BOILERPLATE_START_MARKER)
            end_index = source_code.index(BOILERPLATE_END_MARKER)
            # The boilerplate includes the start marker itself.
            self.boilerplate_code = source_code[start_index:end_index]
            print("[+] Boilerplate code extracted and cached.")
        except ValueError:
            print("[!] Warning: Could not find boilerplate markers in the initial seed file.", file=sys.stderr)
            # Fallback to using an empty boilerplate
            self.boilerplate_code = ""

    def _get_core_code(self, source_code: str) -> str:
        """
        Strips the boilerplate from a full source file to get the dynamic core.
        """
        try:
            end_index = source_code.index(BOILERPLATE_END_MARKER)
            # The core code starts right after the end marker and its newline.
            return source_code[end_index + len(BOILERPLATE_END_MARKER) + 1:]
        except ValueError:
            # If no marker, assume the whole file is the core (for minimized corpus files)
            return source_code

    def _add_new_file_to_corpus(
            self,
            core_code: str,
            baseline_coverage: dict[str, Any],
            execution_time_ms: int,
            parent_id: str | None,
            mutation_info: dict[str, Any],
            mutation_seed: int,
            content_hash: str,
    ) -> str:
        """
        Copies a file to the corpus and saves its rich metadata object.
        """
        # --- Step 1.2: Implement Metadata Tracking ---
        parent_metadata = self.coverage_state["per_file_coverage"].get(parent_id, {}) if parent_id else {}
        lineage_depth = parent_metadata.get("lineage_depth", 0) + 1
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

        new_lineage_profile = self._build_lineage_profile(parent_lineage_profile, baseline_coverage)

        # Increment the global counter and generate the new simple filename.
        self.corpus_file_counter += 1
        new_filename = f"{self.corpus_file_counter}.py"
        corpus_filepath = CORPUS_DIR / new_filename

        # Save only the core code, not the boilerplate.
        corpus_filepath.write_text(core_code)
        print(f"[+] Added minimized file to corpus: {new_filename}")

        metadata = {
            "baseline_coverage": baseline_coverage,
            "lineage_coverage_profile": new_lineage_profile,
            "parent_id": parent_id,
            "lineage_depth": lineage_depth,
            "discovery_time": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": execution_time_ms,
            "file_size_bytes": len(core_code.encode('utf-8')),
            "mutations_since_last_find": 0,
            "total_finds": 0,
            "is_sterile": False,
            "discovery_mutation": mutation_info,
            "mutation_seed": mutation_seed,
            "content_hash": content_hash,
        }
        self.coverage_state["per_file_coverage"][new_filename] = metadata
        self.known_hashes.add(content_hash)
        return new_filename

    def select_parent_from_corpus(self) -> tuple[Path, float] | None:
        """
        Selects a test case from the corpus using a weighted random choice
        and returns the path and its calculated score.
        """
        corpus_files = list(self.coverage_state.get("per_file_coverage", {}).keys())
        if not corpus_files:
            return None

        print("[+] Calculating corpus scores for parent selection...")
        scores = self.scheduler.calculate_scores()

        # Ensure we have scores for all files, providing a default if any are missing.
        corpus_weights = [scores.get(filename, 1.0) for filename in corpus_files]

        if not any(w > 0 for w in corpus_weights):
            # If all scores are zero, fall back to uniform random choice
            chosen_filename = RANDOM.choice(corpus_files)
        else:
            # Perform a weighted random selection.
            chosen_filename = RANDOM.choices(corpus_files, weights=corpus_weights, k=1)[0]

        chosen_score = scores.get(chosen_filename, 1.0)
        return CORPUS_DIR / chosen_filename, chosen_score

    def run_evolutionary_loop(self):
        """
        The main entry point for the deep fuzzing process.

        This method first ensures the corpus has the minimum number of files,
        then enters the infinite loop that drives the fuzzer.
        """
        # --- Bootstrap the corpus if it's smaller than the minimum required size ---
        initial_corpus_size = len(self.coverage_state["per_file_coverage"])
        if initial_corpus_size < self.min_corpus_files:
            print(f"[*] Corpus size ({initial_corpus_size}) is less than minimum ({self.min_corpus_files}).")
            print("[*] Starting corpus generation phase...")
            while len(self.coverage_state["per_file_coverage"]) < self.min_corpus_files:
                # The call to run_generation_session will add one new file to the state.
                self.run_generation_session()
            print(f"[+] Corpus generation complete. New size: {len(self.coverage_state['per_file_coverage'])}.")

        print("[+] Starting Deep Fuzzer Evolutionary Loop. Press Ctrl+C to stop.")
        try:
            while True:
                self.run_stats["total_sessions"] = self.run_stats.get("total_sessions", 0) + 1
                session_num = self.run_stats["total_sessions"]
                print(f"\n--- Fuzzing Session #{self.run_stats['total_sessions']} ---")

                # 1. Selection
                selection = self.select_parent_from_corpus()

                # This should now only happen if min_corpus_files is 0 and corpus is empty.
                if selection is None:
                    print("[!] Corpus is empty and no minimum size was set. Halting.")
                    return
                else:
                    parent_path, parent_score = selection
                    print(f"[+] Selected parent for mutation: {parent_path.name} (Score: {parent_score:.2f})")
                    self.execute_mutation_and_analysis_cycle(parent_path, parent_score,
                                                             self.run_stats['total_sessions'])

                # Update dynamic stats after each session
                self.update_and_save_run_stats()
                if session_num % 10 == 0:
                    print(f"[*] Logging time-series data point at session {session_num}...")
                    self._log_timeseries_datapoint()
        finally:
            print("\n[+] Fuzzing loop terminating. Saving final stats...")
            self.update_and_save_run_stats()
            self._log_timeseries_datapoint()  # Log one final data point on exit

    def update_and_save_run_stats(self):
        """
        Helper to update dynamic stats and save the stats file.
        """
        self.run_stats["last_update_time"] = datetime.now(timezone.utc).isoformat()
        self.run_stats["corpus_size"] = len(self.coverage_state.get("per_file_coverage", {}))
        global_cov = self.coverage_state.get("global_coverage", {})
        self.run_stats["global_uops"] = len(global_cov.get("uops", {}))
        self.run_stats["global_edges"] = len(global_cov.get("edges", {}))
        self.run_stats["global_rare_events"] = len(global_cov.get("rare_events", {}))
        self.run_stats["global_seed_counter"] = self.global_seed_counter
        self.run_stats["corpus_file_counter"] = self.corpus_file_counter

        total_finds = self.run_stats.get("new_coverage_finds", 0)
        if total_finds > 0:
            self.run_stats["average_mutations_per_find"] = (
                self.run_stats.get("sum_of_mutations_per_find", 0) / total_finds
            )

        save_run_stats(self.run_stats)

    def run_generation_session(self):
        """
        Runs a single "generative" session to create a new test case
        from scratch, primarily to seed an empty corpus.
        """
        tmp_source = TMP_DIR / "gen_run.py"
        tmp_log = TMP_DIR / "gen_run.log"

        python_executable = sys.executable
        # Use fusil to generate a new file
        subprocess.run([
            "sudo",
            python_executable,
            FUSIL_PATH,
            "--jit-fuzz",
            "--jit-target-uop=ALL",
            f"--source-output-path={tmp_source}",
            "--classes-number=0",
            "--functions-number=1",
            "--methods-number=0",
            "--objects-number=0",
            "--sessions=1",
            f"--python={python_executable}",
            "--no-jit-external-references",
            "--no-threads",
            "--no-async",
            "--jit-loop-iterations=300",
            "--no-numpy",
            "--modules=encodings.ascii",
            # "--keep-sessions",
        ], check=True)

        # Execute it to get a log
        with open(tmp_log, "w") as log_file:
            subprocess.run(["python3", tmp_source], stdout=log_file, stderr=subprocess.STDOUT, env=ENV)

        # Analyze it for coverage
        self.analyze_run(
            tmp_log,
            tmp_source,
            0,
            {},
            parent_id=None,
            execution_time_ms=0,
            mutation_info={"strategy": "generative_seed"},
            mutation_seed=0,
        )

    def _run_deterministic_stage(self, base_ast: ast.AST, seed: int, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """
        Applies a single, seeded, deterministic mutation and returns info about it.
        """
        mutated_ast, transformers_used = self.ast_mutator.mutate_ast(base_ast, seed=seed)
        mutation_info = {
            "strategy": "deterministic",
            "transformers": [t.__name__ for t in transformers_used]
        }
        return mutated_ast, mutation_info

    def _run_havoc_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """
        Applies a random stack of many different mutations to the AST to
        induce significant "havoc".
        """
        print("  [~] Running HAVOC stage...", file=sys.stderr)
        tree = ast.Module(body=base_ast, type_ignores=[])  # Start with the copied tree from the dispatcher
        num_havoc_mutations = RANDOM.randint(15, 50)
        transformers_applied = []

        for _ in range(num_havoc_mutations):
            transformer_class = RANDOM.choice(self.ast_mutator.transformers)
            transformers_applied.append(transformer_class.__name__)
            tree = transformer_class().visit(tree)

        ast.fix_missing_locations(tree)
        mutation_info = {"strategy": "havoc", "transformers": transformers_applied}
        return tree.body, mutation_info

    def _run_spam_stage(self, base_ast: ast.AST, **kwargs) -> tuple[ast.AST, dict[str, Any]]:
        """
        Repeatedly applies the *same type* of mutation to the AST to
        thoroughly exercise one transformation.
        """
        print("  [~] Running SPAM stage...", file=sys.stderr)
        tree = ast.Module(body=base_ast, type_ignores=[])
        num_spam_mutations = RANDOM.randint(20, 50)

        # Choose one single type of mutation to spam
        chosen_transformer_class = RANDOM.choice(self.ast_mutator.transformers)
        print(f"    -> Spamming with: {chosen_transformer_class.__name__}", file=sys.stderr)

        for _ in range(num_spam_mutations):
            # Apply a new instance of the same transformer each time
            tree = chosen_transformer_class().visit(tree)

        ast.fix_missing_locations(tree)
        mutation_info = {"strategy": "spam", "transformers": [chosen_transformer_class.__name__] * num_spam_mutations}
        return tree.body, mutation_info

    def _analyze_setup_ast(self, setup_nodes: list[ast.stmt]) -> dict[str, str]:
        """
        Analyzes a list of setup AST nodes to map variable names to their
        inferred types based on our naming convention (e.g., 'int_v1').
        """
        variable_map = {}
        for node in setup_nodes:
            # We are interested in simple, top-level assignments
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Infer type from prefix, e.g., "int_v1" -> "int"
                    # This is robust to names that don't have a version suffix.
                    parts = var_name.split('_v')
                    inferred_type = parts[0]
                    variable_map[var_name] = inferred_type
        return variable_map

    def _run_splicing_stage(self, base_core_ast: ast.AST, **kwargs) -> ast.AST:
        """
        Performs a "crossover" by splicing the harness from a second parent
        into the setup of the first parent, remapping variable names.
        """
        print("  [~] Attempting SPLICING stage...", file=sys.stderr)

        selection = self.select_parent_from_corpus()
        if not selection: return base_core_ast
        parent_b_path, _ = selection

        try:
            parent_b_source = parent_b_path.read_text()
            parent_b_core_code = self._get_core_code(parent_b_source)
            parent_b_tree = ast.parse(parent_b_core_code)
        except (IOError, SyntaxError):
            return base_core_ast

        # --- Analysis ---
        setup_nodes_a = [n for n in base_core_ast if not isinstance(n, ast.FunctionDef)]
        provided_vars_a = self._analyze_setup_ast(setup_nodes_a)

        setup_nodes_b = [n for n in parent_b_tree.body if not isinstance(n, ast.FunctionDef)]
        provided_vars_b = self._analyze_setup_ast(setup_nodes_b)

        harness_b = next((n for n in parent_b_tree.body if isinstance(n, ast.FunctionDef)), None)
        if not harness_b: return base_core_ast

        required_vars = {node.id for node in ast.walk(harness_b) if
                         isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}

        # --- Phase 2: Remapping Logic ---
        remapping_dict = {}
        is_possible = True
        available_vars_a = defaultdict(list)
        for name, type_name in provided_vars_a.items():
            available_vars_a[type_name].append(name)

        for required_var in sorted(list(required_vars)):
            required_type = provided_vars_b.get(required_var)
            if not required_type: continue

            if available_vars_a.get(required_type):
                compatible_var = RANDOM.choice(available_vars_a[required_type])
                remapping_dict[required_var] = compatible_var
                available_vars_a[required_type].remove(compatible_var)
            else:
                print(f"    -> Splice failed: No var of type '{required_type}' for '{required_var}'", file=sys.stderr)
                is_possible = False
                break

        if not is_possible:
            return base_core_ast

        print(f"    -> Remapping successful: {remapping_dict}")

        # --- Phase 3: Transformation and Assembly ---
        renamer = VariableRenamer(remapping_dict)
        remapped_harness_b = renamer.visit(copy.deepcopy(harness_b))

        # The new core AST consists of Parent A's setup and the remapped Harness B
        new_core_body = setup_nodes_a + [remapped_harness_b]
        new_core_ast = ast.Module(body=new_core_body, type_ignores=[])
        ast.fix_missing_locations(new_core_ast)

        return new_core_ast

    def apply_mutation_strategy(self, base_ast: ast.AST, seed: int) -> tuple[ast.AST, dict[str, Any]]:
        """
        Applies a single, seeded mutation strategy to an AST.

        This method takes a base AST and a seed, seeds the fuzzer's random
        number generator, and then probabilistically chooses and applies one
        of the available mutation strategies (e.g., deterministic, havoc).

        Args:
            base_ast: The Abstract Syntax Tree to mutate.
            seed: The integer seed to use for all randomized decisions.

        Returns:
            A tuple containing the mutated AST and a dictionary of information
            about the mutation that was performed.
        """
        RANDOM.seed(seed)
        random.seed(seed)

        strategies = [
            self._run_deterministic_stage,
            self._run_havoc_stage,
            self._run_spam_stage,
            # self._run_splicing_stage,
        ]
        weights = [0.85, 0.10, 0.05]

        tree_copy = copy.deepcopy(base_ast)
        chosen_strategy = RANDOM.choices(strategies, weights=weights, k=1)[0]

        # The `seed` argument is used by the deterministic stage for its own
        # seeding, and the other stages use the globally seeded RANDOM instance.
        mutated_ast, mutation_info = chosen_strategy(tree_copy, seed=seed)
        mutation_info['seed'] = seed
        return mutated_ast, mutation_info

    def execute_mutation_and_analysis_cycle(self, parent_path: Path, parent_score: float, session_id: int):
        """
        Takes a parent test case, dynamically determines the number of mutations
        based on its score, and then executes and analyzes each child.
        """
        # --- Step 3.2: Implement Dynamic Mutation Count ---
        base_mutations = 100
        # Normalize the score relative to a baseline of 100 to calculate a multiplier
        score_multiplier = parent_score / 100.0

        # Apply a gentle curve so that very high scores don't lead to extreme mutation counts
        # and very low scores don't get starved completely.
        # We use math.log to dampen the effect. Add 1 to avoid log(0).
        dynamic_multiplier = 0.5 + (math.log(max(1, score_multiplier * 10)) / 2)

        # Clamp the multiplier to a reasonable range (e.g., 0.25x to 3.0x)
        final_multiplier = max(0.25, min(3.0, dynamic_multiplier))

        max_mutations = int(base_mutations * final_multiplier)

        print(
            f"[+] Dynamically adjusting mutation count based on score. Base: {base_mutations}, Multiplier: {final_multiplier:.2f}, Final Count: {max_mutations}")

        parent_id = parent_path.name
        parent_metadata = self.coverage_state["per_file_coverage"].get(parent_id, {})
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})

        try:
            parent_source = parent_path.read_text()

            # If boilerplate isn't cached yet, this must be a full generation file.
            if self.boilerplate_code is None:
                self._extract_and_cache_boilerplate(parent_source)

            # Get the core code for mutation. This works for both full and minimized files.
            parent_core_code = self._get_core_code(parent_source)
            parent_core_tree = ast.parse(parent_core_code)
        except (IOError, SyntaxError) as e:
            print(f"[!] Error processing parent file {parent_path.name}: {e}", file=sys.stderr)
            return

        # Find the first harness function to use as the mutation target.
        # A more advanced strategy could mutate all harnesses.
        base_harness_node = None
        for node in parent_core_tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith('uop_harness_'):
                base_harness_node = node
                break

        if not base_harness_node:
            print(f"[-] No harness function found in {parent_path.name}. Skipping.", file=sys.stderr)
            return

        core_logic_to_mutate = base_harness_node.body

        # Loop through a set number of mutations for this parent.
        for i in range(max_mutations):
            self.run_stats["total_mutations"] = self.run_stats.get("total_mutations", 0) + 1
            self.mutations_since_last_find += 1

            # Increment and use the global seed for this mutation attempt.
            self.global_seed_counter += 1
            current_seed = self.global_seed_counter
            print(f"  \\-> Running mutation #{i + 1} (Seed: {current_seed}) for {parent_path.name}...")

            # 1. Get the mutated AST from our refactored strategy function.
            try:
                mutated_body_ast, mutation_info = self.apply_mutation_strategy(
                    core_logic_to_mutate,
                    seed=current_seed
                )
            except RecursionError:
                print(f"  [!] Warning: Skipping mutation due to RecursionError during AST transformation. The mutator created a tree that was too deep.", file=sys.stderr)
                continue # Skip to the next mutation

            # 2. Re-assemble the full source code for the child.
            child_core_tree = copy.deepcopy(parent_core_tree)
            for node in child_core_tree.body:
                if isinstance(node, ast.FunctionDef) and node.name == base_harness_node.name:
                    node.body = mutated_body_ast
                    break

            # 3. Define temporary file paths for this specific child.
            child_source_path = TMP_DIR / f"child_{session_id}_{i + 1}.py"
            child_log_path = TMP_DIR / f"child_{session_id}_{i + 1}.log"

            # 4. Write and execute the child process.
            try:
                try:
                    mutated_core_code = ast.unparse(child_core_tree)
                    child_full_source = f"{self.boilerplate_code}\n{mutated_core_code}"
                    child_source_path.write_text(child_full_source)
                except RecursionError:
                    print(f"  [!] Warning: Skipping mutation due to RecursionError during ast.unparse. Likely too many nested statements.", file=sys.stderr)
                    continue # Skip to the next mutation
                with open(child_log_path, "w") as log_file:
                    start_time = time.monotonic()
                    result = subprocess.run(
                        ["python3", str(child_source_path)],
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=10,
                        env=ENV,
                    )
                    end_time = time.monotonic()
                    execution_time_ms = int((end_time - start_time) * 1000)
                analysis_result = self.analyze_run(
                    child_log_path,
                    child_source_path,
                    result.returncode,
                    parent_lineage_profile,
                    parent_id,
                    execution_time_ms,
                    mutation_info,
                    mutation_seed=current_seed,
                )
                if analysis_result == "CRASH":
                    self.run_stats["crashes_found"] = self.run_stats.get("crashes_found", 0) + 1
                    continue
                elif analysis_result == "NEW_COVERAGE":
                    self.run_stats["new_coverage_finds"] = self.run_stats.get("new_coverage_finds", 0) + 1
                    self.run_stats["sum_of_mutations_per_find"] += self.mutations_since_last_find
                    self.mutations_since_last_find = 0
                    print(f"  [***] SUCCESS! Mutation #{i + 1} found new coverage. Moving to next parent.")
                    parent_metadata["total_finds"] = parent_metadata.get("total_finds", 0) + 1
                    parent_metadata["mutations_since_last_find"] = 0
                    save_coverage_state(self.coverage_state)
                    break # Move to next parent
                else:
                    parent_metadata["mutations_since_last_find"] = parent_metadata.get("mutations_since_last_find", 0) + 1
                    # Check for sterility
                    if parent_metadata["mutations_since_last_find"] > 599: # Sterility threshold
                        parent_metadata["is_sterile"] = True
            except subprocess.TimeoutExpired:
                self.run_stats["timeouts_found"] = self.run_stats.get("timeouts_found", 0) + 1
                print(f"  [!!!] TIMEOUT DETECTED! Saving test case.", file=sys.stderr)
                timeout_source_path = TIMEOUTS_DIR / f"timeout_{session_id}_{i+1}_{parent_path.name}"
                timeout_log_path = timeout_source_path.with_suffix(".log")
                shutil.copy(child_source_path, timeout_source_path)
                shutil.copy(child_log_path, timeout_log_path)
                continue
            except Exception as e:
                print(f"  [!] Error executing child process: {e}", file=sys.stderr)
                continue  # Move to the next mutation
            finally:
                try:
                    if child_source_path.exists():
                        child_source_path.unlink()
                    if child_log_path.exists():
                        child_log_path.unlink()
                except OSError as e:
                    print(f"  [!] Warning: Could not delete temp file: {e}", file=sys.stderr)

    def analyze_run(
            self,
            log_path: Path,
            source_path: Path,
            return_code: int,
            parent_lineage_profile: dict[str, Any],
            parent_id: str | None,
            execution_time_ms: int,
            mutation_info: dict[str, Any],
            mutation_seed: int,
    ) -> AnalysisResult:
        """
        Analyzes a run for crashes and new coverage against the full lineage.
        """
        # --- Lightweight Crash Monitoring (no change) ---
        if return_code != 0:
            print(f"  [!!!] CRASH DETECTED! Exit code: {return_code}. Saving test case and log.", file=sys.stderr)
            crash_source_path = CRASHES_DIR / f"crash_retcode_{source_path.name}"
            crash_log_path = crash_source_path.with_suffix(".log")
            shutil.copy(source_path, crash_source_path)
            shutil.copy(log_path, crash_log_path)
            return "CRASH"
        try:
            log_content = log_path.read_text()
            for keyword in CRASH_KEYWORDS:
                if keyword.lower() in log_content.lower():
                    print(f"  [!!!] CRASH DETECTED! Found keyword '{keyword}'. Saving test case and log.",
                          file=sys.stderr)
                    crash_source_path = CRASHES_DIR / f"crash_keyword_{source_path.name}"
                    crash_log_path = crash_source_path.with_suffix(".log")
                    shutil.copy(source_path, crash_source_path)
                    shutil.copy(log_path, crash_log_path)
                    return "CRASH"
        except IOError as e:
            print(f"  [!] Warning: Could not read log file for crash analysis: {e}", file=sys.stderr)

        # --- Unified Coverage Analysis ---
        child_coverage = parse_log_for_edge_coverage(log_path)
        is_interesting = False

        global_coverage = self.coverage_state["global_coverage"]

        # This loop runs for ALL files to update global counts and check for newness.
        for harness_id, child_data in child_coverage.items():
            lineage_harness_data = parent_lineage_profile.get(harness_id, {})

            # Helper lambda to process each coverage type (uops, edges, rare_events)
            def process_coverage_type(cov_type: str):
                nonlocal is_interesting
                lineage_set = lineage_harness_data.get(cov_type, set())
                child_dict = child_data.get(cov_type, {})

                for item, count in child_dict.items():
                    is_globally_new = item not in global_coverage.get(cov_type, {})
                    is_new_to_lineage = item not in lineage_set

                    if is_globally_new:
                        print(f"[NEW GLOBAL {cov_type.upper()[:-1]}] '{item}' in harness '{harness_id}'",
                              file=sys.stderr)
                        is_interesting = True
                    elif is_new_to_lineage and parent_id is not None:
                        print(f"[NEW RELATIVE {cov_type.upper()[:-1]}] '{item}' in harness '{harness_id}'",
                              file=sys.stderr)
                        is_interesting = True

                    # ALWAYS update global coverage counts for every item seen.
                    global_coverage.setdefault(cov_type, {})
                    global_coverage[cov_type].setdefault(item, 0)
                    global_coverage[cov_type][item] += count

            process_coverage_type("uops")
            process_coverage_type("edges")
            process_coverage_type("rare_events")

        # For mutations, is_interesting is now correctly set.
        # For seeds, we apply a different rule.
        if parent_id is None:
            is_generative_seed = mutation_info.get("strategy") == "generative_seed"
            # A seed is interesting if it produced any coverage, OR it's the bootstrap seed.
            if child_coverage or is_generative_seed:
                is_interesting = True
            else:
                print(f"  [~] Seed file {source_path.name} produced no JIT coverage. Skipping.", file=sys.stderr)
                is_interesting = False  # Explicitly set to false

        if is_interesting:
            # Read the full source code that was just run
            full_source_code = source_path.read_text()
            # Extract just the core part for saving to the corpus
            core_code_to_save = self._get_core_code(full_source_code)
            content_hash = hashlib.sha256(core_code_to_save.encode('utf-8')).hexdigest()

            # The core duplication check:
            if content_hash in self.known_hashes:
                print(
                    f"  [~] New coverage found, but content is a known duplicate (Hash: {content_hash[:10]}...). Skipping.",
                    file=sys.stderr)
                return "NO_CHANGE"

            new_file_id = self._add_new_file_to_corpus(
                core_code_to_save,
                child_coverage,
                execution_time_ms,
                parent_id,
                mutation_info,
                mutation_seed=mutation_seed,
                content_hash=content_hash,
            )
            print(f"[+] Saved interesting file as {new_file_id}")
            save_coverage_state(self.coverage_state)
            return "NEW_COVERAGE"

        return "NO_CHANGE"

    def _log_timeseries_datapoint(self):
        """
        Step 1.2: Implement the Data Point Logger.
        Appends a snapshot of the current run statistics to the time-series log file.
        """
        # Create a snapshot of the current stats for logging.
        datapoint = self.run_stats.copy()
        datapoint["timestamp"] = datetime.now(timezone.utc).isoformat()

        try:
            # Open in append mode and write the JSON object as a single line.
            with open(self.timeseries_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(datapoint) + "\n")
        except IOError as e:
            print(f"[!] Warning: Could not write to time-series log file: {e}", file=sys.stderr)

    def _build_lineage_profile(self, parent_lineage_profile: dict, child_baseline_profile: dict) -> dict:
        """
        Creates a new lineage profile by taking the union of a parent's
        lineage and a child's own baseline coverage.

        The lineage profile stores sets of coverage keys for efficient lookups,
        not hit counts.
        """
        # Start with a deep copy of the parent's lineage to avoid side effects.
        lineage = copy.deepcopy(parent_lineage_profile)
        for harness_id, child_data in child_baseline_profile.items():
            # Ensure the harness entry exists in the new lineage profile.
            lineage_harness = lineage.setdefault(harness_id, {"uops": set(), "edges": set(), "rare_events": set()})
            for key in ["uops", "edges", "rare_events"]:
                # Get the set of items from the parent's lineage.
                lineage_set = lineage_harness.setdefault(key, set())
                # Add all the keys from the child's new coverage to the set.
                lineage_set.update(child_data.get(key, {}).keys())
        return lineage


def main():
    """
    Main entry point to set up and run the Deep Fuzzer Orchestrator.
    """
    parser = argparse.ArgumentParser(description="Fusil's feedback-driven JIT fuzzer.")
    parser.add_argument(
        '--min-corpus-files',
        type=int,
        default=1,
        help='Ensure the corpus has at least N files before starting the main fuzzing loop. (Default: 1)'
    )
    args = parser.parse_args()

    LOGS_DIR.mkdir(exist_ok=True)
    # Use a consistent timestamp for the whole run
    run_start_time = datetime.now()
    timestamp_iso = run_start_time.isoformat()
    safe_timestamp = timestamp_iso.replace(":", "-").replace("+", "Z")
    orchestrator_log_path = LOGS_DIR / f"deep_fuzzer_run_{safe_timestamp}.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # This initial print goes only to the console
    print(f"[+] Starting deep fuzzer. Full log will be at: {orchestrator_log_path}")

    tee_logger = TeeLogger(orchestrator_log_path, original_stdout)
    sys.stdout = tee_logger
    sys.stderr = tee_logger

    termination_reason = "Completed" # Default reason
    start_stats = load_run_stats() # Capture stats at the start

    try:
        # --- Create and Write the Informative Header ---
        header = f"""
================================================================================
FUSIL DEEP FUZZER RUN
================================================================================
- Hostname:         {socket.gethostname()}
- Platform:         {platform.platform()}
- Process ID:       {os.getpid()}
- Python Version:   {sys.version.replace(chr(10), ' ')}
- Working Dir:      {Path.cwd()}
- Log File:         {orchestrator_log_path}
- Start Time:       {timestamp_iso}
- Command:          {' '.join(sys.argv)}
--------------------------------------------------------------------------------
Initial Stats:
{json.dumps(start_stats, indent=4)}
================================================================================

"""
        print(dedent(header))
        # --- End of Header ---

        orchestrator = DeepFuzzerOrchestrator(min_corpus_files=args.min_corpus_files)
        orchestrator.run_evolutionary_loop()
    except KeyboardInterrupt:
        print("\n[!] Fuzzing stopped by user.")
        termination_reason = "KeyboardInterrupt"
    except Exception as e:
        termination_reason = f"Error: {e}"
        # Use original stderr for the final error message so it's always visible.
        print(f"\n[!!!] An unexpected error occurred in the orchestrator: {e}", file=original_stderr)
        import traceback
        traceback.print_exc(file=original_stderr)
    finally:
        # --- Create and Write the Summary Footer ---
        print("\n" + "="*80)
        print("FUZZING RUN SUMMARY")
        print("="*80)

        end_time = datetime.now()
        duration = end_time - run_start_time
        end_stats = load_run_stats()

        mutations_this_run = end_stats.get("total_mutations", 0) - start_stats.get("total_mutations", 0)
        finds_this_run = end_stats.get("new_coverage_finds", 0) - start_stats.get("new_coverage_finds", 0)
        crashes_this_run = end_stats.get("crashes_found", 0) - start_stats.get("crashes_found", 0)
        duration_secs = duration.total_seconds()
        exec_per_sec = mutations_this_run / duration_secs if duration_secs > 0 else 0

        summary = f"""
- Termination:      {termination_reason}
- End Time:         {end_time.isoformat()}
- Total Duration:   {str(duration)}

--- Discoveries This Run ---
- New Coverage:     {finds_this_run}
- New Crashes:      {crashes_this_run}

--- Performance This Run ---
- Total Executions: {mutations_this_run}
- Execs per Second: {exec_per_sec:.2f}

--- Final Campaign Stats ---
{json.dumps(end_stats, indent=4)}
================================================================================
"""
        print(dedent(summary))

        # Cleanly close the log file and restore streams.
        tee_logger.close()
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        print(f"[+] Fuzzing session finished. Full log saved to: {orchestrator_log_path}")


if __name__ == "__main__":
    # This makes the script directly executable.
    main()
