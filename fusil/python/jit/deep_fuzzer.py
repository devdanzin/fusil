import ast
import copy
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time
from _ast import AST
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent
from typing import Any, Generator, Literal

from fusil.python.jit.jit_coverage_parser import parse_log_for_edge_coverage
from fusil.python.jit.ast_mutator import ASTMutator

RANDOM = random.Random()

# Define paths relative to this file's location
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent

CORPUS_DIR = PROJECT_ROOT / "corpus" / "jit_interesting_tests"
TMP_DIR = PROJECT_ROOT / "tmp_fuzz_run"

CRASHES_DIR = PROJECT_ROOT / "crashes"
TIMEOUTS_DIR = PROJECT_ROOT / "timeouts"

COVERAGE_DIR = PROJECT_ROOT / "coverage"
COVERAGE_STATE_FILE = COVERAGE_DIR / "coverage_state.json"

# Path to the fusil executable itself
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

AnalysisResult = Literal["CRASH", "NEW_COVERAGE", "NO_CHANGE"]


def load_coverage_state() -> dict[str, Any]:
    """
    Loads the global and per-file coverage state from the JSON file.
    Returns a default structure if the file doesn't exist.
    """
    if not COVERAGE_STATE_FILE.is_file():
        # --- Step 1.1: Evolve coverage_state.json structure ---
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {}
        }
    try:
        with open(COVERAGE_STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
            # Ensure both keys are present for backward compatibility
            state.setdefault("global_coverage", {"uops": {}, "edges": {}, "rare_events": {}})
            state.setdefault("per_file_coverage", {})
            return state
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not load coverage state file. Starting fresh. Error: {e}", file=sys.stderr)
        return {
            "global_coverage": {"uops": {}, "edges": {}, "rare_events": {}},
            "per_file_coverage": {}
        }


def save_coverage_state(state: dict[str, Any]):
    """
    Saves the updated global and per-file coverage state to the JSON file.
    """
    COVERAGE_DIR.mkdir(exist_ok=True)
    with open(COVERAGE_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


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


class DeepFuzzerOrchestrator:
    """
    The "brain" of the feedback-driven fuzzer.

    This class manages the main evolutionary loop: selecting interesting
    test cases from the corpus, applying mutation strategies, executing the
    mutated children, and analyzing the results for new coverage.
    """

    def __init__(self):
        self.ast_mutator = ASTMutator()
        self.coverage_state = load_coverage_state()
        self.boilerplate_code = None
        self.scheduler = CorpusScheduler(self.coverage_state)

        # Ensure temporary and corpus directories exist
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
        TIMEOUTS_DIR.mkdir(exist_ok=True)

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
            parent_id: str | None
    ) -> str:
        """
        Copies a file to the corpus and saves its rich metadata object.
        """
        # --- Step 1.2: Implement Metadata Tracking ---
        parent_metadata = self.coverage_state["per_file_coverage"].get(parent_id, {}) if parent_id else {}
        lineage_depth = parent_metadata.get("lineage_depth", 0) + 1

        unique_id = f"id_{RANDOM.randint(10000, 99999)}_{parent_id.replace('.py', '') if parent_id else 'seed'}.py"
        corpus_filepath = CORPUS_DIR / unique_id

        # Save only the core code, not the boilerplate.
        corpus_filepath.write_text(core_code)
        print(f"[+] Added minimized file to corpus: {unique_id}")

        metadata = {
            "baseline_coverage": baseline_coverage,
            "parent_id": parent_id,
            "lineage_depth": lineage_depth,
            "discovery_time": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": execution_time_ms,
            "file_size_bytes": len(core_code.encode('utf-8')),
            "mutations_since_last_find": 0,
            "total_finds": 0,
            "is_sterile": False
        }
        self.coverage_state["per_file_coverage"][unique_id] = metadata
        return unique_id

    def select_parent_from_corpus(self) -> Path | None:
        """
        Selects a test case from the corpus using a weighted random choice
        based on the scheduler's scores.
        """
        corpus_files = list(self.coverage_state.get("per_file_coverage", {}).keys())
        if not corpus_files:
            return None

        # --- Step 2.1 & 2.2: Use the scoring engine ---
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

        return CORPUS_DIR / chosen_filename

    def run_evolutionary_loop(self):
        """
        The main entry point for the deep fuzzing process.
        This method contains the infinite loop that drives the fuzzer.
        """
        print("[+] Starting Deep Fuzzer Evolutionary Loop. Press Ctrl+C to stop.")

        session_count = 0
        while True:
            session_count += 1
            print(f"\n--- Fuzzing Session #{session_count} ---")

            # 1. Selection
            parent_path = self.select_parent_from_corpus()

            if parent_path is None:
                print("[-] Corpus is empty. Running a generation run to seed the corpus.")
                self.run_generation_session()
                continue

            print(f"[+] Selected parent for mutation: {parent_path.name}")

            # This is where the logic from Step 3.2 will go.
            # For now, we'll just show a placeholder for the next step.
            self.execute_mutation_and_analysis_cycle(parent_path, session_count)

    def run_generation_session(self):
        """
        Runs a single "generative" session to create a new test case
        from scratch, primarily to seed an empty corpus.
        """
        tmp_source = TMP_DIR / "gen_run.py"
        tmp_log = TMP_DIR / "gen_run.log"

        # Use fusil to generate a new file
        subprocess.run([
            FUSIL_PATH,
            "--jit-fuzz",
            "--jit-target-uop=ALL",
            f"--source-output-path={tmp_source}",
            "--classes-number=0",
            "--functions-number=1",
            "--methods-number=0",
            "--objects-number=0",
            "--sessions=1",
            "--python=/home/danzin/venvs/jit_cpython_venv/bin/python",
            "-v",
            "--no-threads",
            "--no-async",
            "--jit-loop-iterations=300",
            "--no-numpy",
            "--modules=encodings.ascii",
            # "--keep-sessions",
        ], check=True)

        # Execute it to get a log
        with open(tmp_log, "w") as log_file:
            subprocess.run(["python3", tmp_source], stdout=log_file, stderr=subprocess.STDOUT)

        # Analyze it for coverage
        self.analyze_run(tmp_log, tmp_source, 0, {}, "SEED", 0)

    def apply_mutation_strategy(self, tree: ast.AST, max_mutations: int = 200) -> Generator[AST, None, None]:
        print(f"[+] Applying mutation strategy to base AST, generating {max_mutations} variants...",
              file=sys.stderr)
        for i in range(max_mutations):
            # It is CRITICAL to deepcopy the base AST before each mutation.
            # This ensures each mutation starts from the same pristine state,
            # and we are only testing the effect of the current seed.
            tree_copy = copy.deepcopy(tree)

            # Use the loop counter `i` as the seed for deterministic mutation.
            mutated_ast = self.ast_mutator.mutate_ast(tree_copy, seed=i)

            yield mutated_ast


    def execute_mutation_and_analysis_cycle(self, parent_path: Path, session_id: int):
        """
        Takes a parent test case, applies a mutation strategy, and then
        executes and analyzes each resulting child.
        """
        parent_id = parent_path.name
        parent_metadata = self.coverage_state["per_file_coverage"].get(parent_id, {})
        parent_baseline_coverage = parent_metadata.get("baseline_coverage", {})

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

        # Get the stream of mutated variants from our strategy generator.
        core_logic_to_mutate = base_harness_node.body
        mutation_generator = self.apply_mutation_strategy(core_logic_to_mutate)

        # Loop through a set number of mutations for this parent.
        env = os.environ.copy()
        env.update({
            "PYTHON_LLTRACE": "4",
            "PYTHON_OPT_DEBUG": "4",
        })
        for i, mutated_body_ast in enumerate(mutation_generator):
            print(f"  \\-> Running mutation #{i + 1} for {parent_path.name}...")

            # 1. Re-assemble the full source code for the child.
            # We create a full copy of the parent's AST and then swap in the
            # mutated body to the correct harness function.
            child_core_tree = copy.deepcopy(parent_core_tree)
            for node in child_core_tree.body:
                if isinstance(node, ast.FunctionDef) and node.name == base_harness_node.name:
                    node.body = mutated_body_ast
                    break

            # ast.fix_missing_locations(child_core_tree)
            mutated_core_code = ast.unparse(child_core_tree)
            child_full_source = f"{self.boilerplate_code}\n{mutated_core_code}"

            # 2. Define temporary file paths for this specific child.
            child_source_path = TMP_DIR / f"child_{session_id}_{i + 1}.py"
            child_log_path = TMP_DIR / f"child_{session_id}_{i + 1}.log"

            # 3. Write and execute the child process.
            try:
                child_source_path.write_text(child_full_source)
                with open(child_log_path, "w") as log_file:
                    start_time = time.monotonic()
                    result = subprocess.run(
                        ["python3", str(child_source_path)],
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=10,
                        env=env,
                    )
                    end_time = time.monotonic()
                    execution_time_ms = int((end_time - start_time) * 1000)
                analysis_result = self.analyze_run(
                    child_log_path,
                    child_source_path,
                    result.returncode,
                    parent_baseline_coverage,
                    parent_id,
                    execution_time_ms,
                )
                if analysis_result == "NEW_COVERAGE":
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
                print(f"  [!!!] TIMEOUT DETECTED! Saving test case.", file=sys.stderr)
                timeout_path = TIMEOUTS_DIR / f"timeout_{session_id}_{i + 1}_{parent_path.name}"
                shutil.copy(child_source_path, timeout_path)
                continue
            except Exception as e:
                print(f"  [!] Error executing child process: {e}", file=sys.stderr)
                continue  # Move to the next mutation
            finally:
                # --- NEW: Temporary File Cleanup ---
                # This block ensures that the temporary files for this child
                # are deleted after they are used, even if errors occur.
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
            parent_baseline_coverage: dict[str, Any],
            parent_id: str,
            execution_time_ms: int,
    ) -> AnalysisResult:
        """
        Analyzes a run for crashes (via exit code or log keywords) and new
        coverage. Saves interesting files and returns the run's status.
        """
        # --- Lightweight Crash Monitoring ---
        # 1. Check for non-zero exit code first.
        if return_code != 0:
            print(f"  [!!!] CRASH DETECTED! Exit code: {return_code}. Saving test case.", file=sys.stderr)
            crash_path = CRASHES_DIR / f"crash_retcode_{source_path.name}"
            shutil.copy(source_path, crash_path)
            return "CRASH"

        # 2. If exit code is clean, scan the log for crash keywords.
        try:
            log_content = log_path.read_text()
            for keyword in CRASH_KEYWORDS:
                if keyword.lower() in log_content.lower():
                    print(f"  [!!!] CRASH DETECTED! Found keyword '{keyword}'. Saving test case.", file=sys.stderr)
                    crash_path = CRASHES_DIR / f"crash_keyword_{source_path.name}"
                    shutil.copy(source_path, crash_path)
                    return "CRASH"
        except IOError as e:
            print(f"  [!] Warning: Could not read log file for crash analysis: {e}", file=sys.stderr)


        # --- Coverage Analysis ---
        # This part only runs if no crash was detected.
        child_coverage = parse_log_for_edge_coverage(log_path)
        is_interesting = False

        global_coverage = self.coverage_state["global_coverage"]

        for harness_id, child_data in child_coverage.items():
            parent_harness_data = parent_baseline_coverage.get(harness_id, {})

            # --- Check UOPs ---
            child_uops = child_data.get("uops", {})
            parent_uops = parent_harness_data.get("uops", {})
            for uop, count in child_uops.items():
                if uop not in global_coverage["uops"]:
                    print(f"[NEW GLOBAL UOP] '{uop}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True
                elif uop not in parent_uops:
                    print(f"[NEW RELATIVE UOP] '{uop}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True

                global_coverage["uops"].setdefault(uop, 0)
                global_coverage["uops"][uop] += count

            # --- Check Edges ---
            child_edges = child_data.get("edges", {})
            parent_edges = parent_harness_data.get("edges", {})
            for edge, count in child_edges.items():
                if edge not in global_coverage["edges"]:
                    print(f"[NEW GLOBAL EDGE] '{edge}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True
                elif edge not in parent_edges:
                    print(f"[NEW RELATIVE EDGE] '{edge}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True

                # Update global state
                global_coverage["edges"].setdefault(edge, 0)
                global_coverage["edges"][edge] += count

            # --- Check Rare Events ---
            child_events = child_data.get("rare_events", {})
            parent_events = parent_harness_data.get("rare_events", {})
            for event, count in child_events.items():
                if event not in global_coverage["rare_events"]:
                    print(f"[NEW GLOBAL RARE EVENT] '{event}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True
                elif event not in parent_events:
                    print(f"[NEW RELATIVE RARE EVENT] '{event}' in harness '{harness_id}'", file=sys.stderr)
                    is_interesting = True

                # Update global state
                global_coverage["rare_events"].setdefault(event, 0)
                global_coverage["rare_events"][event] += count

        if is_interesting or parent_id == "SEED":
            # Read the full source code that was just run
            full_source_code = source_path.read_text()
            # Extract just the core part for saving to the corpus
            core_code_to_save = self._get_core_code(full_source_code)

            new_file_id = self._add_new_file_to_corpus(
                core_code_to_save,
                child_coverage,
                execution_time_ms,
                parent_id
            )
            print(f"[+] Saved interesting mutation as {new_file_id}")
            save_coverage_state(self.coverage_state)
            return "NEW_COVERAGE"

        return "NO_CHANGE"


def main():
    """
    Main entry point to set up and run the Deep Fuzzer Orchestrator.
    """
    orchestrator = DeepFuzzerOrchestrator()
    orchestrator.run_evolutionary_loop()


if __name__ == "__main__":
    # This makes the script directly executable.
    main()
