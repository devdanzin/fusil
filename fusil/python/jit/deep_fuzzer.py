import ast
import copy
import json
import os
import random
import shutil
import subprocess
import sys
from _ast import AST
from pathlib import Path
from typing import Any, Generator, Literal

from fusil.python.jit.jit_coverage_parser import parse_log_for_edge_coverage
from fusil.python.jit.ast_mutator import ASTMutator

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

        # Ensure temporary and corpus directories exist
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR.mkdir(exist_ok=True)
        CRASHES_DIR.mkdir(exist_ok=True)
        TIMEOUTS_DIR.mkdir(exist_ok=True)

    def _add_new_file_to_corpus(self, source_path: Path, parent_name: str = "generation") -> str:
        """
        Copies a file to the corpus, calculates its baseline coverage,
        and saves that coverage to the state file.
        """
        unique_id = f"id_{random.randint(10000, 99999)}_{parent_name.replace('.py', '')}.py"
        corpus_filepath = CORPUS_DIR / unique_id
        shutil.copy(source_path, corpus_filepath)
        print(f"[+] Added to corpus: {unique_id}")

        baseline_log_path = TMP_DIR / f"{unique_id}.log"
        try:
            with open(baseline_log_path, "w") as log_file:
                subprocess.run(
                    ["python3", str(corpus_filepath)],
                    stdout=log_file, stderr=subprocess.STDOUT, timeout=10
                )
            baseline_coverage = parse_log_for_edge_coverage(baseline_log_path)
        except (subprocess.TimeoutExpired, IOError) as e:
            print(f"[!] Warning: Could not get baseline coverage for {unique_id}: {e}", file=sys.stderr)
            baseline_coverage = {}
        finally:
            if baseline_log_path.exists():
                baseline_log_path.unlink()

        self.coverage_state["per_file_coverage"][unique_id] = baseline_coverage
        return unique_id

    def select_parent_from_corpus(self) -> Path | None:
        """
        Selects a test case from the corpus to be the parent for a
        round of mutations.
        """
        if not os.listdir(CORPUS_DIR):
            return None

        corpus_files = [f for f in CORPUS_DIR.iterdir() if f.is_file()]
        # Future enhancement: Add heuristics here (e.g., smaller files, rarer coverage)
        return random.choice(corpus_files)

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
        self.analyze_run(tmp_log, tmp_source)

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
        parent_baseline_coverage = self.coverage_state["per_file_coverage"].get(parent_id, {})

        try:
            parent_source = parent_path.read_text()
            parent_tree = ast.parse(parent_source)
        except (IOError, SyntaxError) as e:
            print(f"[!] Error processing parent file {parent_path.name}: {e}", file=sys.stderr)
            return

        # Find the first harness function to use as the mutation target.
        # A more advanced strategy could mutate all harnesses.
        base_harness_node = None
        for node in parent_tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith('uop_harness_'):
                base_harness_node = node
                break

        if not base_harness_node:
            print(f"[-] No harness function found in {parent_path.name}. Skipping.", file=sys.stderr)
            return

        # Get the stream of mutated variants from our strategy generator.
        mutation_generator = self.apply_mutation_strategy(base_harness_node.body)

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
            child_tree = copy.deepcopy(parent_tree)
            for node in child_tree.body:
                if isinstance(node, ast.FunctionDef) and node.name == base_harness_node.name:
                    node.body = mutated_body_ast
                    break

            ast.fix_missing_locations(child_tree)
            child_source_code = ast.unparse(child_tree.body)

            # 2. Define temporary file paths for this specific child.
            child_source_path = TMP_DIR / f"child_{session_id}_{i + 1}.py"
            child_log_path = TMP_DIR / f"child_{session_id}_{i + 1}.log"

            # 3. Write and execute the child process.
            try:
                child_source_path.write_text(child_source_code)
                with open(child_log_path, "w") as log_file:
                    result = subprocess.run(
                        ["python3", str(child_source_path)],
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=10,
                        env=env,
                    )
                analysis_result = self.analyze_run(
                    child_log_path,
                    child_source_path,
                    result.returncode,
                    parent_baseline_coverage,
                    parent_id
                )

                if analysis_result == "CRASH":
                    # Crash was detected and saved by analyze_run. Continue to next mutation.
                    continue
                elif analysis_result == "NEW_COVERAGE":
                    # New coverage was found and saved. Move to the next parent.
                    print(f"  [***] SUCCESS! Mutation #{i + 1} found new coverage. Moving to next parent.")
                    break
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
        current_coverage = parse_log_for_edge_coverage(log_path)
        newly_discovered_globally = False

        global_coverage = self.coverage_state["global_coverage"]

        for harness_id, data in current_coverage.items():
            # (Logic for updating uops, edges, and rare_events remains the same)
            for uop, count in data.get("uops", {}).items():
                if uop not in global_coverage["uops"]:
                    newly_discovered_globally = True
                    global_coverage["uops"][uop] = 0
                global_coverage["uops"][uop] += count
            for edge, count in data.get("edges", {}).items():
                if edge not in global_coverage["edges"]:
                    newly_discovered_globally = True
                    global_coverage["edges"][edge] = 0
                global_coverage["edges"][edge] += count
            for event, count in data.get("rare_events", {}).items():
                if event not in global_coverage["rare_events"]:
                    newly_discovered_globally = True
                    global_coverage["rare_events"][event] = 0
                global_coverage["rare_events"][event] += count

        if newly_discovered_globally:
            print(f"[!!!] NEW COVERAGE FOUND! Saving {source_path.name} to corpus.")
            shutil.copy(source_path, CORPUS_DIR / f"id_{random.randint(1000, 9999)}_{source_path.name}")
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
