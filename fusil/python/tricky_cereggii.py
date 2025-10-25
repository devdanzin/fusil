"""
Aggregator for cereggii Fuzzing Assets.

This module imports all specialized `tricky_cereggii_*` modules,
reads their source code for embedding into generated fuzzing scripts,
and aggregates the names of defined tricky objects and callable scenarios
for use by the argument generator and scenario runner.
"""

import pathlib
import sys
import importlib
import inspect

# --- Helper Functions ---

def _read_module_source(module_name: str) -> str | None:
    """Reads the source code of a sibling module."""
    try:
        filename = f"{module_name}.py"
        path = pathlib.Path(__file__).parent / "samples" / "cereggii" / filename
        source_code = path.read_text(encoding='utf-8')
        print(f"Successfully read source for: {filename}", file=sys.stderr)
        return source_code
    except FileNotFoundError:
        print(f"ERROR: Could not find source file: {filename}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: Failed to read {filename}: {e}", file=sys.stderr)
        return None

def _try_import_and_get_attribute(module_name: str, attribute_name: str) -> object | None:
    """Imports a sibling module and safely retrieves an attribute."""
    try:
        # Perform relative import within the 'fusil.python' package
        module = importlib.import_module(f"fusil.python.samples.cereggii.{module_name}", package=__package__)
    except ImportError as e:
        print(f"ERROR: Failed to import module '{module_name}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error importing '{module_name}': {e}", file=sys.stderr)
        return None

    try:
        attribute = getattr(module, attribute_name)
        # print(f"Successfully retrieved '{attribute_name}' from '{module_name}'.", file=sys.stderr) # Too verbose
        return attribute
    except AttributeError:
        print(f"ERROR: Attribute '{attribute_name}' not found in module '{module_name}'.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error getting '{attribute_name}' from '{module_name}': {e}", file=sys.stderr)
        return None

# --- Aggregate Source Code ---

# List of all specialized tricky modules for cereggii
_MODULE_NAMES = [
    "tricky_atomicint64",
    "tricky_atomicdict",
    "tricky_recursive_cereggii",
    "tricky_colliding_keys",
    "tricky_weird_cereggii",
    "tricky_threadhandle",
    "tricky_atomicint_scenarios",
    "tricky_atomicref_scenarios",
    "tricky_python_utils_scenarios",
    "tricky_threadhandle_scenarios",
    "tricky_stateful_scenarios",
    "tricky_concurrency_hell",
    "tricky_synergy_scenarios",
    "tricky_reduce_nightmares",
]

# Dictionary to hold the source code strings
tricky_cereggii_code_snippets = {}
print("\n--- Aggregating Cereggii Code Snippets ---", file=sys.stderr)
for name in _MODULE_NAMES:
    code = _read_module_source(name)
    tricky_cereggii_code_snippets[f"{name}_code"] = code

print("Finished aggregating code snippets.", file=sys.stderr)


# --- Aggregate Object and Scenario Names ---

# Define the lists/variables that will hold the names/references
tricky_atomicint64_instance_names: list[str] = []
tricky_atomicdict_instance_names: list[str] = []
atomicdict_scenario_names: list[str] = []
tricky_hashable_key_names: list[str] = []
tricky_recursive_object_names: list[str] = []
colliding_key_sets_name: str | None = None # Will hold the variable name string
tricky_weird_cereggii_instance_names: list[str] = []
tricky_threadhandle_instance_names: list[str] = []
atomicint_scenario_names: list[str] = []
atomicref_scenario_names: list[str] = []
python_utils_scenario_names: list[str] = []
threadhandle_scenario_names: list[str] = []
stateful_scenario_names: list[str] = []
concurrency_hell_scenario_names: list[str] = []
synergy_scenario_names: list[str] = []
reduce_nightmares_collection_name: str | None = None # Will hold the variable name string

# Map module names to the attributes they export and where to put the names
_EXPORT_MAP = {
    "tricky_atomicint64": [("tricky_atomic_ints", tricky_atomicint64_instance_names, 'dict_keys')],
    "tricky_atomicdict": [
        ("tricky_hashable_keys", tricky_hashable_key_names, 'dict_keys'),
        ("tricky_atomic_dicts", tricky_atomicdict_instance_names, 'dict_keys'),
        # ("atomicdict_scenarios", atomicdict_scenario_names, 'dict_keys'),
    ],
    "tricky_recursive_cereggii": [("tricky_recursive_objects", tricky_recursive_object_names, 'dict_keys')],
    "tricky_colliding_keys": [("colliding_key_sets", "colliding_key_sets", 'var_name')], # Export name of the var
    "tricky_weird_cereggii": [("tricky_weird_cereggii_objects", tricky_weird_cereggii_instance_names, 'dict_keys')],
    "tricky_threadhandle": [("tricky_threadhandle_collection", tricky_threadhandle_instance_names, 'dict_keys')],
    "tricky_atomicint_scenarios": [("atomicint_scenarios", atomicint_scenario_names, 'dict_keys')],
    "tricky_atomicref_scenarios": [("atomicref_scenarios", atomicref_scenario_names, 'dict_keys')],
    "tricky_python_utils_scenarios": [("python_utils_scenarios", python_utils_scenario_names, 'dict_keys')],
    "tricky_threadhandle_scenarios": [("threadhandle_scenarios", threadhandle_scenario_names, 'dict_keys')],
    "tricky_stateful_scenarios": [("stateful_scenarios", stateful_scenario_names, 'dict_keys')],
    "tricky_concurrency_hell": [("concurrency_hell_scenarios", concurrency_hell_scenario_names, 'dict_keys')],
    "tricky_synergy_scenarios": [("synergy_scenarios", synergy_scenario_names, 'dict_keys')],
    "tricky_reduce_nightmares": [("reduce_nightmares_collection", "reduce_nightmares_collection", 'var_name')], # Export name of the var
}

print("\n--- Aggregating Cereggii Object and Scenario Names ---", file=sys.stderr)
for module_name, exports in _EXPORT_MAP.items():
    for attr_name, target_var_or_list, extraction_type in exports:
        attribute_value = _try_import_and_get_attribute(module_name, attr_name)

        if attribute_value is not None:
            try:
                if extraction_type == 'dict_keys':
                    if isinstance(attribute_value, dict):
                        target_var_or_list.extend(list(attribute_value.keys()))
                        print(f"  + Aggregated {len(list(attribute_value.keys()))} names from {module_name}.{attr_name}", file=sys.stderr)
                    else:
                        print(f"  - WARNING: Expected dict for '{attr_name}' in '{module_name}', got {type(attribute_value)}. Skipping.", file=sys.stderr)
                elif extraction_type == 'var_name':
                    # This is tricky in Python, we store the *name* the fuzzer should use
                    if isinstance(target_var_or_list, str): # Check if the target is the name string
                        globals()[target_var_or_list] = attr_name # Assign the attribute name to the global variable
                        print(f"  + Exported variable name '{attr_name}' as '{target_var_or_list}' from {module_name}", file=sys.stderr)
                    else:
                         print(f"  - WARNING: Target '{target_var_or_list}' for var_name export from {module_name}.{attr_name} is not a string.", file=sys.stderr)

            except Exception as e:
                print(f"  - ERROR processing {module_name}.{attr_name}: {e}", file=sys.stderr)
        else:
            print(f"  - Failed to retrieve {module_name}.{attr_name}. List/Var will be empty.", file=sys.stderr)

print("Finished aggregating names.", file=sys.stderr)


# --- Final Sanity Check ---
print("\n--- Aggregation Summary ---", file=sys.stderr)
loaded_snippets = sum(1 for code in tricky_cereggii_code_snippets.values() if code is not None)
print(f"Code Snippets: Loaded {loaded_snippets} out of {len(_MODULE_NAMES)} expected modules.", file=sys.stderr)

# Print counts for each list
print(f"AtomicInt64 Instances: {len(tricky_atomicint64_instance_names)} names", file=sys.stderr)
print(f"AtomicDict Instances: {len(tricky_atomicdict_instance_names)} names", file=sys.stderr)
print(f"AtomicDict Scenarios: {len(atomicdict_scenario_names)} names", file=sys.stderr)
print(f"Hashable Keys: {len(tricky_hashable_key_names)} names", file=sys.stderr)
print(f"Recursive Objects: {len(tricky_recursive_object_names)} names", file=sys.stderr)
print(f"Colliding Keys Var Name: '{colliding_key_sets_name}'" if colliding_key_sets_name else "Colliding Keys Var Name: Not loaded", file=sys.stderr)
print(f"Weird Cereggii Instances: {len(tricky_weird_cereggii_instance_names)} names", file=sys.stderr)
print(f"ThreadHandle Instances: {len(tricky_threadhandle_instance_names)} names", file=sys.stderr)
print(f"AtomicInt Scenarios: {len(atomicint_scenario_names)} names", file=sys.stderr)
print(f"AtomicRef Scenarios: {len(atomicref_scenario_names)} names", file=sys.stderr)
print(f"Python Utils Scenarios: {len(python_utils_scenario_names)} names", file=sys.stderr)
print(f"ThreadHandle Scenarios: {len(threadhandle_scenario_names)} names", file=sys.stderr)
print(f"Stateful Scenarios: {len(stateful_scenario_names)} names", file=sys.stderr)
print(f"Concurrency Hell Scenarios: {len(concurrency_hell_scenario_names)} names", file=sys.stderr)
print(f"Synergy Scenarios: {len(synergy_scenario_names)} names", file=sys.stderr)
print(f"Reduce Nightmares Var Name: '{reduce_nightmares_collection_name}'" if reduce_nightmares_collection_name else "Reduce Nightmares Var Name: Not loaded", file=sys.stderr)
print("-" * 50, file=sys.stderr)
