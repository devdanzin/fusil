from __future__ import annotations

import uuid
from random import random, randint, choice
from textwrap import dedent
# Import h5py here if type hinting for h5py objects is desired in this module,
# otherwise, it's mostly used within the generated script's context.
import h5py  # Added for isinstance checks if they are directly in this file.

# For type checking if WritePythonCode is passed or its methods are called:
# from typing import TYPE_CHECKING
# if TYPE_CHECKING:
#     from .write_python_code import WritePythonCode # Assuming WriteH5PyCode's parent is WritePythonCode

# Module docstring
"""
Generates Python code specifically for fuzzing h5py library objects and features.

This module provides the `WriteH5PyCode` class, which is responsible for
creating Python script segments that instantiate, manipulate, and test
h5py.File, h5py.Group, h5py.Dataset, and h5py.AttributeManager objects.
It aims to cover a wide range of h5py functionalities, including
various creation parameters, operations, and edge cases. This class is
intended to be used as a component by a more general Python code writer
for fuzzing, allowing for modular h5py-specific fuzz logic.
"""


def _h5_unique_name(base="item"):
    """
    Generates a unique name string with a given base and a short UUID.

    This helper is used to create unique names for HDF5 objects, variables,
    and prefixes within the generated fuzzing script, helping to avoid
    naming conflicts.

    Args:
        base: The base string for the name (e.g., "dataset", "group").

    Returns:
        A string combining the base and an 8-character hexadecimal UUID.
    """
    return f"{base}_{uuid.uuid4().hex[:8]}"


class WriteH5PyCode:
    """
    Handles the generation of h5py-specific Python code for fuzzing scripts.

    This class encapsulates the logic for creating code that interacts with
    h5py objects. It is designed to be instantiated and used by a parent
    Python code writing class, to which it delegates actual code emission
    and argument generation.
    """

    def __init__(self, parent):
        """
        Initializes the WriteH5PyCode instance.

        Args:
            parent: The parent `WritePythonCode` instance. This provides access
                    to the main code writing methods (e.g., `self.parent.write`),
                    the argument generator (`self.parent.arg_generator.h5py_argument_generator`),
                    and other shared fuzzer configurations and utilities.
        """
        super().__init__()
        self.parent = parent

    def _write_h5py_script_header_and_imports(self):
        """
        Writes h5py-specific imports and helper functions to the generated script.

        This method ensures that necessary modules like `h5py` (imported by the
        main `WritePythonCode`) and `numpy` are available. It also defines crucial
        runtime helper functions within the generated script:
        - `_fusil_h5_create_dynamic_slice_for_rank`: Creates diverse slice objects
          based on a dataset's rank, used for testing slicing operations.
        - `_fusil_h5_get_link_target_in_file`: Attempts to find a suitable existing
          Dataset or Group within the same HDF5 file to serve as a target for
          creating hard links, exploring various strategies to find a candidate.
        """
        self.parent.write(0, "import numpy   # For numpy.s_ in the dynamic slice helper, if used directly")
        self.parent.emptyLine()
        self.parent.write(0, dedent(
            """\
            def _fusil_h5_create_dynamic_slice_for_rank(rank_value):
                # ""\"Generates a slice tuple suitable for a dataset of given rank_value.""\"
                if rank_value is None: # Could be for null dataspace or if shape fetch failed
                    # Return a generic slice or an ellipsis for such cases
                    return choice([numpy.s_[...], slice(None), ()])

                if not isinstance(rank_value, int) or rank_value < 0:
                    # Fallback for unexpected rank_value input
                    return numpy.s_[...] # Default to ellipsis if rank is weird

                if rank_value == 0: # Scalar dataset
                    # Common ways to slice scalars: (), ...
                    return choice([(), numpy.s_[...]])

                # For rank > 0, generate a tuple of slice components
                slice_components = []
                # Determine how many components to generate for the slice tuple
                # Usually same as rank, but could be less (e.g., for d[0] on 2D array)
                # or more (h5py might truncate or error). Let's try for same as rank mostly.
                num_dims_to_slice = rank_value
                if random() < 0.1: # Small chance to use fewer slice components
                    num_dims_to_slice = randint(1, max(1, rank_value))

                for i in range(num_dims_to_slice):
                    choice_int = randint(0, 6)
                    if choice_int == 0:
                        slice_components.append(slice(None))  # ':'
                    elif choice_int == 1:
                        # Sensible index: 0, 1, or relative to end if rank_value and current dim size were known
                        # Since we only have rank, let's keep indices small
                        slice_components.append(randint(0, 3))
                    elif choice_int == 2: # start:stop
                        s = randint(0, 2)
                        e = s + randint(1, 3)
                        slice_components.append(slice(s, e))
                    elif choice_int == 3: # :stop
                        slice_components.append(slice(None, randint(1, 4)))
                    elif choice_int == 4: # start:
                        slice_components.append(slice(randint(0, 2), None))
                    elif choice_int == 5: # start:stop:step
                        s = randint(0, 2)
                        e = s + randint(2, 5)
                        st = choice([-2, -1, 1, 2, 3])
                        if st == 0: st = 1 # step cannot be 0
                        slice_components.append(slice(s, e, st))
                    else: # Ellipsis (can appear once)
                        if Ellipsis not in slice_components: # Only add one Ellipsis
                            slice_components.append(Ellipsis)
                        else: # fallback if Ellipsis already there
                            slice_components.append(slice(None))

                if not slice_components: # Should not happen if rank > 0
                     return ()

                # h5py can often take a tuple directly for slicing
                # If only one component and it's not Ellipsis, it might not need to be a tuple
                if len(slice_components) == 1 and isinstance(slice_components[0], (int, slice)) and slice_components[0] is not Ellipsis:
                     return slice_components[0]
                return tuple(slice_components)
            """
        ))
        self.parent.emptyLine()
        self.parent.write(0, dedent(f"""\
            def _fusil_h5_get_link_target_in_file(parent_group_obj, predefined_tricky_objects, runtime_objects):
                # ""\"Attempts to find a suitable existing Dataset or Group in the same file as parent_group_obj.
                # Used as a target for creating hard links.
                # ""\"
                if not parent_group_obj or not hasattr(parent_group_obj, 'file'):
                    return None # Parent group is invalid

                target_file_id = parent_group_obj.file.id
                candidates = []
                try: # Children of parent
                    if len(parent_group_obj) > 0:
                        child_obj = parent_group_obj.get(choice(list(parent_group_obj.keys())))
                        if isinstance(child_obj, (h5py.Group, h5py.Dataset)): candidates.append(child_obj)
                except Exception:
                    pass
                try:  # Top-level items
                    if len(parent_group_obj.file) > 0:
                        root_item_obj = parent_group_obj.file.get(choice(list(parent_group_obj.file.keys())))
                        if isinstance(root_item_obj, (h5py.Group, h5py.Dataset)): candidates.append(root_item_obj)
                except Exception:
                    pass
                try:  # Predefined tricky objects
                    for obj in predefined_tricky_objects.values():
                        if obj and hasattr(obj, 'file') and hasattr(obj.file, 'id') and \\
                                obj.file.id == target_file_id and isinstance(obj, (h5py.Group, h5py.Dataset)):
                            candidates.append(obj)
                        if len(candidates) > 20: break
                except Exception:
                    pass
                try:  # Runtime objects
                    for obj in runtime_objects.values():
                        if obj and hasattr(obj, 'file') and hasattr(obj.file, 'id') and obj.file.id == target_file_id and isinstance(obj, (h5py.Group, h5py.Dataset)):
                            candidates.append(obj)
                        if len(candidates) > 40: break
                except Exception:
                    pass

                if candidates: return choice(candidates)
                return parent_group_obj.file['/']  # Fallback to root


        """))
        self.parent.emptyLine()


    def _fuzz_one_dataset_instance(self, dset_expr_str: str, dset_name_for_log: str, prefix: str, generation_depth: int):
        """
        Generates code to perform a variety of fuzzed operations on a given h5py.Dataset instance.

        This method writes Python code that, at runtime in the generated script, will:
        1.  Attempt to access various properties of the dataset (shape, dtype, chunks, etc.).
        2.  Fuzz the dataset's AttributeManager by dispatching to `_dispatch_fuzz_on_instance`
            (handled by the parent `WritePythonCode` instance).
        3.  Call dataset methods like `.astype()`, `.asstr()`, `.fields()`, `.iter_chunks()`,
            `read_direct()`, and `write_direct()` with fuzzed arguments generated by
            `self.parent.arg_generator.h5py_argument_generator`.
        4.  Perform operations like iteration over the dataset, comparisons with fuzzed values,
            and advanced slicing using dynamically generated slice objects.
        5.  Attempt to trigger specific known h5py issue scenarios related to compound types,
            array dtypes, null dataspaces, large integer handling, and zero-size resizable datasets.
        6.  For results of operations that yield new h5py objects (e.g., `.astype()`), it will
            recursively call `self.parent._dispatch_fuzz_on_instance` to achieve "deep diving"
            fuzzing, up to a defined `generation_depth`.

        Args:
            dset_expr_str: Python expression string representing the dataset instance
                           in the generated script (e.g., "my_dataset_var").
            dset_name_for_log: A clean, human-readable name for the dataset, used in log messages.
            prefix: A string prefix used to generate unique variable names within the
                    generated script for this fuzzing operation.
            generation_depth: The current depth of recursive fuzzing calls. This is used
                              to limit how deep the fuzzer explores nested objects.
        """
        self.parent.write_print_to_stderr(0,
                                          f'f"--- Fuzzing Dataset Instance: {dset_name_for_log} (var: {dset_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()

        # --- Preamble: Get dataset context at runtime in generated script ---
        ctx_p = f"ctx_{prefix}"

        self.parent.write(0, f"{ctx_p}_target_dset = {dset_expr_str}")
        self.parent.write(0, f"if {ctx_p}_target_dset is not None:")
        L_main_if_dset_not_none = self.parent.addLevel(1)
        try:
            self.parent.write(0, f"{ctx_p}_shape = None")
            self.parent.write(0, f"{ctx_p}_dtype_str = None")
            self.parent.write(0, f"{ctx_p}_dtype_obj = None")
            self.parent.write(0, f"{ctx_p}_is_compound = False")
            self.parent.write(0, f"{ctx_p}_is_string_like = False")
            self.parent.write(0, f"{ctx_p}_is_chunked = False")
            self.parent.write(0, f"{ctx_p}_is_scalar = False")
            self.parent.write(0, f"{ctx_p}_rank = 0")
            self.parent.write(0, f"{ctx_p}_is_empty_dataspace = False")
            self.parent.write(0, f"{ctx_p}_actual_product_shape = 0")

            self.parent.write(0, f"try:")
            self.parent.addLevel(1)
            self.parent.write(0, f"{ctx_p}_shape = {ctx_p}_target_dset.shape")
            self.parent.write(0, f"{ctx_p}_dtype_obj = {ctx_p}_target_dset.dtype")
            self.parent.write(0, f"{ctx_p}_dtype_str = str({ctx_p}_dtype_obj)")
            self.parent.write(0, f"{ctx_p}_is_compound = {ctx_p}_dtype_obj.fields is not None")
            self.parent.write(0, f"{ctx_p}_is_string_like = 'S' in {ctx_p}_dtype_str or 'U' in {ctx_p}_dtype_str or \\")
            self.parent.write(1,
                              f"'string' in {ctx_p}_dtype_str or ('vlen' in {ctx_p}_dtype_str and ('str' in {ctx_p}_dtype_str or 'bytes' in {ctx_p}_dtype_str))")
            self.parent.write(0, f"{ctx_p}_is_chunked = {ctx_p}_target_dset.chunks is not None")
            self.parent.write(0, f"{ctx_p}_is_scalar = ({ctx_p}_shape == () )")
            self.parent.write(0, f"{ctx_p}_rank = len({ctx_p}_shape) if {ctx_p}_shape is not None else 0")
            self.parent.write(0,
                              f"if {ctx_p}_shape: {ctx_p}_actual_product_shape = numpy.prod({ctx_p}_shape) if {ctx_p}_shape else 0")  # product from h5py._hl.base previously, numpy is safer
            self.parent.write(0,
                              f"if hasattr(h5py._hl.base, 'is_empty_dataspace'): {ctx_p}_is_empty_dataspace = h5py._hl.base.is_empty_dataspace({ctx_p}_target_dset.id)")
            self.parent.write_print_to_stderr(0,
                                              f"f'''DS_OP_CTX ({dset_name_for_log}): Shape={{ {ctx_p}_shape }}, Dtype={{ {ctx_p}_dtype_str }}, Chunked={{ {ctx_p}_is_chunked }}, Scalar={{ {ctx_p}_is_scalar }}, ProductShape={{ {ctx_p}_actual_product_shape }}'''")
            self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
            self.parent.write(0,
                              f"except Exception as e_op_ctx: print(f'''DS_OP_CTX_ERR ({dset_name_for_log}): {{e_op_ctx}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            self.parent.write(0,
                              f"if {ctx_p}_target_dset is not None:")  # Original check was `if True:`, changed to be more robust
            L_valid_dataset = self.parent.addLevel(1)  # For operations on the valid dataset
            self.parent.write(0, "'INDENTED BLOCK IN CASE NO ISSUE CODE IS USED'")  # Placeholder comment
            # Fuzz .attrs
            if random() < 0.5:  # Chance to fuzz attributes
                self.parent.write(0, f"# Attempting to fuzz .attrs of {dset_name_for_log}")
                self.parent.write(0, "try:")
                L_attrs_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_attrs_obj = {ctx_p}_target_dset.attrs")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''DS_ATTRS_ACCESS ({dset_name_for_log}): Got .attrs object {{ {ctx_p}_attrs_obj!r }}. Dispatching fuzz.'''")
                    self.parent._dispatch_fuzz_on_instance(  # Call parent's dispatcher
                        current_prefix=f"{prefix}_attrs",
                        target_obj_expr_str=f"{ctx_p}_attrs_obj",
                        class_name_hint="AttributeManager",
                        generation_depth=generation_depth + 1
                    )
                finally:
                    self.parent.restoreLevel(L_attrs_try)
                self.parent.write(0,
                                  f"except Exception as e_attrs_access: print(f'''DS_ATTRS_ACCESS_ERR ({dset_name_for_log}): {{e_attrs_access}}''', file=sys.stderr)")
                self.parent.emptyLine()

            # Fuzz .astype() result
            if random() < 0.4:  # Chance to try astype
                self.parent.write(0, f"if {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")
                L_astype_outer_if = self.parent.addLevel(1)
                try:
                    astype_dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsTypeDtype_expr()
                    self.parent.write(0, "try:")
                    L_astype_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_astype_view = {ctx_p}_target_dset.astype({astype_dtype_expr})")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''DS_ASTYPE ({dset_name_for_log}): view created. Dispatching fuzz on view.'''")
                        self.parent._dispatch_fuzz_on_instance(  # Call parent's dispatcher
                            current_prefix=f"{prefix}_astype_view",
                            target_obj_expr_str=f"{ctx_p}_astype_view",
                            class_name_hint="AstypeWrapper",
                            generation_depth=generation_depth + 1
                        )
                    finally:
                        self.parent.restoreLevel(L_astype_try)
                    self.parent.write(0,
                                      f"except Exception as e_astype: print(f'''DS_ASTYPE_ERR ({dset_name_for_log}) with dtype {astype_dtype_expr}: {{e_astype}}''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_astype_outer_if)
                self.parent.emptyLine()

            # Issue 135: Compound Scalar Type Check
            if random() < 0.1:
                self.parent.write(0, f"if {ctx_p}_is_scalar and {ctx_p}_is_compound:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_item = {ctx_p}_target_dset[()]")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE135 ({dset_name_for_log}): Scalar compound item type {{type({ctx_p}_item).__name__}} (expected np.void for single element)'''")
                self.parent.write(0,
                                  f"assert isinstance({ctx_p}_item, numpy.void), f'Expected np.void, got {{type({ctx_p}_item)}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue135: print(f'''G_ISSUE135_ERR ({dset_name_for_log}): {{e_issue135}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Issue 211: Array Dtype Operations
            if random() < 0.2:
                self.parent.write(0, f"# Issue 211 checks for array dtypes")
                self.parent.write(0,
                                  f"if {ctx_p}_dtype_obj is not None and {ctx_p}_dtype_obj.subdtype is not None:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_base_dt_obj = {ctx_p}_dtype_obj.subdtype[0]")
                self.parent.write(0, f"{ctx_p}_el_shape_tuple = {ctx_p}_dtype_obj.subdtype[1]")
                self.parent.write(0, "# Test scalar assignment error (TypeError expected)")  # Comment from original
                self.parent.write(0, "try:")  # Corrected to be try for scalar assignment
                self.parent.addLevel(1)
                data_for_el_expr = self.parent.arg_generator.h5py_argument_generator.genArrayForArrayDtypeElement_expr(
                    f'{ctx_p}_el_shape_tuple',
                    f'{ctx_p}_base_dt_obj'
                )
                self.parent.write(0, f"{ctx_p}_data_for_el = {data_for_el_expr}")
                self.parent.write(0, f"if {ctx_p}_shape and {ctx_p}_actual_product_shape > 0:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_target_dset[0] = {ctx_p}_data_for_el")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE211_B ({dset_name_for_log}): Element write attempted with data of shape {{{ctx_p}_data_for_el.shape}}.'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue211b: print(f'''G_ISSUE211_B_ERR ({dset_name_for_log}): {{e_issue211b}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Issue #1475: Zero Storage Size for Empty/Null Dataspace Dataset
            if random() < 0.1:
                self.parent.write(0, f"if {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"storage_size = {ctx_p}_target_dset.id.get_storage_size()")
                self.parent.write(0, f"offset = {ctx_p}_target_dset.id.get_offset()")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE1475 ({dset_name_for_log}): Empty dataspace. Storage={{storage_size}}, Offset={{offset}} (expected 0 and None)'''")
                self.parent.write(0, "assert storage_size == 0, 'Storage size non-zero for empty dataspace'")
                self.parent.write(0, "assert offset is None, 'Offset not None for empty dataspace'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue1475: print(f'''G_ISSUE1475_ERR ({dset_name_for_log}): {{e_issue1475}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Issue #1547: Large Python Int to uint64 Dataset
            if random() < 0.1:
                self.parent.write(0, f"if {ctx_p}_dtype_str == 'uint64':")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                large_int_expr = self.parent.arg_generator.h5py_argument_generator.genLargePythonInt_expr()
                self.parent.write(0, f"val_to_write = {large_int_expr}")
                self.parent.write(0,
                                  f"idx_to_write = randint(0, {ctx_p}_shape[0]-1) if {ctx_p}_shape and {ctx_p}_shape[0]>0 else 0")
                self.parent.write(0,
                                  f"if {ctx_p}_shape and {ctx_p}_actual_product_shape > 0 : {ctx_p}_target_dset[idx_to_write] = val_to_write")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE1547 ({dset_name_for_log}): Wrote {{val_to_write}} to uint64 dataset at index {{idx_to_write}}'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue1547: print(f'''G_ISSUE1547_ERR ({dset_name_for_log}): {{e_issue1547}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Issue #2549: Write to Zero-Size Resizable Dataset
            if random() < 0.1:
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                                  f"if {ctx_p}_shape and {ctx_p}_actual_product_shape == 0 and {ctx_p}_target_dset.maxshape is not None:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"# Attempt write before resize (might be error or no-op)")
                self.parent.write(0, f"{ctx_p}_target_dset[()] = 0")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE2549 ({dset_name_for_log}): Attempted write to initially zero-size resizable dataset.'''")
                self.parent.write(0, f"# Now resize and write")
                new_len = randint(1, 5)
                self.parent.write(0, f"new_shape_tuple_parts = ({new_len},) + ({ctx_p}_shape[1:] if {ctx_p}_rank > 1 else ())")
                self.parent.write(0, f"new_shape_for_resize = new_shape_tuple_parts")
                self.parent.write(0, f"{ctx_p}_target_dset.resize(new_shape_for_resize)")
                self.parent.write(0,
                                  f"data_for_resize = numpy.arange(numpy.prod(new_shape_for_resize), dtype={ctx_p}_dtype_obj).reshape(new_shape_for_resize)")
                self.parent.write(0, f"{ctx_p}_target_dset[...] = data_for_resize")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''G_ISSUE2549 ({dset_name_for_log}): Resized to {{new_shape_for_resize}} and wrote data.'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue2549_ops: print(f'''G_ISSUE2549_OPS_ERR ({dset_name_for_log}): {{e_issue2549_ops}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_issue2549_setup: print(f'''G_ISSUE2549_SETUP_ERR ({dset_name_for_log}): {{e_issue2549_setup}}''', file=sys.stderr)")
                self.parent.emptyLine()

            # Advanced Slicing Operations
            if random() < 0.5 and f"{ctx_p}_shape is not None":
                self.parent.write(0, "# --- Advanced Slicing Attempt ---")
                dset_fields_keys_expr = f"list({ctx_p}_dtype_obj.fields.keys()) if {ctx_p}_is_compound and {ctx_p}_dtype_obj.fields else []"
                self.parent.write(0, f"try: {ctx_p}_dset_fields_keys = {dset_fields_keys_expr}")
                self.parent.write(0, f"except Exception: {ctx_p}_dset_fields_keys = []")
                adv_slice_arg_expr = self.parent.arg_generator.h5py_argument_generator.genAdvancedSliceArgument_expr(
                    f"{ctx_p}_target_dset", f"{ctx_p}_rank", f"{ctx_p}_dset_fields_keys"
                )
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_adv_slice_obj = {adv_slice_arg_expr}")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ADV_SLICE ({dset_name_for_log}): Attempting slice with {{repr({ctx_p}_adv_slice_obj)}}'''")
                # Read attempt
                self.parent.write(0, f"if not {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_read_data = {ctx_p}_target_dset[{ctx_p}_adv_slice_obj]")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ADV_SLICE_READ ({dset_name_for_log}): Sliced data shape {{getattr({ctx_p}_read_data, \"shape\", \"N/A\")}}'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                # Write attempt
                self.parent.write(0,
                                  f"if not {ctx_p}_is_empty_dataspace and hasattr({ctx_p}_target_dset, 'readonly') and not {ctx_p}_target_dset.readonly:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_data_for_write = None")
                self.parent.write(0,
                                  f"if hasattr({ctx_p}_read_data, 'shape') and hasattr({ctx_p}_read_data, 'dtype'):")
                self.parent.addLevel(1)
                self.parent.write(0,
                                  f"if numpy.prod(getattr({ctx_p}_read_data, 'shape', (0,))) > 0:")  # Corrected product usage
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_data_for_write = numpy.zeros_like({ctx_p}_read_data)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ADV_SLICE_WRITE ({dset_name_for_log}): Generated zeros_like data with shape {{{ctx_p}_data_for_write.shape}}'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0, f"elif {ctx_p}_dtype_obj is not None:")
                self.parent.addLevel(1)
                self.parent.write(0,
                                  f"{ctx_p}_data_for_write = numpy.array(0, dtype={ctx_p}_dtype_obj).item() if {ctx_p}_dtype_obj.kind not in 'SUOV' else (b'' if {ctx_p}_dtype_obj.kind == 'S' else '')")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ADV_SLICE_WRITE ({dset_name_for_log}): Generated scalar data {{{ctx_p}_data_for_write!r}}'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0, f"if {ctx_p}_data_for_write is not None:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_target_dset[{ctx_p}_adv_slice_obj] = {ctx_p}_data_for_write")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ADV_SLICE_WRITE ({dset_name_for_log}): Write attempted with data {{{ctx_p}_data_for_write!r}}'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_adv_write: print(f'''DS_ADV_SLICE_WRITE_ERR ({dset_name_for_log}) for slice {{{ctx_p}_adv_slice_obj!r}}: {{e_adv_write}}''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_adv_slice: print(f'''DS_ADV_SLICE_ERR ({dset_name_for_log}) with slice obj {{repr(locals().get('{ctx_p}_adv_slice_obj', 'ERROR_GETTING_SLICE_OBJ'))}}: {{e_adv_slice}}''', file=sys.stderr)")
                self.parent.emptyLine()

            # Standard Properties and Operations
            properties_to_access = ["name", "shape", "dtype", "size", "chunks", "compression",
                                    "compression_opts", "fillvalue", "shuffle", "fletcher32",
                                    "scaleoffset", "maxshape", "file", "parent"]
            for prop_name in properties_to_access:
                self.parent.write(0,
                                  f"try: print(f'''DS_PROP ({dset_name_for_log}): .{prop_name} = {{repr(getattr({ctx_p}_target_dset, '{prop_name}'))}} ''', file=sys.stderr)")
                self.parent.write(0,
                                  f"except Exception as e_prop: print(f'''DS_PROP_ERR ({dset_name_for_log}) .{prop_name}: {{e_prop}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            # len(), repr()
            self.parent.write(0,
                              f"try: print(f'''DS_LEN ({dset_name_for_log}): len = {{len({ctx_p}_target_dset)}} ''', file=sys.stderr)")
            self.parent.write(0,
                              f"except Exception as e_len: print(f'''DS_LEN_ERR ({dset_name_for_log}): {{e_len}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            self.parent.write(0,
                              f"try: print(f'''DS_REPR ({dset_name_for_log}): repr = {{repr({ctx_p}_target_dset)}} ''', file=sys.stderr)")
            self.parent.write(0,
                              f"except Exception as e_repr_op: print(f'''DS_REPR_ERR ({dset_name_for_log}): {{e_repr_op}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            # Call .astype()
            if random() < 0.4:  # Chance to try astype
                astype_dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsTypeDtype_expr()
                self.parent.write(0,
                           f"if {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")  # Astype on empty might be problematic or less interesting for now
                self.parent.addLevel(1)
                self.parent.write(0, f"try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_astype_view = {ctx_p}_target_dset.astype({astype_dtype_expr})")
                escaped_astype_dtype_expr = "{" + astype_dtype_expr + "}"
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASTYPE ({dset_name_for_log}): view created with dtype {escaped_astype_dtype_expr}. View repr: {{repr({ctx_p}_astype_view)}} '''")
                self.parent.write(0,
                           f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0 :")  # product from h5py._hl.base
                self.parent.addLevel(1)
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASTYPE ({dset_name_for_log}): first elem = {{repr({ctx_p}_astype_view[tuple(0 for _ in range({ctx_p}_rank))])}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if not scalar
                self.parent.write(0,
                           f"{ctx_p}_arr_from_astype = numpy.array({ctx_p}_astype_view)")  # Try converting to numpy array
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASTYPE ({dset_name_for_log}): converted to numpy array with shape {{ {ctx_p}_arr_from_astype.shape }} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for astype
                self.parent.write(0,
                           f"except Exception as e_astype: print(f'''DS_ASTYPE_ERR ({dset_name_for_log}) with dtype {escaped_astype_dtype_expr}: {{e_astype}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if shape is not None
            self.parent.emptyLine()

            # .asstr()
            if random() < 0.4:
                self.parent.write(0,
                                  f"if {ctx_p}_is_string_like and {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                asstr_enc_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsStrEncoding_expr()
                asstr_err_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsStrErrors_expr()
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                                  f"{ctx_p}_asstr_view = {ctx_p}_target_dset.asstr(encoding={asstr_enc_expr}, errors={asstr_err_expr})")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ASSTR ({dset_name_for_log}): view created with enc {asstr_enc_expr}, err {asstr_err_expr}. View repr: {{repr({ctx_p}_asstr_view)}} '''")
                self.parent.write(0,
                                  f"if not {ctx_p}_is_scalar and {ctx_p}_shape and numpy.prod({ctx_p}_shape if {ctx_p}_shape else (0,)) > 0:")  # Corrected numpy.prod
                self.parent.addLevel(1)
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ASSTR ({dset_name_for_log}): first elem = {{repr({ctx_p}_asstr_view[tuple(0 for _ in range({ctx_p}_rank))])}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0, f"{ctx_p}_arr_from_asstr = numpy.array({ctx_p}_asstr_view)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ASSTR ({dset_name_for_log}): converted to numpy array with shape {{ {ctx_p}_arr_from_asstr.shape }} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_asstr: print(f'''DS_ASSTR_ERR ({dset_name_for_log}) with enc {asstr_enc_expr}: {{e_asstr}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.emptyLine()

            # .fields()
            if random() < 0.3:
                self.parent.write(0,
                                  f"if {ctx_p}_is_compound and {ctx_p}_dtype_obj is not None and {ctx_p}_dtype_obj.fields:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"field_names_tuple = tuple({ctx_p}_dtype_obj.fields.keys())")
                self.parent.write(0, f"if field_names_tuple:")
                self.parent.addLevel(1)
                self.parent.write(0, f"field_to_access = choice(field_names_tuple)")
                self.parent.write(0,
                                  f"if random() < 0.5: field_to_access = list(sample(field_names_tuple, k=min(len(field_names_tuple), randint(1,2))))")
                self.parent.write(0, f"{ctx_p}_fields_view = {ctx_p}_target_dset.fields(field_to_access)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_FIELDS ({dset_name_for_log}): view for {{field_to_access}}. View repr: {{repr({ctx_p}_fields_view)}} '''")
                self.parent.write(0,
                                  f"if not {ctx_p}_is_scalar and {ctx_p}_shape and numpy.prod({ctx_p}_shape if {ctx_p}_shape else (0,)) > 0:")  # Corrected numpy.prod
                self.parent.addLevel(1)
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_FIELDS ({dset_name_for_log}): first elem = {{repr({ctx_p}_fields_view[tuple(0 for _ in range({ctx_p}_rank))])}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_fields: print(f'''DS_FIELDS_ERR ({dset_name_for_log}): {{e_fields}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.emptyLine()

            # .iter_chunks()
            if random() < 0.3:
                self.parent.write(0,
                                  f"if {ctx_p}_is_chunked and not {ctx_p}_is_empty_dataspace and {ctx_p}_rank is not None:")
                self.parent.addLevel(1)
                sel_expr_iter = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(
                    f"{ctx_p}_rank")
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_selection_for_iter_chunks = {sel_expr_iter}")
                self.parent.write(0, f"{ctx_p}_chunk_count = 0")
                self.parent.write(0,
                                  f"for {ctx_p}_chunk_slice in {ctx_p}_target_dset.iter_chunks({ctx_p}_selection_for_iter_chunks if {ctx_p}_selection_for_iter_chunks is not None else None):")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_chunk_count += 1")
                self.parent.write(0,
                                  f"if {ctx_p}_chunk_count % 10 == 0: print(f'''DS_ITER_CHUNKS ({dset_name_for_log}): processed {{ {ctx_p}_chunk_count }} chunks...''', file=sys.stderr)")
                self.parent.write(0, f"if {ctx_p}_chunk_count > {randint(5, 20)}: break")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_ITER_CHUNKS ({dset_name_for_log}): iterated {{ {ctx_p}_chunk_count }} chunks for selection {{{ctx_p}_selection_for_iter_chunks!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_iterchunks: print(f'''DS_ITER_CHUNKS_ERR ({dset_name_for_log}): {{e_iterchunks}} for selection {{{ctx_p}_selection_for_iter_chunks!r}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.emptyLine()

            # read_direct / write_direct
            if random() < 0.5 and not ctx_p + "_is_empty_dataspace" and f"{ctx_p}_rank is not None":
                self.parent.write(0,
                                  f"if {ctx_p}_shape is not None and numpy.prod({ctx_p}_shape if {ctx_p}_shape else (0,)) > 0 and numpy.prod({ctx_p}_shape if {ctx_p}_shape else (0,)) < 1000:")  # Corrected numpy.prod
                self.parent.addLevel(1)
                self.parent.write(0, "try:")  # Outer try
                self.parent.addLevel(1)
                source_sel_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(
                    f"{ctx_p}_rank")
                dest_sel_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(
                    f"{ctx_p}_rank")
                self.parent.write(0, f"{ctx_p}_source_sel = {source_sel_expr}")
                self.parent.write(0, f"{ctx_p}_dest_sel = {dest_sel_expr}")
                # Read direct
                self.parent.write(0, f"# For read_direct, np_arr_for_rd is destination")
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_np_arr_for_rd = numpy.empty(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")
                self.parent.write(0,
                                  f"{ctx_p}_target_dset.read_direct({ctx_p}_np_arr_for_rd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_READ_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_readdirect: print(f'''DS_READ_DIRECT_ERR ({dset_name_for_log}): {{e_readdirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} ''', file=sys.stderr)")
                # Write direct
                self.parent.write(0, f"# For write_direct, np_arr_for_wd is source")
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_np_arr_for_wd = numpy.zeros(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")
                self.parent.write(0,
                                  f"{ctx_p}_target_dset.write_direct({ctx_p}_np_arr_for_wd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_WRITE_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_writedirect: print(f'''DS_WRITE_DIRECT_ERR ({dset_name_for_log}): {{e_writedirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit outer try
                self.parent.write(0,
                                  f"except Exception as e_direct_io_setup: print(f'''DS_DIRECT_IO_SETUP_ERR ({dset_name_for_log}): {{e_direct_io_setup}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if shape is small


            self.parent.emptyLine()

            # Fancy indexing setitem
            if random() < 0.15:
                self.parent.write(0, f"if {ctx_p}_rank >= 2 and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and {ctx_p}_shape[1] > 2:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                                  f"{ctx_p}_fancy_indices = sorted(sample(range({ctx_p}_shape[1]), k=min({ctx_p}_shape[1], randint(1,3))))")
                self.parent.write(0, f"{ctx_p}_block_shape = list({ctx_p}_shape)")
                self.parent.write(0, f"{ctx_p}_block_shape[1] = len({ctx_p}_fancy_indices)")
                self.parent.write(0, f"{ctx_p}_block_data = numpy.zeros(tuple({ctx_p}_block_shape), dtype={ctx_p}_dtype_obj)")
                self.parent.write(0, f"{ctx_p}_target_dset[:, {ctx_p}_fancy_indices, ...] = {ctx_p}_block_data")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_FANCY_SETITEM ({dset_name_for_log}): success with indices {{{ctx_p}_fancy_indices}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_fancyitem: print(f'''DS_FANCY_SETITEM_ERR ({dset_name_for_log}): {{e_fancyitem}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Iteration
            if random() < 0.3:
                self.parent.write(0,
                                  f"if not {ctx_p}_is_scalar and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and not {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_iter_count = 0")
                self.parent.write(0, f"for {ctx_p}_row in {ctx_p}_target_dset:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_iter_count += 1")
                self.parent.write(0, f"if {ctx_p}_iter_count > {randint(3, 7)}: break")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write_print_to_stderr(0, f"f'''DS_ITER ({dset_name_for_log}): iterated {{{ctx_p}_iter_count}} rows'''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_iter: print(f'''DS_ITER_ERR ({dset_name_for_log}): {{e_iter}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # Comparisons
            if random() < 0.3:
                comp_val_expr = self.parent.arg_generator.h5py_argument_generator.genNumpyValueForComparison_expr(
                    f"{ctx_p}_dtype_str")
                self.parent.write(0, f"if {ctx_p}_dtype_str is not None:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_comp_val = {comp_val_expr}")
                self.parent.write(0, f"{ctx_p}_is_equal = ({ctx_p}_target_dset == {ctx_p}_comp_val)")
                self.parent.write(0, f"{ctx_p}_is_not_equal = ({ctx_p}_target_dset != {ctx_p}_comp_val)")
                self.parent.write_print_to_stderr(0,
                                                  f"f'''DS_COMPARE ({dset_name_for_log}): == type {{type({ctx_p}_is_equal).__name__}}, != type {{type({ctx_p}_is_not_equal).__name__}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                                  f"except Exception as e_compare: print(f'''DS_COMPARE_ERR ({dset_name_for_log}): {{e_compare}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # .id properties
            if random() < 0.2:
                id_props_to_get = ["get_type()", "get_create_plist()", "get_access_plist()", "get_offset()", "get_storage_size()"]
                for id_prop_call in id_props_to_get:
                    self.parent.write(0,
                                      f"try: print(f'''DS_ID_PROP ({dset_name_for_log}): .id.{id_prop_call} result = {{repr({ctx_p}_target_dset.id.{id_prop_call})}} ''', file=sys.stderr)")
                    self.parent.write(0,
                                      f"except Exception as e_id_prop: print(f'''DS_ID_PROP_ERR ({dset_name_for_log}) .id.{id_prop_call}: {{e_id_prop}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            self.parent.restoreLevel(L_main_if_dset_not_none)
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                f'f"Skipping dataset operations for {dset_name_for_log} as target_dset is None."')
        finally:
            self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.emptyLine()


    def _fuzz_one_file_instance(self, file_expr_str: str, file_name_for_log: str, prefix: str, generation_depth: int):
        """
        Generates fuzzed operations for an h5py.File instance.

        This includes accessing attributes, iterating over root group items,
        creating new datasets and groups (with subsequent deep dives on the created
        objects via `self.parent._dispatch_fuzz_on_instance`), accessing existing items,
        using `require_group`/`require_dataset`, toggling SWMR mode, flushing,
        and (with low probability) closing the file.

        Args:
            file_expr_str: Python expression string for the File instance.
            file_name_for_log: A clean name for logging.
            prefix: A prefix for generating unique variable names.
            generation_depth: Current recursion depth for fuzzing.
        """
        self.parent.write_print_to_stderr(0,
                                          f'f"--- (Depth {generation_depth}) Fuzzing File Instance: {file_name_for_log} (var: {file_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()

        ctx_p = f"ctx_{prefix}_file"
        self.parent.write(0, f"{ctx_p}_target_file = {file_expr_str}")
        self.parent.write(0,
                          f"if {ctx_p}_target_file is not None and hasattr({ctx_p}_target_file, 'id') and {ctx_p}_target_file.id and {ctx_p}_target_file.id.valid:")
        L_main_if_file_valid = self.parent.addLevel(1)
        try:
            file_properties = ["filename", "driver", "libver", "userblock_size", "mode", "swmr_mode", "name", "parent",
                               "attrs"]
            for prop_name in file_properties:
                self.parent.write(0, "try:")
                L_prop_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_prop_val = getattr({ctx_p}_target_file, '{prop_name}')")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''FILE_PROP ({file_name_for_log}): .{prop_name} = {{{ctx_p}_prop_val!r}}'''")
                    if prop_name == "attrs":
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_attrs", f"{ctx_p}_prop_val", "AttributeManager",
                                                               generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_prop_try)
                self.parent.write(0,
                                  f"except Exception as e_prop: print(f'''FILE_PROP_ERR ({file_name_for_log}) .{prop_name}: {{e_prop}}''', file=sys.stderr)")
            self.parent.emptyLine()

            if random() < 0.5:  # Iterate keys, values, items
                self.parent.write(0, "try:")
                L_iter_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_file_len = len({ctx_p}_target_file)")
                    self.parent.write_print_to_stderr(0, f"f'''FILE_LEN ({file_name_for_log}): len = {{{ctx_p}_file_len}}'''")
                    if self.parent.base_level > 0:  # Check to prevent negative indentation on restore
                        self.parent.write(0, f"if {ctx_p}_file_len > 0:")
                        L_iter_if_not_empty = self.parent.addLevel(1)
                        try:
                            self.parent.write(0, f"{ctx_p}_iter_count = 0")
                            self.parent.write(0, f"for {ctx_p}_key in {ctx_p}_target_file:")
                            L_iter_for = self.parent.addLevel(1)
                            try:
                                self.parent.write_print_to_stderr(0,
                                                                  f"f'''FILE_ITER ({file_name_for_log}): key = {{{ctx_p}_key!r}}'''")
                                self.parent.write(0, f"{ctx_p}_iter_count += 1")
                                self.parent.write(0, f"if {ctx_p}_iter_count > 5: break")
                            finally:
                                self.parent.restoreLevel(L_iter_for)
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''FILE_ITER ({file_name_for_log}): iterated {{{ctx_p}_iter_count}} keys'''")
                            self.parent.write(0, f"{ctx_p}_keys_view = {ctx_p}_target_file.keys()")
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''FILE_KEYS ({file_name_for_log}): {{len({ctx_p}_keys_view)}} keys, e.g., {{list({ctx_p}_keys_view)[:3]!r}}'''")
                        finally:
                            self.parent.restoreLevel(L_iter_if_not_empty)
                finally:
                    self.parent.restoreLevel(L_iter_try)
                self.parent.write(0,
                                  "except Exception as e_file_iter: print(f'''FILE_ITER_METHODS_ERR ({file_name_for_log}): {{e_file_iter}}''', file=sys.stderr)")
                self.parent.emptyLine()

            if random() < 0.3:  # Create Dataset
                ds_name_expr = f"'{_h5_unique_name(f'ds_{prefix}')}'"
                ds_instance_var = f"{prefix}_new_ds_in_file"
                self.parent.write(0, f"{ds_instance_var} = None")
                self._write_h5py_dataset_creation_call(f"{ctx_p}_target_file", ds_name_expr, ds_instance_var)
                self.parent.write(0, f"if {ds_instance_var} is not None:")
                L_dd_ds = self.parent.addLevel(1)
                try:
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_ds", ds_instance_var, "Dataset",
                                                           generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_dd_ds)

            if random() < 0.3:  # Create Group
                new_grp_name_expr = f"'{_h5_unique_name(f'grp_{prefix}')}'"
                new_grp_var = f"{prefix}_new_grp_in_file"
                self.parent.write(0, f"{new_grp_var} = None")
                self.parent.write(0, "try:")
                L_cgrp_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{new_grp_var} = {ctx_p}_target_file.create_group({new_grp_name_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''FILE_OP ({file_name_for_log}): Created group {new_grp_name_expr} as {{{new_grp_var!r}}} '''")
                    self.parent.write(0, f"if {new_grp_var} is not None:")
                    L_dd_grp = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"h5py_runtime_objects[{new_grp_name_expr.strip("'")}] = {new_grp_var}")
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_grp", new_grp_var, "Group",
                                          generation_depth + 1)
                    finally:
                        self.parent.restoreLevel(L_dd_grp)
                finally:
                    self.parent.restoreLevel(L_cgrp_try)
                self.parent.write(0,
                                  f"except Exception as e_cgrp_file: print(f'''FILE_OP_ERR ({file_name_for_log}) creating group {new_grp_name_expr}: {{e_cgrp_file}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            if random() < 0.4:  # Access existing item
                self.parent.write(0, f"if len({ctx_p}_target_file) > 0:")
                L_access_item_if = self.parent.addLevel(1)
                try:
                    self.parent.write(0, "try:")
                    L_access_item_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_item_to_access_name = choice(list({ctx_p}_target_file.keys()))")
                        self.parent.write(0,
                                          f"{ctx_p}_resolved_top_item = {ctx_p}_target_file[{ctx_p}_item_to_access_name]")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''FILE_OP ({file_name_for_log}): Accessed top-level item {{{ctx_p}_item_to_access_name!r}}: {{{ctx_p}_resolved_top_item!r}} '''")
                        self.parent.write(0,
                                          f"{ctx_p}_resolved_top_item_type_name = type({ctx_p}_resolved_top_item).__name__")
                        self.parent.write(0,
                                          f"if isinstance({ctx_p}_resolved_top_item, (h5py.Group, h5py.Dataset, h5py.AttributeManager)):")
                        L_access_if_fuzzable = self.parent.addLevel(1)
                        try:
                            self.parent._dispatch_fuzz_on_instance(
                                f"{prefix}_resolved_top_{str(uuid.uuid4())[:4]}",
                                f"{ctx_p}_resolved_top_item",
                                f"{ctx_p}_resolved_top_item_type_name",
                                generation_depth + 1
                            )
                        finally:
                            self.parent.restoreLevel(L_access_if_fuzzable)
                    finally:
                        self.parent.restoreLevel(L_access_item_try)
                    self.parent.write(0,
                                      f"except Exception as e_access_top_item: print(f'''FILE_OP_ERR ({file_name_for_log}) accessing top-level item: {{e_access_top_item}} ''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_access_item_if)
                self.parent.emptyLine()

            if random() < 0.3:  # require_group
                req_grp_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                self.parent.write(0, "try:")
                L_req_grp_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_req_grp = {ctx_p}_target_file.require_group({req_grp_name_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''FILE_OP ({file_name_for_log}): require_group {req_grp_name_expr} -> {{{ctx_p}_req_grp!r}} '''")
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_req_grp", f"{ctx_p}_req_grp", "Group",
                                                           generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_req_grp_try)
                self.parent.write(0,
                                  f"except Exception as e_reqg_file: print(f'''FILE_OP_ERR ({file_name_for_log}) require_group {req_grp_name_expr}: {{e_reqg_file}} ''', file=sys.stderr)")

            if random() < 0.3:  # require_dataset
                req_ds_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                req_ds_shape_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
                req_ds_dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()
                req_ds_exact_expr = choice(["True", "False"])
                self.parent.write(0, "try:")
                L_req_ds_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0,
                                      f"{ctx_p}_req_ds = {ctx_p}_target_file.require_dataset({req_ds_name_expr}, shape={req_ds_shape_expr}, dtype={req_ds_dtype_expr}, exact={req_ds_exact_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''FILE_OP ({file_name_for_log}): require_dataset {req_ds_name_expr} -> {{{ctx_p}_req_ds!r}} '''")
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_req_ds", f"{ctx_p}_req_ds", "Dataset",
                                                           generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_req_ds_try)
                self.parent.write(0,
                                  f"except Exception as e_reqd_file: print(f'''FILE_OP_ERR ({file_name_for_log}) require_dataset {req_ds_name_expr}: {{e_reqd_file}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            if random() < 0.1:  # SWMR mode
                self.parent.write(0,
                                  f"if getattr({ctx_p}_target_file, 'libver', ('earliest','earliest'))[1] in ('latest', 'v110', 'v112', 'v114'):")
                L_swmr_if = self.parent.addLevel(1)
                try:
                    self.parent.write(0, "try:")
                    L_swmr_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_target_file.swmr_mode = True")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''FILE_OP ({file_name_for_log}): Set swmr_mode=True. Current: {{{ctx_p}_target_file.swmr_mode}} '''")
                    finally:
                        self.parent.restoreLevel(L_swmr_try)
                    self.parent.write(0,
                                      f"except Exception as e_swmr: print(f'''FILE_OP_ERR ({file_name_for_log}) setting swmr_mode: {{e_swmr}} ''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_swmr_if)
                self.parent.emptyLine()

            if random() < 0.2:  # Flush
                self.parent.write(0, "try:")
                L_flush_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_target_file.flush()")
                    self.parent.write_print_to_stderr(0, f"f'''FILE_OP ({file_name_for_log}): Flushed file.'''")
                finally:
                    self.parent.restoreLevel(L_flush_try)
                self.parent.write(0,
                                  f"except Exception as e_flush: print(f'''FILE_OP_ERR ({file_name_for_log}) flushing file: {{e_flush}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            if random() < 0.02:  # Close
                self.parent.write(0, "try:")
                L_close_try = self.parent.addLevel(1)
                try:
                    self.parent.write_print_to_stderr(0, f"f'''FILE_OP ({file_name_for_log}): Attempting to close file.'''")
                    self.parent.write(0, f"{ctx_p}_target_file.close()")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''FILE_OP ({file_name_for_log}): File closed. Valid: {{{ctx_p}_target_file.id.valid if hasattr({ctx_p}_target_file, 'id') and {ctx_p}_target_file.id else 'N/A'}} '''")
                finally:
                    self.parent.restoreLevel(L_close_try)
                self.parent.write(0,
                                  f"except Exception as e_close: print(f'''FILE_OP_ERR ({file_name_for_log}) closing file: {{e_close}} ''', file=sys.stderr)")
                self.parent.emptyLine()
        finally:
            self.parent.restoreLevel(L_main_if_file_valid)
        self.parent.write(0, "else:")
        L_else_file_invalid = self.parent.addLevel(1)
        try:
            self.parent.write_print_to_stderr(0,
                                              f'f"Skipping file operations for {file_name_for_log} as its variable ({file_expr_str}) is None or closed."')
        finally:
            self.parent.restoreLevel(L_else_file_invalid)
        self.parent.emptyLine()

    def _fuzz_one_group_instance(self, group_expr_str: str, group_name_for_log: str, prefix: str,
                                 generation_depth: int):
        """
        Generates fuzzed operations for an h5py.Group instance.

        This method writes Python code to interact with the specified h5py Group object
        in the generated fuzzing script. Operations include:
        1.  Accessing basic group properties (name, file, parent, attributes).
        2.  Fuzzing the group's AttributeManager via `_dispatch_fuzz_on_instance`.
        3.  Iterating over group members (keys, values, items).
        4.  Creating new child h5py.Dataset and h5py.Group objects within this group,
            using fuzzed parameters, and then recursively calling
            `self.parent._dispatch_fuzz_on_instance` to fuzz these new children.
        5.  Creating various types of links (SoftLink, ExternalLink, HardLink) with
            fuzzed names and targets.
        6.  Attempting to access and resolve existing items (including links) within
            the group, and if the resolved item is a Group or Dataset, dispatching
            further fuzzing on it.
        7.  Calling `require_group` and `require_dataset` with fuzzed parameters.

        Args:
            group_expr_str: Python expression string representing the group instance
                           in the generated script (e.g., "my_group_var").
            group_name_for_log: A clean, human-readable name for the group, used in log messages.
            prefix: A string prefix used to generate unique variable names within the
                    generated script for this fuzzing operation.
            generation_depth: The current depth of recursive fuzzing calls, used to
                              limit how deeply the fuzzer explores nested objects.
        """
        self.parent.write_print_to_stderr(0,
                                          f'f"--- (Depth {generation_depth}) Fuzzing Group Instance: {group_name_for_log} (var: {group_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()

        ctx_p = f"ctx_{prefix}_grp"  # Unique context prefix for this group fuzzing operation

        self.parent.write(0, f"{ctx_p}_target_grp = {group_expr_str}")
        self.parent.write(0,
                          f"if {ctx_p}_target_grp is not None and isinstance({ctx_p}_target_grp, h5py.Group):")  # Ensure it's a group
        # ---- BLOCK: Main if target_grp is not None and is Group ----
        L_main_if_grp_valid = self.parent.addLevel(1)
        try:
            # --- Basic Group Properties & Methods ---
            group_properties = ["name", "file", "parent", "attrs"]
            for prop_name in group_properties:
                self.parent.write(0, "try:")
                L_prop_try = self.parent.addLevel(1)
                try:
                    # Changed to use f-string directly for evaluated property
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_PROP ({group_name_for_log}): .{prop_name} = {{repr(getattr({ctx_p}_target_grp, '{prop_name}'))}}'''")
                    # Deep dive into .attrs
                    if prop_name == "attrs":
                        self.parent.write(0, f"{ctx_p}_attrs_obj = {ctx_p}_target_grp.attrs")
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_attrs", f"{ctx_p}_attrs_obj",
                                                               "AttributeManager",
                                                               generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_prop_try)
                self.parent.write(0,
                                  f"except Exception as e_prop: print(f'''GRP_PROP_ERR ({group_name_for_log}) .{prop_name}: {{e_prop}}''', file=sys.stderr)")
            self.parent.emptyLine()

            self.parent.write(0, "try:")
            L_len_try = self.parent.addLevel(1)
            try:
                self.parent.write_print_to_stderr(0,
                                                  f"f'''GRP_LEN ({group_name_for_log}): len = {{len({ctx_p}_target_grp)}}'''")
            finally:
                self.parent.restoreLevel(L_len_try)
            self.parent.write(0,
                              f"except Exception as e_len: print(f'''GRP_LEN_ERR ({group_name_for_log}): {{e_len}}''', file=sys.stderr)")
            self.parent.emptyLine()

            if random() < 0.5:
                self.parent.write(0, "try:")
                L_iter_methods_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_iter_count = 0")
                    self.parent.write(0, f"for {ctx_p}_key in {ctx_p}_target_grp:")
                    L_iter_for = self.parent.addLevel(1)
                    try:
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''GRP_ITER ({group_name_for_log}): key = {{{ctx_p}_key!r}}'''")
                        self.parent.write(0, f"{ctx_p}_iter_count += 1")
                        self.parent.write(0, f"if {ctx_p}_iter_count > 5: break")
                    finally:
                        self.parent.restoreLevel(L_iter_for)
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_ITER ({group_name_for_log}): iterated {{{ctx_p}_iter_count}} keys'''")

                    self.parent.write(0, f"{ctx_p}_keys_view = {ctx_p}_target_grp.keys()")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_KEYS ({group_name_for_log}): {{len({ctx_p}_keys_view)}} keys, e.g., {{list({ctx_p}_keys_view)[:3]!r}}'''")
                    # Values and Items can be added similarly if desired, for now focusing on keys and general iter
                finally:
                    self.parent.restoreLevel(L_iter_methods_try)
                self.parent.write(0,
                                  f"except Exception as e_grp_iter: print(f'''GRP_ITER_METHODS_ERR ({group_name_for_log}): {{e_grp_iter}}''', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Create Children (Dataset, Group) with deep dive ---
            if random() < 0.4:  # Dynamic Dataset
                ds_name_expr = f"'{_h5_unique_name(f'ds_in_grp_{prefix}')}'"
                ds_instance_var = f"{prefix}_new_ds_in_grp"
                self.parent.write(0, f"{ds_instance_var} = None")  # Initialize
                # Call _write_h5py_dataset_creation_call from the h5py_writer attribute of the parent
                self.parent.h5py_writer._write_h5py_dataset_creation_call(f"{ctx_p}_target_grp", ds_name_expr,
                                                                          ds_instance_var)
                self.parent.write(0, f"if {ds_instance_var} is not None:")
                L_dd_ds = self.parent.addLevel(1)
                try:
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_ds_grp", ds_instance_var, "Dataset",
                                                           generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_dd_ds)

            if random() < 0.3:  # Dynamic Group
                new_grp_name_expr = f"'{_h5_unique_name(f'subgrp_{prefix}')}'"
                new_grp_var = f"{prefix}_new_subgrp_in_grp"
                self.parent.write(0, f"{new_grp_var} = None")  # Initialize
                self.parent.write(0, "try:")
                L_cgrp_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{new_grp_var} = {ctx_p}_target_grp.create_group({new_grp_name_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_OP ({group_name_for_log}): Created subgroup {new_grp_name_expr} as {{{new_grp_var!r}}} '''")
                    self.parent.write(0, f"if {new_grp_var} is not None:")
                    L_dd_grp = self.parent.addLevel(1)
                    try:
                        self.parent.write(0,
                                          f"h5py_runtime_objects[{new_grp_name_expr.strip("'")}] = {new_grp_var}")
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_grp", new_grp_var,
                                          "Group",
                                          generation_depth + 1)
                    finally:
                        self.parent.restoreLevel(L_dd_grp)
                finally:
                    self.parent.restoreLevel(L_cgrp_try)
                self.parent.write(0,
                                  f"except Exception as e_cgrp: print(f'''GRP_OP_ERR ({group_name_for_log}) creating subgroup {new_grp_name_expr}: {{e_cgrp}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Link Creation Operations ---
            link_op_prefix = f"{prefix}_link"

            if random() < 0.3:  # Create SoftLink
                new_slink_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                softlink_target_path_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyLinkPath_expr(
                    f"getattr({ctx_p}_target_grp, 'name', '/')")
                self.parent.write(0, "try:")
                L_slink_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0,
                                      f"{ctx_p}_target_grp[{new_slink_name_expr}] = h5py.SoftLink({softlink_target_path_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_OP ({group_name_for_log}): Created SoftLink {new_slink_name_expr} -> {{ {softlink_target_path_expr} }} '''")
                finally:
                    self.parent.restoreLevel(L_slink_try)
                self.parent.write(0,
                                  f"except Exception as e_slink: print(f'''GRP_OP_ERR ({group_name_for_log}) creating SoftLink {new_slink_name_expr}: {{e_slink}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            if random() < 0.2:  # Create ExternalLink
                new_elink_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                ext_file_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyExternalLinkFilename_expr(
                    "getattr(_h5_external_target_file, 'filename', 'missing_ext_file.h5') if '_h5_external_target_file' in globals() and _h5_external_target_file else 'dangling_ext_file.h5'")
                ext_internal_path_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyLinkPath_expr("'/'")
                self.parent.write(0, "try:")
                L_elink_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0,
                                      f"{ctx_p}_target_grp[{new_elink_name_expr}] = h5py.ExternalLink({ext_file_name_expr}, {ext_internal_path_expr})")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''GRP_OP ({group_name_for_log}): Created ExternalLink {new_elink_name_expr} -> {{ {ext_file_name_expr} }}:{{ {ext_internal_path_expr} }} '''")
                finally:
                    self.parent.restoreLevel(L_elink_try)
                self.parent.write(0,
                                  f"except Exception as e_elink: print(f'''GRP_OP_ERR ({group_name_for_log}) creating ExternalLink {new_elink_name_expr}: {{e_elink}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            if random() < 0.3:  # Create HardLink
                new_hlink_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                existing_object_to_link_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyExistingObjectPath_expr(
                    f"{ctx_p}_target_grp")
                self.parent.write(0, "try:")
                L_hlink_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{link_op_prefix}_target_obj_for_hlink = {existing_object_to_link_expr}")
                    self.parent.write(0, f"if {link_op_prefix}_target_obj_for_hlink is not None:")
                    L_hlink_if_target = self.parent.addLevel(1)
                    try:
                        self.parent.write(0,
                                          f"{ctx_p}_target_grp[{new_hlink_name_expr}] = {link_op_prefix}_target_obj_for_hlink")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''GRP_OP ({group_name_for_log}): Created HardLink {new_hlink_name_expr} -> {{{link_op_prefix}_target_obj_for_hlink!r}} '''")
                    finally:
                        self.parent.restoreLevel(L_hlink_if_target)
                    self.parent.write(0, "else:")
                    L_hlink_else_target = self.parent.addLevel(1)
                    try:
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''GRP_OP_WARN ({group_name_for_log}): Could not find/resolve target for hardlink {new_hlink_name_expr} '''")
                    finally:
                        self.parent.restoreLevel(L_hlink_else_target)
                finally:
                    self.parent.restoreLevel(L_hlink_try)
                self.parent.write(0,
                                  f"except Exception as e_hlink: print(f'''GRP_OP_ERR ({group_name_for_log}) creating HardLink {new_hlink_name_expr}: {{e_hlink}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            # Get and inspect links
            if random() < 0.2:
                self.parent.write(0, f"if len({ctx_p}_target_grp) > 0:")
                L_inspect_outer_if = self.parent.addLevel(1)
                try:
                    self.parent.write(0, "try:")
                    L_inspect_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_link_item_name = choice(list({ctx_p}_target_grp.keys()))")
                        self.parent.write(0,
                                          f"{ctx_p}_link_obj_itself = {ctx_p}_target_grp.get({ctx_p}_link_item_name, getlink=True)")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''GRP_OP ({group_name_for_log}): Link object {{{ctx_p}_link_item_name!r}}: {{repr({ctx_p}_link_obj_itself)}} type {{type({ctx_p}_link_obj_itself).__name__}} '''")
                        # Could add printing SoftLink.path, ExternalLink.filename/path, or h5l.get_info details
                    finally:
                        self.parent.restoreLevel(L_inspect_try)
                    self.parent.write(0,
                                      f"except Exception as e_getlink: print(f'''GRP_OP_ERR ({group_name_for_log}) getting link object: {{e_getlink}}''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_inspect_outer_if)
                self.parent.emptyLine()

            # Attempt to access/resolve a random item & deep dive
            if random() < 0.4:
                self.parent.write(0, f"if len({ctx_p}_target_grp) > 0:")
                L_access_outer_if = self.parent.addLevel(1)
                try:
                    self.parent.write(0, "try:")
                    L_access_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_item_to_access_name = choice(list({ctx_p}_target_grp.keys()))")
                        self.parent.write(0, f"{ctx_p}_resolved_item = {ctx_p}_target_grp[{ctx_p}_item_to_access_name]")
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''GRP_OP ({group_name_for_log}): Accessed item {{{ctx_p}_item_to_access_name!r}}: {{repr({ctx_p}_resolved_item)}} '''")

                        self.parent.write(0,
                                          f"{ctx_p}_resolved_item_type_name_for_dispatch = type({ctx_p}_resolved_item).__name__")
                        self.parent.write(0,
                                          f"if isinstance({ctx_p}_resolved_item, (h5py.Group, h5py.Dataset, h5py.AttributeManager)):")
                        L_access_if_fuzzable = self.parent.addLevel(1)
                        try:
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''GRP_OP ({group_name_for_log}): Resolved item {{{ctx_p}_item_to_access_name!r}} is fuzzable, dispatching deep dive.'''")
                            self.parent._dispatch_fuzz_on_instance(
                                f"{prefix}_resolved_{str(uuid.uuid4())[:4]}",
                                f"{ctx_p}_resolved_item",
                                f"{ctx_p}_resolved_item_type_name_for_dispatch",
                                generation_depth + 1
                            )
                        finally:
                            self.parent.restoreLevel(L_access_if_fuzzable)
                    finally:
                        self.parent.restoreLevel(L_access_try)
                    self.parent.write(0,
                                      f"except Exception as e_accessitem: print(f'''GRP_OP_ERR ({group_name_for_log}) accessing item: {{e_accessitem}} ''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_access_outer_if)
                self.parent.emptyLine()

            # Call require_group and require_dataset
            if random() < 0.2:  # require_group
                req_grp_name = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                self.parent.write(0,
                                  f"try: {ctx_p}_req_grp = {ctx_p}_target_grp.require_group({req_grp_name}); print(f'''GRP_OP ({group_name_for_log}): require_group {req_grp_name} -> {{{ctx_p}_req_grp!r}} ''', file=sys.stderr)")
                self.parent.write(0,
                                  f"except Exception as e_reqg: print(f'''GRP_OP_ERR ({group_name_for_log}) require_group {req_grp_name}: {{e_reqg}} ''', file=sys.stderr)")

            if random() < 0.2:  # require_dataset
                req_ds_name = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                req_ds_shape = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
                req_ds_dtype = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()
                req_ds_exact = choice(['True', 'False'])
                self.parent.write(0,
                                  f"try: {ctx_p}_req_ds = {ctx_p}_target_grp.require_dataset({req_ds_name}, shape={req_ds_shape}, dtype={req_ds_dtype}, exact={req_ds_exact}); print(f'''GRP_OP ({group_name_for_log}): require_dataset {req_ds_name} -> {{{ctx_p}_req_ds!r}} ''', file=sys.stderr)")
                self.parent.write(0,
                                  f"except Exception as e_reqd: print(f'''GRP_OP_ERR ({group_name_for_log}) require_dataset {req_ds_name}: {{e_reqd}} ''', file=sys.stderr)")

        finally:
            self.parent.restoreLevel(L_main_if_grp_valid)
        self.parent.write(0, "else:")
        L_else_grp_invalid = self.parent.addLevel(1)
        try:
            self.parent.write_print_to_stderr(0,
                                              f'f"Skipping group operations for {group_name_for_log} as its variable ({group_expr_str}) is None or not Group."')
        finally:
            self.parent.restoreLevel(L_else_grp_invalid)
        self.parent.emptyLine()

    def _write_h5py_file(self):
        """
        Generates and writes the Python code to create an h5py.File object.

        This method orchestrates the generation of arguments for the h5py.File()
        constructor, including the file name/object, mode, driver, and various
        keyword arguments like libver, userblock_size, locking, and file space
        strategy options. It handles the logic for creating a filename string for
        disk-based files or an in-memory object expression based on the chosen driver.
        The created file object is stored in `h5py_tricky_objects` and
        `_h5_internal_files_to_keep_open_` lists within the generated script
        to ensure it's accessible and kept alive during the fuzzing session.
        The generated code includes try-except blocks to handle potential errors
        during file creation.
        """
        # 1. Get actual driver and mode strings first
        actual_driver = self.parent.arg_generator.h5py_argument_generator.genH5PyFileDriver_actualval()
        actual_mode = self.parent.arg_generator.h5py_argument_generator.genH5PyFileMode_actualval()

        driver_expr = f"'{actual_driver}'" if actual_driver else "None"
        mode_expr = f"'{actual_mode}'"

        # 2. Determine if backing store is True for core driver
        is_core_backing = False
        driver_kwargs_expr = ""  # Initialize to empty string
        if actual_driver == 'core':
            # genH5PyDriverKwargs returns a list, potentially empty or with one string
            driver_kwargs_str_list = self.parent.arg_generator.h5py_argument_generator.genH5PyDriverKwargs(
                actual_driver)
            if driver_kwargs_str_list and driver_kwargs_str_list[0]:  # Check if not empty string
                driver_kwargs_expr = driver_kwargs_str_list[0]  # This is already like ", kwarg1=val1" or ""
                if "backing_store=True" in driver_kwargs_expr:
                    is_core_backing = True
            else:  # If genH5PyDriverKwargs returned [""], ensure driver_kwargs_expr is just empty
                driver_kwargs_expr = ""

        # 3. Generate the file name or object expression
        name_arg_expression, setup_code_lines = self.parent.arg_generator.h5py_argument_generator.gen_h5py_file_name_or_object(
            actual_driver, actual_mode, is_core_backing
        )

        for line in setup_code_lines:
            self.parent.write(0, line)

        # 4. Generate other kwargs
        libver_expr_list = self.parent.arg_generator.h5py_argument_generator.genH5PyLibver()
        libver_expr = "".join(libver_expr_list) if libver_expr_list else "None"

        userblock_val_str_list = self.parent.arg_generator.h5py_argument_generator.genH5PyUserblockSize()
        userblock_val_str = "".join(userblock_val_str_list) if userblock_val_str_list else "0"

        locking_expr_list = self.parent.arg_generator.h5py_argument_generator.genH5PyLocking()
        locking_expr = "".join(locking_expr_list) if locking_expr_list else "None"

        fs_kwargs_expr = ""

        all_kwargs_parts = []  # Store parts like "driver='core'"
        if actual_driver:
            all_kwargs_parts.append(f"driver={driver_expr}")
        if driver_kwargs_expr.startswith(", "):  # Strip leading comma if present
            all_kwargs_parts.append(driver_kwargs_expr[2:])
        elif driver_kwargs_expr:  # If it's just "kw=val"
            all_kwargs_parts.append(driver_kwargs_expr)

        if libver_expr != "None":
            all_kwargs_parts.append(f"libver={libver_expr}")
        if locking_expr != "None":
            all_kwargs_parts.append(f"locking={locking_expr}")

        if actual_mode in ('w', 'w-', 'x'):
            if userblock_val_str != "0":
                all_kwargs_parts.append(f"userblock_size={userblock_val_str}")
            if randint(0, 9) > 1:  # Reduced chance for fs_strategy
                fs_kwargs_str_list_temp = self.parent.arg_generator.h5py_argument_generator.genH5PyFsStrategyKwargs()
                # genH5PyFsStrategyKwargs returns a list with one string, potentially empty or ", kwarg=val,..."
                fs_kwargs_expr_temp = fs_kwargs_str_list_temp[0] if fs_kwargs_str_list_temp else ""
                if fs_kwargs_expr_temp.startswith(", "):  # Strip leading comma
                    all_kwargs_parts.append(fs_kwargs_expr_temp[2:])
                elif fs_kwargs_expr_temp:  # If it's just "kw=val"
                    all_kwargs_parts.append(fs_kwargs_expr_temp)
                fs_kwargs_expr = fs_kwargs_expr_temp  # For logging

        # Construct the final kwargs string for the File() call
        # Filter out any genuinely empty strings that might have resulted from non-chosen optional args
        kwargs_final_str = ", ".join(part for part in all_kwargs_parts if part)

        # 5. Write the h5py.File call
        self.parent.write(0, f"new_file_obj = None # Initialize before try block")
        self.parent.write(0, f"try:")
        self.parent.addLevel(1)
        # Ensure name_arg_expression is correctly formatted, and mode_expr is also handled.
        # kwargs_final_str might be empty, so add a comma only if it's not.
        file_call_args = f"{name_arg_expression}, mode={mode_expr}"
        if kwargs_final_str:
            file_call_args += f", {kwargs_final_str}"

        self.parent.write(0, f"new_file_obj = h5py.File({file_call_args})")
        self.parent.write(0, f"if new_file_obj: # Check if successfully created")
        self.parent.addLevel(1)
        self.parent.write(0, f"h5py_tricky_objects['runtime_file_{uuid.uuid4().hex[:4]}'] = new_file_obj")
        self.parent.write(0, f"_h5_internal_files_to_keep_open_.append(new_file_obj)")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try

        self.parent.write(0, f"except Exception as e_file_create:")
        self.parent.addLevel(1)
        log_name_arg_expr = name_arg_expression.replace("'", "\\'")  # Escape for f-string
        log_kwargs_final_str = kwargs_final_str.replace("'", "\\'")
        self.parent.write(0,
                          f"print(f'''FUZZ_RUNTIME_WARN: Failed to create h5py.File({log_name_arg_expr}, {mode_expr}, {log_kwargs_final_str}): {{e_file_create.__class__.__name__}} {{e_file_create}} ''', file=sys.stderr)")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit except
        self.parent.emptyLine()

    def _write_h5py_dataset_creation_call(
            self, parent_obj_expr: str, dataset_name_expr: str, instance_var_name: str
    ):
        """
        Generates and writes the Python code for a `parent.create_dataset()` call.

        This method constructs a call to `create_dataset` on the given `parent_obj_expr`
        (which should be an h5py File or Group object expression). It uses the
        `H5PyArgumentGenerator` to produce fuzzed values for various dataset
        parameters, including shape, dtype, data, chunks, fillvalue, compression
        options, and track_times. The resulting dataset object (or None if creation
        fails) is assigned to `instance_var_name` in the generated script.
        The created dataset is also registered in the `h5py_runtime_objects`
        dictionary for potential later use within the same fuzzing session.

        Args:
            parent_obj_expr: Python expression string for the parent h5py File or
                             Group object in the generated script.
            dataset_name_expr: Python expression string for the name of the new dataset.
            instance_var_name: The variable name in the generated script to which the
                               newly created dataset instance will be assigned.
        """
        self.parent.write(0, f"# Dynamically creating dataset: {dataset_name_expr} on {parent_obj_expr}")

        shape_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
        if random() < 0.4:
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyComplexDtype_expr()
            if random() < 0.8 or "vlen" in dtype_expr or "enum" in dtype_expr:
                data_expr = "None"
            else:
                data_expr = f"numpy.zeros({shape_expr}, dtype={dtype_expr})" if shape_expr != "None" and shape_expr != "()" else "None"
            if shape_expr == "None" and data_expr == "None":  # Special case for h5py.Empty
                data_expr = f"h5py.Empty(dtype={dtype_expr})"
        else:
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()
            data_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyData_expr(shape_expr, dtype_expr)

        all_kwargs_dict = {}
        if shape_expr != "None": all_kwargs_dict["shape"] = shape_expr
        all_kwargs_dict["dtype"] = dtype_expr
        if data_expr != "None": all_kwargs_dict["data"] = data_expr

        chunks_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetChunks_expr(shape_expr)
        if chunks_expr != "None":
            all_kwargs_dict["chunks"] = chunks_expr
            if random() < 0.5:  # Chance to add maxshape if chunked
                all_kwargs_dict["maxshape"] = self.parent.arg_generator.h5py_argument_generator.genH5PyMaxshape_expr(
                    shape_expr)

        if random() < 0.7:
            fv_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None": all_kwargs_dict["fillvalue"] = fv_expr
        if random() < 0.5:
            all_kwargs_dict["fill_time"] = self.parent.arg_generator.h5py_argument_generator.genH5PyFillTime_expr()

        compression_kwargs_strings = self.parent.arg_generator.h5py_argument_generator.genH5PyCompressionKwargs_expr()
        for comp_kw_str in compression_kwargs_strings:
            if '=' in comp_kw_str:  # Ensure it's a key=value string
                key, val = comp_kw_str.split('=', 1)
                all_kwargs_dict[key] = val
            elif comp_kw_str:  # Handle boolean flags like 'shuffle=True' if split fails
                all_kwargs_dict[comp_kw_str.split('=')[0]] = comp_kw_str.split('=')[1] if len(
                    comp_kw_str.split('=')) > 1 else 'True'

        if random() < 0.5:
            all_kwargs_dict["track_times"] = self.parent.arg_generator.h5py_argument_generator.genH5PyTrackTimes_expr()

        # Filter out None values from the dict before formatting, unless the value is literally the string "None"
        final_kwargs_str = ", ".join(f"{k}={v}" for k, v in all_kwargs_dict.items())

        self.parent.write(0, f"try:")
        self.parent.addLevel(1)
        self.parent.write(0,
                          f"{instance_var_name} = {parent_obj_expr}.create_dataset({dataset_name_expr}, {final_kwargs_str})")
        self.parent.write(0, f"if {instance_var_name}:")
        self.parent.addLevel(1)
        self.parent.write(0, f"h5py_runtime_objects[{dataset_name_expr.strip("'")}] = {instance_var_name}")
        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.write(0, f"except Exception as e_dset_create:")
        self.parent.addLevel(1)
        self.parent.write(0, f"{instance_var_name} = None")
        # Escape characters in expressions for safe inclusion in the f-string
        log_dataset_name_expr = dataset_name_expr.replace("'", "\\'")
        log_parent_obj_expr = parent_obj_expr.replace("'", "\\'")
        log_final_kwargs_str = final_kwargs_str.replace("'", "\\'")

        self.parent.write(0, f"try:")  # Inner try for printing error, in case repr itself fails
        self.parent.addLevel(1)
        self.parent.write_print_to_stderr(
            0,  # Relative to current indent
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {log_dataset_name_expr} on {{ {log_parent_obj_expr} }} "
            f"with args {{ repr(dict({final_kwargs_str})) if isinstance(dict({final_kwargs_str}), dict) else '{log_final_kwargs_str}' }}: "
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}} '''"
        )
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner try
        self.parent.write(0, "except Exception as e_print_err:")
        self.parent.addLevel(1)
        self.parent.write_print_to_stderr(
            0,  # Relative
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {log_dataset_name_expr} (error printing args): {{e_dset_create}} ; PrintErr: {{e_print_err}}'''"
        )
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner except

        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.emptyLine()

    def _fuzz_one_attributemanager_instance(self, attrs_expr_str: str, owner_name_for_log: str, prefix: str,
                                            generation_depth: int):
        """
        Generates fuzzed operations for an h5py.AttributeManager instance.

        This includes iterating attributes, checking length and containment,
        and creating, modifying, getting, and deleting attributes using fuzzed
        names and values.

        Args:
            attrs_expr_str: Python expression string for the AttributeManager instance.
            owner_name_for_log: Name of the HDF5 object (File, Group, or Dataset)
                                owning these attributes, used for logging.
            prefix: A prefix for generating unique variable names.
            generation_depth: Current recursion depth (AttributeManager itself does not typically lead to further deep dives).
        """
        self.parent.write_print_to_stderr(0,
                                          f'f"--- (Depth {generation_depth}) Fuzzing AttributeManager for {owner_name_for_log} (var: {attrs_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()
        ctx_p = f"ctx_{prefix}"
        self.parent.write(0, f"{ctx_p}_target_attrs = {attrs_expr_str}")
        self.parent.write(0, f"if {ctx_p}_target_attrs is not None:")
        L_main_if_attrs = self.parent.addLevel(1)
        self.parent.write(0, "'INDENTED BLOCK'")  # Placeholder comment
        try:
            # Iteration, len, contains
            if random() < 0.7:
                self.parent.write(0, "try:")
                L_iter_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_attr_count = 0")
                    self.parent.write(0, f"for {ctx_p}_attr_name in {ctx_p}_target_attrs:")
                    L_iter_for = self.parent.addLevel(1)
                    try:
                        self.parent.write_print_to_stderr(0,
                                                          f"f'''ATTR_ITER ({owner_name_for_log}): key = {{{ctx_p}_attr_name!r}}'''")
                        self.parent.write(0, f"{ctx_p}_attr_count += 1")
                        self.parent.write(0, f"if {ctx_p}_attr_count > 5: break")
                    finally:
                        self.parent.restoreLevel(L_iter_for)
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''ATTR_ITER ({owner_name_for_log}): iterated {{{ctx_p}_attr_count}} attrs'''")
                    self.parent.write_print_to_stderr(0,
                                                      f"f'''ATTR_LEN ({owner_name_for_log}): len = {{len({ctx_p}_target_attrs)}}'''")
                    self.parent.write(0,
                                      f"if {ctx_p}_attr_count > 0: {ctx_p}_first_attr_name = list({ctx_p}_target_attrs.keys())[0]")
                    self.parent.write(0,
                                      f"if {ctx_p}_attr_count > 0: print(f'''ATTR_CONTAINS ({owner_name_for_log}): {{{ctx_p}_first_attr_name!r}} in attrs = ({{{ctx_p}_first_attr_name!r}} in {ctx_p}_target_attrs)''', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_iter_try)
                self.parent.write(0,
                                  f"except Exception as e_attr_iter: print(f'''ATTR_ITER_ERR ({owner_name_for_log}): {{e_attr_iter}}''', file=sys.stderr)")
                self.parent.emptyLine()

            # Create/Modify/Get/Delete Attributes
            if random() < 0.6:
                num_attr_ops = randint(1, 3)
                for i in range(num_attr_ops):
                    attr_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAttributeName_expr()
                    attr_val_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAttributeValue_expr()
                    self.parent.write(0, f"# Attribute operation {i + 1}")
                    self.parent.write(0, "try:")
                    L_attr_op_try = self.parent.addLevel(1)
                    try:
                        op_choice = random()
                        if op_choice < 0.5:  # __setitem__ / create / modify
                            self.parent.write(0, f"{ctx_p}_target_attrs[{attr_name_expr}] = {attr_val_expr}")
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''ATTR_SET ({owner_name_for_log}): Set/Create attr {{{attr_name_expr!r}}} = {{{attr_val_expr!r}}} (actual: {{repr({ctx_p}_target_attrs.get({attr_name_expr}))}})'''")
                        elif op_choice < 0.8:  # __getitem__ / get
                            self.parent.write(0, f"{ctx_p}_read_attr_val = {ctx_p}_target_attrs[{attr_name_expr}]")
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''ATTR_GET ({owner_name_for_log}): Got attr {{{attr_name_expr!r}}} = {{{ctx_p}_read_attr_val!r}}'''")
                        else:  # __delitem__
                            self.parent.write(0, f"del {ctx_p}_target_attrs[{attr_name_expr}]")
                            self.parent.write_print_to_stderr(0,
                                                              f"f'''ATTR_DEL ({owner_name_for_log}): Deleted attr {{{attr_name_expr!r}}}'''")
                    finally:
                        self.parent.restoreLevel(L_attr_op_try)
                    self.parent.write(0,
                                      f"except Exception as e_attr_mod: print(f'''ATTR_MOD_ERR ({owner_name_for_log}) with name {{{attr_name_expr!r}}}: {{e_attr_mod}}''', file=sys.stderr)")
                    self.parent.emptyLine()
        finally:
            self.parent.restoreLevel(L_main_if_attrs)
        self.parent.write(0, "else:")
        L_else_attrs_is_none = self.parent.addLevel(1)
        try:
            self.parent.write_print_to_stderr(0,
                                              f"f'''Skipping AttributeManager fuzz for {owner_name_for_log} as its variable ({attrs_expr_str}) is None.'''")
        finally:
            self.parent.restoreLevel(L_else_attrs_is_none)
        self.parent.emptyLine()

    def fuzz_one_h5py_class(self, class_name_str: str, class_type: type, instance_var_name: str, prefix: str) -> bool:
        """
        Handles the instantiation of h5py-specific classes like File, Dataset, Group.

        If the class is recognized as an h5py type that needs special instantiation
        (e.g., File, Dataset, Group requiring a parent or specific parameters),
        this method generates the appropriate creation code by calling specialized
        `_write_h5py_*` methods.

        Args:
            class_name_str: The name of the class to instantiate (e.g., "File").
            class_type: The actual class type object (e.g., `h5py.File`).
            instance_var_name: The variable name to assign the new instance to in the
                               generated script (e.g., "instance_c0_file").
            prefix: A prefix for generating unique names within the script.

        Returns:
            True if the class was identified and handled as a special h5py type,
            False otherwise (indicating generic instantiation should be attempted
            by the caller).
        """
        is_h5py_class_handled = False
        is_h5py_type = hasattr(class_type, "__module__") and \
                       class_type.__module__ and \
                       class_type.__module__.startswith("h5py")

        if is_h5py_type and class_name_str == "File":
            is_h5py_class_handled = True
            # _write_h5py_file will define 'new_file_obj' in the generated script
            self._write_h5py_file()
            self.parent.write(0, f"{instance_var_name} = new_file_obj")
        elif is_h5py_type and class_name_str == "Dataset":
            is_h5py_class_handled = True
            parent_obj_expr_str = "_h5_main_file"  # Default parent for dynamic creation
            dataset_name_expr_str = f"'{_h5_unique_name(f'ds_{prefix}')}'"
            self.parent.write(0, f"if {parent_obj_expr_str} and hasattr({parent_obj_expr_str}, 'create_dataset'):")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")  # Initialize
            self._write_h5py_dataset_creation_call(parent_obj_expr_str, dataset_name_expr_str, instance_var_name)
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                              f"f'''Skipping dynamic Dataset creation for {instance_var_name} as parent {parent_obj_expr_str} is unavailable.'''")
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.restoreLevel(self.parent.base_level - 1)
        elif is_h5py_type and class_name_str == "Group":
            is_h5py_class_handled = True
            parent_obj_expr_str = "_h5_main_file"
            group_name_expr_str = f"'{_h5_unique_name(f'grp_{prefix}')}'"
            self.parent.write(0, f"if {parent_obj_expr_str} and hasattr({parent_obj_expr_str}, 'create_group'):")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")  # Initialize
            self.parent.write(0, "try:")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = {parent_obj_expr_str}.create_group({group_name_expr_str})")
            self.parent.write(0, f"h5py_runtime_objects[{group_name_expr_str.strip("'")}] = {instance_var_name}")
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "except Exception as e_grp_create:")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.write_print_to_stderr(0, f"f'''Failed to create group {group_name_expr_str}: {{e_grp_create}}'''")
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                              f"f'''Skipping dynamic Group creation for {instance_var_name} as parent {parent_obj_expr_str} is unavailable.'''")
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.restoreLevel(self.parent.base_level - 1)
        return is_h5py_class_handled

    def _dispatch_fuzz_on_h5py_instance(self, class_name_hint: str, current_prefix: str, generation_depth: int,
                                        target_obj_expr_str: str) -> int | None:
        """
        Dispatches fuzzing to specialized h5py methods if the target object is an h5py type.

        This method is called by the main `_dispatch_fuzz_on_instance` in `WritePythonCode`.
        It writes `elif` blocks into the generated script to check if the `target_obj_expr_str`
        is an instance of a known h5py type (Dataset, Group, File, AttributeManager).
        If a match is found, it calls the corresponding `_fuzz_one_*_instance` method
        from this class to generate h5py-specific fuzzing operations.

        Args:
            class_name_hint: A string hint for the class name of the target object.
                             Used primarily for logging.
            current_prefix: Prefix for generating unique variable names in the script.
            generation_depth: Current recursion depth for fuzzing operations.
            target_obj_expr_str: Python expression string for the target object instance
                                 in the generated script.

        Returns:
            An indentation level (integer) to restore to in the caller if an h5py type was
            handled and further generic fuzzing in the caller should be nested within
            an `else` block. Returns `None` if no h5py type was specifically handled by
            an `elif` here, implying the caller's `else` block for generic fuzzing
            should follow directly. The current implementation always returns `None` as it only
            adds `elif` blocks, and the final `else` for generic fuzzing is handled by the caller.
        """
        # These isinstance checks will occur at runtime in the generated script
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.Dataset):")
        L_is_dataset = self.parent.addLevel(1)
        try:
            self._fuzz_one_dataset_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_ds", generation_depth)
        finally:
            self.parent.restoreLevel(L_is_dataset)
        # return None # Handled by this elif, caller's else won't be hit for this case.

        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.Group):")
        L_is_group = self.parent.addLevel(1)
        try:
            self._fuzz_one_group_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_grp", generation_depth)
        finally:
            self.parent.restoreLevel(L_is_group)
        # return None

        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.File):")
        L_is_file = self.parent.addLevel(1)
        try:
            self._fuzz_one_file_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_file", generation_depth)
        finally:
            self.parent.restoreLevel(L_is_file)
        # return None

        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.AttributeManager):")
        L_is_attrs = self.parent.addLevel(1)
        try:
            self._fuzz_one_attributemanager_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_attrs",
                                                     generation_depth)
        finally:
            self.parent.restoreLevel(L_is_attrs)
        # return None

        # This method only adds 'elif' blocks. The caller handles the final 'else' for generic objects.
        # Thus, we don't return a level to restore *to* for an 'else' block here.
        return L_is_dataset

    def _write_h5py_dataset_creation_call(
            self, parent_obj_expr: str, dataset_name_expr: str, instance_var_name: str
    ):
        """
        Generates and writes the Python code for a `parent.create_dataset()` call.

        This method constructs a call to `create_dataset` on the given `parent_obj_expr`
        (which should be an h5py File or Group object expression). It uses the
        `H5PyArgumentGenerator` to produce fuzzed values for various dataset
        parameters, including shape, dtype, data, chunks, fillvalue, compression
        options, and track_times. The resulting dataset object (or None if creation
        fails) is assigned to `instance_var_name` in the generated script.
        The created dataset is also registered in the `h5py_runtime_objects`
        dictionary for potential later use within the same fuzzing session.

        Args:
            parent_obj_expr: Python expression string for the parent h5py File or
                             Group object in the generated script.
            dataset_name_expr: Python expression string for the name of the new dataset.
            instance_var_name: The variable name in the generated script to which the
                               newly created dataset instance will be assigned.
        """
        self.parent.write(0, f"# Dynamically creating dataset: {dataset_name_expr} on {parent_obj_expr}")

        shape_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
        if random() < 0.4:
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyComplexDtype_expr()
            if random() < 0.8 or "vlen" in dtype_expr or "enum" in dtype_expr:
                data_expr = "None"
            else:
                data_expr = f"numpy.zeros({shape_expr}, dtype={dtype_expr})" if shape_expr != "None" and shape_expr != "()" else "None"
            if shape_expr == "None" and data_expr == "None":  # Special case for h5py.Empty
                data_expr = f"h5py.Empty(dtype={dtype_expr})"
        else:
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()
            data_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyData_expr(shape_expr, dtype_expr)

        all_kwargs_dict = {}
        if shape_expr != "None": all_kwargs_dict["shape"] = shape_expr
        all_kwargs_dict["dtype"] = dtype_expr
        if data_expr != "None": all_kwargs_dict["data"] = data_expr

        chunks_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetChunks_expr(shape_expr)
        if chunks_expr != "None":
            all_kwargs_dict["chunks"] = chunks_expr
            if random() < 0.5:  # Chance to add maxshape if chunked
                all_kwargs_dict["maxshape"] = self.parent.arg_generator.h5py_argument_generator.genH5PyMaxshape_expr(
                    shape_expr)

        if random() < 0.7:
            fv_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None": all_kwargs_dict["fillvalue"] = fv_expr
        if random() < 0.5:
            all_kwargs_dict["fill_time"] = self.parent.arg_generator.h5py_argument_generator.genH5PyFillTime_expr()

        compression_kwargs_strings = self.parent.arg_generator.h5py_argument_generator.genH5PyCompressionKwargs_expr()
        for comp_kw_str in compression_kwargs_strings:
            if '=' in comp_kw_str:  # Ensure it's a key=value string
                key, val = comp_kw_str.split('=', 1)
                all_kwargs_dict[key] = val
            elif comp_kw_str:  # Handle boolean flags like 'shuffle=True' if split fails
                all_kwargs_dict[comp_kw_str.split('=')[0]] = comp_kw_str.split('=')[1] if len(
                    comp_kw_str.split('=')) > 1 else 'True'

        if random() < 0.5:
            all_kwargs_dict["track_times"] = self.parent.arg_generator.h5py_argument_generator.genH5PyTrackTimes_expr()

        # Filter out None values from the dict before formatting, unless the value is literally the string "None"
        final_kwargs_str = ", ".join(f"{k}={v}" for k, v in all_kwargs_dict.items())

        self.parent.write(0, f"try:")
        self.parent.addLevel(1)
        self.parent.write(0,
                          f"{instance_var_name} = {parent_obj_expr}.create_dataset({dataset_name_expr}, {final_kwargs_str})")
        self.parent.write(0, f"if {instance_var_name}:")
        self.parent.addLevel(1)
        self.parent.write(0, f"h5py_runtime_objects[{dataset_name_expr.strip("'")}] = {instance_var_name}")
        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.write(0, f"except Exception as e_dset_create:")
        self.parent.addLevel(1)
        self.parent.write(0, f"{instance_var_name} = None")
        # Escape characters in expressions for safe inclusion in the f-string
        log_dataset_name_expr = dataset_name_expr.replace("'", "\\'")
        log_parent_obj_expr = parent_obj_expr.replace("'", "\\'")
        log_final_kwargs_str = final_kwargs_str.replace("'", "\\'")

        self.parent.write(0, f"try:")  # Inner try for printing error, in case repr itself fails
        self.parent.addLevel(1)
        self.parent.write_print_to_stderr(
            0,  # Relative to current indent
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {log_dataset_name_expr} on {{ {log_parent_obj_expr} }} "
            f"with args {{ repr(dict({final_kwargs_str})) if isinstance(dict({final_kwargs_str}), dict) else '{log_final_kwargs_str}' }}: "
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}} '''"
        )
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner try
        self.parent.write(0, "except Exception as e_print_err:")
        self.parent.addLevel(1)
        self.parent.write_print_to_stderr(
            0,  # Relative
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {log_dataset_name_expr} (error printing args): {{e_dset_create}} ; PrintErr: {{e_print_err}}'''"
        )
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner except

        self.parent.restoreLevel(self.parent.base_level - 1)
        self.parent.emptyLine()

    def _fuzz_methods_on_h5py_object_or_specific_types(self, current_prefix, target_obj_expr_str):
        """
        (DEPRECATED/Refactored into _dispatch_fuzz_on_h5py_instance and parent's dispatcher)
        Generates code to fuzz methods of an h5py object or specific other types.

        This method would typically check the type of `target_obj_expr_str` at runtime
        and dispatch to specialized fuzzing routines (e.g., `_fuzz_one_dataset_instance`)
        or fall back to generic method fuzzing.

        Note: The logic from this method has largely been integrated into
        `_dispatch_fuzz_on_h5py_instance` (for the h5py specific parts) and
        the main `_dispatch_fuzz_on_instance` in `WritePythonCode` (for the
        generic fallback and initial trivial type checks).

        Args:
            current_prefix: Prefix for generating unique variable names.
            target_obj_expr_str: Python expression string for the target object.
        """
        # This method's functionality is now primarily handled by _dispatch_fuzz_on_h5py_instance
        # and the main _dispatch_fuzz_on_instance in WritePythonCode.
        # Keeping a placeholder or removing it depends on whether the parent calls it.
        # Based on the new structure, this method might be redundant if the dispatch logic
        # in WritePythonCode correctly calls into _dispatch_fuzz_on_h5py_instance.
        self.parent.write_print_to_stderr(0,
                                          f"f'# INFO: _fuzz_methods_on_h5py_object_or_specific_types called for {target_obj_expr_str}, but dispatching is now preferred.'")
        # Fallback to a generic call, or ideally, the parent's dispatcher handles this.
        # self.parent._fuzz_generic_object_methods(current_prefix, target_obj_expr_str, self.parent.options.methods_number)
        pass  # The logic should now be in the main dispatcher in WritePythonCode.
