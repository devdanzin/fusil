from __future__ import annotations

import uuid
from random import random, randint, choice
from textwrap import dedent


def _h5_unique_name(base="item"):
    return f"{base}_{uuid.uuid4().hex[:8]}"


class WriteH5PyCode:
    def __init__(self, parent):
        super().__init__()  # Initialize base WriteCode
        self.parent = parent

    def _write_h5py_script_header_and_imports(self):
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

                # Strategy 1: Direct children of the parent group
                try:
                    if len(parent_group_obj) > 0:
                        child_name = choice(list(parent_group_obj.keys()))
                        child_obj = parent_group_obj.get(child_name) # Resolve link if it is one
                        if isinstance(child_obj, (h5py.Group, h5py.Dataset)):
                            candidates.append(child_obj)
                except Exception:
                    pass # Ignore errors during candidate search

                # Strategy 2: Top-level items in the same file
                try:
                    if len(parent_group_obj.file) > 0:
                        root_item_name = choice(list(parent_group_obj.file.keys()))
                        root_item_obj = parent_group_obj.file.get(root_item_name)
                        if isinstance(root_item_obj, (h5py.Group, h5py.Dataset)):
                            candidates.append(root_item_obj)
                except Exception:
                    pass

                # Strategy 3: Items from predefined_tricky_objects if they are in the same file
                try:
                    for obj_name, obj in predefined_tricky_objects.items():
                        if obj is not None and hasattr(obj, 'file') and hasattr(obj.file, 'id') and obj.file.id == target_file_id:
                            if isinstance(obj, (h5py.Group, h5py.Dataset)):
                                candidates.append(obj)
                        if len(candidates) > 20: break # Limit search
                except Exception:
                    pass

                # Strategy 4: Items from runtime_objects if they are in the same file
                try:
                    for obj_name, obj in runtime_objects.items():
                        if obj is not None and hasattr(obj, 'file') and hasattr(obj.file, 'id') and obj.file.id == target_file_id:
                            if isinstance(obj, (h5py.Group, h5py.Dataset)):
                                candidates.append(obj)
                        if len(candidates) > 40: break # Limit search
                except Exception:
                    pass

                if candidates:
                    return choice(candidates)

                # Fallback: the root group of the parent's file, or parent itself if it's not root
                if parent_group_obj.name != '/':
                    return parent_group_obj 
                return parent_group_obj.file['/'] # Root group as ultimate fallback
        """))
        self.parent.emptyLine()

    def _fuzz_one_dataset_instance(self, dset_expr_str: str, dset_name_for_log: str, prefix: str, generation_depth: int):
        """
        Generates code to perform a variety of operations on a given dataset instance.
        Args:
            dset_expr_str: Python expression string for the dataset instance.
            dset_name_for_log: Clean name for logging.
            prefix: Logging prefix.
        """
        self.parent.write_print_to_stderr(0,
                                   f'f"--- Fuzzing Dataset Instance: {dset_name_for_log} (var: {dset_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()

        # --- Preamble: Get dataset context at runtime in generated script ---
        # These variables will hold the actual properties of the dataset when the fuzzed code runs.
        ctx_p = f"ctx_{prefix}"  # Context prefix to make variables unique per call

        self.parent.write(0, f"{ctx_p}_target_dset = {dset_expr_str}")  # Assign to a short-lived var
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
            self.parent.write(0, f"{ctx_p}_is_empty_dataspace = h5py._hl.base.is_empty_dataspace({ctx_p}_target_dset.id)")
            self.parent.write_print_to_stderr(0,
                                       f"f'''DS_OP_CTX ({dset_name_for_log}): Shape={{ {ctx_p}_shape }}, Dtype={{ {ctx_p}_dtype_str }}, Chunked={{ {ctx_p}_is_chunked }}, Scalar={{ {ctx_p}_is_scalar }} '''")
            self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
            self.parent.write(0,
                       f"except Exception as e_op_ctx: print(f'''DS_OP_CTX_ERR ({dset_name_for_log}): {{e_op_ctx}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            self.parent.write(0, f"if {ctx_p}_target_dset is not None:")
            L_valid_dataset = self.parent.addLevel(1)  # For operations on the valid dataset
            self.parent.write(0, "'INDENTED BLOCK IN CASE NO ISSUE CODE IS USED'")
            if random() < 0.5:  # Chance to fuzz attributes
                self.parent.write(0, f"# Attempting to fuzz .attrs of {dset_name_for_log}")
                self.parent.write(0, "try:")
                L_attrs_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_attrs_obj = {ctx_p}_target_dset.attrs")
                    self.parent.write_print_to_stderr(0,
                                               f"f'DS_ATTRS_ACCESS ({dset_name_for_log}): Got .attrs object {{ {ctx_p}_attrs_obj!r }}. Dispatching fuzz.'")
                    self.parent._dispatch_fuzz_on_instance(
                        current_prefix=f"{prefix}_attrs",
                        target_obj_expr_str=f"{ctx_p}_attrs_obj",
                        class_name_hint="AttributeManager",
                        generation_depth=generation_depth + 1
                    )
                finally:
                    self.parent.restoreLevel(L_attrs_try)
                self.parent.write(0,
                           "except Exception as e_attrs_access: print(f'DS_ATTRS_ACCESS_ERR ({dset_name_for_log}): {{e_attrs_access}}', file=sys.stderr)")
                self.parent.emptyLine()

                # --- Deep Dive on results of view-like methods ---
                # Example for .astype() (already had placeholder for this)
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
                                                   f"f'DS_ASTYPE ({dset_name_for_log}): view created. Dispatching fuzz on view.'")
                        # DEEP DIVE on the view:
                        self.parent._dispatch_fuzz_on_instance(
                            current_prefix=f"{prefix}_astype_view",
                            target_obj_expr_str=f"{ctx_p}_astype_view",
                            class_name_hint="AstypeWrapper",  # Or more generically "DatasetView"
                            generation_depth=generation_depth + 1
                        )
                        # ... (original print/asserts on the view can remain if useful) ...
                    finally:
                        self.parent.restoreLevel(L_astype_try)
                    self.parent.write(0, "except Exception as e_astype: print(f'DS_ASTYPE_ERR ...', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_astype_outer_if)
                self.parent.emptyLine()
            self.parent.restoreLevel(L_valid_dataset)  # Exit if block

            # --- Issue 135: Compound Scalar Type Check ---
            if random() < 0.1:  # Chance to run this specific check
                self.parent.write(0, f"if {ctx_p}_is_scalar and {ctx_p}_is_compound:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_item = {ctx_p}_target_dset[()]")
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE135 ({dset_name_for_log}): Scalar compound item type {{type({ctx_p}_item).__name__}} (expected np.void for single element)'")
                self.parent.write(0,
                           f"assert isinstance({ctx_p}_item, numpy.void), f'Expected np.void, got {{type({ctx_p}_item)}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
                self.parent.write(0,
                           f"except Exception as e_issue135: print(f'G_ISSUE135_ERR ({dset_name_for_log}): {{e_issue135}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if
                self.parent.emptyLine()

            # --- Issue 211: Array Dtype Operations ---
            if random() < 0.2:
                self.parent.write(0, f"# Issue 211 checks for array dtypes")
                self.parent.write(0,
                           f"if {ctx_p}_dtype_obj is not None and {ctx_p}_dtype_obj.subdtype is not None:")  # Check if it's an array dtype
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"{ctx_p}_base_dt_obj = {ctx_p}_dtype_obj.subdtype[0]")  # This will be a dtype object at runtime
                self.parent.write(0,
                           f"{ctx_p}_el_shape_tuple = {ctx_p}_dtype_obj.subdtype[1]")  # This will be a shape tuple at runtime
                # For the expression generated by genArrayForArrayDtypeElement_expr,
                # it's better if the base_dt_expr is a string representation of the dtype,
                # or the variable holding the dtype object itself.
                # Let's pass the variable name that holds the dtype object.

                self.parent.write(0, "# Test scalar assignment error (TypeError expected)")
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                # The AG method now takes expressions that will evaluate to the shape tuple and base dtype object at runtime
                data_for_el_expr = self.parent.arg_generator.h5py_argument_generator.genArrayForArrayDtypeElement_expr(
                    f'{ctx_p}_el_shape_tuple',  # This variable holds the tuple like (3,) at runtime
                    f'{ctx_p}_base_dt_obj'  # This variable holds the base dtype object like np.dtype('i4') at runtime
                )
                self.parent.write(0,
                           f"{ctx_p}_data_for_el = {data_for_el_expr}")  # Evaluate the expression to create the array
                self.parent.write(0,
                           f"if {ctx_p}_shape and {ctx_p}_actual_product_shape > 0:")  # Check if dataset is not empty
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_target_dset[0] = {ctx_p}_data_for_el")  # Assign the created array
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE211_B ({dset_name_for_log}): Element write attempted with data of shape {{{ctx_p}_data_for_el.shape}}.'")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if dataset not empty
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for element write
                self.parent.write(0,
                           f"except Exception as e_issue211b: print(f'G_ISSUE211_B_ERR ({dset_name_for_log}): {{e_issue211b}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if array dtype
                self.parent.emptyLine()
            # --- Issue #1475: Zero Storage Size for Empty/Null Dataspace Dataset ---
            if random() < 0.1:
                self.parent.write(0, f"if {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"storage_size = {ctx_p}_target_dset.id.get_storage_size()")
                self.parent.write(0, f"offset = {ctx_p}_target_dset.id.get_offset()")
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE1475 ({dset_name_for_log}): Empty dataspace. Storage={{storage_size}}, Offset={{offset}} (expected 0 and None)'")
                self.parent.write(0, "assert storage_size == 0, 'Storage size non-zero for empty dataspace'")
                self.parent.write(0, "assert offset is None, 'Offset not None for empty dataspace'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                           f"except Exception as e_issue1475: print(f'G_ISSUE1475_ERR ({dset_name_for_log}): {{e_issue1475}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # --- Issue #1547: Large Python Int to uint64 Dataset ---
            if random() < 0.1:
                self.parent.write(0, f"if {ctx_p}_dtype_str == 'uint64':")  # Check if it's a uint64 dataset
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                large_int_expr = self.parent.arg_generator.h5py_argument_generator.genLargePythonInt_expr()
                self.parent.write(0, f"val_to_write = {large_int_expr}")
                self.parent.write(0,
                           f"idx_to_write = randint(0, {ctx_p}_shape[0]-1) if {ctx_p}_shape and {ctx_p}_shape[0]>0 else 0")
                self.parent.write(0,
                           f"if {ctx_p}_shape and {ctx_p}_actual_product_shape > 0 : {ctx_p}_target_dset[idx_to_write] = val_to_write")  # Assuming 1D for simplicity
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE1547 ({dset_name_for_log}): Wrote {{val_to_write}} to uint64 dataset at index {{idx_to_write}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                           f"except Exception as e_issue1547: print(f'G_ISSUE1547_ERR ({dset_name_for_log}): {{e_issue1547}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.emptyLine()

            # --- Issue #1593: __setitem__ with Fancy Indexing ---
            # This was already added conceptually to _fuzz_one_dataset_instance in Category D. Ensure it's robust.
            # The key is to generate a compatible `block_data` shape based on the fancy_indices.
            # The existing code for this from Category D is a good start.

            # --- Issue #2549: Write to Zero-Size Resizable Dataset ---
            if random() < 0.1:
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"if {ctx_p}_shape and {ctx_p}_actual_product_shape == 0 and {ctx_p}_target_dset.maxshape is not None:")  # Is zero size and resizable
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"# Attempt write before resize (might be error or no-op)")
                self.parent.write(0, f"{ctx_p}_target_dset[()] = 0 # If scalar-like empty, or dset[0]=0 if 1D empty")
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE2549 ({dset_name_for_log}): Attempted write to initially zero-size resizable dataset.'")

                self.parent.write(0, f"# Now resize and write")
                new_len = randint(1, 5)
                new_shape_expr = f"({new_len},) + ({ctx_p}_shape[1:] if {ctx_p}_rank > 1 else ())"  # Resize first dim
                self.parent.write(0, f"new_shape_for_resize = eval(f'{{ {new_shape_expr} }}')")  # Calculate new shape at runtime
                self.parent.write(0, f"{ctx_p}_target_dset.resize(new_shape_for_resize)")
                self.parent.write(0,
                           f"data_for_resize = numpy.arange(product(new_shape_for_resize), dtype={ctx_p}_dtype_obj).reshape(new_shape_for_resize)")
                self.parent.write(0, f"{ctx_p}_target_dset[...] = data_for_resize")
                self.parent.write_print_to_stderr(0,
                                           f"f'G_ISSUE2549 ({dset_name_for_log}): Resized to {{new_shape_for_resize}} and wrote data.'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0,
                           f"except Exception as e_issue2549: print(f'G_ISSUE2549_ERR ({dset_name_for_log}): {{e_issue2549}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0, f"except Exception as e_issue2549: print(f'G_ISSUE2549_ERR ({dset_name_for_log}): {{e_issue2549}}', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Advanced Slicing Operations ---
            if random() < 0.5 and f"{ctx_p}_shape is not None":  # 50% chance to try advanced slicing
                self.parent.write(0, "# --- Advanced Slicing Attempt ---")

                # Prepare context strings for ArgumentGenerator
                dset_fields_keys_expr = f"list({ctx_p}_dtype_obj.fields.keys()) if {ctx_p}_is_compound and {ctx_p}_dtype_obj.fields else []"
                # Note: {ctx_p}_rank is already defined as a variable in generated code.

                adv_slice_arg_expr = self.parent.arg_generator.h5py_argument_generator.genAdvancedSliceArgument_expr(
                    f"{ctx_p}_target_dset",  # Pass the dataset variable name itself
                    f"{ctx_p}_rank",
                    dset_fields_keys_expr
                )

                # Ensure the expression for field keys is evaluated first if needed by AG's generated lambda
                self.parent.write(0, f"try: {ctx_p}_dset_fields_keys = {dset_fields_keys_expr}")  # Evaluate field keys
                self.parent.write(0, f"except Exception: {ctx_p}_dset_fields_keys = []")

                self.parent.write(0, f"try:")
                self.parent.addLevel(1)
                # The adv_slice_arg_expr might itself be a complex expression (like an IIFE lambda)
                # that uses {ctx_p}_rank and {ctx_p}_dset_fields_keys internally.
                self.parent.write(0, f"{ctx_p}_adv_slice_obj = {adv_slice_arg_expr}")
                self.parent.write_print_to_stderr(0,
                                           f"f'DS_ADV_SLICE ({dset_name_for_log}): Attempting slice with {{repr({ctx_p}_adv_slice_obj)}}'")

                # Attempt read
                self.parent.write(0, f"if not {ctx_p}_is_empty_dataspace:")  # Reading from empty might error differently
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_read_data = {ctx_p}_target_dset[{ctx_p}_adv_slice_obj]")
                self.parent.write_print_to_stderr(0,
                                           f"f'DS_ADV_SLICE_READ ({dset_name_for_log}): Sliced data shape {{getattr({ctx_p}_read_data, \"shape\", \"N/A\")}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)

                # Attempt write (if not a field name slice, or if field name slice and data is compatible)
                # Generating compatible data for write with advanced slices is very complex.
                # For now, let's try writing a scalar or a small compatible array if the read succeeded and gave us a shape.
                self.parent.write(0,
                           f"if not {ctx_p}_is_empty_dataspace and hasattr({ctx_p}_target_dset, 'readonly') and not {ctx_p}_target_dset.readonly:")
                self.parent.addLevel(1)  # Start of write block if
                self.parent.write(0, f"try:")  # Try for write
                self.parent.addLevel(1)
                self.parent.write(0, f"# Preparing data for advanced slice write...")
                self.parent.write(0, f"{ctx_p}_data_for_write = None")
                self.parent.write(0,
                           f"if hasattr({ctx_p}_read_data, 'shape') and hasattr({ctx_p}_read_data, 'dtype'):")  # If read gave array
                self.parent.addLevel(1)
                self.parent.write(0, f"if product(getattr({ctx_p}_read_data, 'shape', (0,))) > 0:")  # If read data is not empty
                self.parent.addLevel(1)
                # Create compatible data based on what was read (shape and dtype)
                self.parent.write(0, f"{ctx_p}_data_for_write = numpy.zeros_like({ctx_p}_read_data)")  # Or random, or from AG
                self.parent.write_print_to_stderr(0,
                                           f"f'DS_ADV_SLICE_WRITE ({dset_name_for_log}): Generated zeros_like data with shape {{{ctx_p}_data_for_write.shape}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.restoreLevel(self.parent.base_level - 1)
                self.parent.write(0, f"elif {ctx_p}_dtype_obj is not None:")  # Fallback: scalar based on dataset dtype
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"{ctx_p}_data_for_write = numpy.array(0, dtype={ctx_p}_dtype_obj).item() if {ctx_p}_dtype_obj.kind not in 'SUOV' else (b'' if {ctx_p}_dtype_obj.kind == 'S' else '')")
                self.parent.write_print_to_stderr(0,
                                           f"f'DS_ADV_SLICE_WRITE ({dset_name_for_log}): Generated scalar data {{{ctx_p}_data_for_write!r}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)

                self.parent.write(0, f"if {ctx_p}_data_for_write is not None:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_target_dset[{ctx_p}_adv_slice_obj] = {ctx_p}_data_for_write")
                self.parent.write_print_to_stderr(0,
                                           f"f'DS_ADV_SLICE_WRITE ({dset_name_for_log}): Write attempted with data {{{ctx_p}_data_for_write!r}}'")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if data_for_write
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for write
                self.parent.write(0,
                           f"except Exception as e_adv_write: print(f'DS_ADV_SLICE_WRITE_ERR ({dset_name_for_log}) for slice {{{ctx_p}_adv_slice_obj!r}}: {{e_adv_write}}', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if writable block

                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for adv_slice_obj
                self.parent.write(0,
                           f"except Exception as e_adv_slice: print(f'DS_ADV_SLICE_ERR ({dset_name_for_log}) with slice obj {{repr(locals().get('{ctx_p}_adv_slice_obj', 'ERROR_GETTING_SLICE_OBJ'))}}: {{e_adv_slice}}', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Operations (within the 'if target_dset is not None:' block) ---

            # Access common properties
            properties_to_access = ["name", "shape", "dtype", "size", "chunks", "compression",
                                    "compression_opts", "fillvalue", "shuffle", "fletcher32",
                                    "scaleoffset", "maxshape", "file", "parent"]
            for prop_name in properties_to_access:
                self.parent.write(0,
                           f"try: print(f'''DS_PROP ({dset_name_for_log}): .{prop_name} = {{repr(getattr({ctx_p}_target_dset, '{prop_name}'))}} ''', file=sys.stderr)")
                self.parent.write(0,
                           f"except Exception as e_prop: print(f'''DS_PROP_ERR ({dset_name_for_log}) .{prop_name}: {{e_prop}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            # Call len()
            self.parent.write(0,
                       f"try: print(f'''DS_LEN ({dset_name_for_log}): len = {{len({ctx_p}_target_dset)}} ''', file=sys.stderr)")
            self.parent.write(0,
                       f"except Exception as e_len: print(f'''DS_LEN_ERR ({dset_name_for_log}): {{e_len}} ''', file=sys.stderr)")
            self.parent.emptyLine()

            # Call repr()
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

            # Call .asstr() (conditionally)
            if random() < 0.4:
                self.parent.write(0,
                           f"if {ctx_p}_is_string_like and {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")
                self.parent.addLevel(1)
                asstr_enc_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsStrEncoding_expr()
                asstr_err_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAsStrErrors_expr()
                self.parent.write(0, f"try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"{ctx_p}_asstr_view = {ctx_p}_target_dset.asstr(encoding={asstr_enc_expr}, errors={asstr_err_expr})")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASSTR ({dset_name_for_log}): view created with enc {asstr_enc_expr}, err {asstr_err_expr}. View repr: {{repr({ctx_p}_asstr_view)}} '''")
                self.parent.write(0, f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0:")
                self.parent.addLevel(1)
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASSTR ({dset_name_for_log}): first elem = {{repr({ctx_p}_asstr_view[tuple(0 for _ in range({ctx_p}_rank))])}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if not scalar
                self.parent.write(0, f"{ctx_p}_arr_from_asstr = numpy.array({ctx_p}_asstr_view)")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ASSTR ({dset_name_for_log}): converted to numpy array with shape {{ {ctx_p}_arr_from_asstr.shape }} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for asstr
                self.parent.write(0,
                           f"except Exception as e_asstr: print(f'''DS_ASSTR_ERR ({dset_name_for_log}) with enc {asstr_enc_expr}: {{e_asstr}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if is_string_like
            self.parent.emptyLine()

            # Call .fields() (conditionally)
            if random() < 0.3:
                self.parent.write(0,
                           f"if {ctx_p}_is_compound and {ctx_p}_dtype_obj is not None and {ctx_p}_dtype_obj.fields:")  # Check if fields exist
                self.parent.addLevel(1)
                self.parent.write(0, f"try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"field_names_tuple = tuple({ctx_p}_dtype_obj.fields.keys())")  # Get actual field names
                self.parent.write(0, f"if field_names_tuple:")  # If there are fields
                self.parent.addLevel(1)
                self.parent.write(0, f"field_to_access = choice(field_names_tuple)")
                self.parent.write(0,
                           f"if random() < 0.5: field_to_access = list(sample(field_names_tuple, k=min(len(field_names_tuple), randint(1,2))))")  # List of fields
                self.parent.write(0, f"{ctx_p}_fields_view = {ctx_p}_target_dset.fields(field_to_access)")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_FIELDS ({dset_name_for_log}): view for {{field_to_access}}. View repr: {{repr({ctx_p}_fields_view)}} '''")
                self.parent.write(0, f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0:")
                self.parent.addLevel(1)
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_FIELDS ({dset_name_for_log}): first elem = {{repr({ctx_p}_fields_view[tuple(0 for _ in range({ctx_p}_rank))])}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if not scalar
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if field_names_tuple
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try for fields
                self.parent.write(0,
                           f"except Exception as e_fields: print(f'''DS_FIELDS_ERR ({dset_name_for_log}): {{e_fields}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if is_compound
            self.parent.emptyLine()

            # Call .iter_chunks() (conditionally)
            if random() < 0.3:  # Your original chance
                self.parent.write(0,
                           f"if {ctx_p}_is_chunked and not {ctx_p}_is_empty_dataspace and {ctx_p}_rank is not None:")  # Added rank check
                self.parent.addLevel(1)
                # Use the new AG method, passing the name of the runtime rank variable
                sel_expr_iter = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(f"{ctx_p}_rank")

                self.parent.write(0, f"try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_selection_for_iter_chunks = {sel_expr_iter}")  # Evaluate the slice expression
                self.parent.write(0, f"{ctx_p}_chunk_count = 0")
                # Use the evaluated selection for iter_chunks
                self.parent.write(0,
                           f"for {ctx_p}_chunk_slice in {ctx_p}_target_dset.iter_chunks({ctx_p}_selection_for_iter_chunks if {ctx_p}_selection_for_iter_chunks is not None else None):")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_chunk_count += 1")
                self.parent.write(0,
                           f"if {ctx_p}_chunk_count % 10 == 0: print(f'''DS_ITER_CHUNKS ({dset_name_for_log}): processed {{ {ctx_p}_chunk_count }} chunks...''', file=sys.stderr)")
                self.parent.write(0, f"if {ctx_p}_chunk_count > {randint(5, 20)}: break")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit for loop
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_ITER_CHUNKS ({dset_name_for_log}): iterated {{ {ctx_p}_chunk_count }} chunks for selection {{{ctx_p}_selection_for_iter_chunks!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
                self.parent.write(0,
                           f"except Exception as e_iterchunks: print(f'''DS_ITER_CHUNKS_ERR ({dset_name_for_log}): {{e_iterchunks}} for selection {{{ctx_p}_selection_for_iter_chunks!r}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if is_chunked
            self.parent.emptyLine()

            # Call read_direct() / write_direct()
            if random() < 0.5 and not ctx_p + "_is_empty_dataspace" and f"{ctx_p}_rank is not None":
                # ...
                source_sel_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(f"{ctx_p}_rank")
                dest_sel_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySliceForDirectIO_expr_runtime(
                    f"{ctx_p}_rank")  # Or rank of dest array

                self.parent.write(0,
                           f"if {ctx_p}_shape is not None and product({ctx_p}_shape) > 0 and product({ctx_p}_shape) < 1000: # Only for reasonably small datasets")
                self.parent.addLevel(1)

                self.parent.write(0, f"try:")  # Outer try for this whole block
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_source_sel = {source_sel_expr}")
                self.parent.write(0, f"{ctx_p}_dest_sel = {dest_sel_expr}")

                # Create compatible numpy array for read_direct destination or write_direct source
                # This is still complex: the shape of np_arr_for_rd needs to match dest_sel applied to some array,
                # or be the full shape if dest_sel is None or Ellipsis.
                # And shape of np_arr_for_wd needs to match source_sel applied to it.
                # For now, a simplified approach: create a NumPy array of the *same shape as the dataset*
                # if selections are simple (like None or Ellipsis). If selections are complex, this becomes harder.

                self.parent.write(0, f"# For read_direct, np_arr_for_rd is destination")
                self.parent.write(0, f"try:")  # Try creating dest array
                self.parent.addLevel(1)
                # A more robust way to get shape for dest array if selection is complex is hard here.
                # For full copy or simple slice, using dataset's shape is okay.
                self.parent.write(0, f"{ctx_p}_np_arr_for_rd = numpy.empty(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")
                self.parent.write(0,
                           f"{ctx_p}_target_dset.read_direct({ctx_p}_np_arr_for_rd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_READ_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner try for read_direct
                self.parent.write(0,
                           f"except Exception as e_readdirect: print(f'''DS_READ_DIRECT_ERR ({dset_name_for_log}): {{e_readdirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} ''', file=sys.stderr)")

                self.parent.write(0, f"# For write_direct, np_arr_for_wd is source")
                self.parent.write(0, f"try:")  # Try creating source array
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"{ctx_p}_np_arr_for_wd = numpy.zeros(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")  # Or arange, random etc.
                # This source array should ideally match the shape implied by source_sel
                self.parent.write(0,
                           f"# Note: {ctx_p}_np_arr_for_wd shape should ideally match source_sel's effect on itself.")
                self.parent.write(0,
                           f"{ctx_p}_target_dset.write_direct({ctx_p}_np_arr_for_wd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_WRITE_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit inner try for write_direct
                self.parent.write(0,
                           f"except Exception as e_writedirect: print(f'''DS_WRITE_DIRECT_ERR ({dset_name_for_log}): {{e_writedirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}} ''', file=sys.stderr)")

                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit outer try
                self.parent.write(0,
                           f"except Exception as e_direct_io_setup: print(f'''DS_DIRECT_IO_SETUP_ERR ({dset_name_for_log}): {{e_direct_io_setup}} ''', file=sys.stderr)")

                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if shape is small
            self.parent.emptyLine()

            # __setitem__ with Fancy Indexing (more targeted if possible)
            if random() < 0.15:
                self.parent.write(0,
                           f"if {ctx_p}_rank >= 2 and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and {ctx_p}_shape[1] > 2:")  # Condition for this specific fancy index
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0,
                           f"{ctx_p}_fancy_indices = sorted(sample(range({ctx_p}_shape[1]), k=min({ctx_p}_shape[1], randint(1,3))))")
                # Shape of block_data needs to match dataset[:, fancy_indices, ...].shape
                self.parent.write(0, f"{ctx_p}_block_shape = list({ctx_p}_shape)")
                self.parent.write(0, f"{ctx_p}_block_shape[1] = len({ctx_p}_fancy_indices)")
                self.parent.write(0,
                           f"{ctx_p}_block_data = numpy.zeros(tuple({ctx_p}_block_shape), dtype={ctx_p}_dtype_obj)")  # Or random data
                self.parent.write(0, f"{ctx_p}_target_dset[:, {ctx_p}_fancy_indices, ...] = {ctx_p}_block_data")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_FANCY_SETITEM ({dset_name_for_log}): success with indices {{{ctx_p}_fancy_indices}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
                self.parent.write(0,
                           f"except Exception as e_fancyitem: print(f'''DS_FANCY_SETITEM_ERR ({dset_name_for_log}): {{e_fancyitem}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if rank >=2
            self.parent.emptyLine()

            # Iteration
            if random() < 0.3:
                self.parent.write(0,
                           f"if not {ctx_p}_is_scalar and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and not {ctx_p}_is_empty_dataspace:")  # Can iterate if not scalar and first dim > 0
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_iter_count = 0")
                self.parent.write(0, f"for {ctx_p}_row in {ctx_p}_target_dset:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_iter_count += 1")
                self.parent.write(0, f"if {ctx_p}_iter_count > {randint(3, 7)}: break")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit for
                self.parent.write_print_to_stderr(0, f"f'''DS_ITER ({dset_name_for_log}): iterated {{{ctx_p}_iter_count}} rows'''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
                self.parent.write(0,
                           f"except Exception as e_iter: print(f'''DS_ITER_ERR ({dset_name_for_log}): {{e_iter}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if not scalar
            self.parent.emptyLine()

            # Comparisons
            if random() < 0.3:
                comp_val_expr = self.parent.arg_generator.h5py_argument_generator.genNumpyValueForComparison_expr(f"{ctx_p}_dtype_str")
                self.parent.write(0, f"if {ctx_p}_dtype_str is not None:")  # Only if dtype context was obtained
                self.parent.addLevel(1)
                self.parent.write(0, "try:")
                self.parent.addLevel(1)
                self.parent.write(0, f"{ctx_p}_comp_val = {comp_val_expr}")
                self.parent.write(0, f"{ctx_p}_is_equal = ({ctx_p}_target_dset == {ctx_p}_comp_val)")
                self.parent.write(0, f"{ctx_p}_is_not_equal = ({ctx_p}_target_dset != {ctx_p}_comp_val)")
                self.parent.write_print_to_stderr(0,
                                           f"f'''DS_COMPARE ({dset_name_for_log}): == type {{type({ctx_p}_is_equal).__name__}}, != type {{type({ctx_p}_is_not_equal).__name__}} '''")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
                self.parent.write(0,
                           f"except Exception as e_compare: print(f'''DS_COMPARE_ERR ({dset_name_for_log}): {{e_compare}} ''', file=sys.stderr)")
                self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if dtype_str
            self.parent.emptyLine()

            # Access some .id properties
            if random() < 0.2:
                id_props_to_get = ["get_type()", "get_create_plist()", "get_access_plist()",
                                   "get_offset()", "get_storage_size()"]
                for id_prop_call in id_props_to_get:
                    self.parent.write(0,
                               f"try: print(f'''DS_ID_PROP ({dset_name_for_log}): .id.{id_prop_call} result = {{repr({ctx_p}_target_dset.id.{id_prop_call})}} ''', file=sys.stderr)")
                    self.parent.write(0,
                               f"except Exception as e_id_prop: print(f'''DS_ID_PROP_ERR ({dset_name_for_log}) .id.{id_prop_call}: {{e_id_prop}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            self.parent.restoreLevel(self.parent.base_level - 1)  # Exit 'if target_dset is not None:'
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                       f'f"Skipping dataset operations for {dset_name_for_log} as target_dset is None."')
            self.parent.restoreLevel(self.parent.base_level - 1)  # Exit else
            # self.parent.restoreLevel(self.parent.base_level - 1)  # Exit operations on valid dataset
        finally:
            self.parent.restoreLevel(L_main_if_dset_not_none)
        self.parent.emptyLine()

    def _fuzz_one_file_instance(self, file_expr_str: str, file_name_for_log: str, prefix: str, generation_depth: int):
        """
        Generates code to perform a variety of operations on a given h5py.File instance.
        Args:
            file_expr_str: Python expression string for the File instance.
            file_name_for_log: Clean name for logging.
            prefix: Logging prefix for generating unique variable names.
            generation_depth: Current depth of fuzzing code generation.
        """
        self.parent.write_print_to_stderr(0,
                                   f'f"--- (Depth {generation_depth}) Fuzzing File Instance: {file_name_for_log} (var: {file_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()

        ctx_p = f"ctx_{prefix}_file"  # Unique context prefix for this file fuzzing operation

        self.parent.write(0, f"{ctx_p}_target_file = {file_expr_str}")
        # Check if the file object is not None AND if its ID is valid (i.e., file is open)
        self.parent.write(0,
                   f"if {ctx_p}_target_file is not None and hasattr({ctx_p}_target_file, 'id') and {ctx_p}_target_file.id and {ctx_p}_target_file.id.valid:")
        # ---- BLOCK: Main if target_file is valid and open ----
        L_main_if_file_valid = self.parent.addLevel(1)
        try:
            # --- Basic File Properties ---
            file_properties = ["filename", "driver", "libver", "userblock_size", "mode", "swmr_mode", "name", "parent",
                               "attrs"]
            for prop_name in file_properties:
                self.parent.write(0, "try:")
                L_prop_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_prop_val = getattr({ctx_p}_target_file, '{prop_name}')")
                    self.parent.write_print_to_stderr(0,
                                               f"f'FILE_PROP ({file_name_for_log}): .{prop_name} = {{{ctx_p}_prop_val!r}}'")
                    # Deep dive into .attrs
                    if prop_name == "attrs":
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_attrs", f"{ctx_p}_prop_val", "AttributeManager",
                                                        generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_prop_try)
                self.parent.write(0,
                           f"except Exception as e_prop: print(f'FILE_PROP_ERR ({file_name_for_log}) .{prop_name}: {{e_prop}}', file=sys.stderr)")
            self.parent.emptyLine()

            # --- Iteration, Keys, Values, Items (on the root group) ---
            if random() < 0.5:
                self.parent.write(0, "try:")
                L_iter_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_file_len = len({ctx_p}_target_file)")  # Number of items in root group
                    self.parent.write_print_to_stderr(0, f"f'FILE_LEN ({file_name_for_log}): len = {{{ctx_p}_file_len}}'")
                    self.parent.write(0, f"if {ctx_p}_file_len > 0:")
                    L_iter_if_not_empty = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_iter_count = 0")
                        self.parent.write(0, f"for {ctx_p}_key in {ctx_p}_target_file:")  # Iterates keys in root group
                        L_iter_for = self.parent.addLevel(1)
                        try:
                            self.parent.write_print_to_stderr(0,
                                                       f"f'FILE_ITER ({file_name_for_log}): key = {{{ctx_p}_key!r}}'")
                            self.parent.write(0, f"{ctx_p}_iter_count += 1")
                            self.parent.write(0, f"if {ctx_p}_iter_count > 5: break")
                        finally:
                            self.parent.restoreLevel(L_iter_for)
                        self.parent.write_print_to_stderr(0,
                                                   f"f'FILE_ITER ({file_name_for_log}): iterated {{{ctx_p}_iter_count}} keys'")

                        self.parent.write(0, f"{ctx_p}_keys_view = {ctx_p}_target_file.keys()")
                        self.parent.write_print_to_stderr(0,
                                                   f"f'FILE_KEYS ({file_name_for_log}): {{len({ctx_p}_keys_view)}} keys, e.g., {{list({ctx_p}_keys_view)[:3]!r}}'")
                        # ... (similar for .values() and .items()) ...
                    finally:
                        self.parent.restoreLevel(L_iter_if_not_empty)
                finally:
                    self.parent.restoreLevel(L_iter_try)
                self.parent.write(0,
                           "except Exception as e_file_iter: print(f'FILE_ITER_METHODS_ERR ({file_name_for_log}): {{e_file_iter}}', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Create Top-Level Children (Dataset, Group) & Deep Dive ---
            # Create Dataset
            if random() < 0.3:  # self.options.get("file_create_dataset_chance", 0.3):  # Configurable chance
                ds_name_expr = f"'{_h5_unique_name(f'ds_{prefix}')}'"
                ds_instance_var = f"{prefix}_new_ds_in_file"
                self.parent.write(0, f"{ds_instance_var} = None")
                # Call the existing dataset creation logic, parent is the file object
                self._write_h5py_dataset_creation_call(f"{ctx_p}_target_file", ds_name_expr, ds_instance_var)
                self.parent.write(0, f"if {ds_instance_var} is not None:")
                L_dd_ds = self.parent.addLevel(1)
                try:
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_ds", ds_instance_var, "Dataset",
                                                    generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_dd_ds)

            # Create Group
            if random() < 0.3:  # self.options.get("file_create_group_chance", 0.3):  # Configurable chance
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
                        # Add to runtime_objects if you want other parts of fuzzing to find it
                        self.parent.write(0, f"h5py_runtime_objects[{new_grp_name_expr.strip(chr(39))}] = {new_grp_var}")
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_grp", new_grp_var, "Group",
                                                        generation_depth + 1)
                    finally:
                        self.parent.restoreLevel(L_dd_grp)
                finally:
                    self.parent.restoreLevel(L_cgrp_try)
                self.parent.write(0,
                           f"except Exception as e_cgrp_file: print(f'''FILE_OP_ERR ({file_name_for_log}) creating group {new_grp_name_expr}: {{e_cgrp_file}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Access Existing Top-Level Item & Deep Dive ---
            if random() < 0.4:
                self.parent.write(0, f"if len({ctx_p}_target_file) > 0:")
                L_access_item_if = self.parent.addLevel(1)
                try:
                    self.parent.write(0, "try:")
                    L_access_item_try = self.parent.addLevel(1)
                    try:
                        self.parent.write(0, f"{ctx_p}_item_to_access_name = choice(list({ctx_p}_target_file.keys()))")
                        self.parent.write(0, f"{ctx_p}_resolved_top_item = {ctx_p}_target_file[{ctx_p}_item_to_access_name]")
                        self.parent.write_print_to_stderr(0,
                                                   f"f'''FILE_OP ({file_name_for_log}): Accessed top-level item {{{ctx_p}_item_to_access_name!r}}: {{{ctx_p}_resolved_top_item!r}} '''")

                        self.parent.write(0, f"{ctx_p}_resolved_top_item_type_name = type({ctx_p}_resolved_top_item).__name__")
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

            # --- require_group / require_dataset ---
            if random() < 0.3:
                req_grp_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                self.parent.write(0, "try:")
                L_req_grp_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_req_grp = {ctx_p}_target_file.require_group({req_grp_name_expr})")
                    self.parent.write_print_to_stderr(0,
                                               f"f'''FILE_OP ({file_name_for_log}): require_group {req_grp_name_expr} -> {{{ctx_p}_req_grp!r}} '''")
                    # Deep dive on required group
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_req_grp", f"{ctx_p}_req_grp", "Group",
                                                    generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_req_grp_try)
                self.parent.write(0,
                           f"except Exception as e_reqg_file: print(f'''FILE_OP_ERR ({file_name_for_log}) require_group {req_grp_name_expr}: {{e_reqg_file}} ''', file=sys.stderr)")

            if random() < 0.3:
                req_ds_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                req_ds_shape_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
                req_ds_dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()  # Or complex
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

            # --- SWMR Mode (if libver is appropriate, usually 'latest') ---
            if random() < 0.1:
                self.parent.write(0,
                           f"if getattr({ctx_p}_target_file, 'libver', ('earliest','earliest'))[1] in ('latest', 'v110', 'v112', 'v114'):")  # Check if libver allows SWMR
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

            # --- Flush ---
            if random() < 0.2:
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

            # --- Close (low probability, as it ends interaction with this specific file object) ---
            if random() < 0.02:  # Very low chance
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

        finally:  # Corresponds to L_main_if_file_valid = self.parent.addLevel(1)
            self.parent.restoreLevel(L_main_if_file_valid)
        # ---- END BLOCK: Main if target_file is valid and open ----
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
        Generates code to perform a variety of operations on a given h5py.Group instance,
        including link creation/manipulation and deep diving into children.
        Args:
            group_expr_str: Python expression string for the group instance.
            group_name_for_log: Clean name for logging.
            prefix: Logging prefix for generating unique variable names.
            generation_depth: Current depth of fuzzing code generation.
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
                    self.parent.write_print_to_stderr(0,
                                               f"f'GRP_PROP ({group_name_for_log}): .{prop_name} = {{repr(getattr({ctx_p}_target_grp, '{prop_name}'))}}'")
                    # Deep dive into .attrs
                    if prop_name == "attrs":
                        self.parent.write(0, f"{ctx_p}_attrs_obj = {ctx_p}_target_grp.attrs")
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_attrs", f"{ctx_p}_attrs_obj", "AttributeManager",
                                                        generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_prop_try)
                self.parent.write(0,
                           f"except Exception as e_prop: print(f'GRP_PROP_ERR ({group_name_for_log}) .{prop_name}: {{e_prop}}', file=sys.stderr)")
            self.parent.emptyLine()

            self.parent.write(0, "try:")
            L_len_try = self.parent.addLevel(1)
            try:
                self.parent.write_print_to_stderr(0, f"f'GRP_LEN ({group_name_for_log}): len = {{len({ctx_p}_target_grp)}}'")
            finally:
                self.parent.restoreLevel(L_len_try)
            self.parent.write(0,
                       f"except Exception as e_len: print(f'GRP_LEN_ERR ({group_name_for_log}): {{e_len}}', file=sys.stderr)")
            self.parent.emptyLine()

            if random() < 0.5:
                self.parent.write(0, "try:")
                L_iter_methods_try = self.parent.addLevel(1)
                try:
                    self.parent.write(0, f"{ctx_p}_iter_count = 0")
                    self.parent.write(0, f"for {ctx_p}_key in {ctx_p}_target_grp:")
                    L_iter_for = self.parent.addLevel(1)
                    try:
                        self.parent.write_print_to_stderr(0, f"f'GRP_ITER ({group_name_for_log}): key = {{{ctx_p}_key!r}}'")
                        self.parent.write(0, f"{ctx_p}_iter_count += 1")
                        self.parent.write(0, f"if {ctx_p}_iter_count > 5: break")
                    finally:
                        self.parent.restoreLevel(L_iter_for)
                    self.parent.write_print_to_stderr(0,
                                               f"f'GRP_ITER ({group_name_for_log}): iterated {{{ctx_p}_iter_count}} keys'")

                    self.parent.write(0, f"{ctx_p}_keys_view = {ctx_p}_target_grp.keys()")
                    self.parent.write_print_to_stderr(0,
                                               f"f'GRP_KEYS ({group_name_for_log}): {{len({ctx_p}_keys_view)}} keys, e.g., {{list({ctx_p}_keys_view)[:3]!r}}'")
                    # ... (values, items similar to previous version) ...
                finally:
                    self.parent.restoreLevel(L_iter_methods_try)
                self.parent.write(0,
                           "except Exception as e_grp_iter: print(f'GRP_ITER_METHODS_ERR ({group_name_for_log}): {{e_grp_iter}}', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Create Children (Dataset, Group) with deep dive ---
            if random() < 0.4:  # Dynamic Dataset
                ds_name_expr = f"'{_h5_unique_name(f'ds_{prefix}')}'"
                ds_instance_var = f"{prefix}_new_ds_in_grp"  # Make var name unique
                self.parent.write(0, f"{ds_instance_var} = None")
                self._write_h5py_dataset_creation_call(f"{ctx_p}_target_grp", ds_name_expr, ds_instance_var)
                self.parent.write(0, f"if {ds_instance_var} is not None:")
                L_dd_ds = self.parent.addLevel(1)
                try:
                    self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_ds", ds_instance_var, "Dataset",
                                                    generation_depth + 1)
                finally:
                    self.parent.restoreLevel(L_dd_ds)

            if random() < 0.3:  # Dynamic Group
                new_grp_name_expr = f"'{_h5_unique_name(f'subgrp_{prefix}')}'"
                new_grp_var = f"{prefix}_new_subgrp_in_grp"  # Unique var name
                self.parent.write(0, f"{new_grp_var} = None")
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
                                   f"h5py_runtime_objects[{new_grp_name_expr.strip(chr(39))}] = {new_grp_var}")  # Add to runtime objects
                        self.parent._dispatch_fuzz_on_instance(f"{prefix}_child_grp", new_grp_var, "Group",
                                                        generation_depth + 1)
                    finally:
                        self.parent.restoreLevel(L_dd_grp)
                finally:
                    self.parent.restoreLevel(L_cgrp_try)
                self.parent.write(0,
                           f"except Exception as e_cgrp: print(f'''GRP_OP_ERR ({group_name_for_log}) creating subgroup {new_grp_name_expr}: {{e_cgrp}} ''', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Link Creation Operations ---
            link_op_prefix = f"{prefix}_link"  # Prefix for link operation variables

            # Create SoftLink
            if random() < 0.3:
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

            # Create ExternalLink
            if random() < 0.2:  # and "_h5_external_target_file" in self.parent_python_source.generated_script_globals: (this check is hard here)
                # Assume _h5_external_target_file is defined in the generated script's global scope
                new_elink_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                ext_file_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyExternalLinkFilename_expr(
                    "getattr(_h5_external_target_file, 'filename', 'missing_ext_file.h5') if '_h5_external_target_file' in globals() and _h5_external_target_file else 'dangling_ext_file.h5'")
                ext_internal_path_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyLinkPath_expr("'/'")  # Path inside the external file
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

            # Create HardLink
            if random() < 0.3:
                new_hlink_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                existing_object_to_link_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyExistingObjectPath_expr(f"{ctx_p}_target_grp")
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
                        # ... (print SoftLink.path, ExternalLink.filename/path, h5l.get_info as before) ...
                    finally:
                        self.parent.restoreLevel(L_inspect_try)
                    self.parent.write(0,
                               "except Exception as e_getlink: print(f'GRP_OP_ERR ({group_name_for_log}) getting link object: {{e_getlink}}', file=sys.stderr)")
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
                                   f"{ctx_p}_resolved_item_type_name_for_dispatch = type({ctx_p}_resolved_item).__name__")  # Get runtime type name
                        self.parent.write(0,
                                   f"if isinstance({ctx_p}_resolved_item, (h5py.Group, h5py.Dataset, h5py.AttributeManager)):")  # Add AttributeManager
                        L_access_if_fuzzable = self.parent.addLevel(1)
                        try:
                            self.parent.write_print_to_stderr(0,
                                                       f"f'''GRP_OP ({group_name_for_log}): Resolved item {{{ctx_p}_item_to_access_name!r}} is fuzzable, dispatching deep dive.'''")
                            self.parent._dispatch_fuzz_on_instance(
                                f"{prefix}_resolved_{str(uuid.uuid4())[:4]}",  # Unique prefix
                                f"{ctx_p}_resolved_item",
                                f"{ctx_p}_resolved_item_type_name_for_dispatch",  # Pass the runtime type name string
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
            # ... (similar try/finally structure for these if they use addLevel internally, but they are simple calls usually)
            if random() < 0.2:
                req_grp_name = self.parent.arg_generator.h5py_argument_generator.genH5PyNewLinkName_expr()
                self.parent.write(0,
                           f"try: {ctx_p}_req_grp = {ctx_p}_target_grp.require_group({req_grp_name}); print(f'''GRP_OP ({group_name_for_log}): require_group {req_grp_name} -> {{{ctx_p}_req_grp!r}} ''', file=sys.stderr)")
                self.parent.write(0,
                           f"except Exception as e_reqg: print(f'''GRP_OP_ERR ({group_name_for_log}) require_group {req_grp_name}: {{e_reqg}} ''', file=sys.stderr)")
            # ... (similar for require_dataset) ...

        finally:  # Corresponds to L_main_if_grp_valid = self.parent.addLevel(1)
            self.parent.restoreLevel(L_main_if_grp_valid)
        # ---- END BLOCK: Main if target_grp is not None ----
        self.parent.write(0, "else:")
        L_else_grp_invalid = self.parent.addLevel(1)
        try:
            self.parent.write_print_to_stderr(0,
                                       f'f"Skipping group operations for {group_name_for_log} as its variable ({group_expr_str}) is None or not Group."')
        finally:
            self.parent.restoreLevel(L_else_grp_invalid)
        self.parent.emptyLine()

    def _write_h5py_file(self):
        # In WritePythonCode._write_h5py_file(self):

        # 1. Get actual driver and mode strings first
        actual_driver = self.parent.arg_generator.h5py_argument_generator.genH5PyFileDriver_actualval()  # New AG method
        actual_mode = self.parent.arg_generator.h5py_argument_generator.genH5PyFileMode_actualval()  # New AG method

        driver_expr = f"'{actual_driver}'" if actual_driver else "None"
        mode_expr = f"'{actual_mode}'"

        # 2. Determine if backing store is True for core driver (affects path generation)
        #    This info should come from genH5PyDriverKwargs based on actual_driver
        #    Let's assume driver_kwargs_str_list and driver_kwargs_expr are generated here.
        #    For simplicity, assume a helper:
        #    is_core_backing = (actual_driver == 'core' and self.parent.arg_generator.is_core_backing_store_enabled_in_kwargs(...))
        is_core_backing = False  # Placeholder, needs logic based on generated driver_kwargs
        driver_kwargs_expr = None
        if actual_driver == 'core':
            # A simplified way to decide: if driver_kwargs mentions backing_store=True
            # This is still a bit messy; genH5PyDriverKwargs ideally should not produce
            # incompatible options with driver='core', backing_store=False if path is just an ID.
            # The generation of driver_kwargs needs to be smarter.
            # For now, let's assume it's generated:
            driver_kwargs_str_list = self.parent.arg_generator.h5py_argument_generator.genH5PyDriverKwargs(actual_driver)
            driver_kwargs_expr = "".join(driver_kwargs_str_list)
            if "backing_store=True" in driver_kwargs_expr:
                is_core_backing = True

        # 3. Generate the file name or object expression
        #    This is a crucial change. gen_h5py_file_name_or_object needs to be implemented in AG.
        #    It might return a variable name like 'temp_file_path_xyz' if it means a disk file.
        name_arg_expression, setup_code_lines = self.parent.arg_generator.h5py_argument_generator.gen_h5py_file_name_or_object(
            actual_driver, actual_mode, is_core_backing
        )

        for line in setup_code_lines:  # If gen_... needs to emit setup code (e.g. creating tempfile path variable)
            self.parent.write(0, line)

        # 4. Generate other kwargs
        libver_expr = "".join(self.parent.arg_generator.h5py_argument_generator.genH5PyLibver())
        userblock_val_str = "".join(self.parent.arg_generator.h5py_argument_generator.genH5PyUserblockSize())  # e.g., "512"
        locking_expr = "".join(self.parent.arg_generator.h5py_argument_generator.genH5PyLocking())
        fs_kwargs_expr = ""  # Default to empty

        all_kwargs = []
        if actual_driver: all_kwargs.append(f"driver={driver_expr}")
        if driver_kwargs_expr: all_kwargs.append(driver_kwargs_expr)  # This should be just the kwargs string
        if libver_expr != "None": all_kwargs.append(f"libver={libver_expr}")
        if locking_expr != "None": all_kwargs.append(f"locking={locking_expr}")

        # Conditional creation-only parameters
        if actual_mode in ('w', 'w-', 'x'):  # Only for pure creation modes
            if userblock_val_str != "0":
                all_kwargs.append(f"userblock_size={userblock_val_str}")

            # Your fs_strategy tweak - apply only for creation modes
            if randint(0, 9) > 1:  # Reduced chance further from your "> 8" if still too many errors
                fs_kwargs_str_list_temp = self.parent.arg_generator.h5py_argument_generator.genH5PyFsStrategyKwargs()
                fs_kwargs_expr_temp = "".join(fs_kwargs_str_list_temp)
                if fs_kwargs_expr_temp:  # Only add if it generated something
                    all_kwargs.append(fs_kwargs_expr_temp)
                    fs_kwargs_expr = fs_kwargs_expr_temp  # Store it for logging

        kwargs_final_str = ", ".join(filter(None, all_kwargs))

        # 5. Write the h5py.File call
        self.parent.write(0, f"new_file_obj = None # Initialize before try block")  # Good practice
        self.parent.write(0, f"try:")
        self.parent.addLevel(1)
        self.parent.write(0, f"new_file_obj = h5py.File({name_arg_expression}, mode={mode_expr}, {kwargs_final_str})")
        self.parent.write(0, f"if new_file_obj: # Check if successfully created")
        self.parent.addLevel(1)
        self.parent.write(0, f"h5py_tricky_objects['runtime_file_{uuid.uuid4().hex[:4]}'] = new_file_obj")
        self.parent.write(0, f"_h5_internal_files_to_keep_open_.append(new_file_obj)")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try

        self.parent.write(0, f"except Exception as e_file_create:")
        # The original had new_file_obj = None inside except, but it's already None if exception occurs
        self.parent.addLevel(1)
        # Using triple quotes for the f-string in print to handle potential quotes in expressions
        self.parent.write(0,
                   f"print(f'''FUZZ_RUNTIME_WARN: Failed to create h5py.File({name_arg_expression}, {mode_expr}, {kwargs_final_str}): {{e_file_create.__class__.__name__}} {{e_file_create}} ''', file=sys.stderr)")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit except
        self.parent.emptyLine()

    def _write_h5py_dataset_creation_call(
            self, parent_obj_expr: str, dataset_name_expr: str, instance_var_name: str
    ):
        """
        Generates and writes a call to parent_obj_expr.create_dataset()
        with fuzzed parameters. The result (or None on failure) is assigned
        to instance_var_name.
        """
        self.parent.write(0, f"# Dynamically creating dataset: {dataset_name_expr} on {parent_obj_expr}")

        # Generate parameters using ArgumentGenerator
        # For Category B, we primarily use simple dtypes.
        # Data generation is tricky to make always compatible with shape/dtype via string expr.
        # It's often safer to create dataset first, then write data.
        # Or, create with shape and dtype, and let h5py handle/error on data.

        shape_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetShape_expr()
        if random() < 0.4:  # 40% chance to try a complex dtype
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyComplexDtype_expr()
            # Data generation for complex dtypes is hard; often best to omit data or use h5py.Empty
            if random() < 0.8 or "vlen" in dtype_expr or "enum" in dtype_expr:  # Higher chance to omit data for these
                data_expr = "None"
            else:  # For simpler compound or array dtypes, might try to generate some zeros
                data_expr = f"numpy.zeros({shape_expr}, dtype={dtype_expr})" if shape_expr != "None" and shape_expr != "()" else "None"

            # Special case for h5py.Empty which needs a dtype but not shape/data
            if shape_expr == "None" and data_expr == "None":
                data_expr = f"h5py.Empty(dtype={dtype_expr})"
                # Shape should remain None if data is h5py.Empty
        else:
            dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()
            data_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyData_expr(shape_expr, dtype_expr)  # Existing logic

        # Most other parameters are kwargs
        kwargs_list = []
        if data_expr != "None":
            kwargs_list.append(f"data={data_expr}")

        # Chunks: scaleoffset needs chunks. Some compression benefits from chunks.
        # maxshape always implies chunks (auto-created if not specified).
        chunks_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyDatasetChunks_expr(shape_expr)
        if chunks_expr != "None":  # Only add if not default contiguous
            kwargs_list.append(f"chunks={chunks_expr}")
            # If chunks are being set, it's safer to also set maxshape if we want resizability
            if random() < 0.5:  # Chance to add maxshape if chunked
                kwargs_list.append(f"maxshape={self.parent.arg_generator.h5py_argument_generator.genH5PyMaxshape_expr(shape_expr)}")

        # Fillvalue and FillTime
        # fillvalue needs to be compatible with dtype.
        # genH5PyFillvalue_expr tries to do this for simple dtypes.
        if random() < 0.7:  # 70% chance to specify fillvalue
            fv_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None":  # if generator provided something specific
                kwargs_list.append(f"fillvalue={fv_expr}")

        if random() < 0.5:  # 50% chance to specify fill_time
            kwargs_list.append(f"fill_time={self.parent.arg_generator.h5py_argument_generator.genH5PyFillTime_expr()}")

        # Compression and other filters
        compression_kwargs = self.parent.arg_generator.h5py_argument_generator.genH5PyCompressionKwargs_expr()  # This returns a list of "kw=val"
        kwargs_list.extend(compression_kwargs)

        # Track times
        if random() < 0.5:
            kwargs_list.append(f"track_times={self.parent.arg_generator.h5py_argument_generator.genH5PyTrackTimes_expr()}")

        # Assemble the create_dataset call string
        # Base parameters are shape and dtype, others are kwargs
        # Handle cases: shape only, dtype only (for null dataspace), shape+dtype, or data only

        kwds_for_create = {}  # Use a dict then format
        if shape_expr != "None": kwds_for_create['shape'] = shape_expr
        if dtype_expr != "None": kwds_for_create['dtype'] = dtype_expr  # Always good to have dtype
        if data_expr != "None": kwds_for_create['data'] = data_expr

        # Add other kwargs from kwargs_list (which are already "key=value" strings)
        # This needs refinement. Let's make kwargs_list a list of (key_str, value_expr_str) tuples
        # from ArgumentGenerator, then format them here.

        # Simplified:
        # Assume genH5PyCompressionKwargs_expr returns a list of "kw=val" strings
        # All generated parameters should be in kwargs_list as "key=value" strings.

        # Let's redefine how kwargs are collected:
        all_kwargs_dict = {}
        if shape_expr != "None": all_kwargs_dict["shape"] = shape_expr
        all_kwargs_dict["dtype"] = dtype_expr  # dtype is good to provide generally, or from data
        if data_expr != "None": all_kwargs_dict["data"] = data_expr

        if chunks_expr != "None": all_kwargs_dict["chunks"] = chunks_expr
        if random() < 0.5 and "chunks" in all_kwargs_dict:  # maxshape often with chunks
            all_kwargs_dict["maxshape"] = self.parent.arg_generator.h5py_argument_generator.genH5PyMaxshape_expr(shape_expr)

        if random() < 0.7:
            fv_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None": all_kwargs_dict["fillvalue"] = fv_expr
        if random() < 0.5:
            all_kwargs_dict["fill_time"] = self.parent.arg_generator.h5py_argument_generator.genH5PyFillTime_expr()

        compression_kwargs_strings = self.parent.arg_generator.h5py_argument_generator.genH5PyCompressionKwargs_expr()  # list of "key=val"
        for comp_kw_str in compression_kwargs_strings:
            key, val = comp_kw_str.split('=', 1)
            all_kwargs_dict[key] = val  # Assumes val is already a valid expression string

        if random() < 0.5:
            all_kwargs_dict["track_times"] = self.parent.arg_generator.h5py_argument_generator.genH5PyTrackTimes_expr()

        final_kwargs_str = ", ".join(f"{k}={v}" for k, v in all_kwargs_dict.items() if v is not None)

        self.parent.write(0, f"try:")
        self.parent.addLevel(1)
        self.parent.write(0,
                   f"{instance_var_name} = {parent_obj_expr}.create_dataset({dataset_name_expr}, {final_kwargs_str})")
        self.parent.write(0, f"if {instance_var_name}:")
        self.parent.addLevel(1)
        # Using a different dict key for runtime created datasets for clarity
        self.parent.write(0, f"h5py_runtime_objects['{dataset_name_expr.strip(chr(39))}'] = {instance_var_name}")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit if
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit try
        self.parent.write(0, f"except Exception as e_dset_create:")
        self.parent.addLevel(1)
        # instance_var_name should already be None if try block failed before assignment or if create_dataset returned None
        self.parent.write(0, f"{instance_var_name} = None")  # Ensure it's None on error
        # Using triple quotes for the f-string in print
        self.parent.write(0, f"try:")
        self.parent.write_print_to_stderr(
            1,
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {dataset_name_expr} on {{ {parent_obj_expr} }} "
            f"with args {{ repr(dict({final_kwargs_str})) }}: "  # Log evaluated args if possible, or raw string
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}} '''"
        )
        self.parent.write(0, f"except Exception as e_dset_print_error:")
        self.parent.write(1, f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {dataset_name_expr} on {{ {parent_obj_expr} }} "
            f"with args ERROR_PRINTING_ARGS: "
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}} '''")
        self.parent.restoreLevel(self.parent.base_level - 1)  # Exit except
        self.parent.emptyLine()

    def _fuzz_one_attributemanager_instance(self, attrs_expr_str: str, owner_name_for_log: str, prefix: str,
                                            generation_depth: int):
        self.parent.write_print_to_stderr(0,
                                   f'f"--- (Depth {generation_depth}) Fuzzing AttributeManager for {owner_name_for_log} (var: {attrs_expr_str}, prefix: {prefix}) ---"')
        self.parent.emptyLine()
        ctx_p = f"ctx_{prefix}"

        self.parent.write(0, f"{ctx_p}_target_attrs = {attrs_expr_str}")
        self.parent.write(0, f"if {ctx_p}_target_attrs is not None:")
        # ---- BLOCK: Main if target_attrs not None ----
        L_main_if_attrs = self.parent.addLevel(1)
        self.parent.write(0, "'INDENTED BLOCK'")
        try:
            # --- Basic AttributeManager Operations ---
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
                                                   f"f'ATTR_ITER ({owner_name_for_log}): key = {{{ctx_p}_attr_name!r}}'")
                        self.parent.write(0, f"{ctx_p}_attr_count += 1")
                        self.parent.write(0, f"if {ctx_p}_attr_count > 5: break")
                    finally:
                        self.parent.restoreLevel(L_iter_for)
                    self.parent.write_print_to_stderr(0,
                                               f"f'ATTR_ITER ({owner_name_for_log}): iterated {{{ctx_p}_attr_count}} attrs'")
                    self.parent.write_print_to_stderr(0,
                                               f"f'ATTR_LEN ({owner_name_for_log}): len = {{len({ctx_p}_target_attrs)}}'")
                    self.parent.write(0,
                               f"if {ctx_p}_attr_count > 0: {ctx_p}_first_attr_name = list({ctx_p}_target_attrs.keys())[0]")  # Get a name for contains
                    self.parent.write(0,
                               f"if {ctx_p}_attr_count > 0: print(f'ATTR_CONTAINS ({owner_name_for_log}): {{{ctx_p}_first_attr_name!r}} in attrs = ({{{ctx_p}_first_attr_name!r}} in {ctx_p}_target_attrs)', file=sys.stderr)")
                finally:
                    self.parent.restoreLevel(L_iter_try)
                self.parent.write(0,
                           "except Exception as e_attr_iter: print(f'ATTR_ITER_ERR ({owner_name_for_log}): {{e_attr_iter}}', file=sys.stderr)")
                self.parent.emptyLine()

            # --- Create/Modify Attributes ---
            if random() < 0.6:
                num_attr_ops = randint(1, 3)
                for i in range(num_attr_ops):
                    attr_name_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyAttributeName_expr()  # Needs to be defined in AG
                    # For AttributeValue, it can be simple types, strings, or small numpy arrays
                    # Let's use a generic value generator for now, or a specialized one.
                    attr_val_dtype_expr = self.parent.arg_generator.h5py_argument_generator.genH5PySimpleDtype_expr()  # For numpy array attr
                    attr_val_shape_expr = choice(["()", "(randint(1,3),)"])
                    attr_val_expr = self.parent.arg_generator.h5py_argument_generator.genH5PyData_expr(attr_val_shape_expr,
                                                                        attr_val_dtype_expr)  # Reuse for data

                    self.parent.write(0, f"# Attribute operation {i + 1}")
                    self.parent.write(0, "try:")
                    L_attr_op_try = self.parent.addLevel(1)
                    try:
                        # Could be create, modify, get, delete
                        op_choice = random()
                        if op_choice < 0.5:  # __setitem__ / create / modify
                            self.parent.write(0, f"{ctx_p}_target_attrs[{attr_name_expr}] = {attr_val_expr}")
                            self.parent.write_print_to_stderr(0,
                                                       f"f'ATTR_SET ({owner_name_for_log}): Set/Create attr {{{attr_name_expr!r}}} = {{{attr_val_expr!r}}} (actual: {{repr({ctx_p}_target_attrs.get({attr_name_expr}))}})'")
                        elif op_choice < 0.8:  # __getitem__ / get
                            self.parent.write(0, f"{ctx_p}_read_attr_val = {ctx_p}_target_attrs[{attr_name_expr}]")
                            self.parent.write_print_to_stderr(0,
                                                       f"f'ATTR_GET ({owner_name_for_log}): Got attr {{{attr_name_expr!r}}} = {{{ctx_p}_read_attr_val!r}}'")
                        else:  # __delitem__
                            self.parent.write(0, f"del {ctx_p}_target_attrs[{attr_name_expr}]")
                            self.parent.write_print_to_stderr(0,
                                                       f"f'ATTR_DEL ({owner_name_for_log}): Deleted attr {{{attr_name_expr!r}}}'")
                    finally:
                        self.parent.restoreLevel(L_attr_op_try)
                    self.parent.write(0,
                               f"except Exception as e_attr_mod: print(f'ATTR_MOD_ERR ({owner_name_for_log}) with name {{{attr_name_expr!r}}}: {{e_attr_mod}}', file=sys.stderr)")
                    self.parent.emptyLine()
        finally:
            self.parent.restoreLevel(L_main_if_attrs)
        # ---- END BLOCK: Main if target_attrs not None ----
        self.parent.write(0, "else:")
        L_else_attrs_is_none = self.parent.addLevel(1)
        try:
            self.parent.write_print_to_stderr(0,
                                       f"f'Skipping AttributeManager fuzz for {owner_name_for_log} as its variable ({attrs_expr_str}) is None.'")
        finally:
            self.parent.restoreLevel(L_else_attrs_is_none)
        self.parent.emptyLine()


    def fuzz_one_h5py_class(self, class_name_str, class_type, instance_var_name, prefix):
        is_h5py_class = False
        is_h5py_type = hasattr(class_type, "__module__") and \
                       class_type.__module__ and \
                       class_type.__module__.startswith("h5py")
        is_h5py_file = is_h5py_type and class_name_str == "File"  # Or issubclass(class_type, h5py.File)
        is_h5py_dataset = is_h5py_type and class_name_str == "Dataset"  # Or issubclass(class_type, h5py.Dataset)
        if is_h5py_file:
            is_h5py_class = True
            # Defines 'new_file_obj' in the generated script
            self._write_h5py_file()  # This was name from user's diff
            self.parent.write(0, f"{instance_var_name} = new_file_obj")
        elif is_h5py_dataset:
            is_h5py_class = True
            parent_obj_expr_str = "_h5_main_file"  # Or pick dynamically
            dataset_name_expr_str = f"'{_h5_unique_name(f'ds_{prefix}')}'"
            self.parent.write(0, f"if {parent_obj_expr_str} and hasattr({parent_obj_expr_str}, 'create_dataset'):")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")  # Init
            self._write_h5py_dataset_creation_call(parent_obj_expr_str, dataset_name_expr_str,
                                                               instance_var_name)
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                       f"f'Skipping dynamic Dataset creation for {instance_var_name} as parent is unavailable.'")
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.restoreLevel(self.parent.base_level - 1)
        elif is_h5py_type and class_name_str == "Group":  # Special handling for creating Groups
            is_h5py_class = True
            parent_obj_expr_str = "_h5_main_file"  # Or pick dynamically
            group_name_expr_str = f"'''{_h5_unique_name(f'grp_{prefix}')} '''"
            self.parent.write(0, f"if {parent_obj_expr_str} and hasattr({parent_obj_expr_str}, 'create_group'):")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")  # Init
            self.parent.write(0, "try:")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = {parent_obj_expr_str}.create_group({group_name_expr_str})")
            self.parent.write(0, f"h5py_runtime_objects[{group_name_expr_str.strip(chr(39))}] = {instance_var_name}")
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "except Exception as e_grp_create:")
            self.parent.addLevel(1)
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.write_print_to_stderr(0, f"f'Failed to create group {group_name_expr_str}: {{e_grp_create}}'")
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.restoreLevel(self.parent.base_level - 1)
            self.parent.write(0, "else:")
            self.parent.addLevel(1)
            self.parent.write_print_to_stderr(0,
                                       f"f'Skipping dynamic Group creation for {instance_var_name} as parent is unavailable.'")
            self.parent.write(0, f"{instance_var_name} = None")
            self.parent.restoreLevel(self.parent.base_level - 1)
        return is_h5py_class

    def _dispatch_fuzz_on_h5py_instance(self, class_name_hint, current_prefix, generation_depth, target_obj_expr_str):
        # Specific h5py type checks
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.Dataset):")
        L_is_dataset = self.parent.addLevel(1)
        self.parent.write(0, f"# {self.parent.base_level=}")
        self.parent.write(0, f"# {L_is_dataset=}")
        try:
            self._fuzz_one_dataset_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_ds",
                                                        generation_depth)
        finally:
            self.parent.write(0, f"# {self.parent.base_level=}")
            self.parent.restoreLevel(L_is_dataset)
        self.parent.write(0, f"# {self.parent.base_level=}")
        # self.restoreLevel(self.base_level - 1)
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.Group):  # In _dispatch_fuzz_on_instance")
        L_is_group = self.parent.addLevel(1)
        self.parent.write(0, f"# {self.parent.base_level=}")
        self.parent.write(0, f"# {L_is_group=}")
        try:
            self._fuzz_one_group_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_grp",
                                                      generation_depth)
        finally:
            self.parent.write(0, f"# {self.parent.base_level=}")
            self.parent.restoreLevel(L_is_group)
        self.parent.write(0, f"# {self.parent.base_level=}")
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.File):")
        L_is_file = self.parent.addLevel(1)
        self.parent.write(0, f"# {self.parent.base_level=}")
        try:
            self._fuzz_one_file_instance(target_obj_expr_str, class_name_hint, f"{current_prefix}_file",
                                                     generation_depth)  # We'll define this
        finally:
            self.parent.write(0, f"# {self.parent.base_level=}")
            self.parent.restoreLevel(L_is_file)
        self.parent.write(0, f"# {self.parent.base_level=}")
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.AttributeManager):")  # NEW
        L_is_attrs = self.parent.addLevel(1)
        self.parent.write(0, f"# {self.parent.base_level=}")
        try:
            self._fuzz_one_attributemanager_instance(target_obj_expr_str, class_name_hint,
                                                                 f"{current_prefix}_attrs",
                                                                 generation_depth)  # We'll define this
        finally:
            self.parent.write(0, f"# {self.parent.base_level=}")
            self.parent.restoreLevel(L_is_attrs)
        self.parent.write(0, f"# {self.parent.base_level=}")
        # Add elif for h5py.Datatype, h5py.Reference, views like DatasetFieldsView etc. later if desired
        self.parent.write(0, "else:")  # Fallback to generic method fuzzing
        L_else_generic = self.parent.addLevel(1)
        return L_else_generic

    def _fuzz_methods_on_h5py_object_or_specific_types(self, current_prefix, target_obj_expr_str):
        # Check if it's an h5py.Dataset and call specialized fuzzing for it
        # We need h5py imported in the generated script for isinstance
        self.parent.write(0, f"elif isinstance({target_obj_expr_str}, h5py.Dataset):")
        level = self.parent.addLevel(1)
        # Use a clean name for logging, e.g., derived from target_obj_expr_str or its HDF5 name
        dset_log_name = target_obj_expr_str.split('.')[-1].strip("')\"")  # Basic heuristic for name
        self._fuzz_one_dataset_instance(target_obj_expr_str, dset_log_name, current_prefix, 0)
        self.parent.restoreLevel(level)
        # Optionally, after specific fuzzing, still do some random method calls or reduce num_method_calls_to_make
        # For now, let's assume _fuzz_one_dataset_instance is comprehensive enough for datasets for this pass.
        # elif isinstance({target_obj_expr_str}, h5py.File):
        # self._fuzz_one_file_instance(target_obj_expr_str, ..., current_prefix) # Similarly for files
        # elif isinstance({target_obj_expr_str}, h5py.Group):
        # self._fuzz_one_group_instance(target_obj_expr_str, ..., current_prefix)
