"""
Object Mangling for Python Fuzzing

This module provides functionality to "mangle" Python objects by temporarily replacing
their attributes with mock objects while preserving specific methods for testing.
It helps discover bugs by testing how functions behave when their object dependencies
are corrupted or invalid, then safely restores the original state afterward.
"""

import pathlib

parent_dir = pathlib.Path(__file__).parent
mangle_obj_file =  parent_dir / "samples/mangle_obj.py"
mangle_obj = mangle_obj_file.read_text()

mangle_loop_file =  parent_dir / "samples/mangle_loop.py"
mangle_loop = mangle_loop_file.read_text()
mangle_loop = mangle_loop.replace("REPLACEMENT_PLACEHOLDER", "%s")
