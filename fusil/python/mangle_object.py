"""
Object Mangling for Python Fuzzing

This module provides functionality to "mangle" Python objects by temporarily replacing
their attributes with mock objects while preserving specific methods for testing.
It helps discover bugs by testing how functions behave when their object dependencies
are corrupted or invalid, then safely restores the original state afterward.
"""

import pathlib

mangle_obj = pathlib.Path("./samples/mangle_obj.py").read_text()
mangle_loop = pathlib.Path("./samples/mangle_loop.py").read_text()
mangle_loop = mangle_loop.replace("REPLACEMENT_PLACEHOLDER", "%s")
