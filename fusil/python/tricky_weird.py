"""
Tricky and Weird Objects

This module defines problematic Python objects, classes, and edge cases designed to
trigger bugs. It contains boundary values like maximum integers, weird classes,
circular references, and other pathological objects that can expose crashes and other
undesirable behavior in Python code and C extensions.
"""

import pathlib
from fusil.python.samples import weird_classes, tricky_typing, tricky_objects

try:
    from fusil.python.samples import tricky_numpy
except ImportError:
    print("Could not import tricky_numpy.")
    tricky_numpy = None

weird_instance_names = list(weird_classes.weird_instances.keys())
weird_names = list(weird_classes.weird_classes.keys())

tricky_objects_dict = tricky_objects.__dict__

tricky_objects_names = [
    key for key in tricky_objects_dict.keys()
    if isinstance(key, str) and not key.startswith('_')
]

tricky_numpy_names = [
    name for name in dir(tricky_numpy)
    if name.startswith('numpy_')
] if tricky_numpy else []

weird_classes = pathlib.Path(weird_classes.__file__).read_text()
tricky_typing = pathlib.Path(tricky_typing.__file__).read_text()
tricky_objects = pathlib.Path(tricky_objects.__file__).read_text()
if tricky_numpy:
    tricky_numpy = pathlib.Path(tricky_numpy.__file__).read_text()

type_names = ("list", "tuple", "dict")
