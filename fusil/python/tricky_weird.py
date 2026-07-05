"""
Tricky and Weird Objects

This module defines problematic Python objects, classes, and edge cases designed to
trigger bugs. It contains boundary values like maximum integers, weird classes,
circular references, and other pathological objects that can expose crashes and other
undesirable behavior in Python code and C extensions.
"""

import logging
import pathlib

from fusil.python.samples import bomb_objects, tricky_objects, tricky_typing, weird_classes

logger = logging.getLogger(__name__)

weird_instance_names = list(weird_classes.weird_instances.keys())
weird_names = list(weird_classes.weird_classes.keys())

tricky_objects_dict = tricky_objects.__dict__

tricky_objects_names = [
    key for key in tricky_objects_dict.keys() if isinstance(key, str) and not key.startswith("_")
]

bomb_object_names = list(bomb_objects.BOMB_CLASS_NAMES)
bomb_type_names = list(bomb_objects.BOMB_TYPE_NAMES)

weird_classes = pathlib.Path(weird_classes.__file__).read_text()
tricky_typing = pathlib.Path(tricky_typing.__file__).read_text()
tricky_objects = pathlib.Path(tricky_objects.__file__).read_text()
bomb_objects = pathlib.Path(bomb_objects.__file__).read_text()

type_names = ("list", "tuple", "dict")
