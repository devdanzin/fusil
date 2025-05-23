import sys
from ast import literal_eval
from string.templatelib import Interpolation, Template

from fusil.python.tricky_weird import weird_instance_names, weird_names
from fusil.python.values import INTERESTING, SURROGATES

sys.set_int_max_str_digits(4305)

TEMPLATES = []
for value in SURROGATES:
    TEMPLATES.append(f"""Template({value}, Interpolation({value}, "value"))""")

for value in INTERESTING:
    TEMPLATES.append(f"""Template("\\x00", Interpolation({value}, "value"))""")

for name in weird_instance_names:
    TEMPLATES.append(
        f"""Template("\\x00", Interpolation(weird_instances['{name}'], "name"))"""
    )

for name in weird_names:
    TEMPLATES.append(
        f"""Template("\\x00", Interpolation(weird_classes['{name}'], "name"))"""
    )
