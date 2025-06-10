import inspect
from sys import stderr

if False:
    obj = None
    mangle_obj = None

# The weird indentation is necessary because we write this in two levels
if hasattr(obj.__class__, '__dict__'):
        for key, attr in obj.__class__.__dict__.items():
            args = REPLACEMENT_PLACEHOLDER  # noqa
            try:
                args = len(inspect.getfullargspec(attr).args)
            except Exception:
                pass
            if key.startswith('__'):
                continue
            try:
                mangle_obj(obj, key, (1,) * args)
            except Exception as err:
                print(err, file=stderr)
