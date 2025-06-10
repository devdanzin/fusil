"""
Object Mangling for Python Fuzzing

This module provides functionality to "mangle" Python objects by temporarily replacing
their attributes with mock objects while preserving specific methods for testing.
It helps discover bugs by testing how functions behave when their object dependencies
are corrupted or invalid, then safely restores the original state afterward.
"""

mangle_obj = """def mangle_obj(instance, method, *args):
    print(f'Mangling {instance} with MagicMock()s, leaving {method} intact.', file=stderr)
    real_instance_dict = instance.__dict__.copy()
    real_class_dict = instance.__class__.__dict__.copy()

    func = getattr(instance, method)

    try:
        for key, value in instance.__dict__.items():
            if key.startswith('__') or key == func.__name__:
                continue
            try:
                setattr(instance, key, MagicMock())
            except Exception:
                pass

        for key, value in instance.__class__.__dict__.items():
            if key.startswith('__') or key == func.__name__:
                continue
            try:
                setattr(instance.__class__, key, MagicMock())
            except Exception:
                pass
        print(f'Calling {instance}.{method}...', file=stderr)
        func(*args)

    except Exception as err:
        try:
            errmsg = repr(err)
        except ValueError as e:
            errmsg = repr(e)
        errmsg = errmsg.encode('ASCII', 'replace')
        print ('[%s] %s => %s: %s' % (instance, func.__name__, err.__class__.__name__, errmsg), file=stderr)

    finally:
        instance.__dict__.update(real_instance_dict)
        for key, value in real_class_dict.items():
            if key.startswith('__') or key == func.__name__:
                continue
            try:
                setattr(instance.__class__, key, value)
            except Exception:
                pass
"""

# The weird indentation is necessary because we write this in two levels
mangle_loop = """if hasattr(obj.__class__, '__dict__'):
        for key, attr in obj.__class__.__dict__.items():
            args = %s
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
"""
