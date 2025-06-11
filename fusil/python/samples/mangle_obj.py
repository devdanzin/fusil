
from sys import stderr
from unittest.mock import MagicMock

def mangle_obj(instance, method, *args):
    print(f'Mangling {instance} with MagicMock()s, leaving {method} intact.', file=stderr)

    # If the instance doesn't have a __dict__ (e.g., uses __slots__),
    # we can't mangle its instance attributes. Call the method directly.
    if not hasattr(instance, '__dict__'):
        try:
            func = getattr(instance, method)
            print(f'Calling {instance}.{method} on object without __dict__...', file=stderr)
            func(*args)
        except Exception as err:
            print(f"[{instance}] {method} => {err.__class__.__name__}: {err}", file=stderr)
        return

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
        print (f'[{instance}] {func.__name__} => {err.__class__.__name__}: {errmsg}', file=stderr)

    finally:
        instance.__dict__.update(real_instance_dict)
        for key, value in real_class_dict.items():
            if key.startswith('__') or key == func.__name__:
                continue
            try:
                setattr(instance.__class__, key, value)
            except Exception:
                pass