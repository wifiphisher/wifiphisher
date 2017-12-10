import constants
import importlib
from functools import wraps


def uimethod(func):
    def _decorator(data, *args, **kwargs):
        response = func(data, *args, **kwargs)
        return response

    func.is_uimethod = True
    return wraps(func)(_decorator)
