import importlib
from functools import wraps

import constants


def uimethod(func):
    def _decorator(data, *args, **kwargs):
        response = func(data, *args, **kwargs)
        return response

    func.is_uimethod = True
    return wraps(func)(_decorator)
