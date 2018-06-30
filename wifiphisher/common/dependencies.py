"""Handle dependency check.

This module checks for all the required dependency needed for full
function.
"""

from typing import NamedTuple
from subprocess import (check_call, CalledProcessError)
from .constants import DN

Result = NamedTuple("Result", [("status", bool), ("name", str)])


def is_installed(application):
    # type: (str) -> bool
    """Check if application is installed.

    Return True if application is installed and False otherwise.
    """
    try:
        check_call(["which", application], stdout=DN, stderr=DN)
    except CalledProcessError:
        return False

    return True


def check_dependencies():
    # type: () -> Result
    """Check all required dependencies are installed.

    Check to see if all the required depedencies are installed. It will
    return as soon as it finds a missing dependency.
    """
    dependencies = ["dnsmasq"]

    for dependency in dependencies:
        if not is_installed(dependency):
            return Result(status=False, name=dependency)

    return Result(status=True, name="")
