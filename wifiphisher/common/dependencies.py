"""Handle dependency check.

This module checks for all the required dependency needed for full
function.
"""

from collections import namedtuple
from subprocess import (check_call, CalledProcessError)
from wifiphisher.common.constants import DN


Result = namedtuple("Result", ["status", "missing"])


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


def is_all_dependencies_installed():
    # type: () -> Result
    """Check all required dependencies are installed.

    Check to see if all the required depedencies are installed. It will
    return as soon as it finds a missing dependency.
    """
    dependencies = ["dnsmasq", "roguehostapd"]
    missing = []  # type: List[str]

    for dependency in dependencies:
        if not is_installed(dependency):
            missing.append(dependency)

    return Result(status=not missing, missing=missing)
