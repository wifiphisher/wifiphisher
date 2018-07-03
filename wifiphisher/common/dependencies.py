"""Handle dependency check.

This module checks for all the required dependency needed for full
function.
"""

from collections import namedtuple
from distutils.spawn import find_executable


Result = namedtuple("Result", ["status", "missing"])


def is_all_dependencies_installed():
    # type: () -> Result
    """Check all required dependencies are installed.

    Check to see if all the required depedencies are installed. It will
    return as soon as it finds a missing dependency.
    """
    dependencies = ["dnsmasq", "roguehostapd"]
    missing = []  # type: List[str]

    for dependency in dependencies:
        if not find_executable(dependency):
            missing.append(dependency)

    return Result(status=not missing, missing=missing)
