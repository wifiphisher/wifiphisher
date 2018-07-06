"""Handle dependency check.

This module checks for all the required dependency needed for full
function.
"""
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from itertools import ifilterfalse
from subprocess import (check_call, CalledProcessError)
from wifiphisher.common.constants import DN


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


def find_missing_dependencies():
    # type: () -> List[str]
    """Check all required dependencies are installed.

    Check to see if all the required depedencies are installed. It will
    return a list of all missing dependencies.
    """
    dependencies = ["dnsmasq", "iptables"]

    return list(ifilterfalse(is_installed, dependencies))
