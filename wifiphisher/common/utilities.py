"""Host common and generic functions.

Host all the common and generic functions that are used throughout
the project.

"""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from logging import getLogger
from subprocess import PIPE, Popen

from wifiphisher.common.constants import DN

# pylint: disable=C0103
logger = getLogger(__name__)


def execute_commands(commands):
    """Execute each command and log any errors."""
    for command in commands:
        _, error = Popen(command.split(), stderr=PIPE, stdout=DN).communicate()
        if error:
            logger.error(
                "{command} has failed with the following error:\n{error}".
                format(command=command, error=error))
