"""Host common and generic functions.

Host all the common and generic functions that are used throughout
the project.

"""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from logging import getLogger
from subprocess import (PIPE, Popen)
from ConfigParser import ConfigParser
from wifiphisher.common.constants import DN

# pylint: disable=C0103
logger = getLogger(__name__)


def execute_commands(commands):
    # type: (List[str]) -> None
    """Execute each command and log any errors."""
    for command in commands:
        _, error = Popen(command.split(), stderr=PIPE, stdout=DN).communicate()
        if error:
            logger.error(
                "{command} has failed with the following error:\n{error}".
                format(command=command, error=error))


def config_section_map(config_file, section):
    """Map the values of a config file to a dictionary."""
    config = ConfigParser()
    config.read(config_file)
    dict1 = {}

    if section not in config.sections():
        return dict1

    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
        except KeyError:
            dict1[option] = None
    return dict1
