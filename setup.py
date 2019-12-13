#!/usr/bin/env python3
r"""
                     _  __ _       _     _     _
                    (_)/ _(_)     | |   (_)   | |
  ((.))    __      ___| |_ _ _ __ | |__  _ ___| |__   ___ _ __
    |      \ \ /\ / / |  _| | '_ \| '_ \| / __| '_ \ / _ \ '__|
   /_\      \ V  V /| | | | | |_) | | | | \__ \ | | |  __/ |
  /___\      \_/\_/ |_|_| |_| .__/|_| |_|_|___/_| |_|\___|_|
 /     \                    | |
                            |_|  Version {}
"""



import os
import sys

from setuptools import Command, find_packages, setup

import wifiphisher.common.constants as constants

try:
    raw_input  # Python 2
    sys.exit("Please use Python 3 to install Wifiphisher.")
except NameError:
    pass  # Python 3


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')

def get_dnsmasq():
    """
    Try to install dnsmasq on host machine if not present.

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        install = input(("[" + constants.T + "*" + constants.W + "] dnsmasq not found " +
                             "in /usr/sbin/dnsmasq, " + "install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S dnsmasq")
            elif os.path.isfile("/usr/bin/yum"):
                os.system("yum install dnsmasq")
            elif os.path.isfile("/usr/bin/dnf"):
                os.system("dnf -y install dnsmasq")
            else:
                os.system("apt-get -y install dnsmasq")
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] dnsmasq " +
                      "not found in /usr/sbin/dnsmasq"))

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        dnsmasq_message = ("\n[" + constants.R + "-" + constants.W +
                           "] Unable to install the \'dnsmasq\' package!\n" + "[" + constants.T +
                           "*" + constants.W + "] This process requires a persistent internet " +
                           "connection!\nPlease follow the link below to configure your " +
                           "sources.list\n" + constants.B + "http://docs.kali.org/general-use/" +
                           "kali-linux-sources-list-repositories\n" + constants.W + "[" +
                           constants.G + "+" + constants.W + "] Run apt-get update for changes " +
                           "to take effect.\n" + "[" + constants.G + "+" + constants.W + "] " +
                           "Rerun the script to install dnsmasq.\n[" + constants.R + "!" +
                           constants.W + "] Closing")

        sys.exit(dnsmasq_message)

# setup settings
NAME = "wifiphisher"
AUTHOR = "sophron"
AUTHOR_EMAIL = "sophron@latthi.com"
URL = "https://github.com/wifiphisher/wifiphisher"
DESCRIPTION = "Automated phishing attacks against Wi-Fi networks"
LICENSE = "GPL"
KEYWORDS = ["wifiphisher", "evil", "twin", "phishing"]
PACKAGES = find_packages(exclude=["docs", "tests"])
INCLUDE_PACKAGE_DATA = True
VERSION = "1.4"
CLASSIFIERS = ["Development Status :: 5 - Production/Stable",
               "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
               "Natural Language :: English", "Operating System :: Unix",
               "Programming Language :: Python :: 2", "Programming Language :: Python :: 2.7",
               "Programming Language :: Python :: 2 :: Only", "Topic :: Security",
               "Topic :: System :: Networking", "Intended Audience :: End Users/Desktop",
               "Intended Audience :: System Administrators",
               "Intended Audience :: Information Technology"]
ENTRY_POINTS = {"console_scripts": ["wifiphisher = wifiphisher.pywifiphisher:run"]}
# WORKAROUND: Download tornado 4.5.3 instead of latest so travis won't complain
INSTALL_REQUIRES = ["pbkdf2", "scapy", "tornado==4.5.3", "roguehostapd", "pyric"]
DEPENDENCY_LINKS = \
["http://github.com/wifiphisher/roguehostapd/tarball/master#egg=roguehostapd-1.9.0", \
"http://github.com/sophron/pyric/tarball/master#egg=pyric-0.5.0"]
CMDCLASS = {"clean": CleanCommand,}

# run setup
setup(name=NAME, author=AUTHOR, author_email=AUTHOR_EMAIL, description=DESCRIPTION,
      license=LICENSE, keywords=KEYWORDS, packages=PACKAGES,
      include_package_data=INCLUDE_PACKAGE_DATA, version=VERSION, entry_points=ENTRY_POINTS,
      install_requires=INSTALL_REQUIRES, dependency_links=DEPENDENCY_LINKS,
      classifiers=CLASSIFIERS, url=URL, cmdclass=CMDCLASS)

get_dnsmasq()

print(__doc__.format(VERSION))  # print the docstring located at the top of this file
