#!/usr/bin/env python
"""
This module tries to install all the required software.
"""

from __future__ import print_function
import sys
import os
from setuptools import setup, find_packages, Command
import wifiphisher.common.constants as constants


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
    Try to install dnsmasq on host machine if not present

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        install = raw_input(
            ("[" + constants.T + "*" + constants.W + "] dnsmasq not found " +
             "in /usr/sbin/dnsmasq, " + "install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S dnsmasq")
            elif os.path.isfile("/usr/bin/yum"):
                os.system("yum install dnsmasq")
            else:
                os.system("apt-get -y install dnsmasq")
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] dnsmasq " +
                      "not found in /usr/sbin/dnsmasq"))

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        dnsmasq_message = (
            "\n[" + constants.R + "-" + constants.W +
            "] Unable to install the \'dnsmasq\' package!\n" + "[" +
            constants.T + "*" + constants.W +
            "] This process requires a persistent internet " +
            "connection!\nPlease follow the link below to configure your " +
            "sources.list\n" + constants.B +
            "http://docs.kali.org/general-use/" +
            "kali-linux-sources-list-repositories\n" + constants.W + "[" +
            constants.G + "+" + constants.W +
            "] Run apt-get update for changes " + "to take effect.\n" + "[" +
            constants.G + "+" + constants.W + "] " +
            "Rerun the script to install dnsmasq.\n[" + constants.R + "!" +
            constants.W + "] Closing")

        sys.exit(dnsmasq_message)


THIS_DIR = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(THIS_DIR, "README.md")) as f:
    LONG_DESCRIPTION = f.read()

setup(
    name="wifiphisher",
    author="sophron",
    author_email="sophron@latthi.com",
    description="Automated phishing attacks against Wi-Fi networks",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    license="GPL",
    keywords=["wifiphisher", "evil", "twin", "phishing"],
    packages=find_packages(exclude=["docs", "tests"]),
    include_package_data=True,
    version="1.4",
    python_requires="~=2.7",
    url="https://github.com/wifiphisher/wifiphisher",
    project_urls={
        "Documentation": "http://wifiphisher.readthedocs.io/en/latest/",
        "Source": "https://github.com/wifiphisher/wifiphisher/",
        "Tracker": "https://github.com/wifiphisher/wifiphisher/issues",
    },
    entry_points={
        "console_scripts": ["wifiphisher = wifiphisher.pywifiphisher:run"]
    },
    install_requires=[
        "PyRIC", "tornado==4.5.3", "pbkdf2", "roguehostapd", "scapy"
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Natural Language :: English", "Operating System :: Unix",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 2 :: Only", "Topic :: Security",
        "Topic :: System :: Networking",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology"
    ],
    cmdclass={
        "clean": CleanCommand,
    })

get_dnsmasq()

print()
print("                     _  __ _       _     _     _               ")
print("                    (_)/ _(_)     | |   (_)   | |              ")
print("  ((.))    __      ___| |_ _ _ __ | |__  _ ___| |__   ___ _ __ ")
print(r"    |      \ \ /\ / / |  _| | '_ \| '_ \| / __| '_ \ / _ \ '__|")
print(r"   /_\      \ V  V /| | | | | |_) | | | | \__ \ | | |  __/ |   ")
print(r"  /___\      \_/\_/ |_|_| |_| .__/|_| |_|_|___/_| |_|\___|_|   ")
print(r" /     \                    | |                                ")
print("                            |_|                                ")
print("                                                               ")
