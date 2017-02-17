#!/usr/bin/env python
"""
This module tries to install all the required software.
"""

from __future__ import print_function
import sys
import os
from distutils.spawn import find_executable
from setuptools import setup, find_packages
import wifiphisher.constants as constants


def get_dnsmasq():
    """
    Try to install dnsmasq on host machine if not present

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] dnsmasq not found " +
                             "in /usr/bin/dnsmasq, " + "install now? [y/n] "))

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


def get_hostapd():
    """
    Try to install hostapd on host system if not present

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/hostapd"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] hostapd not found in " +
                             "/usr/sbin/hostapd, install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S hostapd")
            elif os.path.isfile("/usr/bin/yum"):
                os.system("yum install hostapd")
            else:
                os.system("apt-get -y install hostapd")
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] hostapd not found in " +
                      "/usr/sbin/hostapd"))

    if not os.path.isfile("/usr/sbin/hostapd"):
        hostapd_message = ("\n[" + constants.R + "-" + constants.W + "] Unable to install the " +
                           "\'hostapd\' package!\n[" + constants.T + "*" + constants.W + "] " +
                           "This process requires a persistent internet connection!\nPlease " +
                           "follow the link below to configure your sources.list\n" + constants.B +
                           "http://docs.kali.org/general-use/kali-linux-sources-list-" +
                           "repositories\n" + constants.W + "[" + constants.G + "+" + constants.W +
                           "] Run apt-get update for changes to take effect.\n[" + constants.G +
                           "+" + constants.W + "] Rerun the script to install hostapd.\n[" +
                           constants.R + "!" + constants.W + "] Closing")

        sys.exit(hostapd_message)


def get_ifconfig():
    """
    Try to install ifconfig on host machine if not present

    :return: None
    :trype: None
    """

    # this is only useful for Arch Linux which does not contain
    # ifconfig by default
    if not find_executable("ifconfig"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] ifconfig not found. " +
                             "install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S net-tools")
            else:
                sys.exit(("\n[" + constants.R + "-" + constants.W + "] Don\'t know how to " +
                          "install ifconfig for your distribution.\n[" + constants.G + "+" +
                          constants.W + "] Rerun the script after installing it manually.\n[" +
                          constants.R + "!" + constants.W + "] Closing"))
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] ifconfig not found"))

    if not find_executable("ifconfig"):
        ifconfig_message = ("\n[" + constants.R + "-" + constants.W + "] Unable to install the " +
                            "\"net-tools\" package!\n[" + constants.T + "*" + constants.W + "] " +
                            "This process requires a persistent internet connection!\n[" +
                            constants.G + "+" + constants.W + "] Run pacman -Syu to make sure " +
                            "you are up to date first.\n[" + constants.G + "+" + constants.W +
                            "] Rerun the script to " + "install net-tools.\n[" + constants.R +
                            "!" + constants.W + "] Closing")

        sys.exit(ifconfig_message)


# setup settings
NAME = "wifiphisher"
AUTHOR = "sophron"
AUTHOR_EMAIL = "sophron@latthi.com"
DESCRIPTION = "Automated phishing attacks against Wi-Fi networks"
LICENSE = "GPL"
KEYWORDS = ["wifiphisher", "evil", "twin", "phishing"]
PACKAGES = find_packages()
INCLUDE_PACKAGE_DATA = True
VERSION = "1.2"
ENTRY_POINTS = {"console_scripts": ["wifiphisher = wifiphisher.pywifiphisher:run"]}
INSTALL_REQUIRES = ["PyRIC", "tornado", "blessings>=1.6"]


# run setup
setup(name=NAME, author=AUTHOR, author_email=AUTHOR_EMAIL, description=DESCRIPTION,
      license=LICENSE, keywords=KEYWORDS, packages=PACKAGES,
      include_package_data=INCLUDE_PACKAGE_DATA, version=VERSION, entry_points=ENTRY_POINTS,
      install_requires=INSTALL_REQUIRES)

# Get hostapd, dnsmasq or ifconfig if needed
get_hostapd()
get_dnsmasq()
get_ifconfig()

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
