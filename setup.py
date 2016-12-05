#!/usr/bin/env python
import sys
import os
from setuptools import setup, find_packages
from distutils.spawn import find_executable
from wifiphisher.constants import *
setup(
name = "wifiphisher",
author = "sophron",
author_email = "sophron@latthi.com",
description = ("Automated phishing attacks against Wi-Fi networks"),
license = "GPL",
keywords = ['wifiphisher', 'evil', 'twin', 'phishing'],
packages = find_packages(),
include_package_data = True,
version = "1.2",
entry_points = {
'console_scripts': [
'wifiphisher = wifiphisher.pywifiphisher:run'
]
},
install_requires = [
'PyRIC',
'jinja2']
)

def get_dnsmasq():
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        install = raw_input(
            ('[' + T + '*' + W + '] dnsmasq not found ' +
             'in /usr/bin/dnsmasq, install now? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S dnsmasq')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install dnsmasq')
            else:
                os.system('apt-get -y install dnsmasq')
        else:
            sys.exit(('[' + R + '-' + W + '] dnsmasq' +
                     ' not found in /usr/sbin/dnsmasq'))
    if not os.path.isfile('/usr/sbin/dnsmasq'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'dnsmasq\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script to install dnsmasq.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

def get_hostapd():
    if not os.path.isfile('/usr/sbin/hostapd'):
        install = raw_input(
            ('[' + T + '*' + W + '] hostapd not found ' +
             'in /usr/sbin/hostapd, install now? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S hostapd')
            elif os.path.isfile('/usr/bin/yum'):
                os.system('yum install hostapd')
            else:
                os.system('apt-get -y install hostapd')
        else:
            sys.exit(('[' + R + '-' + W + '] hostapd' +
                     ' not found in /usr/sbin/hostapd'))
    if not os.path.isfile('/usr/sbin/hostapd'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'hostapd\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            'Please follow the link below to configure your sources.list\n' +
            B + 'http://docs.kali.org/general-use/kali-linux-sources-list-repositories\n' + W +
            '[' + G + '+' + W + '] Run apt-get update for changes to take effect.\n' +
            '[' + G + '+' + W + '] Rerun the script to install hostapd.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

def get_ifconfig():
    # This is only useful for Arch Linux which does not contain ifconfig by default
    if not find_executable('ifconfig'):
        install = raw_input(
            ('[' + T + '*' + W + '] ifconfig not found. ' +
             'install now? [y/n] ')
        )
        if install == 'y':
            if os.path.isfile('/usr/bin/pacman'):
                os.system('pacman -S net-tools')
            else:
                sys.exit((
                    '\n[' + R + '-' + W + '] Don\'t know how to install ifconfig for your distribution.\n' +
                    '[' + G + '+' + W + '] Rerun the script after installing it manually.\n' +
                    '[' + R + '!' + W + '] Closing'
                ))
        else:
            sys.exit(('[' + R + '-' + W + '] ifconfig' +
                     ' not found'))
    if not find_executable('ifconfig'):
        sys.exit((
            '\n[' + R + '-' + W + '] Unable to install the \'net-tools\' package!\n' +
            '[' + T + '*' + W + '] This process requires a persistent internet connection!\n' +
            '[' + G + '+' + W + '] Run pacman -Syu to make sure you are up to date first.\n' +
            '[' + G + '+' + W + '] Rerun the script to install net-tools.\n' +
            '[' + R + '!' + W + '] Closing'
         ))

# Get hostapd, dnsmasq or ifconfig if needed
get_hostapd()
get_dnsmasq()
get_ifconfig()

print
print "                     _  __ _       _     _     _               "
print "                    (_)/ _(_)     | |   (_)   | |              "
print "  ((.))    __      ___| |_ _ _ __ | |__  _ ___| |__   ___ _ __ "
print "    |      \ \ /\ / / |  _| | '_ \| '_ \| / __| '_ \ / _ \ '__|"
print "   /_\      \ V  V /| | | | | |_) | | | | \__ \ | | |  __/ |   "
print "  /___\      \_/\_/ |_|_| |_| .__/|_| |_|_|___/_| |_|\___|_|   "
print " /     \                    | |                                "
print "                            |_|                                "
print "                                                               "
