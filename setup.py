#!/usr/bin/env python
import sys
from setuptools import setup, find_packages
setup(
name = "wifiphisher",
author = "sophron",
author_email = "sophron@latthi.com",
description = ("Automated phishing attacks against Wi-Fi networks"),
license = "GPL",
keywords = ['wifiphisher', 'evil', 'twin', 'phishing'],
packages = find_packages(),
include_package_data = True,
version = "1.1",
entry_points = {
'console_scripts': [
'wifiphisher = wifiphisher.pywifiphisher:run'
]
},
install_requires = [
'PyRIC == 0.1.2.1',
'jinja2']
)

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
