#!/usr/bin/env python
import sys
from setuptools import setup, find_packages
setup(
name = "wifiphisher",
author = "sophron",
author_email = "sophron@latthi.com",
description = ("Automated phishing attacks against Wi-Fi networks"),
license = "GPL",
keywords = ['wifiphisher', 'evil', 'twin'],
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
